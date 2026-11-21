"""Static feature extraction for sample similarity.

PE structure comes from pefile. Native code (PE, ELF, Mach-O) is cut into
function ranges that cover every executable section (native.py), then
disassembled with capstone and hashed on normalised instruction tokens, so the
same code at a different address gives the same fingerprint. Managed .NET
assemblies use the CIL method bodies instead (cil.py).

Everything returned is plain JSON-serialisable data. The raw sample is never
stored: callers persist the returned dict and delete the file.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from typing import Dict, List, Optional, Set

try:  # optional: fuzzy whole-file hash
    import tlsh as _tlsh
except Exception:  # pragma: no cover
    _tlsh = None

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None

from sample_similarity import identity, native, pyinstaller

EXTRACTOR_VERSION = 7

MAX_CODE_BYTES = 8 * 1024 * 1024   # total executable bytes scanned per sample
SHINGLE = 8                       # bytes per code shingle
SAMPLE_MASK = 0xF                 # keep ~1 in 16 shingles (content-defined)
SKETCH_K = 64                     # bottom-k sketch size for .text shingles
MAX_STRINGS = 50000  # per sample; a cap that cuts by file order silently drops shared strings
MIN_STRING = 6
PROGRAM_TLSH_MIN = 4096      # program bytes below this are too small for a TLSH distance

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx0": "UPX", ".upx1": "UPX",
    ".themida": "Themida", ".winlice": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".nsp0": "NsPack", ".nsp1": "NsPack",
}
VERSION_KEYS = ("CompanyName", "ProductName", "OriginalFilename", "InternalName")

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 4)


def _hash_hex(data: bytes, algo: str) -> str:
    return hashlib.new(algo, data).hexdigest()


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # 32-bit, both byte orders
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit, both byte orders
    b"\xca\xfe\xba\xbe",                          # fat (universal) header
}


def _file_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in MACHO_MAGICS:
        return "MACHO"
    return "other"


def extract_strings(data: bytes) -> List[str]:
    found: Dict[str, None] = {}
    for m in _ASCII_RE.finditer(data):
        if len(found) >= MAX_STRINGS:
            break
        found.setdefault(m.group().decode("ascii").strip().lower(), None)
    for m in _UTF16_RE.finditer(data):
        if len(found) >= MAX_STRINGS:
            break
        found.setdefault(m.group().decode("utf-16-le").strip().lower(), None)
    return [s[:200] for s in found if s]


def mask_code(code: bytes) -> bytes:
    """Zero the displacement bytes of position-dependent x64 operands.

    This is a byte-pattern heuristic, not instruction decoding:
      E8/E9 rel32            call/jmp near
      FF 15 / FF 25 disp32   call/jmp [rip+disp]
      48|4C 8B|8D modrm05    mov/lea reg,[rip+disp]
    False positives only blank a few extra bytes, which is acceptable for
    fingerprinting.
    """
    buf = bytearray(code)
    n = len(buf)
    i = 0
    while i < n:
        b = buf[i]
        if b in (0xE8, 0xE9) and i + 5 <= n:
            buf[i + 1:i + 5] = b"\0\0\0\0"
            i += 5
            continue
        if b == 0xFF and i + 6 <= n and buf[i + 1] in (0x15, 0x25):
            buf[i + 2:i + 6] = b"\0\0\0\0"
            i += 6
            continue
        if b in (0x48, 0x4C) and i + 7 <= n and buf[i + 1] in (0x8B, 0x8D) and (buf[i + 2] & 0xC7) == 0x05:
            buf[i + 3:i + 7] = b"\0\0\0\0"
            i += 7
            continue
        i += 1
    return bytes(buf)


def _sketch(shingles: Set[int], k: int = SKETCH_K) -> List[int]:
    return sorted(shingles)[:k]


def _shingle_hashes(code: bytes) -> Set[int]:
    """Content-defined sample of 8-byte shingles (position independent)."""
    out: Set[int] = set()
    add = out.add
    for i in range(0, max(0, len(code) - SHINGLE + 1)):
        v = int.from_bytes(code[i:i + SHINGLE], "little")
        h = (v * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        if (h >> 60) & SAMPLE_MASK == 0:
            add(h)
    return out


def _pe_features(pe, data: bytes) -> dict:
    out: dict = {}
    out["imphash"] = ""
    try:
        out["imphash"] = pe.get_imphash() or ""
    except Exception:
        pass

    # imports: lower-cased function names only (DLL and ordinal differences ignored)
    names: Set[str] = set()
    iat_map: Dict[int, str] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports or []:
            if imp.name:
                nm = imp.name.decode("ascii", "ignore").lower()
                names.add(nm)
                if imp.address:
                    iat_map[int(imp.address) - int(pe.OPTIONAL_HEADER.ImageBase)] = nm
    out["imports"] = sorted(names)

    rich = None
    try:
        rich = pe.parse_rich_header()
    except Exception:
        rich = None
    if rich and rich.get("values"):
        seq = ",".join(f"{cid}:{cnt}" for cid, cnt in zip(rich["values"][0::2], rich["values"][1::2]))
        out["rich_hash"] = hashlib.sha256(seq.encode()).hexdigest()
    else:
        out["rich_hash"] = ""

    version: Dict[str, str] = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi if isinstance(fi, list) else [fi]:
                if getattr(entry, "Key", b"") == b"StringFileInfo":
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            key = k.decode("utf-8", "ignore")
                            if key in VERSION_KEYS and v:
                                version[key] = v.decode("utf-8", "ignore").strip().lower()
    except Exception:
        pass
    out["version_info"] = version

    pdb = ""
    try:
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            if getattr(dbg.struct, "Type", 0) == 2 and hasattr(dbg.entry, "PdbFileName"):
                pdb = dbg.entry.PdbFileName.rstrip(b"\0").decode("utf-8", "ignore").lower()
    except Exception:
        pass
    out["pdb_path"] = pdb

    sections = []
    packer = ""
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("utf-8", "ignore").lower()
        raw = s.get_data()
        ent = entropy(raw) if raw else 0.0
        sections.append({
            "name": name,
            "raw_size": int(s.SizeOfRawData),
            "virtual_size": int(s.Misc_VirtualSize),
            "entropy": ent,
            "executable": bool(s.Characteristics & 0x20000000),
            "discardable": bool(s.Characteristics & 0x02000000),
        })
        if not packer and name in PACKER_SECTIONS:
            packer = PACKER_SECTIONS[name]
    if not packer and any(s["entropy"] > 7.2 and s["executable"] and s["raw_size"] > 4096 for s in sections):
        packer = "unknown (high-entropy code)"
    out["sections"] = sections
    out["packer"] = packer

    try:
        overlay_off = pe.get_overlay_data_start_offset()
    except Exception:
        overlay_off = None
    if overlay_off and overlay_off < len(data):
        ov = data[overlay_off:]
        out["overlay"] = {"size": len(ov), "sha256": hashlib.sha256(ov).hexdigest()}
    else:
        out["overlay"] = {"size": 0, "sha256": ""}

    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
    out["signed"] = bool(sec_dir.Size)

    out["code"], out["api_behaviour"] = _pe_code(pe, data, iat_map)
    return out


def _is_managed(pe) -> bool:
    """True when the PE carries a CLI header (a .NET assembly)."""
    try:
        cli = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        return bool(cli.VirtualAddress and cli.Size)
    except Exception:
        return False


def _managed_code(data: bytes):
    """CIL method features for .NET assemblies. Returns (code, apis, status)."""
    from sample_similarity import cil
    res = cil.analyse(data, MAX_CODE_BYTES)
    if res["status"] != "success":
        return ({"function_count": 0, "function_hashes": [], "sketch": [], "bytes_scanned": 0,
                 "kind": "managed"}, [], res["status"])
    code = {
        "kind": "managed",
        "function_count": res["decoded"],
        "function_hashes": sorted({f["hash"] for f in res["functions"]}),
        "sketch": _sketch(res["shingles"]),
        "bytes_scanned": res["bytes_scanned"],
        "skipped": res["skipped"],
        "failed": res["failed"],
    }
    return code, sorted(res["apis"]), "success"


def _pe_code(pe, data: bytes, iat_map: Dict[int, str]):
    """Function-level code features. Managed assemblies use CIL bodies; native
    x64 code uses the .pdata exception table for function bounds."""
    if _is_managed(pe):
        code, apis, status = _managed_code(data)
        if status == "success":
            return code, apis
    functions: List[dict] = []
    exec_ranges = []
    for s in pe.sections:
        if s.Characteristics & 0x20000000:
            exec_ranges.append((int(s.VirtualAddress), int(s.VirtualAddress + s.Misc_VirtualSize)))

    budget = MAX_CODE_BYTES
    text_shingles: Set[int] = set()
    entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None) or []
    for e in entries:
        begin = int(getattr(e.struct, "BeginAddress", 0))
        end = int(getattr(e.struct, "EndAddress", 0))
        if end <= begin or not any(a <= begin < b for a, b in exec_ranges):
            continue
        size = end - begin
        if size > budget:
            break
        try:
            off = pe.get_offset_from_rva(begin)
        except Exception:
            continue
        raw = data[off:off + size]
        if len(raw) < size:
            continue
        budget -= size
        masked = mask_code(raw)
        fn_hash = hashlib.sha256(masked).hexdigest()[:32]
        apis = set()
        for m in re.finditer(rb"\xff\x15(.{4})", raw, re.S):
            pos = m.start()
            disp = struct.unpack("<i", m.group(1))[0]
            target = begin + pos + 6 + disp
            if target in iat_map:
                apis.add(iat_map[target])
        functions.append({
            "hash": fn_hash,
            "size": size,
            "apis": sorted(apis),
        })
        text_shingles |= _shingle_hashes(masked)

    if not functions:
        return {"function_count": 0, "function_hashes": [], "sketch": [], "bytes_scanned": 0}, []

    code = {
        "function_count": len(functions),
        "function_hashes": sorted({f["hash"] for f in functions}),
        "sketch": _sketch(text_shingles),
        "bytes_scanned": MAX_CODE_BYTES - budget,
    }
    all_apis = sorted({a for f in functions for a in f["apis"]})
    return code, all_apis


def extract_features(data: bytes, file_name: str = "") -> dict:
    """Return the feature document for one sample. `data` is the full file."""
    ftype = _file_type(data)
    feats: dict = {
        "extractor_version": EXTRACTOR_VERSION,
        "file_name": file_name,
        "file_type": ftype,
        "file_size": len(data),
        "sha256": _hash_hex(data, "sha256"),
        "sha1": _hash_hex(data, "sha1"),
        "md5": _hash_hex(data, "md5"),
        "entropy": entropy(data),
        "tlsh": "",
        "strings": extract_strings(data),
        "imphash": "",
        "imports": [],
        "rich_hash": "",
        "version_info": {},
        "pdb_path": "",
        "sections": [],
        "packer": "",
        "overlay": {"size": 0, "sha256": ""},
        "signed": False,
        "code": {"function_count": 0, "function_hashes": [], "sketch": []},
        "api_behaviour": [],  # resolved import names reached from code
        "statuses": {"hashes": "success", "strings": "success", "pe": "skipped", "code": "skipped", "tlsh": "skipped"},
    }

    if _tlsh is not None and len(data) >= 256:
        try:
            t = _tlsh.hash(data)
            if t and t != "TNULL":
                feats["tlsh"] = t
                feats["statuses"]["tlsh"] = "success"
        except Exception:
            feats["statuses"]["tlsh"] = "failed"

    if ftype == "PE" and pefile is not None:
        try:
            pe = pefile.PE(data=data, fast_load=False)
            try:
                feats.update(_pe_features(pe, data))
                feats["statuses"]["pe"] = "success"
                if feats["code"].get("kind") == "managed":
                    feats["statuses"]["code"] = "success" if feats["code"]["function_count"] else "no decodable functions"
            finally:
                pe.close()
        except Exception as exc:
            feats["statuses"]["pe"] = "failed"
            feats["statuses"]["pe_error"] = str(exc)[:200]

    # Language identity first: GoReSym's exact Go function bounds feed native analysis.
    ident = identity.analyse(data, ftype)
    feats["go"] = ident["go"]
    feats["lang"] = ident["lang"]
    feats["statuses"]["go"] = ident["go"]["status"]
    feats["statuses"]["lang"] = ident["lang"]["status"]

    # PyInstaller bundle: the program is the bundled Python, not the launcher.
    # Score its own modules and literals; the launcher and embedded standard
    # library are shared by every bundle of this PyInstaller version.
    bundle = False
    if ftype in ("PE", "ELF", "MACHO"):
        pyi = pyinstaller.analyse(data)
        feats["statuses"]["pyinstaller"] = pyi["status"]
        if pyi["status"] == "success":
            bundle = True
            feats["py_modules"] = sorted(m for m in pyi.get("modules") or [] if pyinstaller.is_program_module(m))
            sym = pyinstaller.program_symbols(pyi)
            feats["py_symbols"] = sym["names"]
            feats["statuses"]["py_symbols"] = sym["status"]
            # Literals come from the program's unmarshalled code objects, not a raw
            # byte scan: marshal bytes produce junk runs like "<module>r".
            feats["program_strings"] = sym["strings"]
            feats["statuses"]["program_strings"] = sym["status"]
            own = pyinstaller.program_bytes(pyi)
            # Fuzzy similarity over the program's own code bytes (the launcher's
            # code is the same in every bundle, so it is never fingerprinted).
            if own:
                feats["code"] = {"kind": "python", "function_count": 0, "function_hashes": [],
                                 "sketch": _sketch(_shingle_hashes(own))}
                feats["statuses"]["code_fuzzy"] = "success" if feats["code"]["sketch"] else "too small"
            # Whole-file TLSH would describe the shared launcher; hash the program.
            # Small payloads are skipped: a few hundred bytes of marshal data differ
            # structurally at every offset, so a distance there says nothing.
            # Always override: the whole-file hash is the launcher's, and leaving it
            # in place would score every bundle against every other bundle.
            feats["tlsh"] = ""
            if _tlsh is not None and len(own) >= PROGRAM_TLSH_MIN:
                try:
                    t = _tlsh.hash(own)
                    if t and t != "TNULL":
                        feats["tlsh"] = t
                        feats["tlsh_scope"] = "program"
                except Exception:
                    feats["statuses"]["tlsh"] = "failed"
            feats["statuses"].setdefault("tlsh", "payload too small")
            if feats["tlsh"]:
                feats["statuses"]["tlsh"] = "success"

    # Native code for every executable format. Managed PE keeps its IL path
    # (set by _pe_features); native PE, ELF and Mach-O use capstone.
    # A PyInstaller bundle's native code is its launcher, identical in every
    # bundle, so it is reported but never used as evidence about the program.
    if ftype in ("PE", "ELF", "MACHO") and bundle:
        feats["statuses"]["code"] = "launcher (not the program)"
    elif ftype in ("PE", "ELF", "MACHO") and not (
        feats["statuses"].get("pe") == "success" and feats["code"].get("kind") == "managed"
    ):
        exact = [tuple(r) for r in ident["go"].get("ranges", [])]
        res = native.analyse(data, ftype, MAX_CODE_BYTES, exact=exact or None)
        feats["statuses"]["code"] = res["status"]
        feats["statuses"]["code_arch"] = res.get("arch", "")
        if res["status"] == "success":
            feats["code"] = {
                "function_count": res["function_count"],
                "function_hashes": res["function_hashes"],
                "sketch": res["sketch"],
                "bytes_scanned": res["bytes_scanned"],
                "kind": "native",
            }
            feats["native"] = {"arch": res["arch"], "skipped": res["skipped"], "failed": res["failed"]}
        elif "error" in res:
            feats["statuses"]["code_error"] = res["error"]

    return feats


# --------------------------------------------------------------------------- FLOSS

FLOSS_TIMEOUT = 60          # seconds per sample; static stage takes ~4 s on a 2.6 MB binary
FLOSS_MAX_STRINGS = 50000   # cap on FLOSS strings kept per sample
FLOSS_MIN_LENGTH = 6
FLOSS_STAGES = ("static",)  # emulated stages (stack/tight/decoded) are opt-in: they can exceed minutes


def floss_binary() -> str:
    """Path to the installed FLOSS executable, or '' when it is not installed."""
    import os
    import sys
    from deployment_config import DATA_DIR
    name = "floss.exe" if sys.platform.startswith("win") else "floss"
    path = os.path.join(DATA_DIR, "tools", "floss", name)
    return path if os.path.isfile(path) else ""


def floss_strings(data: bytes, stages=FLOSS_STAGES, timeout: int = FLOSS_TIMEOUT) -> dict:
    """Run FLOSS on the sample and return its strings as a separate feature.

    FLOSS scores differently from the plain strings extractor, so the result is
    kept as its own feature kind. Never raises: returns {status, strings}.
    """
    import json as _json
    import os
    import subprocess
    import tempfile

    out = {"status": "", "strings": [], "stages": list(stages), "count": 0}
    exe = floss_binary()
    if not exe:
        out["status"] = "not_installed"
        return out
    tmpdir = tempfile.mkdtemp(prefix="mantis-floss-")
    sample = os.path.join(tmpdir, "sample.bin")
    try:
        with open(sample, "wb") as fh:
            fh.write(data)
        cmd = [exe, "-j", "--disable-progress", "-q", "-n", str(FLOSS_MIN_LENGTH),
               "--only", *stages, "--", sample]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=tmpdir)
        except subprocess.TimeoutExpired:
            out["status"] = "timeout"
            return out
        if proc.returncode != 0:
            out["status"] = f"failed: exit {proc.returncode}"
            return out
        try:
            doc = _json.loads(proc.stdout.decode("utf-8", "replace"))
        except ValueError:
            out["status"] = "failed: unreadable output"
            return out
        seen: Set[str] = set()
        groups = ("static_strings", "language_strings", "stack_strings", "tight_strings", "decoded_strings")
        for group in groups:
            for item in (doc.get("strings") or {}).get(group, []) or []:
                text = item.get("string") if isinstance(item, dict) else item
                if not text:
                    continue
                text = str(text)
                if len(text) < FLOSS_MIN_LENGTH or not text.strip():
                    continue
                if len(set(text)) < 3:  # runs like '\t\t\t' or 'AAAAAA' are padding, not identity
                    continue
                seen.add(text)
                if len(seen) >= FLOSS_MAX_STRINGS:
                    break
            if len(seen) >= FLOSS_MAX_STRINGS:
                break
        out["strings"] = sorted(seen)
        out["count"] = len(out["strings"])
        out["truncated"] = len(seen) >= FLOSS_MAX_STRINGS
        out["status"] = "success"
        return out
    except Exception as exc:
        out["status"] = f"failed: {str(exc)[:120]}"
        return out
    finally:
        try:
            os.remove(sample)
        except OSError:
            pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def sketch_similarity(a: List[int], b: List[int], k: int = SKETCH_K) -> Optional[float]:
    """Estimate Jaccard of two bottom-k sketches (0..1), None if either is empty."""
    if not a or not b:
        return None
    union_k = sorted(set(a) | set(b))[:k]
    sa, sb = set(a), set(b)
    if not union_k:
        return None
    both = sum(1 for x in union_k if x in sa and x in sb)
    return both / len(union_k)
