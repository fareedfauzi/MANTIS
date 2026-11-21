"""PyInstaller archive reader: module names and bytecode from a frozen executable.

Reads the CArchive appended to a PyInstaller bundle (onefile or onedir ELF, PE or
Mach-O) and the PYZ archive inside it. Pure Python, no PyInstaller import, and
no code is executed. It only decompresses and unmarshals the bytes.

Limits: an encrypted PYZ (cipher key in the bundle) fails to decompress and
contributes no modules, so its status is "no python modules". Bytecode is not
used for scoring: opcode n-grams of ordinary Python are shared by unrelated
programs (see the stage (c) notes), so only module names are kept.
"""
from __future__ import annotations

import builtins
import marshal
import struct
import zlib
from typing import Dict, List, Optional, Tuple

COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_FMT = "!8siiii64s"          # magic, package length, toc offset, toc length, python version, lib name
COOKIE_SIZE = struct.calcsize(COOKIE_FMT)
TOC_FMT = "!iiiiBc"                # entry length, data pos, compressed len, uncompressed len, compressed flag, type
TOC_SIZE = struct.calcsize(TOC_FMT)
PYZ_MAGIC = b"PYZ\x00"
PYC_HEADER = 16                    # pyc magic (4) + flags (4) + mtime/hash (8) for 3.7+
MAX_ENTRIES = 50000
MAX_BLOB = 64 * 1024 * 1024        # cap per entry so a crafted archive cannot exhaust memory


def _cookie(data: bytes) -> Optional[Tuple[int, int, int, int]]:
    pos = data.rfind(COOKIE_MAGIC)
    if pos < 0 or pos + COOKIE_SIZE > len(data):
        return None
    magic, pkg_len, toc_pos, toc_len, pyver, _lib = struct.unpack(COOKIE_FMT, data[pos:pos + COOKIE_SIZE])
    # archive starts pkg_len bytes before the cookie (pkg_len counts the cookie too)
    archive_start = pos + COOKIE_SIZE - pkg_len
    if archive_start < 0 or toc_len <= 0:
        return None
    return archive_start, toc_pos, toc_len, pyver


def read_toc(data: bytes) -> Dict[str, object]:
    """Table of contents of a PyInstaller bundle. Returns {'status', 'entries', 'pyver'}."""
    cookie = _cookie(data)
    if cookie is None:
        return {"status": "not pyinstaller", "entries": [], "pyver": 0}
    base, toc_pos, toc_len, pyver = cookie
    entries: List[dict] = []
    p = base + toc_pos
    end = min(base + toc_pos + toc_len, len(data))
    while p + TOC_SIZE <= end and len(entries) < MAX_ENTRIES:
        ulen_entry, dpos, clen, ulen, flag, typ = struct.unpack(TOC_FMT, data[p:p + TOC_SIZE])
        if ulen_entry < TOC_SIZE or p + ulen_entry > end:
            break
        raw_name = data[p + TOC_SIZE:p + ulen_entry]
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
        entries.append({"name": name, "type": typ.decode("latin-1"), "pos": base + dpos,
                        "clen": clen, "ulen": ulen, "compressed": bool(flag)})
        p += ulen_entry
    if not entries:
        return {"status": "empty toc", "entries": [], "pyver": pyver}
    return {"status": "success", "entries": entries, "pyver": pyver}


def _entry_bytes(data: bytes, e: dict) -> Optional[bytes]:
    if e["clen"] <= 0 or e["clen"] > MAX_BLOB:
        return None
    raw = data[e["pos"]:e["pos"] + e["clen"]]
    if len(raw) != e["clen"]:
        return None
    if e["compressed"]:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return None
    return raw


def _marshal_code(blob: Optional[bytes]) -> Optional[bytes]:
    """Marshalled code object from a script/module entry: raw marshal ('c' type code)
    or a .pyc with a 16-byte header. Returns None for anything else."""
    if not blob:
        return None
    if blob[:1] == b"c":                       # PyInstaller 6 script entries: raw marshal
        return blob
    if len(blob) > PYC_HEADER and blob[PYC_HEADER:PYC_HEADER + 1] == b"c":
        return blob[PYC_HEADER:]
    return None


def read_pyz(blob: bytes) -> Dict[str, object]:
    """Modules in a PYZ archive: {'magic': bytes, 'modules': {name: (is_pkg, zlib_bytes)}}.

    Layout: 'PYZ\\0', pyc magic (4), big-endian TOC offset (4), entry data, then a
    marshalled list of (name, (is_pkg, pos, length)) tuples."""
    if blob[:4] != PYZ_MAGIC or len(blob) < 12:
        return {"magic": b"", "modules": {}}
    magic = blob[4:8]
    toc_off = struct.unpack(">i", blob[8:12])[0]
    try:
        toc = marshal.loads(blob[toc_off:])
    except Exception:
        return {"magic": magic, "modules": {}}
    items = toc.items() if isinstance(toc, dict) else toc
    modules = {}
    for item in items:
        try:
            name, (is_pkg, pos, length) = item
            raw = blob[pos:pos + length]
            modules[name] = (bool(is_pkg), zlib.decompress(raw))
        except Exception:
            continue
        if len(modules) >= MAX_ENTRIES:
            break
    return {"magic": magic, "modules": modules}


def analyse(data: bytes) -> Dict[str, object]:
    """Module names and per-module marshal blobs for a PyInstaller bundle.

    Returns {'status', 'pyver', 'modules': [names], 'scripts': [names],
             'blobs': {module_name: marshal_bytes}, 'magic': pyc magic bytes}.
    """
    out: Dict[str, object] = {"status": "skipped", "pyver": 0, "modules": [], "scripts": [],
                              "blobs": {}, "magic": b""}
    toc = read_toc(data)
    out["pyver"] = toc.get("pyver", 0)
    if toc["status"] != "success":
        out["status"] = toc["status"]
        return out
    scripts, modules, blobs = [], [], {}
    magic = b""
    for e in toc["entries"]:
        if e["type"] == "z":
            blob = _entry_bytes(data, e)
            if blob is None:
                continue
            pyz = read_pyz(blob)
            magic = magic or pyz["magic"]
            for name, (_is_pkg, code) in pyz["modules"].items():
                modules.append(name)
                blobs[name] = code
        elif e["type"] in ("s", "m", "M"):
            # script entry points and loose modules are .pyc files (16-byte header + marshal)
            if e["type"] == "s":
                scripts.append(e["name"])
            else:
                modules.append(e["name"])
            blob = _entry_bytes(data, e)
            code = _marshal_code(blob)
            if code is not None:
                blobs[e["name"]] = code
    if not modules and not scripts:
        out["status"] = "no python modules"
        return out
    out.update(status="success", modules=sorted(set(modules)), scripts=sorted(set(scripts)),
               blobs=blobs, magic=magic)
    return out


def _generic_name(name: str) -> bool:
    """True for names that say nothing about a program.

    Dunder and single-underscore names, Python builtins, attribute-protocol names
    and marshal markers are the same in every Python program, so counting them
    makes unrelated programs look alike.
    """
    if len(name) < 3 or len(name) > 200:
        return True
    if name.startswith("<") or name.startswith("__") or name.endswith("__"):
        return True
    return name in _BUILTIN_NAMES


_BUILTIN_NAMES = frozenset(dir(builtins)) | frozenset({
    "self", "cls", "args", "kwargs", "name", "value", "data", "path", "file",
    "True", "False", "None", "print", "input", "open", "range", "len", "str",
    "int", "float", "list", "dict", "set", "tuple", "type", "object", "super",
})


def program_symbols(result: Dict[str, object], limit: int = 40000) -> Dict[str, object]:
    """Names and literals defined by the program's own code objects.

    Function, class and variable names plus string constants are the Python
    analogue of Go symbols or demangled C++ names: they say what this program is
    made of, while the launcher and the embedded standard library say nothing.
    Bytecode is unmarshalled with xdis so a bundle built by a different CPython
    version than the analyser can still be read. Generic names (dunders,
    builtins) are dropped; they are identical in every Python program.
    """
    out: Dict[str, object] = {"status": "skipped", "names": [], "strings": []}
    blobs = result.get("blobs") or {}
    targets = [(n, b) for n, b in sorted(blobs.items()) if is_program_module(n)]
    if not targets:
        out["status"] = "no program code"
        return out
    try:
        import io
        import xdis.magics as _magics
        import xdis.unmarshal as _unmarshal
    except Exception:
        out["status"] = "xdis missing"
        return out
    try:
        magic_int = _magics.magic2int(result.get("magic") or b"")
    except Exception:
        out["status"] = "unknown magic"
        return out
    names: set = set()
    literals: set = set()

    def add_name(value) -> None:
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if isinstance(value, str) and not _generic_name(value) and len(names) < limit:
            names.add(value)

    def walk(code, depth: int = 0) -> None:
        if depth > 12 or len(names) >= limit:
            return
        for value in getattr(code, "co_consts", ()) or ():
            if isinstance(value, (str, bytes)):
                if isinstance(value, bytes):
                    value = value.decode("latin-1")
                if (4 <= len(value) <= 120 and not _generic_name(value)
                        and len(literals) < limit):
                    literals.add(value)
            elif hasattr(value, "co_code"):
                walk(value, depth + 1)
        for attr in ("co_names", "co_varnames"):
            for value in getattr(code, attr, ()) or ():
                add_name(value)

    read = 0
    for _name, blob in targets:
        if len(names) >= limit:
            break
        try:
            walk(_unmarshal.load_code(io.BytesIO(blob), magic_int))
            read += 1
        except Exception:
            continue
    if not read:
        out["status"] = "unparsed"
        return out
    out["names"] = sorted(names)[:limit]
    out["strings"] = sorted(literals)[:limit]
    out["status"] = "success"
    return out


def program_bytes(result: Dict[str, object], limit: int = 32 * 1024 * 1024) -> bytes:
    """Concatenated bytes of the program's own code objects, for its own strings.

    Everything else in a bundle (the launcher, the embedded interpreter and the
    standard library) is identical across every bundle built with the same
    PyInstaller and Python, so its strings say nothing about this program.
    """
    chunks, total = [], 0
    blobs = result.get("blobs") or {}
    for name in sorted(blobs):
        if not is_program_module(name):
            continue
        blob = blobs[name]
        if total + len(blob) > limit:
            break
        chunks.append(blob)
        total += len(blob)
    return b"\n".join(chunks)


RUNTIME_PREFIXES = ("pyi_rth_", "pyiboot", "pyimod")


def is_program_module(name: str) -> bool:
    """False for PyInstaller's bootstrap/runtime hooks and for the standard library.

    Those modules are identical in every bundle built with the same PyInstaller and
    Python, so keeping them would make unrelated programs look alike. Third-party
    dependencies are kept here; scoring's rarity rule down-weights the ones shared
    across families."""
    import sys
    if name.startswith(RUNTIME_PREFIXES):
        return False
    top = name.split(".", 1)[0]
    return top not in sys.stdlib_module_names
