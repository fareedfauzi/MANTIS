"""Native code features for ELF, Mach-O and PE (32/64-bit).

Function boundaries and format metadata come from `lief`; instructions are
decoded with `capstone`. Each instruction's position-dependent operands
(relative branch targets, RIP-relative displacements, absolute immediates that
look like addresses) are replaced by a placeholder, so the same code compiled at
a different base address produces the same shingles.

Everything here is best effort: `analyse` never raises. It returns a dict with
a `status` and the feature fields, and callers keep whatever was produced.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set, Tuple

try:
    import lief
except Exception:  # pragma: no cover
    lief = None

try:
    import capstone
except Exception:  # pragma: no cover
    capstone = None

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None

# Shingle over normalised instruction mnemonic + operand-kind tokens.
INSN_WINDOW = 4          # instructions per shingle
MIN_FUNCTION_BYTES = 16  # smaller bodies are thunks and add noise
MAX_FUNCTION_BYTES = 1 << 20
SAMPLE_MASK = 0x3        # keep ~1 in 4 instruction shingles (content-defined)



def _arch(binary) -> Optional[Tuple[int, int, str]]:
    """Return (capstone_arch, capstone_mode, label) or None if unsupported."""
    if capstone is None or lief is None:
        return None
    try:
        arch = str(binary.abstract.header.architecture)
        modes = str(binary.abstract.header.modes)
    except Exception:
        return None
    if "X86_64" in arch:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86_64"
    if arch.endswith("X86") and "BITS_32" in modes:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86"
    if "ARM64" in arch:
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, "arm64"
    return None


def _kind(op) -> str:
    """Map a capstone operand to a position-independent token."""
    if op.type == capstone.CS_OP_REG:
        return "r"
    if op.type == capstone.CS_OP_IMM:
        v = op.imm
        # small immediates are part of the logic; large ones are often addresses
        return f"i{v}" if -256 <= v <= 256 else "I"
    if op.type == capstone.CS_OP_MEM:
        return "m"
    return "o"


def _insn_token(insn) -> str:
    """Normalised token: mnemonic plus operand kinds, no addresses."""
    kinds = []
    for op in insn.operands:
        kinds.append(_kind(op))
    return insn.mnemonic + ":" + ",".join(kinds)


def _function_bytes(binary, start: int, end: int) -> Optional[bytes]:
    try:
        raw = binary.get_content_from_virtual_address(start, end - start)
        return bytes(raw) if raw is not None else None
    except Exception:
        return None


def _exact_ranges(exec_ranges: List[Tuple[int, int]], exact: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Keep external function bounds that start inside an executable section, clipped to it."""
    out: List[Tuple[int, int]] = []
    for start, end in sorted(exact):
        for lo, hi in exec_ranges:
            if lo <= start < hi:
                if end > start:
                    out.append((start, min(end, hi)))
                break
    return out


def _function_ranges(binary, exec_ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    return _segments(exec_ranges, _lief_starts(binary, exec_ranges), {})


def _lief_starts(binary, exec_ranges: List[Tuple[int, int]]) -> Set[int]:
    """Function start addresses reported by lief that fall in executable ranges.
    lief gives size 0 for many ELF/Mach-O starts, so ends come from the next start."""
    starts: Set[int] = set()
    try:
        for f in binary.functions:
            a = int(f.address)
            if a and any(lo <= a < hi for lo, hi in exec_ranges):
                starts.add(a)
    except Exception:
        pass
    return starts


def _is_exec(section) -> bool:
    """Executable flag per format: ELF SHF_EXECINSTR (0x4) and Mach-O
    S_ATTR_PURE_INSTRUCTIONS / SOME_INSTRUCTIONS, PE IMAGE_SCN_MEM_EXECUTE."""
    flags = getattr(section, "flags", None)
    if isinstance(flags, int):
        return bool(flags & 0x4)                      # ELF sh_flags
    if flags is not None:
        text = str(flags)
        if "INSTRUCTIONS" in text:                    # Mach-O section flags
            return True
    chars = getattr(section, "characteristics", None)
    if isinstance(chars, int):
        return bool(chars & 0x20000000)               # PE section characteristics
    return False


def _exec_ranges(binary) -> List[Tuple[int, int]]:
    out = []
    for s in binary.sections:
        if _is_exec(s) and s.size:
            out.append((int(s.virtual_address), int(s.virtual_address + s.size)))
    return out


def _call_targets(code: bytes, base: int, exec_ranges: List[Tuple[int, int]]) -> Set[int]:
    """Direct E8 (call rel32) targets that land inside an executable range."""
    out: Set[int] = set()
    n = len(code)
    i = 0
    while i + 5 <= n:
        if code[i] == 0xE8:
            disp = int.from_bytes(code[i + 1:i + 5], "little", signed=True)
            tgt = base + i + 5 + disp
            if any(lo <= tgt < hi for lo, hi in exec_ranges):
                out.add(tgt)
            i += 5
            continue
        i += 1
    return out


def _segments(exec_ranges: List[Tuple[int, int]], starts: Set[int],
              exact_end: Dict[int, int]) -> List[Tuple[int, int]]:
    """Cut every executable section into function ranges. Each start runs to
    the next start in its section (or to `exact_end` when known). Because the
    section start is always a start, no executable byte is left uncovered."""
    out: List[Tuple[int, int]] = []
    for lo, hi in exec_ranges:
        inside = sorted(a for a in starts if lo <= a < hi)
        if not inside or inside[0] != lo:
            inside.insert(0, lo)
        for i, a in enumerate(inside):
            nxt = inside[i + 1] if i + 1 < len(inside) else hi
            end = min(exact_end.get(a, nxt), nxt, hi)
            if end > a:
                out.append((a, end))
    return out


def _pe_ranges(binary, data: bytes, exec_ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Function ranges covering every executable section of a PE.

    Starts come from three sources:
      - .pdata begin addresses (x64 unwind table), with exact .pdata ends;
      - direct call targets found by scanning each executable section (works
        for x86, which has no .pdata, and for code outside .pdata);
      - the section start and the entry point, so no executable byte is left
        without a function.
    Every other start runs to the next start inside the same section.
    """
    exact_end: Dict[int, int] = {}
    for a, b in _pdata_pairs(data):
        if any(lo <= a < hi for lo, hi in exec_ranges):
            exact_end[a] = b

    starts: Set[int] = set(exact_end)
    pdata_spans = sorted(exact_end.items())

    def in_pdata(x: int) -> bool:
        return any(a <= x < b for a, b in pdata_spans)

    for lo, hi in exec_ranges:
        starts.add(lo)
        raw = _function_bytes(binary, lo, hi)
        if raw:
            # .pdata bounds are authoritative: a call inside a known function
            # is an internal jump, not a new function start.
            starts |= {t for t in _call_targets(raw, lo, exec_ranges) if not in_pdata(t)}
    try:
        ep = int(binary.entrypoint)
        if any(lo <= ep < hi for lo, hi in exec_ranges):
            starts.add(ep)
    except Exception:
        pass

    # Every .pdata end is a start too, so the bytes after a unwind-described
    # function (padding, unwind-less code) get their own range.
    for a, b in exact_end.items():
        if any(lo <= b < hi for lo, hi in exec_ranges):
            starts.add(b)
    return _segments(exec_ranges, starts, exact_end)


def _pdata_pairs(data: bytes) -> List[Tuple[int, int]]:
    """(BeginAddress, EndAddress) RVA pairs from the .pdata exception table."""
    if pefile is None:
        return []
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception:
        return []
    try:
        return [(int(getattr(e.struct, "BeginAddress", 0)), int(getattr(e.struct, "EndAddress", 0)))
                for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None) or []]
    finally:
        pe.close()


# Import thunks (`jmp [mem]`) and padding carry no program logic, and their
# token streams are identical across unrelated binaries. Skip functions made
# only of these.
_TRIVIAL_MNEMONICS = {"jmp", "int3", "nop", "ud2"}


def _is_trivial(insns: list) -> bool:
    return all(i.mnemonic in _TRIVIAL_MNEMONICS for i in insns)


def _hash_function(md, code: bytes, start: int) -> Tuple[Optional[str], List[str], Set[int]]:
    """Disassemble one function. Returns (hash, token list, shingle hashes).
    The hash covers normalised tokens only, so it survives relocation.
    Returns hash None for empty or trivial bodies."""
    insns = list(md.disasm(code, start))
    if not insns or _is_trivial(insns):
        return None, [], set()
    tokens: List[str] = [_insn_token(i) for i in insns]
    fn_hash = hashlib.sha256("|".join(tokens).encode()).hexdigest()[:32]
    shingles: Set[int] = set()
    for i in range(0, max(0, len(tokens) - INSN_WINDOW + 1)):
        h = int.from_bytes(hashlib.blake2b("|".join(tokens[i:i + INSN_WINDOW]).encode(), digest_size=8).digest(), "little")
        if (h >> 60) & SAMPLE_MASK == 0:
            shingles.add(h)
    return fn_hash, tokens, shingles


def analyse(data: bytes, file_type: str, budget: int,
            exact: Optional[List[Tuple[int, int]]] = None) -> Dict:
    """Function hashes and sketch for a native ELF/Mach-O/PE sample.

    `exact` are (start, end) virtual addresses from an external function table
    (Go .gopclntab via GoReSym). They are used instead of heuristic boundaries
    when they fall inside executable sections; stripped Go binaries otherwise
    yield only a handful of starts and most of .text is never hashed."""
    out: Dict = {
        "status": "skipped",
        "arch": "",
        "function_count": 0,
        "function_hashes": [],
        "sketch": [],
        "bytes_scanned": 0,
        "skipped": 0,
        "failed": 0,
    }
    if lief is None or capstone is None:
        out["status"] = "unavailable"
        return out
    try:
        binary = lief.parse(data)
    except Exception as exc:
        out["status"] = "failed"
        out["error"] = str(exc)[:160]
        return out
    if binary is None:
        out["status"] = "failed"
        return out

    arch = _arch(binary)
    if arch is None:
        out["status"] = "unsupported_arch"
        return out
    cs_arch, cs_mode, label = arch
    out["arch"] = label
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True

    exec_ranges = _exec_ranges(binary)
    ranges = _exact_ranges(exec_ranges, exact) if exact else []
    out["range_source"] = "external" if ranges else "heuristic"
    if not ranges:
        if file_type == "PE":
            ranges = _pe_ranges(binary, data, exec_ranges)
        else:
            ranges = _function_ranges(binary, exec_ranges)
    if not ranges:
        out["status"] = "no functions"
        return out

    hashes: Set[str] = set()
    sketch_src: Set[int] = set()
    spent = 0
    for start, end in ranges:
        size = end - start
        if size < MIN_FUNCTION_BYTES:
            out["skipped"] += 1
            continue
        if size > MAX_FUNCTION_BYTES:
            out["skipped"] += 1
            continue
        if spent + size > budget:
            break
        code = _function_bytes(binary, start, end)
        if not code:
            out["failed"] += 1
            continue
        try:
            fn_hash, _tokens, shingles = _hash_function(md, code, start)
        except Exception:
            out["failed"] += 1
            continue
        if fn_hash is None:
            # empty body or trivial thunk: expected, not a decode failure
            out["skipped"] += 1
            continue
        spent += size
        hashes.add(fn_hash)
        sketch_src |= shingles

    out["function_count"] = len(hashes)
    out["function_hashes"] = sorted(hashes)
    out["sketch"] = sorted(sketch_src)[:64]
    out["bytes_scanned"] = spent
    out["status"] = "success" if hashes else "no decodable functions"
    return out
