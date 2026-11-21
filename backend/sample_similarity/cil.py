"""Managed (.NET) method features from CIL method bodies.

Native x64 code has an exception table (.pdata) that gives function bounds.
Managed code does not: its methods are described by the CLI metadata tables
and their bodies are CIL bytecode. This module reads those bodies with
`dnfile` (pure Python) and produces the same kind of per-function record as
the native path, so scoring does not need to know which one ran.

Position-dependent content is removed before hashing: the 4-byte metadata
token operands of call/field/type/string instructions. Those tokens are
table indexes that change whenever the assembly is rebuilt, so the same
method compiled twice gets the same hash.

Branch offsets, literal constants and local/argument indexes are kept: they
are part of the method's logic.

The opcode operand table is verified, not assumed: every method body must
decode to exactly its declared code size. Methods that fail that check are
counted and skipped instead of being hashed with a wrong boundary.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

try:
    import dnfile as _dnfile
except Exception:  # pragma: no cover - optional dependency
    _dnfile = None

MIN_METHOD_BYTES = 16          # tiny stubs (getters, forwarders) are noise
TABLE_METHODDEF = 0x06
TABLE_MEMBERREF = 0x0A

# single-byte opcodes -> operand size (in bytes); -1 = switch (variable)
_OPS1: Dict[int, int] = {}
for _op in (0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F, 0xDE):
    _OPS1[_op] = 1
for _op in range(0x2B, 0x38):            # short branches
    _OPS1[_op] = 1
for _op in (0x20, 0x22, 0x27, 0x28, 0x29, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79,
            0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5,
            0xC2, 0xC6, 0xD0, 0xDD):
    _OPS1[_op] = 4
_OPS1[0x21] = 8                          # ldc.i8
_OPS1[0x23] = 8                          # ldc.r8
_OPS1[0x45] = -1                         # switch

# opcodes whose 4-byte operand is a metadata token (masked before hashing)
_TOKEN1 = {
    0x27, 0x28, 0x29, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7B, 0x7C, 0x7D,
    0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0,
}

# two-byte opcodes (0xFE prefix) -> operand size
_OPS2: Dict[int, int] = {
    0x00: 0, 0x01: 0, 0x02: 0, 0x03: 0, 0x04: 0, 0x05: 0,   # ceq/cgt/cgt.un/clt/clt.un
    0x06: 4, 0x07: 4,                                       # ldftn, ldvirtftn
    0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2,  # ldarg/ldarga/starg/ldloc/ldloca/stloc
    0x0F: 0, 0x11: 0, 0x12: 1, 0x13: 0, 0x14: 0,           # localloc, endfilter, unaligned., volatile., tail.
    0x15: 4, 0x16: 4, 0x17: 0, 0x18: 0, 0x19: 1, 0x1A: 0,  # initobj, constrained., cpblk, initblk, no., rethrow
    0x1C: 4, 0x1D: 0, 0x1E: 0,                              # sizeof, refanytype, readonly.
}
_TOKEN2 = {0x06, 0x07, 0x15, 0x16, 0x1C}


def method_body_code(data_off: int, data: bytes) -> Optional[bytes]:
    """Return the IL bytes of a method body starting at `data_off`, or None."""
    if data_off <= 0 or data_off >= len(data):
        return None
    first = data[data_off]
    if first & 0x3 == 0x2:                       # tiny header
        size = first >> 2
        start = data_off + 1
    elif first & 0x3 == 0x3:                     # fat header
        if data_off + 12 > len(data):
            return None
        flags_size = struct.unpack_from("<H", data, data_off)[0]
        header_words = (flags_size >> 12) & 0xF
        size = struct.unpack_from("<I", data, data_off + 4)[0]
        start = data_off + header_words * 4
    else:
        return None
    if size <= 0 or size > 0x100000 or start + size > len(data):
        return None
    return data[start:start + size]


def decode_masked(il: bytes) -> Optional[Tuple[bytes, List[int]]]:
    """Walk the instruction stream. Returns (masked bytes, call-token list) or None.

    None means the stream did not end exactly on the body boundary, which means
    the operand table is wrong for this method. The caller skips the method.
    """
    buf = bytearray(il)
    n = len(il)
    i = 0
    calls: List[int] = []
    while i < n:
        op = il[i]
        if op == 0xFE:
            if i + 1 >= n:
                return None
            op2 = il[i + 1]
            if op2 not in _OPS2:
                return None
            size = _OPS2[op2]
            head = 2
            is_token = op2 in _TOKEN2
        else:
            if op in _OPS1:
                size = _OPS1[op]
            elif op in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                        0x0D, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                        0x25, 0x26, 0x2A, 0x2B) or 0x46 <= op <= 0xE1 or op in (0x50,) or op == 0x58 or op == 0x59:
                size = 0
            else:
                return None
            head = 1
            is_token = op in _TOKEN1
            if op == 0x45:                       # switch: count + count * rel32
                if i + 5 > n:
                    return None
                count = struct.unpack_from("<I", il, i + 1)[0]
                size = 4 + 4 * count
                head = 1
                is_token = False
            if op == 0x28 or op == 0x6F or op == 0x73:
                if i + 5 <= n:
                    calls.append(struct.unpack_from("<I", il, i + 1)[0])
        end = i + head + size
        if end > n:
            return None
        if is_token and size == 4:
            buf[i + head:end] = b"\0\0\0\0"
        i = end
    if i != n:
        return None
    return bytes(buf), calls


def _table(md, number: int):
    """Rows of a metadata table by its numeric id (dnfile keeps tables in a dict
    keyed by number; attribute names like md.MethodDef are not populated)."""
    tables = getattr(md, "tables", None) or {}
    return tables.get(number)


def _token_name(md, token: int) -> str:
    table = token >> 24
    row = token & 0xFFFFFF
    try:
        rows = _table(md, TABLE_MEMBERREF) if table == TABLE_MEMBERREF else None
        if rows is not None and 0 < row <= len(rows):
            return str(rows[row - 1].Name.value or "").lower()
    except Exception:
        pass
    return ""


def analyse(data: bytes, budget: int) -> dict:
    """Extract managed method features from a .NET assembly.

    Returns {status, functions:[{hash,size,apis}], shingles:set, apis:set,
             decoded, failed, skipped, bytes_scanned}
    """
    from . import extract as _extract  # local import avoids a cycle

    out = {"status": "unavailable", "functions": [], "shingles": set(), "apis": set(),
           "decoded": 0, "failed": 0, "skipped": 0, "bytes_scanned": 0}
    if _dnfile is None:
        return out
    try:
        dn = _dnfile.dnPE(data=data)
    except Exception as exc:
        out["status"] = f"failed: {str(exc)[:120]}"
        return out
    try:
        net = getattr(dn, "net", None)
        md = getattr(net, "mdtables", None) if net else None
        mdef = _table(md, TABLE_METHODDEF) if md else None
        if mdef is None:
            out["status"] = "no metadata"
            return out
        for row in mdef:
            rva = int(getattr(row, "Rva", 0) or 0)
            if rva == 0:
                out["skipped"] += 1           # abstract / extern / runtime-implemented
                continue
            try:
                off = dn.get_offset_from_rva(rva)
            except Exception:
                out["failed"] += 1
                continue
            il = method_body_code(off, data)
            if il is None:
                out["failed"] += 1
                continue
            if len(il) < MIN_METHOD_BYTES:
                out["skipped"] += 1
                continue
            if out["bytes_scanned"] + len(il) > budget:
                break
            res = decode_masked(il)
            if res is None:
                out["failed"] += 1
                continue
            masked, calls = res
            out["decoded"] += 1
            out["bytes_scanned"] += len(il)
            out["functions"].append({
                "hash": __import__("hashlib").sha256(masked).hexdigest()[:32],
                "size": len(il),
                "apis": sorted({nm for nm in (_token_name(md, t) for t in calls) if nm}),
            })
            out["shingles"] |= _extract._shingle_hashes(masked)
        for f in out["functions"]:
            out["apis"].update(f["apis"])
        out["status"] = "success" if out["decoded"] else "no decodable methods"
    except Exception as exc:
        out["status"] = f"failed: {str(exc)[:120]}"
    finally:
        try:
            dn.close()
        except Exception:
            pass
    return out
