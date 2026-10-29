# -*- coding: utf-8 -*-
"""Find Crypt Explorer: locate and label cryptographic constants."""
import json
import os
import re

import idaapi
import ida_bytes
import idautils
import idc
import ida_kernwin

from genesect.ui.semantic_explorer import SemanticExplorerForm
from genesect.api_knowledge import describe_api, normalize_api_name
from genesect.qt_compat import QtWidgets


_explorer = None
_MAX_RESULTS = 200000
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_SUPPLEMENTAL_SIGNATURES = (
    ("BLAKE2b_IV", "Hashing", "08C9BCF367E6096A3BA7CA8485AE67BB2BF894FE72F36E3CF1361D5F3AF54FA5D182E6AD7F520E511F6C3E2B8C68059B6BBd41FBABD9831F79217E1319CDE05B"),
    ("BLAKE2s_IV", "Hashing", "67E6096A85AE67BB72F36E3CF54FF53A510E527F9B05688C1F83D9AB5BE0CD19"),
    ("ChaCha20_Sigma", "Cryptography", "657870616E642033322D62797465206B"),
    ("ChaCha_Sigma_16Byte_Key", "Cryptography", "657870616E642031362D62797465206B"),
    ("SM3_Initial_State", "Hashing", "6F168073B9B21449742D7B4A00D182ADA0F8434D509F275FADE682D1B7380166"),
    ("Keccak_SHA3_Round_Constants", "Hashing", b"".join(value.to_bytes(8, "little") for value in _KECCAK_ROUND_CONSTANTS).hex()),
    ("Base64_Standard_Alphabet", "Encoding", "4142434445464748494A4B4C4D4E4F505152535455565758595A6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435363738392B2F"),
    ("Base64_URLSafe_Alphabet", "Encoding", "4142434445464748494A4B4C4D4E4F505152535455565758595A6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435363738392D5F"),
)

_API_RULES = (
    ("Hashing", re.compile(r"(?:CryptCreateHash|CryptHashData|CryptGetHashParam|BCryptCreateHash|BCryptHashData|BCryptFinishHash|BCryptHash|RtlComputeCrc32|HMAC|SipHash|CityHash|FarmHash|HighwayHash|(?:^|_)(?:MD[2456]|SHA(?:1|2|224|256|384|512|3)|BLAKE[23]?|RIPEMD|WHIRLPOOL|KECCAK|XXHASH|MURMUR|CRC32C?|ADLER32)(?:_|$))", re.I)),
    ("Compression", re.compile(r"(?:RtlCompressBuffer|RtlDecompressBuffer|CreateCompressor|(?:^|_)(?:deflate|inflate|zlib|gzip|LZ4|LZMA|LZSS|XZ|ZSTD|Brotli|BZ2|bzip2?|snappy|lzo|lzfse|quicklz|heatshrink|huffman|FCI|FDI)(?:_|$))", re.I)),
    ("Encoding", re.compile(r"(?:CryptBinaryToString|CryptStringToBinary|CryptEncodeObject|CryptDecodeObject|(?:^|_)(?:Base64|Base32|Base85|Ascii85|hex_(?:encode|decode)|urlencode|urldecode|percent_encode|quoted.?printable|uuencode|yenc|punycode|protobuf|msgpack|CBOR|BSON|ASN1|ASN_1|DER_(?:encode|decode)|BER_(?:encode|decode))(?:_|$))", re.I)),
    ("Cryptography", re.compile(r"(?:^BCrypt|^NCrypt|CryptAcquireContext|CryptReleaseContext|CryptGenRandom|CryptDeriveKey|CryptImportKey|CryptExportKey|CryptEncrypt|CryptDecrypt|CryptSignHash|CryptVerifySignature|CryptMsg|Cert(?:Open|Create|Verify|Get|Find)|PFXImportCertStore|WinVerifyTrust|CryptProtectData|CryptUnprotectData|CryptProtectMemory|CryptUnprotectMemory|RtlEncryptMemory|RtlDecryptMemory|SystemFunction0(?:32|33)|AcquireCredentialsHandle|InitializeSecurityContext|AcceptSecurityContext|EncryptMessage|DecryptMessage|(?:^|_)(?:EVP|OpenSSL|AES|DES|3DES|RC[2456]|RSA|ECDSA|ECDH|Ed25519|X25519|ChaCha|Poly1305|Salsa20|Twofish|Serpent|Camellia|Blowfish|CAST|IDEA|TEA|XTEA|SEED|ARIA|Rabbit|HC128|Sosemanuk|Speck|Simon|Ascon|GOST|SM[234]|Argon2|scrypt|PBKDF2|HKDF|Kyber|MLKEM|Dilithium|MLDSA|SPHINCS|crypto|sodium)(?:_|$))", re.I)),
)


def _category_for_constant(name):
    value = str(name or "").casefold()
    if any(token in value for token in ("deflate", "inflate", "zlib", "lz", "brotli", "zstd", "compress")):
        return "Compression"
    if any(token in value for token in ("base64", "base32", "ascii85", "encoding", "alphabet")):
        return "Encoding"
    if any(token in value for token in ("sha", "md4", "md5", "haval", "tiger", "whirlpool", "blake", "keccak", "ripemd", "crc", "hash")):
        return "Hashing"
    return "Cryptography"


def _classify_api(name):
    for category, pattern in _API_RULES:
        if pattern.search(name):
            return category
    knowledge = describe_api(name)
    taxonomy = knowledge.get("taxonomy") or {}
    if taxonomy.get("category") in ("Cryptography", "Hashing", "Compression", "Encoding"):
        return taxonomy["category"]
    return ""


def _load_signatures(path):
    with open(path, "r", encoding="utf-8") as handle:
        db = json.load(handle)
    signatures, seen = [], set()
    for entry in list(db) + [{"name": name, "category": category, "hexBytes": data} for name, category, data in _SUPPLEMENTAL_SIGNATURES]:
        name, value = entry.get("name"), re.sub(r"\s+", "", str(entry.get("hexBytes") or ""))
        if not name or len(value) < 8 or len(value) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        signatures.append((name, entry.get("category") or _category_for_constant(name), value))
    return signatures


class FindCryptExplorer(SemanticExplorerForm):
    title = "Find Crypt Explorer"
    subtitle = "Find crypto, hash, compression, and encoding constants plus Windows and library API usage"
    columns = (("category", "Category"), ("name", "Algorithm / API"), ("kind", "Kind"), ("address", "Address"), ("size", "Size"), ("evidence", "Evidence"))
    wait_message = "Scanning for cryptographic signatures..."
    export_name = "findcrypt.csv"

    def scan(self):
        db_path = os.path.join(os.path.dirname(__file__), "findcrypt_db.json")
        try:
            db = _load_signatures(db_path)
        except Exception as e:
            ida_kernwin.warning(f"Failed to load FindCrypt database:\n{e}")
            return []

        results = []
        
        for name, category, hex_bytes in db:
            if ida_kernwin.user_cancelled():
                return results

            # Format as spaced hex for IDA's parser
            spaced_hex = " ".join([hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)])
            
            pattern = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(pattern, 0, spaced_hex, 16)
            if err:
                continue
                
            for segment in idautils.Segments():
                if ida_kernwin.user_cancelled():
                    return results

                ea = segment
                seg_end = idc.get_segm_end(segment)
                if seg_end <= segment or ida_bytes.get_bytes(segment, 1) is None:
                    continue
                
                while ea < seg_end:
                    search_result = ida_bytes.bin_search(ea, seg_end, pattern, ida_bytes.BIN_SEARCH_FORWARD)
                    if isinstance(search_result, tuple):
                        match_ea, _ = search_result
                    else:
                        match_ea = search_result
                        
                    if match_ea == idaapi.BADADDR:
                        break
                        
                    size = len(hex_bytes) // 2
                    
                    results.append({
                        "ea": match_ea,
                        "address": "0x%X" % match_ea,
                        "name": name,
                        "category": category,
                        "kind": "Constant/table",
                        "size": size,
                        "evidence": f"Exact byte signature ({size} bytes)",
                        "details": "%s constant/table\nAddress: 0x%X\nSize: %d bytes\n\nExact match against the bundled FindCrypt signature database. Validate surrounding code before assigning an algorithm." % (category, match_ea, size),
                    })
                    ea = match_ea + size

                    if len(results) >= _MAX_RESULTS:
                        return sorted(results, key=lambda row: row["ea"])

        # API/symbol evidence supplements constants and catches library-backed code.
        for api_ea, raw_name in idautils.Names():
            name = normalize_api_name(raw_name)
            category = _classify_api(name)
            if not category:
                continue
            knowledge = describe_api(name)
            signature = knowledge.get("signature") or {}
            for xref in idautils.XrefsTo(api_ea, 0):
                if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                    continue
                module = signature.get("module") or ", ".join(knowledge.get("modules") or []) or "library/symbol"
                results.append({
                    "ea": int(xref.frm), "address": "0x%X" % xref.frm, "name": name,
                    "category": category, "kind": "API call", "size": "-",
                    "evidence": "Direct call to %s API/symbol" % module,
                    "details": "%s API evidence\nCall site: 0x%X\nTarget: %s\nProvider/module: %s\n\nDirect-call evidence identifies capability, not proof of malicious use." % (category, xref.frm, name, module),
                })
                if len(results) >= _MAX_RESULTS:
                    break
            if ida_kernwin.user_cancelled() or len(results) >= _MAX_RESULTS:
                break

        unique = {(row["ea"], row["name"], row["kind"]): row for row in results}
        return sorted(unique.values(), key=lambda row: (row["category"], row["ea"], row["name"].casefold()))

    def OnCreate(self, form):
        super().OnCreate(form)
        annotate = QtWidgets.QPushButton("Annotate Selected...")
        annotate.clicked.connect(self.annotate_selected)
        self.parent.layout().insertWidget(2, annotate)

    def annotate_selected(self):
        row = self.selected_row()
        if not row or row.get("kind") != "Constant/table":
            ida_kernwin.info("Select a constant/table finding to annotate.")
            return
        current = idc.get_name(row["ea"]) or ""
        if current and not current.startswith(("unk_", "byte_", "word_", "dword_", "qword_")):
            ida_kernwin.info("Genesect preserved the existing analyst-defined name: %s" % current)
            return
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Annotate 0x%X as %s?\n\nThis will add a name and repeatable comment to the IDB." % (row["ea"], row["name"])) != ida_kernwin.ASKBTN_YES:
            return
        safe_name = "CRYPT_" + re.sub(r"\W+", "_", row["name"]).strip("_")
        if idc.set_name(row["ea"], safe_name, idc.SN_CHECK | idc.SN_NOWARN):
            idc.set_cmt(row["ea"], "%s %s - %s bytes" % (row["category"], row["name"], row["size"]), 1)
            self.status.setText("Annotated 0x%X as %s" % (row["ea"], safe_name))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_findcrypt_explorer():
    global _explorer
    if _explorer is None:
        _explorer = FindCryptExplorer()
    _explorer.Show("Genesect - Find Crypt Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class FindCryptExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_findcrypt_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
