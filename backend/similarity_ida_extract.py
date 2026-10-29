"""IDAPython extractor for MANTIS code similarity.

Run by IDA with:
    ida64 -A -Ssimilarity_ida_extract.py <output.json> <config.json> <sample>

The script emits compact derived features only: hashes, mnemonic n-grams,
API-call sequences, constants, string references, and CFG fingerprints.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from collections import Counter

try:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import ida_lines
    import ida_name
    import idaapi
    import idautils
    import idc
except Exception:
    ida_auto = ida_bytes = ida_funcs = ida_hexrays = ida_kernwin = ida_lines = ida_name = idaapi = idautils = idc = None


REGISTER_RE = re.compile(r"\b(e?[abcd]x|e?[sd]i|e?[sb]p|r(?:[0-9]+|[abcd]x|[sd]i|[sb]p)|[abcd][lh]|xmm\d+|ymm\d+|zmm\d+)\b", re.I)
HEX_RE = re.compile(r"^[+-]?(?:0x)?[0-9a-f]+h?$", re.I)
API_PREFIX_RE = re.compile(r"^(?:__imp_|imp_)", re.I)
API_DLL_RE = re.compile(r"^([a-z0-9_.-]+?)(?:\.dll)?[!._]+([a-z_][a-z0-9_@$?]{2,})$", re.I)
COMMON_CONSTANTS = {-1, 0, 1, 2, 4, 8, 16, 32, 64}
SEMANTIC_API_CATEGORY_RULES = [
    ("MEMORY_ALLOC", ("virtualalloc", "virtualallocex", "heapalloc", "malloc")),
    ("MEMORY_PROTECT", ("virtualprotect", "virtualprotectex", "ntprotectvirtualmemory")),
    ("MEMORY_COPY", ("memcpy", "rtlcopymemory", "copymemory", "writeprocessmemory")),
    ("PROCESS_CREATE", ("createprocess", "shellexecute", "winexec")),
    ("PROCESS_ENUM", ("process32first", "process32next", "enumprocesses", "ntquerysysteminformation")),
    ("THREAD_CREATE", ("createthread", "createremotethread", "ntcreatethreadex")),
    ("FILE_OPEN", ("createfile", "openfile", "ntopenfile")),
    ("FILE_READ", ("readfile", "ntreadfile")),
    ("FILE_WRITE", ("writefile", "ntwritefile")),
    ("FILE_DELETE", ("deletefile", "ntdeletefile")),
    ("REGISTRY_READ", ("regqueryvalue", "regopenkey")),
    ("REGISTRY_WRITE", ("regsetvalue", "regcreatekey")),
    ("NETWORK_INIT", ("internetopen", "wsastartup", "winhttpopen")),
    ("NETWORK_CONNECT", ("connect", "internetconnect", "winhttpconnect", "internetopenurl")),
    ("NETWORK_SEND", ("send", "httpsendrequest", "winhttpsendrequest")),
    ("NETWORK_RECEIVE", ("recv", "internetreadfile", "winhttpreaddata")),
    ("CRYPTO_HASH", ("crypthashdata", "bcryptcreatehash", "cryptcreatehash")),
    ("CRYPTO_ENCRYPT", ("cryptencrypt", "bcryptencrypt")),
    ("CRYPTO_DECRYPT", ("cryptdecrypt", "bcryptdecrypt")),
    ("COMPRESSION", ("compress", "uncompress", "rtlcompressbuffer", "rtldecompressbuffer")),
    ("MODULE_LOAD", ("loadlibrary", "ldrloaddll")),
    ("API_RESOLVE", ("getprocaddress", "ldrgetprocedureaddress")),
]


def sha256_text(value):
    return hashlib.sha256((value or "").encode("utf-8", "ignore")).hexdigest()


def hash_sequence(values):
    cleaned = [str(v) for v in values if str(v)]
    return sha256_text("\n".join(cleaned)) if cleaned else ""


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def load_config(path):
    defaults = {
        "minimum_function_instructions": 5,
        "minimum_block_instructions": 2,
        "mnemonic_ngram_size": 4,
        "exclude_thunks": True,
        "normalization_version": 1,
        "feature_schema_version": 2,
        "enable_semantic_similarity": False,
        "enable_pseudocode_similarity": True,
        "enable_ast_similarity": True,
        "enable_microcode_similarity": True,
        "maximum_semantic_functions": 100,
        "ida_timeout_seconds": 300,
        "hexrays_timeout_seconds": 120,
        "hexrays_function_timeout_seconds": 10,
        "minimum_semantic_function_instructions": 10,
        "semantic_ngram_size": 4,
        "semantic_schema_version": 1,
        "pseudocode_normalization_version": 1,
        "ast_normalization_version": 1,
        "microcode_normalization_version": 1,
        "api_semantic_map_version": 1,
    }
    if not path:
        return defaults
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            defaults.update(raw)
    except Exception:
        pass
    return defaults


def ida_version():
    try:
        return ida_kernwin.get_kernel_version()
    except Exception:
        try:
            return idaapi.get_kernel_version()
        except Exception:
            return ""


def is_api_name(name):
    if not name:
        return False
    low = name.lower()
    if low.startswith(("sub_", "loc_", "nullsub_", "j_", "unknown_")):
        return False
    return bool(re.search(r"[a-z_][a-z0-9_@$?]{2,}", low))


def is_common_library_function(name):
    low = (name or "").lower()
    common = (
        "security_check_cookie", "security_init_cookie", "chkstk", "memcpy", "memset", "strcmp",
        "strcpy", "strlen", "crt", "atexit", "tls_callback", "maincrtstartup", "winmaincrtstartup",
    )
    return any(token in low for token in common)


def ida_flag_value(name, default=0):
    for module in (ida_funcs, idaapi, idc):
        try:
            return int(getattr(module, name))
        except Exception:
            continue
    return default


def function_flags(func, start):
    for attr in ("flags", "flags64"):
        try:
            return int(getattr(func, attr))
        except Exception:
            pass
    try:
        return int(ida_funcs.get_func_attr(start, idc.FUNCATTR_FLAGS))
    except Exception:
        pass
    try:
        return int(idc.get_func_attr(start, idc.FUNCATTR_FLAGS))
    except Exception:
        pass
    try:
        return int(idaapi.get_func_attr(start, idc.FUNCATTR_FLAGS))
    except Exception:
        return 0


def clean_api_name(name):
    name = API_PREFIX_RE.sub("", (name or "").strip())
    name = name.replace("::", "!").replace("/", "!").replace("\\", "!")
    name = re.sub(r"\s+", "", name)
    match = API_DLL_RE.match(name)
    if match:
        module = match.group(1).lower()
        func = match.group(2).lower()
        if not module.endswith(".dll") and "." not in module:
            module = f"{module}.dll"
        return f"{module}!{func}"[:160]
    return name.strip("_").lower()[:160]


def is_loaded_address(value):
    try:
        return bool(ida_bytes.is_loaded(int(value)))
    except Exception:
        return False


def meaningful_constant(value):
    try:
        ivalue = int(value)
    except Exception:
        return ""
    if ivalue in COMMON_CONSTANTS:
        return ""
    if is_loaded_address(ivalue):
        return ""
    return hex(ivalue & 0xffffffffffffffff)


def api_semantic_category(value):
    api = clean_api_name(value)
    func = api.split("!")[-1].lower()
    func = re.sub(r"[aw]$", "", func)
    for category, tokens in SEMANTIC_API_CATEGORY_RULES:
        if any(func.startswith(token.lower()) or token.lower() in func for token in tokens):
            return category
    return "API_OTHER" if api else ""


def hexrays_available():
    if ida_hexrays is None:
        return False, "unavailable", ""
    try:
        ok = ida_hexrays.init_hexrays_plugin()
        if not ok:
            return False, "failed", ""
        version = ""
        try:
            version = ida_hexrays.get_hexrays_version()
        except Exception:
            version = ""
        return True, "success", version
    except Exception as exc:
        text = str(exc).lower()
        status = "license_error" if "license" in text else "failed"
        return False, status, str(exc)


def normalize_type_text(text):
    replacements = [
        (r"\b(?:unsigned\s+char|uint8_t|BYTE)\s*\*", "PTR_BYTE"),
        (r"\b(?:char|CHAR)\s*\*", "PTR_CHAR"),
        (r"\b(?:unsigned\s+int|uint32_t|DWORD)\b", "U32"),
        (r"\b(?:int|int32_t|LONG)\b", "I32"),
        (r"\b(?:__int64|long\s+long|int64_t|QWORD)\b", "I64"),
        (r"\b(?:unsigned\s+__int64|unsigned\s+long\s+long|uint64_t)\b", "U64"),
        (r"\b(?:unsigned\s+short|uint16_t|WORD)\b", "U16"),
        (r"\b(?:short|int16_t)\b", "I16"),
        (r"\b(?:void|char|unsigned\s+char|BYTE|DWORD|QWORD|WORD)\s*\*", "PTR"),
    ]
    out = text
    for pattern, repl in replacements:
        out = re.sub(pattern, repl, out, flags=re.I)
    return out


def normalize_constant_token(match):
    raw = match.group(0).lower()
    try:
        value = int(raw, 16) if raw.startswith("0x") else int(raw, 10)
    except Exception:
        return "CONST"
    if value in COMMON_CONSTANTS:
        return "SMALL_CONST"
    return f"CONST_{hex(value & 0xffffffffffffffff)}"


def normalize_pseudocode_text(text, state=None):
    state = state if isinstance(state, dict) else {"vars": {}, "next_var": 0}
    text = re.sub(r"/\*.*?\*/", " ", text or "")
    text = re.sub(r"\b(sub|loc|off|byte|word|dword|qword)_[0-9a-f]+\b", "CALL_INTERNAL", text, flags=re.I)
    text = normalize_type_text(text)

    def arg_repl(match):
        idx = max(0, safe_int(match.group(1), 1) - 1)
        return f"ARG_{idx}"

    def var_repl(match):
        name = match.group(0).lower()
        if name not in state["vars"]:
            state["vars"][name] = f"VAR_{state['next_var']}"
            state["next_var"] += 1
        return state["vars"][name]

    text = re.sub(r"\ba(\d+)\b", arg_repl, text)
    text = re.sub(r"\bv\d+\b", var_repl, text)
    text = re.sub(r"0x[0-9a-f]+|\b\d+\b", normalize_constant_token, text, flags=re.I)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalized_pseudocode_lines(cfunc):
    lines = []
    state = {"vars": {}, "next_var": 0}
    try:
        pseudo = cfunc.get_pseudocode()
    except Exception:
        return lines
    for line in pseudo:
        try:
            text = ida_lines.tag_remove(str(line.line))
        except Exception:
            text = str(getattr(line, "line", line))
        text = normalize_pseudocode_text(text, state)
        if text:
            lines.append(text)
    return lines


def pseudocode_tokens(lines):
    out = []
    for line in lines:
        low = line.lower()
        if low.startswith("if"):
            out.append("CONTROL_IF")
        if any(low.startswith(x) for x in ("for", "while", "do ")):
            out.append("CONTROL_LOOP")
        if low.startswith("switch"):
            out.append("CONTROL_SWITCH")
        if low.startswith("return"):
            out.append("RETURN")
        if "=" in line and "==" not in line:
            out.append("ASSIGN")
        if any(op in line for op in ("==", "!=", "<=", ">=", " < ", " > ")):
            out.append("COMPARE")
        if any(op in line for op in ("+", "-", "*", "/", "%")):
            out.append("ARITHMETIC")
        if any(op in line for op in ("^", "&", "|", "<<", ">>")):
            out.append("BITWISE")
        if "*" in line or "[" in line:
            out.append("MEMORY_ACCESS")
        for api_match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_@$]{2,})\s*\(", line):
            name = clean_api_name(api_match.group(1))
            if is_api_name(name):
                if name.startswith(("call_internal", "sub_")):
                    out.append("CALL_INTERNAL")
                else:
                    out.extend(["CALL_API", name])
        out.extend(re.findall(r"\b(?:ARG_\d+|VAR_\d+|SMALL_CONST|CONST_0x[0-9a-f]+|I\d+|U\d+|PTR(?:_[A-Z]+)?)\b", line))
    return out


def semantic_ngrams(tokens, n):
    return [{"ngram_hash": hash_sequence(tokens[i:i + n]), "ngram_size": n} for i in range(max(0, len(tokens) - n + 1))]


def ast_counts_from_tokens(tokens):
    return {
        "ast_node_count": len(tokens),
        "if_count": tokens.count("CONTROL_IF"),
        "loop_count": tokens.count("CONTROL_LOOP"),
        "switch_count": tokens.count("CONTROL_SWITCH"),
        "call_count": tokens.count("CALL_API") + tokens.count("CALL_INTERNAL"),
        "assignment_count": tokens.count("ASSIGN"),
        "return_count": tokens.count("RETURN"),
        "pointer_deref_count": tokens.count("MEMORY_ACCESS"),
        "arithmetic_count": tokens.count("ARITHMETIC"),
        "bitwise_count": tokens.count("BITWISE"),
        "comparison_count": tokens.count("COMPARE"),
    }


def semantic_category_for_call_name(name, semantic_categories):
    category = api_semantic_category(name)
    if category != "API_OTHER":
        return category
    low = clean_api_name(name).split("!")[-1]
    for existing in semantic_categories:
        if existing and existing.lower() in low:
            return existing
    return category


def dataflow_patterns_from_lines(lines, semantic_categories):
    alloc_vars = set()
    copied_vars = set()
    out = []
    for line in lines:
        calls = [m.group(1) for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_@$!]*)\s*\(", line)]
        categories = [semantic_category_for_call_name(c, semantic_categories) for c in calls]
        assigned = re.match(r"\s*(VAR_\d+)\s*=", line)
        if assigned and "MEMORY_ALLOC" in categories:
            alloc_vars.add(assigned.group(1))
        if "MEMORY_COPY" in categories:
            for var in alloc_vars:
                if re.search(rf"\b{re.escape(var)}\b", line):
                    copied_vars.add(var)
        if "THREAD_CREATE" in categories:
            for var in copied_vars:
                if re.search(rf"\b{re.escape(var)}\b", line):
                    out.append({"pattern_hash": hash_sequence(["ALLOC", "COPY", "EXECUTE"]), "pattern_type": "ALLOC_COPY_EXEC"})
        if "REGISTRY_WRITE" in categories:
            out.append({"pattern_hash": hash_sequence(["REGISTRY_WRITE"]), "pattern_type": "REGISTRY_PERSISTENCE"})
    seen = set()
    unique = []
    for item in out:
        key = (item["pattern_hash"], item["pattern_type"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def semantic_from_function(func, apis, constants, config, hexrays_version):
    if not config.get("enable_semantic_similarity"):
        return {}
    if ida_hexrays is None:
        return {"decompiler_status": "hexrays_unavailable", "decompiler_error": "ida_hexrays unavailable"}
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as exc:
        return {"decompiler_status": "failed", "decompiler_error": str(exc)[:300]}
    if not cfunc:
        return {"decompiler_status": "failed", "decompiler_error": "decompile returned no function"}
    lines = normalized_pseudocode_lines(cfunc) if config.get("enable_pseudocode_similarity") else []
    tokens = pseudocode_tokens(lines)
    n = safe_int(config.get("semantic_ngram_size"), 4)
    control_tokens = [t for t in tokens if t.startswith("CONTROL_") or t == "RETURN" or t.startswith("CALL")]
    ast_subtrees = Counter()
    if config.get("enable_ast_similarity") and tokens:
        for i in range(max(0, len(tokens) - 2)):
            ast_subtrees[hash_sequence(tokens[i:i + 3])] += 1
    sem_apis = []
    for pos, api in enumerate(apis[:200]):
        category = api_semantic_category(api)
        if category:
            sem_apis.append({"position": pos, "api_category": category, "api_name": clean_api_name(api)})
    semantic_categories = [a["api_category"] for a in sem_apis]
    dataflow = dataflow_patterns_from_lines(lines, semantic_categories)
    sem_constants = [{"constant_value": c, "semantic_category": "CONST"} for c in sorted(constants)[:200]]
    version_prefix = [
        f"semantic:{safe_int(config.get('semantic_schema_version'), 1)}",
        f"pseudo:{safe_int(config.get('pseudocode_normalization_version'), 1)}",
        f"ast:{safe_int(config.get('ast_normalization_version'), 1)}",
        f"micro:{safe_int(config.get('microcode_normalization_version'), 1)}",
        f"api:{safe_int(config.get('api_semantic_map_version'), 1)}",
    ]
    return {
        "decompiler_status": "success",
        "decompiler_error": "",
        "hexrays_version": hexrays_version,
        "semantic_version": safe_int(config.get("semantic_schema_version"), 1),
        "pseudocode_norm_version": safe_int(config.get("pseudocode_normalization_version"), 1),
        "ast_norm_version": safe_int(config.get("ast_normalization_version"), 1),
        "microcode_norm_version": safe_int(config.get("microcode_normalization_version"), 1),
        "api_semantic_map_version": safe_int(config.get("api_semantic_map_version"), 1),
        "pseudocode_hash": hash_sequence(version_prefix + ["PSEUDOCODE"] + tokens) if config.get("enable_pseudocode_similarity") and tokens else "",
        "pseudocode_ngrams": semantic_ngrams(tokens, n) if config.get("enable_pseudocode_similarity") and tokens else [],
        "ast_hash": hash_sequence(version_prefix + ["AST"] + tokens) if config.get("enable_ast_similarity") and tokens else "",
        "ast_subtrees": [{"subtree_hash": k, "occurrence_count": v} for k, v in ast_subtrees.items()],
        "ast_counts": ast_counts_from_tokens(tokens) if config.get("enable_ast_similarity") and tokens else ast_counts_from_tokens([]),
        "control_structure_hash": hash_sequence(version_prefix + ["CONTROL"] + control_tokens) if config.get("enable_ast_similarity") and control_tokens else "",
        "semantic_apis": sem_apis,
        "semantic_api_hash": hash_sequence(version_prefix + ["API"] + semantic_categories),
        "semantic_constants": sem_constants,
        "dataflow_patterns": dataflow,
        "microcode_hash": "",
        "microcode_ngrams": [],
        "micro_blocks": [],
        "token_count": len(tokens),
    }


def target_name(ea, op_index):
    try:
        target = idc.get_operand_value(ea, op_index)
        if target in (None, idc.BADADDR):
            return ""
        name = ida_name.get_name(target) or idc.get_name(target) or ""
        if not name:
            name = idc.print_operand(ea, op_index) or ""
        name = clean_api_name(name)
        return name if is_api_name(name) else ""
    except Exception:
        return ""


def normalize_operand(ea, op_index, mnemonic):
    try:
        op_type = idc.get_operand_type(ea, op_index)
        text = (idc.print_operand(ea, op_index) or "").strip()
    except Exception:
        return ""
    if not text:
        return ""
    if op_type == getattr(idc, "o_reg", -1) or REGISTER_RE.search(text):
        return "REG"
    if op_type == getattr(idc, "o_imm", -1):
        return "IMM"
    if op_type in {
        getattr(idc, "o_mem", -2),
        getattr(idc, "o_phrase", -3),
        getattr(idc, "o_displ", -4),
    } or "[" in text or "]" in text:
        return "MEM"
    if op_type in {getattr(idc, "o_near", -5), getattr(idc, "o_far", -6)}:
        api = target_name(ea, op_index) if mnemonic.startswith("call") else ""
        if mnemonic.startswith("call"):
            return f"API:{api}" if api else "CALL_INTERNAL"
        return "ADDR"
    if HEX_RE.match(text):
        return "IMM"
    return re.sub(r"\s+", "", text.lower())[:80]


def normalize_instruction(ea):
    mnemonic = (idc.print_insn_mnem(ea) or "").lower()
    operands = []
    apis = []
    constants = []
    for i in range(6):
        try:
            raw = idc.print_operand(ea, i)
        except Exception:
            raw = ""
        if not raw:
            continue
        norm = normalize_operand(ea, i, mnemonic)
        if norm:
            operands.append(norm)
        try:
            if idc.get_operand_type(ea, i) == getattr(idc, "o_imm", -1):
                val = idc.get_operand_value(ea, i)
                constant = meaningful_constant(val)
                if constant:
                    constants.append(constant)
        except Exception:
            pass
        if mnemonic.startswith("call"):
            api = target_name(ea, i)
            if api:
                apis.append(api)
    return {
        "mnemonic": mnemonic,
        "normalized": " ".join([mnemonic] + operands)[:200],
        "apis": apis,
        "constants": constants,
    }


def function_strings(start, end):
    refs = set()
    for ea in idautils.Heads(start, end):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        try:
            for ref in idautils.DataRefsFrom(ea):
                raw = ida_bytes.get_strlit_contents(ref, -1, 0) or ida_bytes.get_strlit_contents(ref, -1, 1)
                if not raw:
                    continue
                if isinstance(raw, bytes):
                    text = raw.decode("utf-8", "ignore")
                else:
                    text = str(raw)
                text = re.sub(r"\s+", " ", text).strip()
                if len(text) >= 4:
                    refs.add(text[:500])
        except Exception:
            continue
    return sorted(refs)


def raw_function_hash(start, end):
    try:
        data = ida_bytes.get_bytes(start, max(0, end - start)) or b""
        return hashlib.sha256(data).hexdigest() if data else ""
    except Exception:
        return ""


def basic_blocks(func, instruction_map, minimum_block_instructions):
    blocks = []
    degree_parts = []
    edge_parts = []
    edge_count = 0
    try:
        flow = list(idaapi.FlowChart(func))
        index_by_start = {block.start_ea: idx for idx, block in enumerate(flow)}
        for block in flow:
            ins = []
            for ea in idautils.Heads(block.start_ea, block.end_ea):
                item = instruction_map.get(ea)
                if item:
                    ins.append(item["normalized"])
            preds = list(block.preds())
            succs = list(block.succs())
            edge_count += len(succs)
            degree_parts.append(f"{len(preds)}:{len(succs)}")
            src_idx = index_by_start.get(block.start_ea, 0)
            for succ in succs:
                edge_parts.append(f"{src_idx}>{index_by_start.get(succ.start_ea, -1)}")
            if len(ins) >= minimum_block_instructions:
                blocks.append({
                    "block_hash": hash_sequence(ins),
                    "instruction_count": len(ins),
                    "predecessor_count": len(preds),
                    "successor_count": len(succs),
                })
    except Exception:
        pass
    degree_signature = ",".join(sorted(degree_parts))
    edge_signature = ",".join(sorted(edge_parts))
    complexity = max(1, edge_count - len(degree_parts) + 2) if degree_parts else 0
    cfg_hash = hash_sequence([degree_signature, edge_signature, str(len(degree_parts)), str(edge_count), str(complexity)])
    return blocks, {
        "cfg_hash": cfg_hash,
        "nodes": len(degree_parts),
        "edges": edge_count,
        "complexity": complexity,
        "degree_signature": degree_signature[:1000],
        "traversal_hash": hash_sequence(sorted(edge_parts) or degree_parts),
    }


def extract_function(index, start, config, hexrays_version=""):
    func = ida_funcs.get_func(start)
    if not func:
        return None
    flags = function_flags(func, start)
    is_thunk = bool(flags & ida_flag_value("FUNC_THUNK"))
    func_name = ida_name.get_name(func.start_ea) or idc.get_func_name(func.start_ea) or ""
    is_library = bool(flags & ida_flag_value("FUNC_LIB")) or is_common_library_function(func_name)
    if is_thunk and config.get("exclude_thunks"):
        return None
    instruction_map = {}
    mnemonics = []
    normalized = []
    apis = []
    constants = set()
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        item = normalize_instruction(ea)
        if not item["mnemonic"]:
            continue
        instruction_map[ea] = item
        mnemonics.append(item["mnemonic"])
        normalized.append(item["normalized"])
        apis.extend(item["apis"])
        constants.update(item["constants"])
    blocks, cfg = basic_blocks(func, instruction_map, safe_int(config.get("minimum_block_instructions"), 2))
    n = safe_int(config.get("mnemonic_ngram_size"), 4)
    ngrams = []
    for i in range(max(0, len(mnemonics) - n + 1)):
        ngrams.append({"ngram_hash": hash_sequence(mnemonics[i:i + n]), "ngram_size": n})
    out = {
        "function_index": index,
        "ida_address": hex(int(func.start_ea)),
        "size": max(0, int(func.end_ea - func.start_ea)),
        "instruction_count": len(normalized),
        "block_count": len(blocks),
        "cyclomatic_complexity": cfg["complexity"],
        "callers_count": len(list(idautils.CodeRefsTo(func.start_ea, 0))),
        "callees_count": len(set(apis)),
        "referenced_strings_count": 0,
        "imported_api_calls_count": len(apis),
        "raw_hash": raw_function_hash(func.start_ea, func.end_ea),
        "normalized_hash": hash_sequence(normalized),
        "is_library": 1 if is_library else 0,
        "is_thunk": 1 if is_thunk else 0,
        "ngrams": ngrams,
        "blocks": blocks,
        "apis": apis[:200],
        "constants": sorted(constants)[:200],
        "strings": function_strings(func.start_ea, func.end_ea)[:200],
        "cfg": cfg,
    }
    if (
        config.get("enable_semantic_similarity")
        and not is_thunk
        and not is_library
        and len(normalized) >= safe_int(config.get("minimum_semantic_function_instructions"), 10)
    ):
        out["semantic"] = semantic_from_function(func, apis, constants, config, hexrays_version)
    return out


def run_extraction(config):
    started = time.time()
    result = {
        "status": "failed",
        "reason": "",
        "analysis_engine": "ida",
        "analysis_engine_version": ida_version(),
        "normalization_version": safe_int(config.get("normalization_version"), 1),
        "feature_schema_version": safe_int(config.get("feature_schema_version"), 2),
        "profile": {},
        "functions": [],
    }
    try:
        ida_auto.auto_wait()
        analysis_done = time.time()
        functions = []
        hexrays_ok, hexrays_state, hexrays_version = hexrays_available() if config.get("enable_semantic_similarity") else (False, "disabled", "")
        semantic_attempted = 0
        semantic_success = 0
        semantic_failed = 0
        semantic_skipped = 0
        semantic_budget_exhausted = False
        max_semantic = safe_int(config.get("maximum_semantic_functions"), 100)
        ida_timeout = safe_int(config.get("ida_timeout_seconds"), 300)
        hexrays_timeout = safe_int(config.get("hexrays_timeout_seconds"), 120)
        per_function_timeout = safe_int(config.get("hexrays_function_timeout_seconds"), 10)
        reserve = max(30, per_function_timeout * 2)
        semantic_budget = max(0, min(hexrays_timeout, ida_timeout - reserve))
        semantic_deadline = analysis_done + semantic_budget
        function_errors = 0
        for idx, start in enumerate(idautils.Functions()):
            try:
                semantic_enabled = bool(config.get("enable_semantic_similarity") and hexrays_ok)
                if semantic_enabled and semantic_budget and time.time() >= semantic_deadline:
                    semantic_budget_exhausted = True
                    semantic_enabled = False
                if semantic_enabled and semantic_attempted >= max_semantic:
                    semantic_enabled = False
                if config.get("enable_semantic_similarity") and not semantic_enabled:
                    semantic_skipped += 1
                    item = extract_function(idx, start, {**config, "enable_semantic_similarity": False}, "")
                else:
                    item = extract_function(idx, start, {**config, "enable_semantic_similarity": semantic_enabled}, hexrays_version)
            except Exception:
                function_errors += 1
                continue
            if item:
                if isinstance(item.get("semantic"), dict):
                    semantic_attempted += 1
                    if item["semantic"].get("decompiler_status") == "success":
                        semantic_success += 1
                    else:
                        semantic_failed += 1
                item["referenced_strings_count"] = len(item.get("strings") or [])
                functions.append(item)
        minimum = safe_int(config.get("minimum_function_instructions"), 5)
        meaningful = [f for f in functions if safe_int(f.get("instruction_count")) >= minimum and f.get("normalized_hash")]
        all_blocks = {b.get("block_hash") for f in functions for b in f.get("blocks", []) if b.get("block_hash")}
        all_ngrams = {n.get("ngram_hash") for f in functions for n in f.get("ngrams", []) if n.get("ngram_hash")}
        api_patterns = 0
        for f in functions:
            apis = [a for a in f.get("apis", []) if a]
            api_patterns += 1 if apis else 0
            api_patterns += max(0, len(apis) - 1)
        cfg_hashes = {f.get("cfg", {}).get("cfg_hash") for f in functions if f.get("cfg", {}).get("cfg_hash")}
        partial_reasons = []
        if function_errors:
            partial_reasons.append(f"{function_errors} functions failed during extraction")
        if semantic_budget_exhausted:
            partial_reasons.append(f"Hex-Rays semantic budget exhausted after {semantic_attempted} attempts")
        elif config.get("enable_semantic_similarity") and semantic_attempted >= max_semantic:
            partial_reasons.append(f"Hex-Rays semantic function cap reached ({max_semantic})")
        result["status"] = "partial" if partial_reasons else "success"
        result["functions"] = functions
        result["profile"] = {
            "status": "partial" if partial_reasons else "success",
            "reason": "; ".join(partial_reasons) + "." if partial_reasons else "",
            "analysis_engine": "ida",
            "analysis_engine_version": result["analysis_engine_version"],
            "normalization_version": result["normalization_version"],
            "feature_schema_version": result["feature_schema_version"],
            "ida_analysis_time": round(analysis_done - started, 4),
            "feature_extraction_time": round(time.time() - analysis_done, 4),
            "function_count": len(functions),
            "meaningful_function_count": len(meaningful),
            "block_count": sum(len(f.get("blocks", [])) for f in functions),
            "instruction_count": sum(safe_int(f.get("instruction_count")) for f in functions),
            "unique_normalized_functions": len({f.get("normalized_hash") for f in meaningful if f.get("normalized_hash")}),
            "unique_block_hashes": len(all_blocks),
            "unique_ngram_hashes": len(all_ngrams),
            "api_pattern_count": api_patterns,
            "constant_count": len({c for f in functions for c in f.get("constants", []) if c}),
            "cfg_hash_count": len(cfg_hashes),
            "hexrays_status": hexrays_state,
            "hexrays_version": hexrays_version,
            "semantic_function_count": semantic_attempted,
            "semantic_success_count": semantic_success,
            "semantic_failed_count": semantic_failed,
            "semantic_coverage": round((semantic_success / len(meaningful) * 100.0), 4) if meaningful else 0,
            "function_error_count": function_errors,
            "semantic_skipped_count": semantic_skipped,
            "semantic_max_functions": max_semantic,
            "semantic_budget_seconds": semantic_budget,
            "semantic_budget_exhausted": 1 if semantic_budget_exhausted else 0,
        }
    except Exception as exc:
        result["reason"] = str(exc)
        result["profile"] = {"status": "failed", "reason": str(exc), "analysis_engine": "ida"}
    return result


def main():
    output_path = idc.ARGV[1] if idc and len(idc.ARGV) > 1 else (sys.argv[1] if len(sys.argv) > 1 else "")
    config_path = idc.ARGV[2] if idc and len(idc.ARGV) > 2 else (sys.argv[2] if len(sys.argv) > 2 else "")
    config = load_config(config_path)
    result = run_extraction(config)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, separators=(",", ":"))
    try:
        idc.qexit(0 if result.get("status") in {"success", "partial"} else 1)
    except Exception:
        return


if __name__ == "__main__":
    main()
