"""Declarative right-click menu organized around reverse-engineering tasks."""

ROOT = "Genesect/"

COMMON_GROUPS = (
    ("", (
        "genesect:settings",
        "genesect:view_display_options",
    )),
    ("AI Assistant/Explain && Document", (
        "genesect:explain_document", "genesect:list",
    )),
    ("AI Assistant/Chat && Investigation", (
        "genesect:ask_chat", "-", "genesect:agentic_analysis",
    )),
    ("AI Assistant/Bulk Analysis && Workflow", (
        "genesect:batch_ai_workbench", "-",
        "genesect:deep_analyzer", "-",
        "genesect:export_ai_workspace",
    )),
    ("Utilities/Navigation && Views", (
        "genesect:hex_viewer",
        "genesect:comment_explorer",
    )),
    ("Utilities/Program Structure", (
        "genesect:dnspy_xrefs", "genesect:copy_function_tree", "-",
        "genesect:callback_dispatch_resolver", "-",
        "genesect:global_variable_explorer", "genesect:copy_global_xref_tree",
        "genesect:com_explorer", "-",
        "genesect:entry_point_explorer", "genesect:thread_explorer",
    )),
    ("Utilities/C++", (
        "genesect:virtual_class_explorer",
        "genesect:rtti_explorer",
        "genesect:itanium_rtti_explorer",
    )),
    ("Utilities/Go", (
        "genesect:goresym", "genesect:go_package_organizer", "-",
        "genesect:go_user_code_map", "genesect:go_mark_idb",
    )),
    ("Utilities/Rust", (
        "genesect:rust_triage", "genesect:rust_string_fixups", "-",
        "genesect:rust_demangle", "genesect:rift_library_recognition", "-",
        "genesect:rust_user_code_map", "genesect:rust_mark_idb",
    )),
    ("Utilities/Malware Analysis", (
        "genesect:malware_analysis_assist", "genesect:findcrypt_explorer", "-",
        "genesect:shellcode_analyst", "genesect:callback_shellcode_explorer", "-",
        "genesect:driver_rootkit_explorer", "-",
        "genesect:runtime_trace_viewer",
    )),
    ("Utilities/Strings && Search", (
        "genesect:regex_idb_search", "-",
        "genesect:floss_strings",
    )),
    ("Utilities/Emulation && Decryption", (
        "genesect:emulate_call",
        "genesect:batch_emulate_xrefs", "-",
        "genesect:micro_emulator",
    )),
    ("Utilities/Linux", (
        "genesect:linux_syscall_resolver",
        "genesect:elf_got_cleaner",
        "genesect:elf_runtime_fingerprinter",
        "genesect:elf_header_repair",
        "genesect:itanium_rtti_explorer",
    )),
    ("Utilities/macOS", (
        "genesect:macho_objc_resolver",
        "genesect:macho_class_dumper",
        "genesect:macho_entitlements_explorer",
        "genesect:macho_syscall_resolver",
    )),
)

PSEUDOCODE_GROUPS = (
    ("AI Assistant/Current Function", (
        "genesect:rename_function",
        "genesect:rename_variables", "-",
        "genesect:suggest_function_prototype", "genesect:analyze_struct", "-",
        "genesect:add_comments", "genesect:delete_comments",
    )),
)

DISASSEMBLY_GROUPS = (
    ("AI Assistant/Current Function", (
        "genesect:rename_function", "-",
        "genesect:add_comments", "genesect:delete_comments",
    )),
)

EXTERNAL_TEXT_SEARCH = (
    "genesect:search_str_vt", "genesect:search_str_google",
    "genesect:search_str_github", "genesect:search_str_msdn",
    "genesect:search_str_cyberchef",
)


def menu_groups(pseudocode=False, bookmarks=None):
    additions = PSEUDOCODE_GROUPS if pseudocode else DISASSEMBLY_GROUPS
    groups = [(name, list(actions)) for name, actions in COMMON_GROUPS]
    for name, actions in additions:
        existing = next((items for group, items in groups if group == name), None)
        if existing is None:
            if name.startswith("AI Assistant/"):
                insert_at = next(
                    (i for i, (group, _) in enumerate(groups) if group.startswith("Utilities/")),
                    len(groups),
                )
                groups.insert(insert_at, (name, list(actions)))
            else:
                groups.append((name, list(actions)))
        else:
            existing.extend(actions)
    groups.append(("Utilities/Copy Bytes && Code", [
        "genesect:dump_bytes", "-",
        "genesect:copy_disasm", "-",
        "genesect:copy_yara_raw", "genesect:copy_python", "genesect:copy_c_array", "-",
        "genesect:copy_yara_rule",
    ]))
    pivots = list(EXTERNAL_TEXT_SEARCH)
    if not pseudocode:
        pivots = [
            "genesect:search_bytes_vt",
            "genesect:search_bytes_cyberchef", "-",
        ] + pivots
    groups.append(("Utilities/External Pivot Search", pivots))

    if bookmarks is None:
        bookmarks = []
    available = {
        action_id for _group, actions in groups for action_id in actions
        if action_id not in ("-", "genesect:settings")
    }
    bookmark_aliases = {
        "genesect:readable_code": "genesect:explain_document",
        "genesect:analyst_notes": "genesect:explain_document",
        "genesect:rename_function_malware": "genesect:rename_function",
        "genesect:add_asm_comments": "genesect:add_comments",
        "genesect:delete_asm_comments": "genesect:delete_comments",
        "genesect:anti_analysis_explorer": "genesect:malware_analysis_assist",
        "genesect:driver_rootkit_explorer": "genesect:malware_analysis_assist",
        "genesect:process_injection_explorer": "genesect:malware_analysis_assist",
        "genesect:api_sequence_explorer": "genesect:malware_analysis_assist",
        "genesect:protocol_packet_explorer": "genesect:malware_analysis_assist",
        "genesect:config_ioc_extractor": "genesect:malware_analysis_assist",
        "genesect:evidence_graph": "genesect:malware_analysis_assist",
        "genesect:bulk_rename": "genesect:batch_ai_workbench",
        "genesect:bulk_var_rename": "genesect:batch_ai_workbench",
        "genesect:bulk_analyze": "genesect:batch_ai_workbench",
        "genesect:toggle_highlight": "genesect:view_display_options",
        "genesect:toggle_disasm_highlight": "genesect:view_display_options",
        "genesect:toggle_indent_guides": "genesect:view_display_options",
        "genesect:toggle_pseudocode_block": "genesect:view_display_options",
        "genesect:argument_name_hints": "genesect:view_display_options",
        "genesect:zoom_all_views": "genesect:view_display_options",
        "genesect:side_by_side_sync": "genesect:side_by_side_sync",
        "genesect:call_ranking_explorer": "genesect:callback_dispatch_resolver",
        "genesect:memory_browser": "genesect:batch_ai_workbench",
        "genesect:vftable_list": "genesect:virtual_class_explorer",
        "genesect:go_rust_user_code_map": "genesect:go_user_code_map",
        "genesect:go_rust_mark_idb": "genesect:go_mark_idb",
        "genesect:copy_yara_mask": "genesect:copy_yara_rule",
        "genesect:copy_yara_no_imm": "genesect:copy_yara_rule",
        "genesect:copy_yara_opcodes": "genesect:copy_yara_rule",
    }
    bookmarked = []
    for action_id in bookmarks:
        canonical = bookmark_aliases.get(action_id, action_id)
        if canonical in available and canonical not in bookmarked:
            bookmarked.append(canonical)
    groups.append(("Bookmarks", bookmarked or ["genesect:bookmarks_empty"]))
    return groups


def bookmark_candidates():
    """Return every bookmarkable feature once, across both IDA view types."""
    candidates = []
    seen = set()
    for pseudocode in (True, False):
        for group, actions in menu_groups(pseudocode, bookmarks=[]):
            if group in ("", "Bookmarks"):
                continue
            category = group.split("/", 1)[0]
            for action_id in actions:
                if action_id in ("-", "genesect:bookmarks_empty") or action_id in seen:
                    continue
                seen.add(action_id)
                candidates.append((category, action_id))
    return candidates
