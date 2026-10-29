# -*- coding: utf-8 -*-
"""
GenesectPlugin — the main IDA plugin_t subclass.
"""
import idaapi
import ida_hexrays

from genesect.qt_compat import QT_BINDING, QT_MAJOR, QtCore, QtWidgets
from genesect.config import CONFIG
from genesect.ai_client import SimpleAI
import genesect.ai_client as _ai_mod
from genesect.highlight import (
    _create_highlight_hooks,
    destroy_highlight_hooks,
    toggle_highlight_handler,
    toggle_disasm_highlight_handler,
)
from genesect.indent import create_indent_guide_hooks, destroy_indent_guide_hooks, ToggleIndentGuidesHandler
from genesect.pseudocode_folding import (
    create_pseudocode_folding_hooks, destroy_pseudocode_folding_hooks,
    TogglePseudocodeBlockHandler,
)
from genesect.argument_hints import (
    create_argument_name_hint_hooks, destroy_argument_name_hint_hooks,
    ToggleArgumentNameHintsHandler,
)
from genesect.default_visuals import create_default_visual_hooks, destroy_default_visual_hooks
from genesect.zoom import (
    ToggleZoomAllViewsHandler, initialize_zoom_all_views, shutdown_zoom_all_views,
)
from genesect.view_options import ViewDisplayOptionsHandler
from genesect.xrefs import DnspyXrefsHandler
from genesect.handlers import (
    RenameVariablesHandler,
    RenameFunctionHandler,
    RenameMalwareFunctionHandler,
    SuggestFunctionPrototypeHandler,
    CommentHandler,
    DeleteCommentsHandler,
    AsmCommentHandler,
    DeleteAsmCommentsHandler,
    StructAnalysisHandler,
    BatchAIWorkbenchHandler,
    BulkRenameHandler,
    SettingsHandler,
    ShellcodeAnalystHandler,
    BulkVarRenameHandler,
    BulkAnalyzeHandler,
    SearchBytesVTHandler,
    SearchStringHandler,
    SearchBytesCyberChefHandler,
    FlossStringsHandler,
    AdvancedCopyHandler,
    DumpBytesHandler,
    CopyFunctionTreeHandler,
    CopyGlobalXrefTreeHandler,
)
from genesect.deep_analyzer import DeepAnalyzerHandler
from genesect.unified_chat import (
    SCOPE_CHAIN_SUMMARY,
    SCOPE_FUNCTION_CHAIN,
    UnifiedAIChatHandler,
)
from genesect.hexview import OpenHexViewHandler
from genesect.vftable import VftableListHandler
from genesect.global_explorer import GlobalVariableExplorerHandler
from genesect.virtual_class_explorer import VirtualClassExplorerHandler
from genesect.rtti_parser import RTTIExplorerHandler
from genesect.com_explorer import COMExplorerHandler
from genesect.callback_resolver import CallbackDispatchResolverHandler
from genesect.callback_shellcode_explorer import CallbackShellcodeExplorerHandler
from genesect.thread_sync_explorer import ThreadExplorerHandler
from genesect.entry_point_explorer import EntryPointExplorerHandler
from genesect.regex_idb_search import RegexIDBSearchHandler
from genesect.findcrypt_explorer import FindCryptExplorerHandler
from genesect.malware_triage import MalwareAnalysisAssistHandler
from genesect.malware_triage_model import (
    DETECTOR_ANTI_ANALYSIS,
    DETECTOR_API_CLASSIFICATION,
    DETECTOR_API_SEQUENCE,
    DETECTOR_CONFIG_IOC,
    DETECTOR_PROCESS_INJECTION,
    DETECTOR_PROTOCOL,
)
from genesect.evidence_graph import EvidenceGraphHandler
from genesect.comment_explorer import CommentExplorerHandler
from genesect.agentic_analyzer import AgenticAnalysisHandler
from genesect.go_rust_user_code_map import (
    GoRustMarkIDBHandler,
    GoRustUserCodeMapHandler,
    GoUserCodeMapHandler,
    GoMarkIDBHandler,
    RustUserCodeMapHandler,
    RustMarkIDBHandler,
)
from genesect.goresym_integration import GoReSymHandler
from genesect.go_package_tools import GoPackageOrganizerHandler
from genesect.rust_analysis_tools import (
    RustDemangleHandler,
    RustTriageHandler,
    ToggleRustStringFixupsHandler,
    create_rust_string_fixup_hooks,
    destroy_rust_string_fixup_hooks,
)
from genesect.rift_integration import RiftLibraryRecognitionHandler
from genesect.ai_workspace_export import ExportAIWorkspaceHandler
from genesect.metadata import PLUGIN_DISPLAY_NAME, __version__
from genesect.ui.preview import UIPreviewHandler
from genesect.migration import LegacyMigrationHandler
from genesect.idb_storage import ensure_storage_schema
from genesect.trace_viewer import RuntimeTraceViewerHandler
from genesect.driver_rootkit_explorer import DriverRootkitExplorerHandler
from genesect.side_by_side_sync import SideBySideSyncHandler
from genesect.micro_emulator import (
    EmulateCallHandler,
    BatchEmulateXrefsHandler,
    MicroEmulatorHandler,
)
from genesect.linux_syscall_resolver import LinuxSyscallResolverHandler
from genesect.elf_got_cleaner import ELFPltGotCleanerHandler
from genesect.itanium_rtti_parser import ItaniumRTTIExplorerHandler
from genesect.macho_objc_resolver import (
    MachOObjCResolverHandler,
    MachOClassDumperHandler,
    MachOEntitlementsHandler,
)
from genesect.macho_syscall_resolver import MachOSyscallResolverHandler
from genesect.call_explainer import (
    ToggleCallExplanationsHandler,
    create_call_explainer_hooks,
    destroy_call_explainer_hooks,
)
from genesect.elf_runtime_fingerprinter import ELFRuntimeFingerprinterHandler
from genesect.elf_header_repair import ELFHeaderRepairHandler
from genesect.ui.icons import free_menu_icons, load_menu_icons

# These will be imported lazily to avoid circular imports
_view_module = None


class EmptyBookmarksHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        return 0

    def update(self, ctx):
        return getattr(idaapi, "AST_DISABLE_ALWAYS", getattr(idaapi, "AST_DISABLE", 0))

def _get_view_module():
    global _view_module
    if _view_module is None:
        import genesect.view as _vm
        _view_module = _vm
    return _view_module


class GenesectPlugin(idaapi.plugin_t):
    # PLUGIN_HIDE suppresses IDA's automatic Edit > Plugins entry. Genesect
    # remains resident (PLUGIN_FIX), keeps its hotkey, and exposes its complete
    # command tree exclusively through the Disassembly/Pseudocode context menu.
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Genesect: AI-assisted reverse engineering for IDA Pro"
    help = "AI-assisted analysis, annotation, renaming, and malware research utilities"
    wanted_name = PLUGIN_DISPLAY_NAME
    wanted_hotkey = "Ctrl-Shift-G"

    def __init__(self):
        super(GenesectPlugin, self).__init__()
        self.view = None
        self.code_view = None
        self.notes_view = None
        self.hooks = None
        self.config = CONFIG
        self.ctx_hooks = None
        self.highlight_hooks = None
        self.indent_guide_hooks = None
        self.pseudocode_folding_hooks = None
        self.argument_hint_hooks = None
        self.call_explainer_hooks = None
        self.default_visual_hooks = None
        self.rust_string_fixup_hooks = None

    def init(self):
        if not QtWidgets:
            return idaapi.PLUGIN_SKIP

        vm = _get_view_module()
        vm.plugin_instance = self
        ensure_storage_schema()
        self.menu_icons = load_menu_icons()
        icon = lambda name, fallback: self.menu_icons.get(name, fallback)

        _ai_mod.AI_CLIENT = SimpleAI(self.config)

        # Register Highlighter Actions (Pseudocode)
        # Register Highlighter Actions (Pseudocode)
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:toggle_highlight", "Toggle Call Highlight (Pseudocode)",
            toggle_highlight_handler(), "Ctrl+Alt+H",
            "Toggle function call highlighting in pseudocode", icon("toggle_highlight", 48)
        ))
        # Register Highlighter Actions (Disasm)
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:toggle_disasm_highlight", "Toggle Call Highlight (Assembly)",
            toggle_disasm_highlight_handler(), "Ctrl+Shift+H",
            "Toggle function call highlighting in Graph/Linear view", icon("toggle_disasm_highlight", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:toggle_indent_guides", "Toggle Indent Marks",
            ToggleIndentGuidesHandler(), "Ctrl+Alt+I",
            "Toggle colorful nesting-level indent marks in Hex-Rays pseudocode", icon("toggle_indent_guides", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:toggle_pseudocode_block", "Interactive Code Blocks",
            TogglePseudocodeBlockHandler(), "",
            "Single-click a brace to highlight its block; double-click to collapse or expand it",
            icon("toggle_pseudocode_block", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:argument_name_hints", "Display function argument names",
            ToggleArgumentNameHintsHandler(), "",
            "Toggle parameter-name inlay hints in Hex-Rays function calls",
            icon("argument_name_hints", 48), getattr(idaapi, "ADF_CHECKABLE", 0)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:toggle_call_explanations", "Explain Calls & Bitmask Constants",
            ToggleCallExplanationsHandler(), "",
            "Toggle dynamic constant and bitmask explanations (open flags, mmap RWX, syscalls) in Hex-Rays",
            icon("toggle_call_explanations", 48), getattr(idaapi, "ADF_CHECKABLE", 0)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:bookmarks_empty", "No bookmarks configured",
            EmptyBookmarksHandler(), "",
            "Choose bookmarked features in Genesect Settings", icon("bookmarks_empty", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:zoom_all_views", "Zoom Views (Ctrl+Wheel)",
            ToggleZoomAllViewsHandler(), "",
            "Toggle Ctrl+wheel font zoom for scrollable IDA and Genesect views",
            icon("zoom_all_views", 48), getattr(idaapi, "ADF_CHECKABLE", 0)
        ))
        initialize_zoom_all_views()

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:side_by_side_sync", "Side-by-Side Sync (Ghidra Style)",
            SideBySideSyncHandler(), "Ctrl+Alt+Y",
            "Dock Disassembly and Pseudocode side-by-side with synchronized cursor and highlight",
            icon("side_by_side_sync", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:view_display_options", "View & Display Options...",
            ViewDisplayOptionsHandler(), "Ctrl+Alt+V",
            "Configure visual overlays, call highlighting, indent guides, and zoom options",
            icon("view_display_options", icon("settings", 48))
        ))

        if ida_hexrays.init_hexrays_plugin():
            self.highlight_hooks = _create_highlight_hooks()
            self.indent_guide_hooks = create_indent_guide_hooks()
            self.pseudocode_folding_hooks = create_pseudocode_folding_hooks()
            self.argument_hint_hooks = create_argument_name_hint_hooks()
            self.rust_string_fixup_hooks = create_rust_string_fixup_hooks()
        else:
            print("[Genesect] Hex-Rays not available at init time, hooks will be installed on first enable")
            self.highlight_hooks = None

        self.default_visual_hooks = create_default_visual_hooks()

        print("-" * 60)
        print(f"{PLUGIN_DISPLAY_NAME} {__version__} initialized.")
        print(f"Qt backend: {QT_BINDING or 'unknown'} (Qt {QT_MAJOR or 'unknown'}).")
        print("Use Ctrl+Shift+G, or right-click in Disassembly/Pseudocode and open Genesect.")
        print("-" * 60)

        # Unified function explanation and documentation workspace.
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:explain_document",
            "Explain & Document Function...",
            vm.GenesectHandler("explanation"),
            "Ctrl+Alt+G",
            "Explain the current function, generate readable code, and maintain analyst notes",
            icon("readable_code", 109),
        ))

        # Compatibility aliases route old commands into the unified workspace.
        readable_code_desc = idaapi.action_desc_t(
            "genesect:readable_code",
            "Explain & Document - Readable Code",
            vm.GenesectHandler("code"),
            "",
            "Compatibility action: open the Readable Code section",
            icon("readable_code", 109)
        )
        idaapi.register_action(readable_code_desc)

        # Register Analyst Notes Action
        analyst_notes_desc = idaapi.action_desc_t(
            "genesect:analyst_notes",
            "Explain & Document - Analyst Notes",
            vm.GenesectHandler("notes"),
            "Ctrl+Alt+Shift+G",
            "Compatibility action: open the Analyst Notes section",
            icon("analyst_notes", 109)
        )
        idaapi.register_action(analyst_notes_desc)
        # Main menu entry removed - focusing on right-click menu

        list_action_desc = idaapi.action_desc_t(
            "genesect:list",
            "Browse Saved Artifacts",
            vm.SavedNotesHandler(),
            "Ctrl+Alt+L",
            "List all functions with saved Genesects",
            icon("list", 58)
        )
        idaapi.register_action(list_action_desc)

        # Register Settings Action
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:settings",
            "Settings...",
            SettingsHandler(),
            "Ctrl+Alt+P",
            "Configure AI Provider and Performance settings",
            icon("settings", 147)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:ui_preview",
            "UI Component Preview...",
            UIPreviewHandler(),
            "",
            "Review the Genesect interface foundation",
            icon("ui_preview", 147)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:migrate_legacy",
            "Migrate Legacy Data...",
            LegacyMigrationHandler.create(),
            "",
            "Non-destructively copy missing legacy IDB and configuration data",
            icon("migrate_legacy", 147),
        ))

        rename_func_desc = idaapi.action_desc_t(
            "genesect:rename_function",
            "Suggest Function Name",
            RenameFunctionHandler(),
            "Ctrl+Alt+N",
            "Use AI to suggest a concise, descriptive name for the current function",
            icon("rename_function", 204)
        )
        idaapi.register_action(rename_func_desc)

        rename_malware_desc = idaapi.action_desc_t(
            "genesect:rename_function_malware",
            "Suggest Function Name (Compatibility)",
            RenameMalwareFunctionHandler(),
            "Ctrl+Alt+M",
            "Use AI to suggest a concise, descriptive name for the current function",
            icon("rename_function_malware", 204)
        )
        idaapi.register_action(rename_malware_desc)

        rename_vars_desc = idaapi.action_desc_t(
            "genesect:rename_variables",
            "Suggest Variable Name",
            RenameVariablesHandler(),
            "Ctrl+Alt+R",
            "Use AI to rename variables in the current function",
            icon("rename_variables", 203)
        )
        idaapi.register_action(rename_vars_desc)

        # Suggest Function Prototype Action
        sugg_sig_desc = idaapi.action_desc_t(
            "genesect:suggest_function_prototype",
            "Suggest Function Prototype",
            SuggestFunctionPrototypeHandler(),
            "Ctrl+Alt+S",
            "Ask AI to infer and apply a function prototype",
            icon("suggest_function_prototype", 138)
        )
        idaapi.register_action(sugg_sig_desc)

        comment_handler_desc = idaapi.action_desc_t(
            "genesect:add_comments",
            "Generate Comments",
            CommentHandler(),
            "Ctrl+Alt+C",
            "Ask AI to add helpful comments to the current function or disassembly range",
            icon("add_comments", 109)
        )
        idaapi.register_action(comment_handler_desc)

        asm_comment_handler_desc = idaapi.action_desc_t(
            "genesect:add_asm_comments",
            "Generate Disassembly Comments",
            AsmCommentHandler(),
            "Ctrl+Shift+C",
            "Ask AI to add concise section comments to the disassembly",
            icon("add_asm_comments", 109)
        )
        idaapi.register_action(asm_comment_handler_desc)

        del_asm_comments_desc = idaapi.action_desc_t(
            "genesect:delete_asm_comments",
            "Remove Disassembly Comments...",
            DeleteAsmCommentsHandler(),
            "Ctrl+Shift+D",
            "Remove Genesect-generated comments while preserving analyst notes",
            icon("delete_asm_comments", 109)
        )
        idaapi.register_action(del_asm_comments_desc)

        # Bytes/Instructions/Shellcode Analysis
        shell_analyst_desc = idaapi.action_desc_t(
            "genesect:shellcode_analyst",
            "Analyze Selected Bytes / Shellcode",
            ShellcodeAnalystHandler(),
            "Ctrl+Shift+E",
            "Open the static shellcode analysis window",
            icon("shellcode_analyst", 124)
        )
        idaapi.register_action(shell_analyst_desc)

        delete_comments_desc = idaapi.action_desc_t(
            "genesect:delete_comments",
            "Remove Comments...",
            DeleteCommentsHandler(),
            "Ctrl+Alt+D",
            "Remove Genesect-generated comments while preserving analyst notes",
            icon("delete_comments", 109)
        )
        idaapi.register_action(delete_comments_desc)

        xrefs_desc = idaapi.action_desc_t(
            "genesect:dnspy_xrefs",
            "Call Tree",
            DnspyXrefsHandler(),
            "Ctrl+Alt+X",
            "View interactive dnSpy style call hierarchy",
            icon("dnspy_xrefs", 73)
        )
        idaapi.register_action(xrefs_desc)
        # (Call Tree attached in the tools separator group above)

        # Structure Analysis Action
        struct_action_desc = idaapi.action_desc_t(
            "genesect:analyze_struct", "Infer / Edit Structure",
            StructAnalysisHandler(), "Ctrl+Alt+E",
            "Analyze variable usage to infer structure", icon("analyze_struct", 101)
        )
        idaapi.register_action(struct_action_desc)

        # Batch AI Workbench Action (Primary Consolidated Action)
        batch_workbench_desc = idaapi.action_desc_t(
            "genesect:batch_ai_workbench",
            "Batch AI Workbench",
            BatchAIWorkbenchHandler(0),
            "Ctrl+Shift+R",
            "Unified batch AI workbench for functions, variables, and function analysis",
            icon("bulk_rename", 205),
        )
        idaapi.register_action(batch_workbench_desc)

        # Compatibility actions for direct tab routing and existing shortcuts
        bulk_rename_desc = idaapi.action_desc_t(
            "genesect:bulk_rename",
            "Batch AI Workbench - Function Renamer",
            BulkRenameHandler(),
            "",
            "Compatibility action: open Batch AI Workbench on Function Renamer",
            icon("bulk_rename", 205),
        )
        idaapi.register_action(bulk_rename_desc)

        bulk_var_rename_desc = idaapi.action_desc_t(
            "genesect:bulk_var_rename",
            "Batch AI Workbench - Variable Renamer",
            BulkVarRenameHandler(),
            "Ctrl+Shift+V",
            "Compatibility action: open Batch AI Workbench on Variable Renamer",
            icon("bulk_var_rename", 206),
        )
        idaapi.register_action(bulk_var_rename_desc)

        bulk_analyze_desc = idaapi.action_desc_t(
            "genesect:bulk_analyze",
            "Batch AI Workbench - Function Analysis",
            BulkAnalyzeHandler(),
            "Ctrl+Shift+A",
            "Compatibility action: open Batch AI Workbench on Function Analysis",
            icon("bulk_analyze", 110),
        )
        idaapi.register_action(bulk_analyze_desc)

        # Deep Analyzer Action
        deep_analyzer_desc = idaapi.action_desc_t(
            "genesect:deep_analyzer",
            "Deep Analyzer with Report",
            DeepAnalyzerHandler(),
            "Ctrl+Shift+S",
            "Automated bottom-up recursive function analysis and summarization",
            icon("deep_analyzer", 122),
        )
        idaapi.register_action(deep_analyzer_desc)

        # Summarizer Action
        summarizer_desc = idaapi.action_desc_t(
            "genesect:summarizer",
            "AI Chat - Function Chain Summary",
            UnifiedAIChatHandler(SCOPE_CHAIN_SUMMARY),
            "Ctrl+Alt+Z",
            "Compatibility shortcut: open AI Chat with Function Chain Summary selected",
            icon("summarizer", 122),
        )
        idaapi.register_action(summarizer_desc)
        
        # FLOSS Strings Discovery Action
        floss_strings_desc = idaapi.action_desc_t(
            "genesect:floss_strings",
            "Discover Strings with FLOSS",
            FlossStringsHandler(),
            "Ctrl+Shift+F",
            "Discover strings built dynamically (Stack, Tight, Decoded) using FLOSS",
            icon("floss_strings", 183)
        )
        idaapi.register_action(floss_strings_desc)

        goresym_desc = idaapi.action_desc_t(
            "genesect:goresym",
            "GoReSym",
            GoReSymHandler(),
            "",
            "Recover Go runtime symbols and types with Mandiant GoReSym",
            icon("goresym", 73)
        )
        idaapi.register_action(goresym_desc)

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:go_package_organizer",
            "Organize Go Packages",
            GoPackageOrganizerHandler(),
            "",
            "Organize Go functions into package folders in IDA's function tree",
            icon("go_package_organizer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:go_user_code_map",
            "Go User-Code Coverage Map",
            GoUserCodeMapHandler(),
            "",
            "Classify Go runtime, stdlib, third-party, and likely user code",
            icon("go_user_code_map", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:go_mark_idb",
            "Mark Go Code in IDB",
            GoMarkIDBHandler(),
            "",
            "Add comments and colors for likely Go user and third-party code",
            icon("go_mark_idb", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rust_user_code_map",
            "Rust User-Code Coverage Map",
            RustUserCodeMapHandler(),
            "",
            "Classify Rust runtime, stdlib, third-party, and likely user code",
            icon("rust_user_code_map", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rust_mark_idb",
            "Mark Rust Code in IDB",
            RustMarkIDBHandler(),
            "",
            "Add comments and colors for likely Rust user and third-party code",
            icon("rust_mark_idb", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:go_rust_user_code_map",
            "Go/Rust User Code Map",
            GoRustUserCodeMapHandler(),
            "",
            "Classify Go/Rust runtime, stdlib, third-party, and likely user code",
            icon("go_rust_user_code_map", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:go_rust_mark_idb",
            "Mark Go/Rust User Code in IDB",
            GoRustMarkIDBHandler(),
            "",
            "Add comments and colors for likely Go/Rust user and third-party code",
            icon("go_rust_mark_idb", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rust_triage",
            "Rust Binary Triage",
            RustTriageHandler(),
            "",
            "Score Rust indicators and summarize reverse-engineering leads",
            icon("rust_triage", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rust_string_fixups",
            "Display Rust Strings",
            ToggleRustStringFixupsHandler(),
            "",
            "Render Rust string literals inline in Hex-Rays pseudocode",
            icon("rust_string_fixups", 48),
            getattr(idaapi, "ADF_CHECKABLE", 0)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rust_demangle",
            "Demangle Rust Symbols",
            RustDemangleHandler(),
            "",
            "Rename Rust legacy/v0 mangled function symbols when possible",
            icon("rust_demangle", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rift_library_recognition",
            "RIFT Library Recognition",
            RiftLibraryRecognitionHandler(),
            "",
            "Generate Rust library FLIRT signatures through a Microsoft RIFT server",
            icon("rift_library_recognition", 73)
        ))
        

        ask_chat_desc = idaapi.action_desc_t(
            "genesect:ask_chat",
            "AI Chat...",
            UnifiedAIChatHandler(),
            "Ctrl+Alt+A",
            "Chat about the current function, a function chain, or generate a chain summary",
            icon("ask_chat", 124)
        )
        idaapi.register_action(ask_chat_desc)

        ask_chat_chain_desc = idaapi.action_desc_t(
            "genesect:ask_chat_chain",
            "AI Chat - Function Chain",
            UnifiedAIChatHandler(SCOPE_FUNCTION_CHAIN),
            "Ctrl+Alt+Shift+A",
            "Compatibility shortcut: open AI Chat with Function Chain selected",
            icon("ask_chat_chain", 124)
        )
        idaapi.register_action(ask_chat_chain_desc)

        agentic_desc = idaapi.action_desc_t(
            "genesect:agentic_analysis",
            "Autonomous Investigation",
            AgenticAnalysisHandler(),
            "Ctrl+Alt+Shift+M",
            "Run autonomous agentic loop to reverse engineer the current function",
            icon("agentic_analysis", 204)
        )
        idaapi.register_action(agentic_desc)

        # Register Search Utils Actions
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_bytes_vt", "Search Selected Bytes on VirusTotal...",
            SearchBytesVTHandler(), "",
            "Search highlighted bytes in VirusTotal", icon("search_bytes_vt", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_bytes_cyberchef", "Open Selected Bytes in CyberChef...",
            SearchBytesCyberChefHandler(), "",
            "Add highlighted bytes to CyberChef input", icon("search_bytes_cyberchef", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_str_vt", "Search Text on VirusTotal...",
            SearchStringHandler("vt"), "",
            "Search string in VirusTotal", icon("search_str_vt", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_str_google", "Search Text on Google...",
            SearchStringHandler("google"), "",
            "Search string in Google", icon("search_str_google", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_str_github", "Search Text on GitHub...",
            SearchStringHandler("github"), "",
            "Search string in GitHub", icon("search_str_github", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_str_msdn", "Search WinAPI Documentation...",
            SearchStringHandler("msdn"), "",
            "Search string (WinAPI) in MSDN Documentation", icon("search_str_msdn", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:search_str_cyberchef", "Open Text in CyberChef...",
            SearchStringHandler("cyberchef"), "",
            "Add string to CyberChef input", icon("search_str_cyberchef", 128)
        ))
        
        # Advanced Copy Actions
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_yara_raw", "Copy Hex Bytes", AdvancedCopyHandler("yara_raw"), "", "Copy selected bytes as hex string", icon("copy_yara_raw", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_yara_rule", "Generate YARA Rule...", AdvancedCopyHandler("yara_rule"), "", "Generate a simple YARA rule from selected bytes", icon("copy_yara_rule", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_yara_mask", "Copy Hex (Mask Targets/Relocs)", AdvancedCopyHandler("yara_mask"), "", "Copy selected bytes masking jumps and memory references", icon("copy_yara_mask", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_yara_no_imm", "Copy Hex (Mask Immediates)", AdvancedCopyHandler("yara_no_imm"), "", "Copy selected bytes masking immediates and addresses", icon("copy_yara_no_imm", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_yara_opcodes", "Copy Hex (Opcodes Only)", AdvancedCopyHandler("yara_opcodes"), "", "Copy selected bytes masking everything but opcodes", icon("copy_yara_opcodes", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_python", "Copy Python Byte Literal", AdvancedCopyHandler("python"), "", 'Copy selected bytes as python string', icon("copy_python", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_c_array", "Copy C/C++ Byte Array", AdvancedCopyHandler("c_array"), "", "Copy selected bytes as a C array", icon("copy_c_array", 31)))
        idaapi.register_action(idaapi.action_desc_t("genesect:copy_disasm", "Copy Disassembly Text", AdvancedCopyHandler("disasm"), "", "Copy selected disassembly lines", icon("copy_disasm", 31)))

        # Dump Bytes Action
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:dump_bytes",
            "Dump Selected Bytes...",
            DumpBytesHandler(),
            "",
            "Dump a range of bytes or a global variable to a file",
            icon("dump_bytes", 31)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:export_ai_workspace",
            "Export AI Workspace...",
            ExportAIWorkspaceHandler(),
            "",
            "Export decompilation, disassembly, callgraph, strings, imports, and Genesect evidence for local AI analysis",
            icon("export_ai_workspace", 31)
        ))

        # Hex Viewer Action (attached in the tools separator group above)
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:hex_viewer",
            "Hex Viewer",
            OpenHexViewHandler(),
            "Ctrl+Alt+B",
            "Open the Genesect Hex Viewer (synced with current function)",
            icon("hex_viewer", 80)
        ))

        # Vftable method browser
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:vftable_list",
            "VTable Explorer",
            VftableListHandler(),
            "",
            "Scan vftables and browse their functions, callers, and users",
            icon("vftable_list", 73)
        ))

        # Copy Function Tree Action
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:copy_function_tree",
            "Copy Function Tree",
            CopyFunctionTreeHandler(),
            "Ctrl+Alt+T",
            "Recursively copy decompiled sub-functions called by the current function",
            icon("copy_function_tree", 31)
        ))

        # Copy Global Variable Xref Tree Action
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:copy_global_xref_tree",
            "Copy Global Xref Tree",
            CopyGlobalXrefTreeHandler(),
            "",
            "Recursively copy functions and their callers that use the selected global variable",
            icon("copy_global_xref_tree", 31)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:global_variable_explorer",
            "Global Variable Explorer",
            GlobalVariableExplorerHandler(),
            "",
            "Explore global reads, writes, initialization, inferred types, aliases, and affected functions",
            icon("global_variable_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:virtual_class_explorer",
            "Virtual-Class Explorer",
            VirtualClassExplorerHandler(),
            "",
            "Recover virtual tables, class hierarchies, constructors, destructors, methods, RTTI, and inheritance",
            icon("virtual_class_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:rtti_explorer",
            "MSVC RTTI Explorer...",
            RTTIExplorerHandler(),
            "",
            "Scan MSVC RTTI, recover exact C++ class names, and generate typed VTable structs",
            icon("rtti_explorer", icon("virtual_class_explorer", 73))
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:com_explorer",
            "COM Explorer",
            COMExplorerHandler(),
            "",
            "Track COM GUID references and infer Hex-Rays interface types",
            icon("com_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:callback_dispatch_resolver",
            "Indirect Call Explorer",
            CallbackDispatchResolverHandler(),
            "",
            "Identify dynamic indirect calls, function pointers, and dispatch tables",
            icon("callback_dispatch_resolver", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:callback_shellcode_explorer",
            "Callback Shellcode APIs",
            CallbackShellcodeExplorerHandler(),
            "",
            "Identify APIs commonly abused for executing shellcode via callbacks",
            icon("inspect", 73)
        ))


        idaapi.register_action(idaapi.action_desc_t(
            "genesect:thread_explorer",
            "Thread Explorer",
            ThreadExplorerHandler(),
            "",
            "Map thread creation, entry points, APCs, queues, and message activity",
            icon("thread_explorer", 73)
        ))





        idaapi.register_action(idaapi.action_desc_t(
            "genesect:entry_point_explorer",
            "Entry-Point Explorer",
            EntryPointExplorerHandler(),
            "",
            "Show executable entry points, exports, TLS callbacks, constructors, initialization arrays, and thread entries",
            icon("entry_point_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:regex_idb_search",
            "Regex Search Across IDB",
            RegexIDBSearchHandler(),
            "",
            "Search decompilation, disassembly, strings, names, and comments using regular expressions",
            icon("regex_idb_search", 73)
        ))


        idaapi.register_action(idaapi.action_desc_t(
            "genesect:comment_explorer",
            "Comment Explorer",
            CommentExplorerHandler(),
            "",
            "Search, navigate, edit, delete, and export disassembly and Hex-Rays comments",
            icon("comment_explorer", 73)
        ))


        idaapi.register_action(idaapi.action_desc_t(
            "genesect:malware_analysis_assist",
            "Malware Analysis Assist",
            MalwareAnalysisAssistHandler(),
            "",
            "Correlate anti-analysis, injection, API sequence, network/C2, configuration, and IOC evidence",
            icon("anti_analysis_explorer", 73),
        ))

        # Compatibility actions route the former standalone explorers into the
        # unified Malware Analysis Assist workspace with a focused detector.
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:protocol_packet_explorer",
            "Malware Analysis Assist - Network / C2",
            MalwareAnalysisAssistHandler(DETECTOR_PROTOCOL),
            "",
            "Compatibility action: open Malware Analysis Assist focused on network and C2 evidence",
            icon("protocol_packet_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:process_injection_explorer",
            "Malware Analysis Assist - Process Injection",
            MalwareAnalysisAssistHandler(DETECTOR_PROCESS_INJECTION),
            "",
            "Compatibility action: open Malware Analysis Assist focused on process injection",
            icon("process_injection_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:config_ioc_extractor",
            "Malware Analysis Assist - Configuration / IOCs",
            MalwareAnalysisAssistHandler(DETECTOR_CONFIG_IOC),
            "",
            "Compatibility action: open Malware Analysis Assist focused on configuration and IOCs",
            icon("config_ioc_extractor", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:anti_analysis_explorer",
            "Malware Analysis Assist - Anti-Analysis",
            MalwareAnalysisAssistHandler(DETECTOR_ANTI_ANALYSIS),
            "",
            "Compatibility action: open Malware Analysis Assist focused on anti-analysis evidence",
            icon("anti_analysis_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:findcrypt_explorer",
            "Find Crypt Explorer",
            FindCryptExplorerHandler(),
            "",
            "Detect crypto, hash, compression, and encoding constants and API usage",
            icon("findcrypt_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "genesect:api_sequence_explorer", "Malware Analysis Assist - API Behavior",
            MalwareAnalysisAssistHandler(DETECTOR_API_SEQUENCE), "", "Compatibility action: open Malware Analysis Assist focused on ordered API behavior",
            icon("api_sequence_explorer", 73)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:runtime_trace_viewer",
            "Runtime Trace Viewer",
            RuntimeTraceViewerHandler(),
            "",
            "Import Speakeasy/runtime artifacts, inspect events, and apply coverage overlays",
            icon("inspect", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:driver_rootkit_explorer",
            "Windows Driver & Rootkit Explorer",
            DriverRootkitExplorerHandler(),
            "Ctrl+Alt+K",
            "Analyze driver IOCTL dispatch tables, device objects, DKOM/MSR/DSE rootkit primitives, and kernel structures",
            icon("driver_rootkit_explorer", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:evidence_graph",
            "Malware Analysis Assist - API Classification",
            MalwareAnalysisAssistHandler(DETECTOR_API_CLASSIFICATION),
            "",
            "Compatibility action: open Malware Analysis Assist focused on API classification",
            icon("evidence_graph", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:emulate_call",
            "Emulate Function Call...",
            EmulateCallHandler(),
            "Ctrl+Alt+U",
            "Emulate call AST using Unicorn engine, decrypt return buffers, and annotate IDB",
            icon("emulate_call", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:batch_emulate_xrefs",
            "Batch Emulate All Callers...",
            BatchEmulateXrefsHandler(),
            "",
            "Batch emulate all cross-references to this decrypter function across the IDB",
            icon("batch_emulate_xrefs", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:micro_emulator",
            "Interactive Micro-Emulator...",
            MicroEmulatorHandler(),
            "Ctrl+Shift+U",
            "Step-into, step-over, live registers, and memory tracking CPU micro-emulator",
            icon("micro_emulator", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:linux_syscall_resolver",
            "Raw Syscall Resolver",
            LinuxSyscallResolverHandler(),
            "",
            "Scan raw syscall/int 0x80/svc instructions, resolve kernel syscalls, and detect rootkit primitives",
            icon("linux_syscall_resolver", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:elf_got_cleaner",
            "PLT/GOT Cleaner...",
            ELFPltGotCleanerHandler(),
            "",
            "Resolve obfuscated GOT slots, restore unnamed PLT stubs, and propagate libc prototypes",
            icon("elf_got_cleaner", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:elf_runtime_fingerprinter",
            "Libc Fingerprinter...",
            ELFRuntimeFingerprinterHandler(),
            "",
            "Identify glibc/musl versions and compiler toolchains in stripped static ELFs",
            icon("elf_runtime_fingerprinter", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:elf_header_repair",
            "ELF Header Repair...",
            ELFHeaderRepairHandler(),
            "",
            "Detect and rectify anti-analysis tampered ELF headers (EI_CLASS, EI_DATA, e_shoff)",
            icon("elf_header_repair", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:itanium_rtti_explorer",
            "Itanium RTTI Explorer",
            ItaniumRTTIExplorerHandler(),
            "",
            "Scan GCC/Clang Itanium ABI typeinfo descriptors, reconstruct class hierarchies, and export VTable structs",
            icon("itanium_rtti_explorer", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:macho_objc_resolver",
            "ObjC MsgSend Resolver",
            MachOObjCResolverHandler(),
            "",
            "Reconstruct dynamic objc_msgSend calls into readable [Class method] signatures and annotate IDB",
            icon("macho_objc_resolver", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:macho_class_dumper",
            "ObjC Class Dumper...",
            MachOClassDumperHandler(),
            "",
            "Parse __objc_classlist, reconstruct class hierarchies, and dump @interface headers",
            icon("macho_class_dumper", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:macho_entitlements_explorer",
            "Entitlements Audit",
            MachOEntitlementsHandler(),
            "",
            "Inspect embedded XML Code Signing Entitlements, TCC bypasses, and dylib hijack vectors",
            icon("macho_entitlements_explorer", 73),
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "genesect:macho_syscall_resolver",
            "Mach Trap & Syscall Resolver...",
            MachOSyscallResolverHandler(),
            "",
            "Scan raw svc and syscall instructions, resolve XNU BSD syscalls and Mach traps",
            icon("macho_syscall_resolver", 73),
        ))

        self.ctx_hooks = vm.ContextMenuHooks()
        self.ctx_hooks.hook()
        self.call_explainer_hooks = create_call_explainer_hooks()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.open_view()

    def term(self):
        destroy_default_visual_hooks()
        self.default_visual_hooks = None
        destroy_highlight_hooks()
        self.highlight_hooks = None
        destroy_indent_guide_hooks()
        self.indent_guide_hooks = None
        destroy_pseudocode_folding_hooks()
        self.pseudocode_folding_hooks = None
        destroy_argument_name_hint_hooks()
        self.argument_hint_hooks = None
        destroy_call_explainer_hooks()
        self.call_explainer_hooks = None
        destroy_rust_string_fixup_hooks()
        self.rust_string_fixup_hooks = None
        shutdown_zoom_all_views()
        if self.ctx_hooks:
            self.ctx_hooks.unhook()
            self.ctx_hooks = None

        # Unregister all actions
        for action_id in [
            "genesect:explain_document", "genesect:readable_code", "genesect:analyst_notes", "genesect:list",
            "genesect:settings",
            "genesect:ui_preview",
            "genesect:migrate_legacy",
            "genesect:rename_variables", "genesect:rename_function",
            "genesect:rename_function_malware", "genesect:suggest_function_prototype",
            "genesect:add_comments", "genesect:delete_comments",
            "genesect:add_asm_comments", "genesect:delete_asm_comments",
            "genesect:shellcode_analyst",
            "genesect:analyze_struct", "genesect:batch_ai_workbench", "genesect:bulk_rename",
            "genesect:bulk_var_rename",
            "genesect:toggle_highlight", "genesect:toggle_disasm_highlight",
            "genesect:toggle_indent_guides",
            "genesect:toggle_pseudocode_block",
            "genesect:argument_name_hints",
            "genesect:toggle_call_explanations",
            "genesect:bookmarks_empty",
            "genesect:zoom_all_views",
            "genesect:ask_chat", "genesect:ask_chat_chain", "genesect:agentic_analysis", "genesect:deep_analyzer", "genesect:summarizer", "genesect:floss_strings", "genesect:go_user_code_map", "genesect:go_mark_idb", "genesect:rust_user_code_map", "genesect:rust_mark_idb", "genesect:go_rust_user_code_map", "genesect:go_rust_mark_idb", "genesect:goresym", "genesect:go_package_organizer", "genesect:rust_triage", "genesect:rust_string_fixups", "genesect:rust_demangle", "genesect:rift_library_recognition",
            "genesect:bulk_analyze", "genesect:dnspy_xrefs",
            "genesect:search_bytes_vt", "genesect:search_str_vt",
            "genesect:search_str_google", "genesect:search_str_github",
            "genesect:search_str_msdn", "genesect:search_bytes_cyberchef",
            "genesect:search_str_cyberchef", "genesect:copy_yara_raw",
            "genesect:copy_yara_rule", "genesect:copy_yara_mask",
            "genesect:copy_yara_no_imm", "genesect:copy_yara_opcodes",
            "genesect:copy_python", "genesect:copy_c_array", "genesect:copy_disasm",
            "genesect:dump_bytes", "genesect:export_ai_workspace", "genesect:hex_viewer",
            "genesect:vftable_list",
            "genesect:copy_function_tree",
            "genesect:copy_global_xref_tree",
            "genesect:global_variable_explorer",
            "genesect:virtual_class_explorer",
            "genesect:com_explorer",
            "genesect:callback_dispatch_resolver",
            "genesect:thread_explorer",
            "genesect:entry_point_explorer",
            "genesect:regex_idb_search",
            "genesect:malware_analysis_assist",
            "genesect:protocol_packet_explorer",
            "genesect:process_injection_explorer",
            "genesect:config_ioc_extractor",
            "genesect:anti_analysis_explorer",
            "genesect:findcrypt_explorer",
            "genesect:api_sequence_explorer",
            "genesect:runtime_trace_viewer",
            "genesect:driver_rootkit_explorer",
            "genesect:evidence_graph",
            "genesect:comment_explorer",
            "genesect:emulate_call",
            "genesect:batch_emulate_xrefs",
            "genesect:micro_emulator",
            "genesect:linux_syscall_resolver",
            "genesect:elf_runtime_fingerprinter",
            "genesect:elf_header_repair",
            "genesect:itanium_rtti_explorer",
            "genesect:macho_objc_resolver",
            "genesect:macho_entitlements_explorer",
        ]:
            idaapi.unregister_action(action_id)
        free_menu_icons()

    def open_view(self, ea=idaapi.BADADDR):
        self.open_document_view(ea, "explanation")

    def open_document_view(self, ea=idaapi.BADADDR, section="explanation"):
        vm = _get_view_module()
        if not self.view:
            self.view = vm.GenesectView(self.config, mode="both")
        self.view._target_ea = ea if ea != idaapi.BADADDR else idaapi.get_screen_ea()
        self.view._initial_section = section
        self.view.Show("Genesect - Explain & Document Function")
        self.view.select_workflow_section(section)
        if ea != idaapi.BADADDR:
            self.view.refresh_ui(force=True, target_ea=ea)

    def open_code_view(self, ea=idaapi.BADADDR):
        self.open_document_view(ea, "readable_code")

    def open_notes_view(self, ea=idaapi.BADADDR):
        self.open_document_view(ea, "analyst_notes")

    def Unregister(self):
        if self.view:
            self.view.Close()
            self.view = None
        if self.code_view:
            self.code_view.Close()
            self.code_view = None
        if self.notes_view:
            self.notes_view.Close()
            self.notes_view = None
