# -*- coding: utf-8 -*-
"""Explore APIs commonly used for callback-based shellcode execution."""
import ida_funcs
import ida_kernwin
import idautils
import idc
import idaapi

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.api_knowledge import normalize_api_name

_CALLBACK_APIS = {
    "AddVectoredContinueHandler", "AddVectoredExceptionHandler", "CallWindowProcA", "CallWindowProcW",
    "CertEnumSystemStore", "CertEnumSystemStoreLocation", "ChooseColorA", "ChooseColorW",
    "ChooseFontA", "ChooseFontW", "CopyFileExA", "CopyFileExW", "CreateFiber", "CreateFiberEx",
    "CreateThreadpoolTimer", "CreateThreadpoolWait", "CreateThreadpoolWork", "CreateTimerQueueTimer",
    "CryptEnumOIDFunction", "CryptEnumOIDInfo", "EnumCalendarInfoA", "EnumCalendarInfoExA",
    "EnumCalendarInfoExEx", "EnumCalendarInfoExW", "EnumCalendarInfoW", "EnumChildWindows",
    "EnumDateFormatsA", "EnumDateFormatsExA", "EnumDateFormatsExEx", "EnumDateFormatsExW",
    "EnumDateFormatsW", "EnumDesktopWindows", "EnumDesktopsA", "EnumDesktopsW", "EnumDisplayMonitors",
    "EnumEnhMetaFile", "EnumFontFamiliesA", "EnumFontFamiliesExA", "EnumFontFamiliesExW",
    "EnumFontFamiliesW", "EnumFontsA", "EnumFontsW", "EnumICMProfilesA", "EnumICMProfilesW",
    "EnumLanguageGroupLocalesA", "EnumLanguageGroupLocalesW", "EnumMetaFile", "EnumObjects",
    "EnumPropsA", "EnumPropsExA", "EnumPropsExW", "EnumPropsW", "EnumResourceLanguagesA",
    "EnumResourceLanguagesExA", "EnumResourceLanguagesExW", "EnumResourceLanguagesW",
    "EnumResourceNamesA", "EnumResourceNamesExA", "EnumResourceNamesExW", "EnumResourceNamesW",
    "EnumResourceTypesA", "EnumResourceTypesExA", "EnumResourceTypesExW", "EnumResourceTypesW",
    "EnumSystemCodePagesA", "EnumSystemCodePagesW", "EnumSystemGeoID", "EnumSystemGeoNames",
    "EnumSystemLanguageGroupsA", "EnumSystemLanguageGroupsW", "EnumSystemLocalesA",
    "EnumSystemLocalesEx", "EnumSystemLocalesW", "EnumThreadWindows", "EnumTimeFormatsA",
    "EnumTimeFormatsEx", "EnumTimeFormatsW", "EnumUILanguagesA", "EnumUILanguagesW",
    "EnumWindowStationsA", "EnumWindowStationsW", "EnumWindows", "EnumerateLoadedModules64",
    "EnumerateLoadedModulesW64", "FlsAlloc", "GetAddrInfoExA", "GetAddrInfoExW", "GrayStringA",
    "GrayStringW", "ImmEnumInputContext", "InitOnceExecuteOnce", "LineDDA", "MiniDumpWriteDump",
    "MoveFileWithProgressA", "MoveFileWithProgressW", "NtQueueApcThread", "NtQueueApcThreadEx",
    "NtQueueApcThreadEx2", "OpenTraceA", "OpenTraceW", "ProcessTrace", "PropertySheetA",
    "PropertySheetW", "QueueUserAPC", "QueueUserAPC2", "QueueUserWorkItem", "ReadFileEx",
    "RegisterWaitForSingleObject", "RegisterWaitForSingleObjectEx", "RpcServerRegisterIfEx",
    "SHBrowseForFolderA", "SHBrowseForFolderW", "SendMessageCallbackA", "SendMessageCallbackW",
    "SetThreadpoolTimer", "SetThreadpoolWait", "SetTimer", "SetUnhandledExceptionFilter",
    "SetWinEventHook", "SetWindowsHookExA", "SetWindowsHookExW", "SetupCommitFileQueueA",
    "SetupCommitFileQueueW", "SetupIterateCabinetA", "SetupIterateCabinetW", "SleepEx",
    "SubmitThreadpoolWork", "SwitchToFiber", "SymEnumSymbols", "SymEnumTypes", "SymEnumTypesByName",
    "SymRegisterCallback64", "SymRegisterCallbackW64", "TrySubmitThreadpoolCallback",
    "WaitForMultipleObjectsEx", "WaitForSingleObjectEx", "WriteFileEx", "bsearch", "midiInOpen",
    "midiOutOpen", "qsort", "timeSetEvent", "waveInOpen", "waveOutOpen"
}


def _hex(ea):
    return "0x%X" % int(ea)


def scan_callback_shellcode_apis():
    rows = []
    normalized_targets = {name.lower() for name in _CALLBACK_APIS}
    
    for api_ea, api_name in idautils.Names():
        normalized = normalize_api_name(api_name)
        if normalized.lower() not in normalized_targets:
            continue
            
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                continue
                
            frm = xref.frm
            func = ida_funcs.get_func(frm)
            func_name = idc.get_func_name(func.start_ea) if func else ""
            owner = "%s (%s)" % (func_name, _hex(func.start_ea)) if func_name else "<outside function>"
            
            detail = idc.generate_disasm_line(frm, 0) or idc.GetDisasm(frm)
            
            rows.append({
                "api": normalized,
                "site": int(frm),
                "owner": owner,
                "detail": detail
            })
            
    return sorted(rows, key=lambda item: (item["api"], item["site"]))


class CallbackShellcodeExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        
        header = PageHeader("Callback Shellcode Explorer", "APIs commonly abused for executing shellcode via callbacks")
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        
        copy = QtWidgets.QPushButton("Copy Selected")
        copy.clicked.connect(self.copy_selected)
        header.add_action(copy)
        
        root.addWidget(header)
        
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by API, address, function, or instruction...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["API", "Call Site", "Containing Function", "Instruction"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemDoubleClicked.connect(self.navigate_selected)
        table_card.add_widget(self.table)
        root.addWidget(table_card, 1)
        
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Scanning for callback shellcode APIs...")
        try:
            self.rows = scan_callback_shellcode_apis()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Callback Shellcode Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.apply_filter()

    def apply_filter(self):
        query = self.filter_edit.text().strip().lower()
        self.table.setRowCount(0)
        self.table.setSortingEnabled(False)
        
        for item in self.rows:
            site_hex = _hex(item["site"])
            match = not query or query in item["api"].lower() or query in site_hex.lower() or query in item["owner"].lower() or query in item["detail"].lower()
            if not match:
                continue
                
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            api_item = QtWidgets.QTableWidgetItem(item["api"])
            api_item.setData(QtCore.Qt.UserRole, item["site"])
            self.table.setItem(row, 0, api_item)
            
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(site_hex))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(item["owner"]))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(item["detail"]))
            
        self.table.setSortingEnabled(True)
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(1)
        self.table.resizeColumnToContents(2)
        self.status.setText("Found %d API calls" % self.table.rowCount())

    def navigate_selected(self, table_item):
        row = table_item.row()
        item = self.table.item(row, 0)
        if not item:
            return
        ea = item.data(QtCore.Qt.UserRole)
        ida_kernwin.jumpto(ea)

    def copy_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        text = "\t".join(self.table.item(row, col).text() for col in range(self.table.columnCount()) if self.table.item(row, col))
        QtWidgets.QApplication.clipboard().setText(text)
        self.status.setText("Copied to clipboard.")

    def OnClose(self, form):
        pass


class CallbackShellcodeExplorerHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global _explorer_instance
        _explorer_instance = CallbackShellcodeExplorer()
        _explorer_instance.Show("Callback Shellcode Explorer")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
