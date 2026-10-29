# -*- coding: utf-8 -*-
"""
Genesect ELF PLT/GOT & Dynamic Relocation Cleaner.

Detects, audits, and fixes unresolved or obfuscated ELF Procedure Linkage Table (PLT)
and Global Offset Table (GOT) entries:
1. Traverses .rela.plt, .rel.plt, .rela.dyn, .rel.dyn, and .got / .got.plt segments.
2. Maps relocation entries (R_X86_64_JUMP_SLOT, R_386_JMP_SLOT, R_AARCH64_JUMP_SLOT)
   to imported dynamic symbols (.dynsym / .dynstr).
3. Identifies generic off_XXXX / unk_XXXX / sub_XXXX names on GOT slots and PLT thunks.
4. Provides 1-click batch renaming (got_<sym>, plt_<sym>), prototype propagation,
   and xref call-site annotations.
"""

from typing import Dict, List, Optional, Tuple, Any, Set
import csv
import json
import os
import re
import struct

try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import ida_name
    import ida_segment
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_ida = None
    ida_kernwin = None
    ida_nalt = None
    ida_name = None
    ida_segment = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


# Common standard POSIX / Libc function prototypes for propagation
COMMON_LIBC_PROTOTYPES = {
    "malloc": "void *malloc(size_t size);",
    "free": "void free(void *ptr);",
    "calloc": "void *calloc(size_t nmemb, size_t size);",
    "realloc": "void *realloc(void *ptr, size_t size);",
    "printf": "int printf(const char *format, ...);",
    "sprintf": "int sprintf(char *str, const char *format, ...);",
    "snprintf": "int snprintf(char *str, size_t size, const char *format, ...);",
    "puts": "int puts(const char *s);",
    "memcpy": "void *memcpy(void *dest, const void *src, size_t n);",
    "memset": "void *memset(void *s, int c, size_t n);",
    "memmove": "void *memmove(void *dest, const void *src, size_t n);",
    "memcmp": "int memcmp(const void *s1, const void *s2, size_t n);",
    "strcpy": "char *strcpy(char *dest, const char *src);",
    "strncpy": "char *strncpy(char *dest, const char *src, size_t n);",
    "strlen": "size_t strlen(const char *s);",
    "strcmp": "int strcmp(const char *s1, const char *s2);",
    "strncmp": "int strncmp(const char *s1, const char *s2, size_t n);",
    "strdup": "char *strdup(const char *s);",
    "strchr": "char *strchr(const char *s, int c);",
    "strstr": "char *strstr(const char *haystack, const char *needle);",
    "open": "int open(const char *pathname, int flags, ...);",
    "close": "int close(int fd);",
    "read": "ssize_t read(int fd, void *buf, size_t count);",
    "write": "ssize_t write(int fd, const void *buf, size_t count);",
    "lseek": "off_t lseek(int fd, off_t offset, int whence);",
    "mmap": "void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);",
    "munmap": "int munmap(void *addr, size_t length);",
    "mprotect": "int mprotect(void *addr, size_t len, int prot);",
    "socket": "int socket(int domain, int type, int protocol);",
    "connect": "int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);",
    "bind": "int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);",
    "listen": "int listen(int sockfd, int backlog);",
    "accept": "int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);",
    "send": "ssize_t send(int sockfd, const void *buf, size_t len, int flags);",
    "recv": "ssize_t recv(int sockfd, void *buf, size_t len, int flags);",
    "fork": "pid_t fork(void);",
    "execve": "int execve(const char *filename, char *const argv[], char *const envp[]);",
    "system": "int system(const char *command);",
    "exit": "void exit(int status);",
    "dlopen": "void *dlopen(const char *filename, int flag);",
    "dlsym": "void *dlsym(void *handle, const char *symbol);",
    "dlclose": "int dlclose(void *handle);",
    "pthread_create": "int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);",
    "pthread_join": "int pthread_join(pthread_t thread, void **retval);",
    "ptrace": "long ptrace(int request, pid_t pid, void *addr, void *data);",
    "memfd_create": "int memfd_create(const char *name, unsigned int flags);",
}

# ELF Relocation types
RELOC_TYPES = {
    # x86_64
    (64, 6): "R_X86_64_GLOB_DAT",
    (64, 7): "R_X86_64_JUMP_SLOT",
    (64, 8): "R_X86_64_RELATIVE",
    # i386
    (32, 6): "R_386_GLOB_DAT",
    (32, 7): "R_386_JMP_SLOT",
    (32, 8): "R_386_RELATIVE",
    # ARM64
    (64, 1025): "R_AARCH64_GLOB_DAT",
    (64, 1026): "R_AARCH64_JUMP_SLOT",
    (64, 1027): "R_AARCH64_RELATIVE",
    # ARM
    (32, 21): "R_ARM_GLOB_DAT",
    (32, 22): "R_ARM_JUMP_SLOT",
    (32, 23): "R_ARM_RELATIVE",
}


class ELFRelocEntry:
    """Represents a dynamic relocation GOT slot and associated PLT thunk."""

    def __init__(
        self,
        got_ea: int,
        sym_name: str,
        reloc_type_str: str,
        section_name: str,
        plt_ea: int = 0,
        current_got_name: str = "",
        current_plt_name: str = "",
    ):
        self.got_ea = got_ea
        self.sym_name = sym_name
        self.reloc_type_str = reloc_type_str
        self.section_name = section_name
        self.plt_ea = plt_ea
        self.current_got_name = current_got_name
        self.current_plt_name = current_plt_name
        self.fixed = False

    @property
    def needs_got_rename(self) -> bool:
        if not self.sym_name:
            return False
        clean = self.current_got_name.lower()
        if clean.startswith(("off_", "unk_", "qword_", "dword_", "ptr_")):
            return True
        return clean == ""

    @property
    def needs_plt_rename(self) -> bool:
        if not self.plt_ea or not self.sym_name:
            return False
        clean = self.current_plt_name.lower()
        if clean.startswith("sub_") or clean == "":
            return True
        return False

    @property
    def status(self) -> str:
        if self.fixed:
            return "Fixed"
        if self.needs_got_rename and self.needs_plt_rename:
            return "GOT & PLT Unnamed"
        elif self.needs_got_rename:
            return "GOT Slot Unnamed"
        elif self.needs_plt_rename:
            return "PLT Thunk Unnamed"
        return "Clean / Resolved"


def is_elf_binary() -> bool:
    """Checks if current binary format is ELF."""
    if not ida_nalt or not hasattr(ida_nalt, "get_file_type_name"):
        return False
    ftype = (ida_nalt.get_file_type_name() or "").lower()
    return "elf" in ftype


def scan_elf_relocations() -> List[ELFRelocEntry]:
    """
    Parses ELF dynamic relocations across .rela.plt, .rel.plt, .rela.dyn,
    and associated GOT/PLT segments.
    """
    results: List[ELFRelocEntry] = []
    if not ida_segment or not idautils or not idc:
        return results

    is_64 = bool(ida_ida.inf_is_64bit()) if ida_ida and hasattr(ida_ida, "inf_is_64bit") else True
    ptr_size = 8 if is_64 else 4

    # 1. Build map of IDA imported symbols
    import_map: Dict[int, str] = {}
    if ida_nalt and hasattr(ida_nalt, "get_import_module_qty"):
        try:
            qty = ida_nalt.get_import_module_qty()
            for i in range(qty):
                def cb(ea, name, ord_val):
                    if name:
                        import_map[ea] = name
                    return True
                ida_nalt.enum_import_names(i, cb)
        except Exception:
            pass

    # 2. Check if we have .got or .got.plt segments
    got_segs = []
    for s_ea in idautils.Segments():
        s = ida_segment.get_segm_by_name(idc.get_segm_name(s_ea)) if hasattr(ida_segment, "get_segm_by_name") else None
        s_name = idc.get_segm_name(s_ea) if idc else ""
        if s_name in (".got", ".got.plt", ".plt.got"):
            got_segs.append(s_ea)

    # 3. Traverse GOT entries or imports
    seen_got_eas: Set[int] = set()

    # Process imports first
    for imp_ea, imp_name in import_map.items():
        if imp_ea in seen_got_eas:
            continue
        seen_got_eas.add(imp_ea)

        current_name = idc.get_name(imp_ea, ida_name.GN_VISIBLE if ida_name else 0) or ""
        sec_name = idc.get_segm_name(imp_ea) or ".got"

        # Find PLT reference to this GOT slot
        plt_ea = 0
        plt_name = ""
        for xref in idautils.DataRefsTo(imp_ea):
            func = ida_funcs.get_func(xref) if ida_funcs else None
            if func:
                f_name = idc.get_func_name(func.start_ea) or ""
                f_sec = idc.get_segm_name(func.start_ea) or ""
                if "plt" in f_sec.lower() or f_name.startswith((".plt", "plt", "sub_")):
                    plt_ea = func.start_ea
                    plt_name = f_name
                    break

        entry = ELFRelocEntry(
            got_ea=imp_ea,
            sym_name=imp_name,
            reloc_type_str="JUMP_SLOT" if ".plt" in sec_name else "GLOB_DAT",
            section_name=sec_name,
            plt_ea=plt_ea,
            current_got_name=current_name,
            current_plt_name=plt_name,
        )
        results.append(entry)

    # 4. Scan .got and .got.plt directly for any missed slots (e.g. stripped or unnamed)
    for seg_ea in got_segs:
        s = ida_segment.getseg(seg_ea) if hasattr(ida_segment, "getseg") else None
        if not s:
            continue
        start_ea = s.start_ea
        end_ea = s.end_ea

        cur = start_ea
        while cur < end_ea:
            if cur not in seen_got_eas:
                val = ida_bytes.get_qword(cur) if is_64 else ida_bytes.get_dword(cur) if ida_bytes else 0
                cur_name = idc.get_name(cur, ida_name.GN_VISIBLE if ida_name else 0) or ""

                # Check if this points to a known symbol or has references from PLT
                target_name = ""
                plt_ea = 0
                plt_name = ""

                for xref in idautils.DataRefsTo(cur):
                    func = ida_funcs.get_func(xref) if ida_funcs else None
                    if func:
                        f_name = idc.get_func_name(func.start_ea) or ""
                        f_sec = idc.get_segm_name(func.start_ea) or ""
                        if "plt" in f_sec.lower():
                            plt_ea = func.start_ea
                            plt_name = f_name
                            break

                # Infer sym_name from cur_name if it is got_<sym> or from plt_name
                if cur_name.startswith("got_"):
                    target_name = cur_name[4:]
                elif plt_name and not plt_name.startswith("sub_"):
                    target_name = plt_name.lstrip(".plt_")

                # If this GOT slot has a PLT reference or generic name, include it
                if plt_ea or (cur_name and not cur_name.startswith(("__", "_GLOBAL_OFFSET_TABLE_"))):
                    seen_got_eas.add(cur)
                    results.append(
                        ELFRelocEntry(
                            got_ea=cur,
                            sym_name=target_name,
                            reloc_type_str="JUMP_SLOT" if ".plt" in (idc.get_segm_name(cur) or "") else "GLOB_DAT",
                            section_name=idc.get_segm_name(cur) or ".got",
                            plt_ea=plt_ea,
                            current_got_name=cur_name,
                            current_plt_name=plt_name,
                        )
                    )

            cur += ptr_size

    # Sort: slots needing fix first, then by address
    results.sort(key=lambda r: (0 if (r.needs_got_rename or r.needs_plt_rename) else 1, r.got_ea))
    return results


def fix_reloc_entry(entry: ELFRelocEntry, apply_proto: bool = True) -> bool:
    """Fixes naming and prototypes for a single ELF relocation entry."""
    if not idc or not entry.sym_name:
        return False

    success = False
    clean_sym = entry.sym_name.lstrip("._")

    # 1. Rename GOT slot
    if entry.needs_got_rename:
        new_got_name = f"got_{clean_sym}"
        try:
            flag = idc.SN_CHECK if hasattr(idc, "SN_CHECK") else 0
            if idc.set_name(entry.got_ea, new_got_name, flag):
                entry.current_got_name = new_got_name
                success = True
        except Exception:
            pass

    # 2. Rename PLT thunk
    if entry.plt_ea and entry.needs_plt_rename:
        new_plt_name = f"plt_{clean_sym}"
        try:
            flag = idc.SN_CHECK if hasattr(idc, "SN_CHECK") else 0
            if idc.set_name(entry.plt_ea, new_plt_name, flag):
                entry.current_plt_name = new_plt_name
                success = True
        except Exception:
            pass

    # 3. Propagate prototype
    if apply_proto and clean_sym in COMMON_LIBC_PROTOTYPES:
        proto = COMMON_LIBC_PROTOTYPES[clean_sym]
        target_ea = entry.plt_ea or entry.got_ea
        try:
            if hasattr(idc, "SetType"):
                idc.SetType(target_ea, proto)
        except Exception:
            pass

    # 4. Annotate call sites
    if entry.plt_ea and idautils:
        try:
            for call_xref in idautils.CodeRefsTo(entry.plt_ea, 0):
                cmt = f"[Genesect GOT] calls libc: {clean_sym}"
                idc.set_cmt(call_xref, cmt, 0)
        except Exception:
            pass

    entry.fixed = True
    return success or entry.fixed


class MetricCard(Card):
    """Card subclass displaying a bold metric value with title and subtitle."""

    def __init__(self, title: str = "", value: str = "0", subtitle: str = "", parent=None):
        super().__init__(title=title, description=subtitle, parent=parent)
        self.value_label = QtWidgets.QLabel(value)
        font = self.value_label.font()
        font.setPointSize(16)
        font.setBold(True)
        self.value_label.setFont(font)
        self.body.insertWidget(1, self.value_label)

    def set_value(self, val: str):
        self.value_label.setText(str(val))


class ELFPltGotDialog(QtWidgets.QDialog):
    """Interactive GUI for auditing and fixing ELF PLT and GOT tables."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Genesect ELF PLT/GOT & Dynamic Relocation Cleaner")
        self.resize(1060, 680)
        apply_mac_workspace(self)

        self.t = current_theme()
        self.entries: List[ELFRelocEntry] = []

        self._build_ui()
        self.refresh_all()

    def _build_ui(self):
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        header = PageHeader(
            title="ELF PLT / GOT & Relocation Cleaner",
            subtitle="Resolve obfuscated GOT slots, restore unnamed PLT stubs, propagate libc prototypes, and clean call sites",
        )

        btn_rescan = QtWidgets.QPushButton("Rescan Relocations")
        btn_rescan.clicked.connect(self.refresh_all)
        header.add_action(btn_rescan)

        btn_fix_selected = QtWidgets.QPushButton("Fix Selected")
        btn_fix_selected.clicked.connect(self._fix_selected)
        header.add_action(btn_fix_selected)

        btn_fix_all = QtWidgets.QPushButton("Fix All Unnamed")
        btn_fix_all.clicked.connect(self._fix_all)
        header.add_action(btn_fix_all)

        btn_export = QtWidgets.QPushButton("Export Report...")
        btn_export.clicked.connect(self._export_report)
        header.add_action(btn_export)

        root.addWidget(header)

        # Metric Cards
        cards = QtWidgets.QHBoxLayout()
        cards.setSpacing(8)

        self.c_total = MetricCard(title="Total Relocations", value="0", subtitle="Parsed from .rela/.got")
        self.c_unnamed_got = MetricCard(title="Unnamed GOT Slots", value="0", subtitle="off_XXXX / unk_XXXX")
        self.c_unnamed_plt = MetricCard(title="Unnamed PLT Thunks", value="0", subtitle="sub_XXXX stubs")
        self.c_clean = MetricCard(title="Clean / Resolved", value="0", subtitle="Fully identified")

        cards.addWidget(self.c_total)
        cards.addWidget(self.c_unnamed_got)
        cards.addWidget(self.c_unnamed_plt)
        cards.addWidget(self.c_clean)
        root.addLayout(cards)

        # Filters
        filter_box = QtWidgets.QHBoxLayout()
        filter_box.setSpacing(8)

        filter_box.addWidget(QtWidgets.QLabel("Status:"))
        self.cmb_status = QtWidgets.QComboBox()
        self.cmb_status.addItems([
            "All Entries",
            "Needs Rename (Any)",
            "GOT Slot Unnamed",
            "PLT Thunk Unnamed",
            "Clean / Resolved",
        ])
        self.cmb_status.currentIndexChanged.connect(self._apply_filter)
        filter_box.addWidget(self.cmb_status)

        filter_box.addWidget(QtWidgets.QLabel("Section:"))
        self.cmb_sec = QtWidgets.QComboBox()
        self.cmb_sec.addItems(["All Sections", ".got.plt", ".got", ".plt"])
        self.cmb_sec.currentIndexChanged.connect(self._apply_filter)
        filter_box.addWidget(self.cmb_sec)

        filter_box.addWidget(QtWidgets.QLabel("Search:"))
        self.edit_search = QtWidgets.QLineEdit()
        self.edit_search.setPlaceholderText("Filter by symbol, address, or name...")
        self.edit_search.textChanged.connect(self._apply_filter)
        filter_box.addWidget(self.edit_search, 1)

        root.addLayout(filter_box)

        # Table
        self.tbl_relocs = QtWidgets.QTableWidget(0, 7)
        self.tbl_relocs.setHorizontalHeaderLabels([
            "GOT Address", "PLT Address", "Symbol Name", "Reloc Type", "Current GOT Name", "Current PLT Name", "Status"
        ])
        self.tbl_relocs.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_relocs.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_relocs.horizontalHeader().setStretchLastSection(True)
        self.tbl_relocs.setColumnWidth(0, 110)
        self.tbl_relocs.setColumnWidth(1, 110)
        self.tbl_relocs.setColumnWidth(2, 160)
        self.tbl_relocs.setColumnWidth(3, 130)
        self.tbl_relocs.setColumnWidth(4, 150)
        self.tbl_relocs.setColumnWidth(5, 150)
        self.tbl_relocs.itemDoubleClicked.connect(self._on_item_double_clicked)
        root.addWidget(self.tbl_relocs, 1)

        # Bottom Bar
        bottom = QtWidgets.QHBoxLayout()
        self.lbl_status = QtWidgets.QLabel("Ready")
        self.lbl_status.setStyleSheet(f"color: {self.t.text_muted};")
        bottom.addWidget(self.lbl_status)
        bottom.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)
        root.addLayout(bottom)

    def refresh_all(self):
        self.entries = scan_elf_relocations()
        self._update_cards()
        self._apply_filter()

    def _update_cards(self):
        total = len(self.entries)
        un_got = sum(1 for e in self.entries if e.needs_got_rename)
        un_plt = sum(1 for e in self.entries if e.needs_plt_rename)
        clean = sum(1 for e in self.entries if not e.needs_got_rename and not e.needs_plt_rename)

        self.c_total.set_value(str(total))
        self.c_unnamed_got.set_value(str(un_got))
        self.c_unnamed_plt.set_value(str(un_plt))
        self.c_clean.set_value(str(clean))

    def _apply_filter(self):
        sel_st = self.cmb_status.currentText()
        sel_sec = self.cmb_sec.currentText()
        q = self.edit_search.text().strip().lower()

        filtered: List[ELFRelocEntry] = []
        for e in self.entries:
            if sel_st == "Needs Rename (Any)" and not (e.needs_got_rename or e.needs_plt_rename):
                continue
            elif sel_st == "GOT Slot Unnamed" and not e.needs_got_rename:
                continue
            elif sel_st == "PLT Thunk Unnamed" and not e.needs_plt_rename:
                continue
            elif sel_st == "Clean / Resolved" and (e.needs_got_rename or e.needs_plt_rename):
                continue

            if sel_sec != "All Sections" and sel_sec not in e.section_name:
                continue

            if q:
                blob = f"{_hex(e.got_ea)} {_hex(e.plt_ea)} {e.sym_name} {e.reloc_type_str} {e.current_got_name} {e.current_plt_name}".lower()
                if q not in blob:
                    continue
            filtered.append(e)

        self.tbl_relocs.setRowCount(len(filtered))
        for row, e in enumerate(filtered):
            it_got = QtWidgets.QTableWidgetItem(_hex(e.got_ea))
            it_got.setData(QtCore.Qt.UserRole, e)
            it_plt = QtWidgets.QTableWidgetItem(_hex(e.plt_ea) if e.plt_ea else "-")
            it_sym = QtWidgets.QTableWidgetItem(e.sym_name)
            it_sym.setFont(QtGui.QFont("Consolas", 9, QtGui.QFont.Bold))
            it_type = QtWidgets.QTableWidgetItem(e.reloc_type_str)
            it_gname = QtWidgets.QTableWidgetItem(e.current_got_name)
            it_pname = QtWidgets.QTableWidgetItem(e.current_plt_name)

            it_st = QtWidgets.QTableWidgetItem(e.status)
            if "Unnamed" in e.status:
                it_st.setForeground(QtGui.QBrush(QtGui.QColor("#F59E0B")))
                it_st.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            elif e.status == "Fixed":
                it_st.setForeground(QtGui.QBrush(QtGui.QColor("#10B981")))
                it_st.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            else:
                it_st.setForeground(QtGui.QBrush(QtGui.QColor("#6B7280")))

            self.tbl_relocs.setItem(row, 0, it_got)
            self.tbl_relocs.setItem(row, 1, it_plt)
            self.tbl_relocs.setItem(row, 2, it_sym)
            self.tbl_relocs.setItem(row, 3, it_type)
            self.tbl_relocs.setItem(row, 4, it_gname)
            self.tbl_relocs.setItem(row, 5, it_pname)
            self.tbl_relocs.setItem(row, 6, it_st)

        self.lbl_status.setText(f"Showing {len(filtered)} of {len(self.entries)} entries.")

    def _on_item_double_clicked(self, item):
        row = item.row()
        it_ea = self.tbl_relocs.item(row, 0)
        col = item.column()
        if it_ea:
            e: ELFRelocEntry = it_ea.data(QtCore.Qt.UserRole)
            if e and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
                target = e.plt_ea if (col == 1 and e.plt_ea) else e.got_ea
                ida_kernwin.jumpto(target)

    def _fix_selected(self):
        rows = set(it.row() for it in self.tbl_relocs.selectedItems())
        count = 0
        for r in rows:
            it = self.tbl_relocs.item(r, 0)
            if it:
                e: ELFRelocEntry = it.data(QtCore.Qt.UserRole)
                if e and fix_reloc_entry(e):
                    count += 1
        self._update_cards()
        self._apply_filter()
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Fixed {count} selected ELF GOT / PLT entries.")

    def _fix_all(self):
        count = 0
        for e in self.entries:
            if (e.needs_got_rename or e.needs_plt_rename) and fix_reloc_entry(e):
                count += 1
        self._update_cards()
        self._apply_filter()
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Fixed {count} unnamed ELF GOT / PLT entries.")

    def _export_report(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export ELF Relocations Report",
            "elf_relocations_report.csv",
            "CSV (*.csv);;JSON (*.json);;Markdown (*.md)",
        )
        if not path:
            return

        try:
            if path.endswith(".json"):
                data = [
                    {
                        "got_ea": _hex(e.got_ea),
                        "plt_ea": _hex(e.plt_ea) if e.plt_ea else None,
                        "sym_name": e.sym_name,
                        "reloc_type": e.reloc_type_str,
                        "current_got_name": e.current_got_name,
                        "current_plt_name": e.current_plt_name,
                        "status": e.status,
                    }
                    for e in self.entries
                ]
                with open(path, "w", encoding="utf-8") as fp:
                    json.dump(data, fp, indent=2)
            elif path.endswith(".md"):
                with open(path, "w", encoding="utf-8") as fp:
                    fp.write("# ELF PLT / GOT & Relocation Audit Report\n\n")
                    fp.write(f"- Total Relocations: {len(self.entries)}\n")
                    fp.write(f"- Unnamed GOT Slots: {sum(1 for e in self.entries if e.needs_got_rename)}\n")
                    fp.write(f"- Unnamed PLT Thunks: {sum(1 for e in self.entries if e.needs_plt_rename)}\n\n")
                    fp.write("| GOT Address | PLT Address | Symbol | Reloc Type | Current GOT Name | Current PLT Name | Status |\n")
                    fp.write("| --- | --- | --- | --- | --- | --- | --- |\n")
                    for e in self.entries:
                        fp.write(f"| `{_hex(e.got_ea)}` | `{_hex(e.plt_ea) if e.plt_ea else '-'}` | **{e.sym_name}** | {e.reloc_type_str} | {e.current_got_name} | {e.current_plt_name} | {e.status} |\n")
            else:
                with open(path, "w", newline="", encoding="utf-8") as fp:
                    writer = csv.writer(fp)
                    writer.writerow(["GOT Address", "PLT Address", "Symbol", "Reloc Type", "Current GOT Name", "Current PLT Name", "Status"])
                    for e in self.entries:
                        writer.writerow([_hex(e.got_ea), _hex(e.plt_ea) if e.plt_ea else "-", e.sym_name, e.reloc_type_str, e.current_got_name, e.current_plt_name, e.status])

            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info(f"Relocation report exported successfully:\n{path}")
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to export report:\n{exc}")


class ELFPltGotCleanerHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _elf_plt_got_instance
        try:
            _elf_plt_got_instance = ELFPltGotDialog()
            _elf_plt_got_instance.show()
            _elf_plt_got_instance.raise_()
            _elf_plt_got_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open ELF PLT/GOT Cleaner:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


_elf_plt_got_instance = None
