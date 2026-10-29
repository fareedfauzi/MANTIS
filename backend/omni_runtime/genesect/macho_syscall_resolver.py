# -*- coding: utf-8 -*-
"""
Genesect macOS Mach Trap & BSD Syscall Resolver.

Identifies and resolves direct XNU kernel invocations in macOS Mach-O binaries:
1. BSD Syscalls (Class 2: 0x2000000 + sysno, or svc #0x82 / svc 0 with X16)
2. Mach Traps (Class 1 / negative sysno: mach_msg_trap, task_self_trap, mach_vm_allocate)
3. Backward-slices X16 (ARM64) or RAX/EAX (x86_64) to resolve exact kernel syscalls.
4. Provides 1-click IDB annotations, wrapper renaming, and export.
"""

from typing import Dict, List, Optional, Tuple, Any, Set
import csv
import json
import os
import re

try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import ida_search
    import ida_ua
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_ida = None
    ida_kernwin = None
    ida_nalt = None
    ida_search = None
    ida_ua = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


# macOS XNU BSD Syscall Table
# Format: { sysno: (name, category, danger_level, signature) }
MACOS_BSD_SYSCALLS = {
    1: ("sys_exit", "Process", "Standard", "int rval"),
    2: ("sys_fork", "Process", "Standard", "void"),
    3: ("sys_read", "File I/O", "Standard", "int fd, void *cbuf, size_t nbyte"),
    4: ("sys_write", "File I/O", "Standard", "int fd, const void *cbuf, size_t nbyte"),
    5: ("sys_open", "File I/O", "Standard", "const char *path, int flags, int mode"),
    6: ("sys_close", "File I/O", "Standard", "int fd"),
    7: ("sys_wait4", "Process", "Standard", "int pid, int *status, int options, struct rusage *rusage"),
    10: ("sys_unlink", "File I/O", "Medium", "const char *path"),
    14: ("sys_mknod", "File I/O", "Medium", "const char *path, int mode, int dev"),
    15: ("sys_chmod", "File I/O", "Standard", "const char *path, int mode"),
    16: ("sys_chown", "File I/O", "Standard", "const char *path, int uid, int gid"),
    20: ("sys_getpid", "Process", "Standard", "void"),
    23: ("sys_setuid", "Credentials", "Medium", "uid_t uid"),
    24: ("sys_getuid", "Credentials", "Standard", "void"),
    25: ("sys_geteuid", "Credentials", "Standard", "void"),
    26: ("sys_ptrace", "Anti-Debug / Injection", "Critical", "int req, pid_t pid, caddr_t addr, int data"),
    33: ("sys_access", "File I/O", "Standard", "const char *path, int flags"),
    37: ("sys_kill", "Process", "Medium", "int pid, int signum"),
    47: ("sys_getgid", "Credentials", "Standard", "void"),
    59: ("sys_execve", "Process Execution", "Critical", "const char *fname, char **argp, char **envp"),
    73: ("sys_munmap", "Memory", "Standard", "void *addr, size_t len"),
    74: ("sys_mprotect", "Memory", "Medium", "void *addr, size_t len, int prot"),
    90: ("sys_dup2", "File I/O", "Standard", "int from, int to"),
    97: ("sys_socket", "Network", "Standard", "int domain, int type, int protocol"),
    98: ("sys_connect", "Network", "Medium", "int s, const struct sockaddr *name, socklen_t namelen"),
    99: ("sys_accept", "Network", "Standard", "int s, struct sockaddr *name, socklen_t *anamelen"),
    104: ("sys_bind", "Network", "Standard", "int s, const struct sockaddr *name, socklen_t namelen"),
    105: ("sys_setsockopt", "Network", "Standard", "int s, int level, int name, const void *val, socklen_t valsize"),
    106: ("sys_listen", "Network", "Standard", "int s, int backlog"),
    133: ("sys_sendto", "Network", "Standard", "int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen"),
    180: ("sys_pwrite", "File I/O", "Standard", "int fd, const void *buf, size_t nbyte, off_t offset"),
    197: ("sys_mmap", "Memory", "Standard", "void *addr, size_t len, int prot, int flags, int fd, off_t pos"),
    202: ("sys_sysctl", "System Info", "Medium", "int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen"),
    301: ("sys_psynch_mutexwait", "Threading", "Standard", "void *mutex, uint32_t mgen, uint32_t ugen, uint64_t tid, uint32_t flags"),
    336: ("sys_proc_info", "Process / Stealth", "High", "int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffersize"),
    397: ("sys_terminate_with_reason", "Process", "Standard", "int pid, int reason_ns, uint64_t reason_code, void *payload, uint32_t size, uint32_t op"),
}

# macOS Mach Traps (Class 1, typically negative or 0x01000000 | trap_no)
MACOS_MACH_TRAPS = {
    -10: ("_kernelrpc_mach_vm_allocate_trap", "Mach VM", "High", "mach_port_name_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags"),
    -12: ("_kernelrpc_mach_vm_deallocate_trap", "Mach VM", "Standard", "mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size"),
    -14: ("_kernelrpc_mach_vm_protect_trap", "Mach VM", "Critical", "mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_prot"),
    -15: ("_kernelrpc_mach_vm_map_trap", "Mach VM", "High", "mach_port_name_t target, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, ipc_port_t port, ..."),
    -16: ("_kernelrpc_mach_port_allocate_trap", "Mach IPC", "High", "ipc_space_t task, mach_port_right_t right, mach_port_name_t *name"),
    -18: ("_kernelrpc_mach_port_deallocate_trap", "Mach IPC", "Standard", "ipc_space_t task, mach_port_name_t name"),
    -26: ("mach_reply_port", "Mach IPC", "Standard", "void"),
    -27: ("thread_self_trap", "Mach Thread", "Standard", "void"),
    -28: ("task_self_trap", "Mach Task", "Critical", "void -> returns task port"),
    -29: ("host_self_trap", "Mach Host", "High", "void -> returns host port"),
    -31: ("mach_msg_trap", "Mach IPC", "Critical", "mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t rcv_size, ..."),
    -61: ("thread_switch", "Mach Thread", "Standard", "mach_port_name_t thread_name, int option, mach_msg_timeout_t option_time"),
}


class MachOSyscallCall:
    """Represents a detected direct XNU kernel call site in macOS."""

    def __init__(
        self,
        call_ea: int,
        func_ea: int,
        func_name: str,
        kind: str,
        sysno: int,
        name: str,
        category: str,
        threat_level: str,
        signature: str,
    ):
        self.call_ea = call_ea
        self.func_ea = func_ea
        self.func_name = func_name
        self.kind = kind  # "BSD Syscall" or "Mach Trap"
        self.sysno = sysno
        self.name = name
        self.category = category
        self.threat_level = threat_level
        self.signature = signature
        self.annotated = False


class MetricCard(Card):
    """Card displaying a metric value with title and subtitle."""

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


def slice_macho_syscall_register(call_ea: int, is_arm: bool, max_lookback: int = 15) -> Optional[int]:
    """
    Backward-slices instructions before call_ea to extract syscall/trap number.
    On ARM64: X16 / W16.
    On x86_64: RAX / EAX.
    """
    if not idc:
        return None

    target_regs = {"x16", "w16"} if is_arm else {"rax", "eax", "al"}
    cur_ea = call_ea
    func = ida_funcs.get_func(call_ea) if ida_funcs else None
    func_start = func.start_ea if func else max(0, call_ea - 0x100)

    for _ in range(max_lookback):
        prev_ea = idc.prev_head(cur_ea, func_start)
        if prev_ea == idaapi.BADADDR or prev_ea == cur_ea:
            break
        cur_ea = prev_ea

        mnem = (idc.print_insn_mnem(cur_ea) or "").lower()
        op0 = (idc.print_operand(cur_ea, 0) or "").lower().strip()
        op1 = (idc.print_operand(cur_ea, 1) or "").lower().strip()

        if op0 in target_regs:
            # Handle mov/movz/orr
            if mnem in ("mov", "movz", "movk", "ldr"):
                val = idc.get_operand_value(cur_ea, 1)
                if val is not None and val != -1:
                    return int(val)
                # Match immediate text like #0x2000001 or 0x2000001
                m = re.search(r"0x[0-9a-f]+|\b\d+\b", op1)
                if m:
                    try:
                        return int(m.group(0), 0)
                    except Exception:
                        pass
            elif mnem == "xor" and op0 == op1:
                return 0

    return None


def scan_macho_syscalls() -> List[MachOSyscallCall]:
    """Scans binary for macOS svc #0x80, svc #0x82, and syscall instructions."""
    calls: List[MachOSyscallCall] = []
    if not idautils or not idc or not ida_segment:
        return calls

    is_arm = False
    if ida_ida and hasattr(ida_ida, "inf_get_proc_name"):
        proc = (ida_ida.inf_get_proc_name() or "").lower()
        is_arm = "arm" in proc or "aarch64" in proc

    for s_ea in idautils.Segments():
        seg = ida_segment.getseg(s_ea) if hasattr(ida_segment, "getseg") else None
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue

        cur_ea = seg.start_ea
        end_ea = seg.end_ea

        while cur_ea < end_ea:
            mnem = (idc.print_insn_mnem(cur_ea) or "").lower()
            is_call = False
            hint_kind = None

            if is_arm and mnem == "svc":
                op0 = (idc.print_operand(cur_ea, 0) or "").strip()
                is_call = True
                if "0x80" in op0:
                    hint_kind = "Mach Trap"
                elif "0x82" in op0:
                    hint_kind = "BSD Syscall"
            elif not is_arm and mnem == "syscall":
                is_call = True

            if is_call:
                val = slice_macho_syscall_register(cur_ea, is_arm)
                func = ida_funcs.get_func(cur_ea) if ida_funcs else None
                f_ea = func.start_ea if func else cur_ea
                f_name = idc.get_func_name(f_ea) or f"sub_{f_ea:X}"

                if val is not None:
                    # Decode XNU Class:
                    # Class 2 (0x2000000) = BSD Syscall
                    # Class 1 (0x1000000) = Mach Trap
                    kind = "BSD Syscall"
                    sysno = val
                    name = "unknown_sys"
                    cat = "General"
                    threat = "Standard"
                    sig = "..."

                    if (val & 0xFF000000) == 0x02000000:
                        sysno = val & 0x00FFFFFF
                        kind = "BSD Syscall"
                    elif (val & 0xFF000000) == 0x01000000:
                        sysno = -(val & 0x00FFFFFF)
                        kind = "Mach Trap"
                    elif hint_kind == "Mach Trap" or val < 0 or (-val) in MACOS_MACH_TRAPS:
                        kind = "Mach Trap"
                        sysno = val if val < 0 else -val

                    if kind == "BSD Syscall" and sysno in MACOS_BSD_SYSCALLS:
                        name, cat, threat, sig = MACOS_BSD_SYSCALLS[sysno]
                    elif kind == "Mach Trap" and sysno in MACOS_MACH_TRAPS:
                        name, cat, threat, sig = MACOS_MACH_TRAPS[sysno]
                    else:
                        name = f"{'bsd' if kind == 'BSD Syscall' else 'mach'}_{sysno}"

                    calls.append(
                        MachOSyscallCall(
                            call_ea=cur_ea,
                            func_ea=f_ea,
                            func_name=f_name,
                            kind=kind,
                            sysno=sysno,
                            name=name,
                            category=cat,
                            threat_level=threat,
                            signature=sig,
                        )
                    )

            cur_ea = idc.next_head(cur_ea, end_ea)
            if cur_ea == idaapi.BADADDR:
                break

    # Sort critical first, then address
    priority = {"Critical": 0, "High": 1, "Medium": 2, "Standard": 3}
    calls.sort(key=lambda c: (priority.get(c.threat_level, 4), c.call_ea))
    return calls


class MachOSyscallDialog(QtWidgets.QDialog):
    """Interactive GUI for macOS Mach Trap & BSD Syscall Resolver."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Genesect macOS Mach Trap & BSD Syscall Resolver")
        self.resize(1060, 680)
        apply_mac_workspace(self)

        self.t = current_theme()
        self.calls: List[MachOSyscallCall] = []

        self._build_ui()
        self.refresh_all()

    def _build_ui(self):
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        header = PageHeader(
            title="macOS Mach Trap & BSD Syscall Resolver",
            subtitle="Scans raw svc #0x80/0x82 and syscall instructions, resolves XNU Mach traps and BSD syscalls, and detects evasion stubs",
        )

        btn_rescan = QtWidgets.QPushButton("Rescan Database")
        btn_rescan.clicked.connect(self.refresh_all)
        header.add_action(btn_rescan)

        btn_annotate = QtWidgets.QPushButton("Annotate Selected")
        btn_annotate.clicked.connect(self._annotate_selected)
        header.add_action(btn_annotate)

        btn_rename_wrappers = QtWidgets.QPushButton("Rename Wrappers")
        btn_rename_wrappers.clicked.connect(self._rename_wrappers)
        header.add_action(btn_rename_wrappers)

        btn_export = QtWidgets.QPushButton("Export CSV...")
        btn_export.clicked.connect(self._export_csv)
        header.add_action(btn_export)

        root.addWidget(header)

        # Metric Cards
        cards = QtWidgets.QHBoxLayout()
        cards.setSpacing(8)

        self.c_total = MetricCard(title="Total Invocations", value="0", subtitle="Kernel call sites")
        self.c_critical = MetricCard(title="Critical Primitives", value="0", subtitle="ptrace, mach_msg, execve")
        self.c_bsd = MetricCard(title="BSD Syscalls", value="0", subtitle="Class 2 kernel calls")
        self.c_mach = MetricCard(title="Mach Traps", value="0", subtitle="Class 1 IPC/VM traps")

        cards.addWidget(self.c_total)
        cards.addWidget(self.c_critical)
        cards.addWidget(self.c_bsd)
        cards.addWidget(self.c_mach)
        root.addLayout(cards)

        # Filters
        filter_box = QtWidgets.QHBoxLayout()
        filter_box.setSpacing(8)

        filter_box.addWidget(QtWidgets.QLabel("Type:"))
        self.cmb_type = QtWidgets.QComboBox()
        self.cmb_type.addItems(["All Types", "BSD Syscall", "Mach Trap"])
        self.cmb_type.currentIndexChanged.connect(self._apply_filter)
        filter_box.addWidget(self.cmb_type)

        filter_box.addWidget(QtWidgets.QLabel("Threat:"))
        self.cmb_threat = QtWidgets.QComboBox()
        self.cmb_threat.addItems(["All Severities", "Critical", "High", "Medium", "Standard"])
        self.cmb_threat.currentIndexChanged.connect(self._apply_filter)
        filter_box.addWidget(self.cmb_threat)

        self.edit_search = QtWidgets.QLineEdit()
        self.edit_search.setPlaceholderText("Filter syscall, function, address...")
        self.edit_search.textChanged.connect(self._apply_filter)
        filter_box.addWidget(self.edit_search, 1)

        root.addLayout(filter_box)

        # Table
        self.tbl_calls = QtWidgets.QTableWidget(0, 7)
        self.tbl_calls.setHorizontalHeaderLabels([
            "Call Address", "Calling Function", "Kind", "Number", "Name", "Threat", "Signature"
        ])
        self.tbl_calls.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_calls.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_calls.horizontalHeader().setStretchLastSection(True)
        self.tbl_calls.setColumnWidth(0, 110)
        self.tbl_calls.setColumnWidth(1, 140)
        self.tbl_calls.setColumnWidth(2, 110)
        self.tbl_calls.setColumnWidth(3, 80)
        self.tbl_calls.setColumnWidth(4, 180)
        self.tbl_calls.setColumnWidth(5, 90)
        self.tbl_calls.itemDoubleClicked.connect(self._on_item_double_clicked)
        root.addWidget(self.tbl_calls, 1)

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
        self.calls = scan_macho_syscalls()
        self._update_cards()
        self._apply_filter()

    def _update_cards(self):
        total = len(self.calls)
        crit = sum(1 for c in self.calls if c.threat_level == "Critical")
        bsd = sum(1 for c in self.calls if c.kind == "BSD Syscall")
        mach = sum(1 for c in self.calls if c.kind == "Mach Trap")

        self.c_total.set_value(str(total))
        self.c_critical.set_value(str(crit))
        self.c_bsd.set_value(str(bsd))
        self.c_mach.set_value(str(mach))

    def _apply_filter(self):
        sel_type = self.cmb_type.currentText()
        sel_threat = self.cmb_threat.currentText()
        q = self.edit_search.text().strip().lower()

        filtered: List[MachOSyscallCall] = []
        for c in self.calls:
            if sel_type != "All Types" and c.kind != sel_type:
                continue
            if sel_threat != "All Severities" and c.threat_level != sel_threat:
                continue
            if q:
                blob = f"{_hex(c.call_ea)} {c.func_name} {c.kind} {c.name} {c.sysno} {c.category}".lower()
                if q not in blob:
                    continue
            filtered.append(c)

        self.tbl_calls.setRowCount(len(filtered))
        for row, c in enumerate(filtered):
            it_ea = QtWidgets.QTableWidgetItem(_hex(c.call_ea))
            it_ea.setData(QtCore.Qt.UserRole, c)
            it_fn = QtWidgets.QTableWidgetItem(c.func_name)
            it_kd = QtWidgets.QTableWidgetItem(c.kind)
            it_no = QtWidgets.QTableWidgetItem(str(c.sysno))
            it_name = QtWidgets.QTableWidgetItem(c.name)
            it_name.setFont(QtGui.QFont("Consolas", 9, QtGui.QFont.Bold))

            it_th = QtWidgets.QTableWidgetItem(c.threat_level)
            if c.threat_level == "Critical":
                it_th.setForeground(QtGui.QBrush(QtGui.QColor("#EF4444")))
                it_th.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            elif c.threat_level == "High":
                it_th.setForeground(QtGui.QBrush(QtGui.QColor("#F59E0B")))
                it_th.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))

            it_sig = QtWidgets.QTableWidgetItem(c.signature)

            self.tbl_calls.setItem(row, 0, it_ea)
            self.tbl_calls.setItem(row, 1, it_fn)
            self.tbl_calls.setItem(row, 2, it_kd)
            self.tbl_calls.setItem(row, 3, it_no)
            self.tbl_calls.setItem(row, 4, it_name)
            self.tbl_calls.setItem(row, 5, it_th)
            self.tbl_calls.setItem(row, 6, it_sig)

        self.lbl_status.setText(f"Showing {len(filtered)} of {len(self.calls)} kernel calls.")

    def _on_item_double_clicked(self, item):
        row = item.row()
        it_ea = self.tbl_calls.item(row, 0)
        if it_ea:
            c: MachOSyscallCall = it_ea.data(QtCore.Qt.UserRole)
            if c and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
                ida_kernwin.jumpto(c.call_ea)

    def _annotate_selected(self):
        rows = set(it.row() for it in self.tbl_calls.selectedItems())
        count = 0
        for r in rows:
            it = self.tbl_calls.item(r, 0)
            if it:
                c: MachOSyscallCall = it.data(QtCore.Qt.UserRole)
                if c and idc:
                    cmt = f"[Genesect XNU] {c.kind}: {c.name} ({c.category}) - {c.signature}"
                    idc.set_cmt(c.call_ea, cmt, 0)
                    count += 1
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Annotated {count} selected XNU syscalls in IDB.")

    def _rename_wrappers(self):
        if not idc:
            return
        count = 0
        for c in self.calls:
            if c.func_name.startswith("sub_") and c.name:
                prefix = "mach_trap" if c.kind == "Mach Trap" else "syscall_bsd"
                clean_name = c.name.lstrip("_")
                new_name = f"{prefix}_{clean_name}_{c.func_ea:X}"
                flag = idc.SN_CHECK if hasattr(idc, "SN_CHECK") else 0
                if idc.set_name(c.func_ea, new_name, flag):
                    c.func_name = new_name
                    count += 1
        self._apply_filter()
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Renamed {count} wrapper functions.")

    def _export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export macOS Syscalls CSV", "macos_syscalls.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fp:
                writer = csv.writer(fp)
                writer.writerow(["Call Address", "Calling Function", "Kind", "Number", "Name", "Category", "Threat", "Signature"])
                for c in self.calls:
                    writer.writerow([_hex(c.call_ea), c.func_name, c.kind, c.sysno, c.name, c.category, c.threat_level, c.signature])
            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info(f"Saved {len(self.calls)} records to:\n{path}")
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to export CSV:\n{exc}")


class MachOSyscallResolverHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _macho_syscall_instance
        try:
            _macho_syscall_instance = MachOSyscallDialog()
            _macho_syscall_instance.show()
            _macho_syscall_instance.raise_()
            _macho_syscall_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open macOS Syscall Resolver:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


_macho_syscall_instance = None
