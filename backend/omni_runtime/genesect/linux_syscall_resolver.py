# -*- coding: utf-8 -*-
"""
Genesect Linux Raw Syscall & Threat Explorer.

Identifies raw Linux syscall invocations (syscall, sysenter, int 0x80, svc #0),
backward-slices registers (RAX, EAX, X8, R7) to resolve exact kernel syscalls,
categorizes rootkit/malware capabilities (eBPF, kernel modules, memfd execution,
process memory injection, anti-debugging), and provides 1-click IDB annotations.
"""

from typing import Dict, List, Optional, Tuple, Any, Set
import csv
import io
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


# Linux Syscall Tables for x86_64, x86 (i386), ARM64, and ARM
# Format: { syscall_number: (name, category, danger_level, args_signature) }
# Danger levels: "Critical" (rootkit/kernel module/injection), "High" (evasion/anti-debug/mem execution), "Standard" (normal OS)

SYSCALLS_X86_64 = {
    0: ("sys_read", "File I/O", "Standard", "int fd, char *buf, size_t count"),
    1: ("sys_write", "File I/O", "Standard", "int fd, const char *buf, size_t count"),
    2: ("sys_open", "File I/O", "Standard", "const char *filename, int flags, umode_t mode"),
    3: ("sys_close", "File I/O", "Standard", "int fd"),
    4: ("sys_stat", "File I/O", "Standard", "const char *filename, struct stat *statbuf"),
    5: ("sys_fstat", "File I/O", "Standard", "int fd, struct stat *statbuf"),
    8: ("sys_lseek", "File I/O", "Standard", "int fd, off_t offset, int whence"),
    9: ("sys_mmap", "Memory", "Standard", "unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off"),
    10: ("sys_mprotect", "Memory", "Medium", "unsigned long start, size_t len, unsigned long prot"),
    11: ("sys_munmap", "Memory", "Standard", "unsigned long addr, size_t len"),
    12: ("sys_brk", "Memory", "Standard", "unsigned long brk"),
    13: ("sys_rt_sigaction", "Signal", "Medium", "int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize"),
    14: ("sys_rt_sigprocmask", "Signal", "Standard", "int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize"),
    20: ("sys_writev", "File I/O", "Standard", "int fd, const struct iovec *vec, unsigned long vlen"),
    21: ("sys_access", "File I/O", "Standard", "const char *filename, int mode"),
    22: ("sys_pipe", "IPC", "Standard", "int *fildes"),
    23: ("sys_select", "Network", "Standard", "int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timeval *tvp"),
    39: ("sys_getpid", "Process", "Standard", "void"),
    41: ("sys_socket", "Network", "Standard", "int family, int type, int protocol"),
    42: ("sys_connect", "Network", "Medium", "int fd, struct sockaddr *uservaddr, int addrlen"),
    43: ("sys_accept", "Network", "Standard", "int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen"),
    44: ("sys_sendto", "Network", "Standard", "int fd, void *buff, size_t len, unsigned flags, struct sockaddr *addr, int addr_len"),
    45: ("sys_recvfrom", "Network", "Standard", "int fd, void *ubuf, size_t size, unsigned flags, struct sockaddr *addr, int *addr_len"),
    49: ("sys_bind", "Network", "Standard", "int fd, struct sockaddr *umyaddr, int addrlen"),
    50: ("sys_listen", "Network", "Standard", "int fd, int backlog"),
    56: ("sys_clone", "Process", "Medium", "unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, int *child_tidptr, unsigned long tls"),
    57: ("sys_fork", "Process", "Standard", "void"),
    58: ("sys_vfork", "Process", "Standard", "void"),
    59: ("sys_execve", "Process", "High", "const char *filename, const char *const *argv, const char *const *envp"),
    60: ("sys_exit", "Process", "Standard", "int error_code"),
    61: ("sys_wait4", "Process", "Standard", "pid_t upid, int *stat_addr, int options, struct rusage *ru"),
    62: ("sys_kill", "Process", "Medium", "pid_t pid, int sig"),
    72: ("sys_fcntl", "File I/O", "Standard", "int fd, unsigned int cmd, unsigned long arg"),
    79: ("sys_getcwd", "File I/O", "Standard", "char *buf, unsigned long size"),
    80: ("sys_chdir", "File I/O", "Standard", "const char *filename"),
    82: ("sys_rename", "File I/O", "Standard", "const char *oldname, const char *newname"),
    83: ("sys_mkdir", "File I/O", "Standard", "const char *pathname, umode_t mode"),
    84: ("sys_rmdir", "File I/O", "Standard", "const char *pathname"),
    85: ("sys_creat", "File I/O", "Standard", "const char *pathname, umode_t mode"),
    86: ("sys_link", "File I/O", "Standard", "const char *oldname, const char *newname"),
    87: ("sys_unlink", "File I/O", "Medium", "const char *pathname"),
    88: ("sys_symlink", "File I/O", "Standard", "const char *old, const char *new"),
    89: ("sys_readlink", "File I/O", "Standard", "const char *path, char *buf, int bufsiz"),
    90: ("sys_chmod", "File I/O", "Standard", "const char *filename, umode_t mode"),
    92: ("sys_chown", "File I/O", "Standard", "const char *filename, uid_t user, gid_t group"),
    101: ("sys_ptrace", "Anti-Debug / Injection", "Critical", "long request, long pid, unsigned long addr, unsigned long data"),
    102: ("sys_getuid", "Credentials", "Standard", "void"),
    105: ("sys_setuid", "Credentials", "Medium", "uid_t uid"),
    106: ("sys_setgid", "Credentials", "Medium", "gid_t gid"),
    107: ("sys_geteuid", "Credentials", "Standard", "void"),
    157: ("sys_prctl", "Evasion / Stealth", "High", "int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5"),
    165: ("sys_mount", "System", "Medium", "char *dev_name, char *dir_name, char *type, unsigned long flags, void *data"),
    166: ("sys_umount2", "System", "Medium", "const char *target, int flags"),
    175: ("sys_init_module", "Rootkit / Kernel", "Critical", "void *umod, unsigned long len, const char *uargs"),
    176: ("sys_delete_module", "Rootkit / Kernel", "Critical", "const char *name_user, unsigned int flags"),
    200: ("sys_tkill", "Process", "Standard", "pid_t pid, int sig"),
    234: ("sys_tgkill", "Process", "Standard", "pid_t tgid, pid_t pid, int sig"),
    257: ("sys_openat", "File I/O", "Standard", "int dfd, const char *filename, int flags, umode_t mode"),
    263: ("sys_unlinkat", "File I/O", "Medium", "int dfd, const char *pathname, int flag"),
    267: ("sys_readlinkat", "File I/O", "Standard", "int dfd, const char *pathname, char *buf, int bufsiz"),
    302: ("sys_prlimit64", "System", "Standard", "pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim"),
    310: ("sys_process_vm_readv", "Process / Injection", "High", "pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags"),
    311: ("sys_process_vm_writev", "Process / Injection", "Critical", "pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags"),
    313: ("sys_finit_module", "Rootkit / Kernel", "Critical", "int fd, const char *uargs, int flags"),
    319: ("sys_memfd_create", "Memory Execution / Stealth", "Critical", "const char *uname, unsigned int flags"),
    321: ("sys_bpf", "Rootkit / eBPF", "Critical", "int cmd, union bpf_attr *attr, unsigned int size"),
    322: ("sys_execveat", "Process Execution", "Critical", "int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags"),
    326: ("sys_copy_file_range", "File I/O", "Standard", "int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags"),
}

SYSCALLS_X86 = {
    1: ("sys_exit", "Process", "Standard", "int error_code"),
    2: ("sys_fork", "Process", "Standard", "void"),
    3: ("sys_read", "File I/O", "Standard", "int fd, char *buf, size_t count"),
    4: ("sys_write", "File I/O", "Standard", "int fd, const char *buf, size_t count"),
    5: ("sys_open", "File I/O", "Standard", "const char *filename, int flags, umode_t mode"),
    6: ("sys_close", "File I/O", "Standard", "int fd"),
    10: ("sys_unlink", "File I/O", "Medium", "const char *pathname"),
    11: ("sys_execve", "Process", "High", "const char *filename, const char *const *argv, const char *const *envp"),
    26: ("sys_ptrace", "Anti-Debug / Injection", "Critical", "long request, long pid, unsigned long addr, unsigned long data"),
    37: ("sys_kill", "Process", "Medium", "pid_t pid, int sig"),
    102: ("sys_socketcall", "Network", "Medium", "int call, unsigned long *args"),
    128: ("sys_init_module", "Rootkit / Kernel", "Critical", "void *umod, unsigned long len, const char *uargs"),
    129: ("sys_delete_module", "Rootkit / Kernel", "Critical", "const char *name_user, unsigned int flags"),
    172: ("sys_prctl", "Evasion / Stealth", "High", "int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5"),
    295: ("sys_openat", "File I/O", "Standard", "int dfd, const char *filename, int flags, umode_t mode"),
    347: ("sys_process_vm_readv", "Process / Injection", "High", "pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags"),
    348: ("sys_process_vm_writev", "Process / Injection", "Critical", "pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags"),
    350: ("sys_finit_module", "Rootkit / Kernel", "Critical", "int fd, const char *uargs, int flags"),
    356: ("sys_memfd_create", "Memory Execution / Stealth", "Critical", "const char *uname, unsigned int flags"),
    357: ("sys_bpf", "Rootkit / eBPF", "Critical", "int cmd, union bpf_attr *attr, unsigned int size"),
    358: ("sys_execveat", "Process Execution", "Critical", "int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags"),
}

SYSCALLS_ARM64 = {
    56: ("sys_openat", "File I/O", "Standard", "int dfd, const char *filename, int flags, umode_t mode"),
    57: ("sys_close", "File I/O", "Standard", "int fd"),
    63: ("sys_read", "File I/O", "Standard", "int fd, char *buf, size_t count"),
    64: ("sys_write", "File I/O", "Standard", "int fd, const char *buf, size_t count"),
    93: ("sys_exit", "Process", "Standard", "int error_code"),
    117: ("sys_ptrace", "Anti-Debug / Injection", "Critical", "long request, long pid, unsigned long addr, unsigned long data"),
    129: ("sys_kill", "Process", "Medium", "pid_t pid, int sig"),
    167: ("sys_prctl", "Evasion / Stealth", "High", "int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5"),
    105: ("sys_init_module", "Rootkit / Kernel", "Critical", "void *umod, unsigned long len, const char *uargs"),
    106: ("sys_delete_module", "Rootkit / Kernel", "Critical", "const char *name_user, unsigned int flags"),
    220: ("sys_clone", "Process", "Medium", "unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, int *child_tidptr, unsigned long tls"),
    221: ("sys_execve", "Process", "High", "const char *filename, const char *const *argv, const char *const *envp"),
    270: ("sys_process_vm_readv", "Process / Injection", "High", "pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags"),
    271: ("sys_process_vm_writev", "Process / Injection", "Critical", "pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags"),
    273: ("sys_finit_module", "Rootkit / Kernel", "Critical", "int fd, const char *uargs, int flags"),
    279: ("sys_memfd_create", "Memory Execution / Stealth", "Critical", "const char *uname, unsigned int flags"),
    280: ("sys_bpf", "Rootkit / eBPF", "Critical", "int cmd, union bpf_attr *attr, unsigned int size"),
    281: ("sys_execveat", "Process Execution", "Critical", "int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags"),
}


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


def get_current_architecture() -> str:
    """Detect binary architecture: 'x86_64', 'x86', 'arm64', or 'arm'."""
    if not ida_ida or not hasattr(ida_ida, "inf_get_proc_name"):
        return "x86_64"
    proc = ida_ida.inf_get_proc_name().lower()
    is_64 = bool(ida_ida.inf_is_64bit()) if hasattr(ida_ida, "inf_is_64bit") else True

    if "arm" in proc or "aarch64" in proc:
        return "arm64" if is_64 else "arm"
    return "x86_64" if is_64 else "x86"


def get_syscall_table_for_arch(arch: str) -> Dict[int, Tuple[str, str, str, str]]:
    if arch == "x86":
        return SYSCALLS_X86
    elif arch == "arm64":
        return SYSCALLS_ARM64
    return SYSCALLS_X86_64


def slice_syscall_register(syscall_ea: int, arch: str, max_lookback: int = 15) -> Optional[int]:
    """
    Backward-slices instructions preceding syscall_ea to resolve the syscall number.
    Inspects RAX/EAX (x86_64/x86) or X8/R7 (ARM64/ARM).
    """
    if not idc or not ida_bytes:
        return None

    target_regs = {
        "x86_64": {"rax", "eax", "al"},
        "x86": {"eax", "al"},
        "arm64": {"x8", "w8"},
        "arm": {"r7"},
    }.get(arch, {"rax", "eax", "al"})

    cur_ea = syscall_ea
    func = ida_funcs.get_func(syscall_ea) if ida_funcs else None
    func_start = func.start_ea if func else max(0, syscall_ea - 0x100)

    for _ in range(max_lookback):
        prev_ea = idc.prev_head(cur_ea, func_start)
        if prev_ea == idaapi.BADADDR or prev_ea == cur_ea:
            break
        cur_ea = prev_ea

        mnem = (idc.print_insn_mnem(cur_ea) or "").lower()
        op0 = (idc.print_operand(cur_ea, 0) or "").lower().strip()
        op1 = (idc.print_operand(cur_ea, 1) or "").lower().strip()

        # Handle direct mov reg, imm
        if mnem in ("mov", "movsxd", "movzx", "movz", "movk", "ldr") and op0 in target_regs:
            # Try to evaluate op1 as integer
            val = idc.get_operand_value(cur_ea, 1)
            if val is not None and val != -1 and val != 0:
                return int(val)
            # If literal representation
            try:
                if op1.startswith("0x") or op1.startswith("#0x"):
                    return int(op1.replace("#", ""), 16)
                if op1.isdigit() or (op1.startswith("#") and op1[1:].isdigit()):
                    return int(op1.replace("#", ""))
            except ValueError:
                pass

        # Handle xor reg, reg -> followed by inc/add
        if mnem == "xor" and op0 in target_regs and op1 in target_regs:
            return 0

    return None


def scan_raw_syscalls() -> List[Dict[str, Any]]:
    """Scan the entire database for raw syscall invocations and resolve them."""
    results = []
    if not idc or not ida_bytes:
        return results

    arch = get_current_architecture()
    table = get_syscall_table_for_arch(arch)

    # Search patterns
    # x86_64: 0F 05 (syscall)
    # x86: CD 80 (int 0x80) or 0F 34 (sysenter)
    # ARM64: 01 00 00 D4 (svc #0)
    for seg_ea in idautils.Segments() if idautils else []:
        seg_start = idc.get_segm_start(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)
        cur_ea = seg_start

        while cur_ea < seg_end:
            mnem = (idc.print_insn_mnem(cur_ea) or "").lower()
            is_syscall = False

            if arch in ("x86_64", "x86"):
                if mnem in ("syscall", "sysenter"):
                    is_syscall = True
                elif mnem == "int" and (idc.print_operand(cur_ea, 0) or "").strip() in ("80h", "0x80", "128"):
                    is_syscall = True
            elif arch in ("arm64", "arm"):
                if mnem in ("svc", "swi"):
                    is_syscall = True

            if is_syscall:
                num = slice_syscall_register(cur_ea, arch)
                meta = table.get(num) if num is not None else None
                if meta:
                    name, cat, danger, args = meta
                else:
                    name = "sys_unknown_%s" % num if num is not None else "sys_dynamic"
                    cat = "Unknown"
                    danger = "Standard"
                    args = "..."

                func = ida_funcs.get_func(cur_ea) if ida_funcs else None
                func_name = (idc.get_func_name(func.start_ea) if func else "") or "outside_function"
                func_start = func.start_ea if func else cur_ea

                results.append({
                    "ea": cur_ea,
                    "arch": arch,
                    "syscall_num": num,
                    "syscall_name": name,
                    "category": cat,
                    "danger": danger,
                    "args": args,
                    "func_name": func_name,
                    "func_ea": func_start,
                    "annotated": False,
                })

            next_ea = idc.next_head(cur_ea, seg_end)
            if next_ea <= cur_ea:
                break
            cur_ea = next_ea

    return results


class LinuxSyscallDialog(QtWidgets.QDialog):
    """Interactive GUI dialog for Linux Raw Syscall & Threat Explorer."""

    def __init__(self, parent=None):
        super(LinuxSyscallDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - Linux Syscall & Threat Explorer")
        self.resize(1100, 640)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.results: List[Dict[str, Any]] = []

        self._setup_ui()
        QtCore.QTimer.singleShot(0, self.refresh_scan)

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{ background: {t.window}; color: {t.text}; }}
            QLineEdit, QComboBox, QTableWidget {{
                background: {t.surface};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                padding: 6px;
            }}
            QTableWidget {{ gridline-color: {t.border}; }}
            QHeaderView::section {{
                background: {t.surface_alt};
                color: {t.text_muted};
                padding: 6px;
                font-weight: 700;
                border: none;
                border-bottom: 1px solid {t.border};
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        header = PageHeader(
            "Linux Raw Syscall & Threat Explorer",
            "Scans raw syscall/int 0x80/svc instructions, resolves kernel syscall numbers via register slicing, and flags rootkit/evasion behaviors."
        )

        btn_rescan = QtWidgets.QPushButton("Rescan Database")
        btn_rescan.setProperty("pnVariant", "primary")
        btn_rescan.clicked.connect(self.refresh_scan)
        header.add_action(btn_rescan)

        btn_annotate = QtWidgets.QPushButton("Annotate Selected")
        btn_annotate.clicked.connect(self._annotate_selected)
        header.add_action(btn_annotate)

        btn_rename_wrappers = QtWidgets.QPushButton("Rename Wrappers")
        btn_rename_wrappers.clicked.connect(self._rename_wrappers)
        header.add_action(btn_rename_wrappers)

        btn_export = QtWidgets.QPushButton("Export CSV")
        btn_export.clicked.connect(self._export_csv)
        header.add_action(btn_export)

        root.addWidget(header)

        # Filters
        card_filter = Card()
        l_filt = QtWidgets.QHBoxLayout(card_filter)
        l_filt.setContentsMargins(12, 8, 12, 8)
        l_filt.addWidget(QtWidgets.QLabel("Search:"))
        self.edit_search = QtWidgets.QLineEdit()
        self.edit_search.setPlaceholderText("Filter by name, address, or category...")
        self.edit_search.textChanged.connect(self._apply_filter)
        l_filt.addWidget(self.edit_search, 1)

        l_filt.addWidget(QtWidgets.QLabel("Category:"))
        self.cmb_cat = QtWidgets.QComboBox()
        self.cmb_cat.addItems(["All", "Rootkit / Kernel", "Rootkit / eBPF", "Process / Injection", "Anti-Debug / Injection", "Memory Execution / Stealth", "File I/O", "Network"])
        self.cmb_cat.currentIndexChanged.connect(self._apply_filter)
        l_filt.addWidget(self.cmb_cat)

        root.addWidget(card_filter)

        # Table
        self.tbl = QtWidgets.QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels([
            "Syscall Address", "Function", "Arch", "Syscall #", "Resolved Name", "Category", "Danger / Threat Level"
        ])
        self.tbl.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self.tbl, 1)

        # Bottom Bar
        bottom = QtWidgets.QHBoxLayout()
        self.lbl_stats = QtWidgets.QLabel("Found 0 raw syscalls.")
        self.lbl_stats.setStyleSheet(f"color: {t.text_muted};")
        bottom.addWidget(self.lbl_stats)
        bottom.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)
        root.addLayout(bottom)

    def refresh_scan(self):
        self.results = scan_raw_syscalls()
        self._apply_filter()

    def _apply_filter(self):
        query = self.edit_search.text().strip().lower()
        selected_cat = self.cmb_cat.currentText()

        filtered = []
        for r in self.results:
            if selected_cat != "All" and r["category"] != selected_cat:
                continue
            if query:
                combined = f"{_hex(r['ea'])} {r['func_name']} {r['syscall_name']} {r['category']} {r['danger']}".lower()
                if query not in combined:
                    continue
            filtered.append(r)

        self.tbl.setRowCount(len(filtered))
        for row, r in enumerate(filtered):
            it_ea = QtWidgets.QTableWidgetItem(_hex(r["ea"]))
            it_ea.setData(QtCore.Qt.UserRole, r)
            it_fn = QtWidgets.QTableWidgetItem(r["func_name"])
            it_arch = QtWidgets.QTableWidgetItem(r["arch"])
            it_num = QtWidgets.QTableWidgetItem(str(r["syscall_num"]) if r["syscall_num"] is not None else "?")
            it_name = QtWidgets.QTableWidgetItem(r["syscall_name"])
            it_cat = QtWidgets.QTableWidgetItem(r["category"])
            it_danger = QtWidgets.QTableWidgetItem(r["danger"])

            # Highlight danger level
            if r["danger"] == "Critical":
                it_danger.setForeground(QtGui.QBrush(QtGui.QColor("#EF4444"))) # Red
                it_danger.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            elif r["danger"] == "High":
                it_danger.setForeground(QtGui.QBrush(QtGui.QColor("#F59E0B"))) # Amber
            elif r["danger"] == "Medium":
                it_danger.setForeground(QtGui.QBrush(QtGui.QColor("#3B82F6"))) # Blue

            self.tbl.setItem(row, 0, it_ea)
            self.tbl.setItem(row, 1, it_fn)
            self.tbl.setItem(row, 2, it_arch)
            self.tbl.setItem(row, 3, it_num)
            self.tbl.setItem(row, 4, it_name)
            self.tbl.setItem(row, 5, it_cat)
            self.tbl.setItem(row, 6, it_danger)

        crit_count = sum(1 for r in self.results if r["danger"] == "Critical")
        self.lbl_stats.setText(f"Found {len(self.results)} raw syscalls ({crit_count} Critical / Rootkit primitives). Showing {len(filtered)}.")

    def _on_double_click(self, item):
        row = item.row()
        it_ea = self.tbl.item(row, 0)
        if it_ea:
            r = it_ea.data(QtCore.Qt.UserRole)
            if r and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
                ida_kernwin.jumpto(r["ea"])

    def _annotate_selected(self):
        rows = set(it.row() for it in self.tbl.selectedItems())
        count = 0
        for row in rows:
            it = self.tbl.item(row, 0)
            if not it:
                continue
            r = it.data(QtCore.Qt.UserRole)
            if not r or not idc:
                continue

            comment = f"[Genesect] Linux Syscall: {r['syscall_name']} ({r['syscall_num']}) [{r['category']} - {r['danger']}]\nArgs: ({r['args']})"
            idc.set_cmt(r["ea"], comment, 0)
            count += 1

        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Successfully annotated {count} syscall instructions.")

    def _rename_wrappers(self):
        """Rename wrapper functions (e.g. sub_XXXX) containing single syscalls."""
        rows = set(it.row() for it in self.tbl.selectedItems())
        if not rows:
            rows = range(self.tbl.rowCount())

        renamed = 0
        for row in rows:
            it = self.tbl.item(row, 0)
            if not it:
                continue
            r = it.data(QtCore.Qt.UserRole)
            if not r or not idc:
                continue

            func_name = r["func_name"]
            func_ea = r["func_ea"]
            if func_name.startswith("sub_") and r["syscall_name"].startswith("sys_"):
                new_name = f"syscall_{r['syscall_name'][4:]}_{_hex(func_ea)[2:]}"
                if idc.set_name(func_ea, new_name):
                    renamed += 1

        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Renamed {renamed} wrapper functions.")
        self.refresh_scan()

    def _export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Linux Syscalls CSV", "linux_syscalls.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fp:
                writer = csv.writer(fp)
                writer.writerow(["Address", "Calling Function", "Architecture", "Syscall Number", "Syscall Name", "Category", "Danger Level", "Arguments"])
                for r in self.results:
                    writer.writerow([
                        _hex(r["ea"]), r["func_name"], r["arch"], r["syscall_num"],
                        r["syscall_name"], r["category"], r["danger"], r["args"]
                    ])
            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info(f"Saved {len(self.results)} syscall records to:\n{path}")
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to export CSV:\n{exc}")


class LinuxSyscallResolverHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _linux_syscall_instance
        try:
            _linux_syscall_instance = LinuxSyscallDialog()
            _linux_syscall_instance.show()
            _linux_syscall_instance.raise_()
            _linux_syscall_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open Linux Syscall Explorer:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


_linux_syscall_instance = None
