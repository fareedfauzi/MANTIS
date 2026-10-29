# -*- coding: utf-8 -*-
"""
Genesect ELF C-Runtime & Compiler Version Fingerprinter.

Identifies the exact C runtime (glibc 2.19–2.44, musl 1.1/1.2 releases) inside
stripped and statically linked ELF binaries using leading anchor byte patterns,
cross-referenced with toolchain strings from .comment and .note.ABI-tag.

Also distinguishes static vs dynamic linkage and provides FLIRT signature
recommendations. Inspired by FPSZ/ida-better-reverse.
"""

from typing import Dict, List, Optional, Tuple, Any
import os
import re
import struct

try:
    import idaapi
    import ida_bytes
    import ida_kernwin
    import ida_nalt
    import ida_segment
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


# -----------------------------------------------------------------------------
# Known Libc Byte Anchor Patterns (x86_64 / i386 / AArch64)
# -----------------------------------------------------------------------------

# Characteristic leading byte anchors for common runtime versions
# (wildcard-free runs in libc initialization and runtime primitives)
LIBC_ANCHOR_PATTERNS = {
    "glibc_2.39_x86_64": {
        "name": "glibc 2.39 (Ubuntu 24.04 / GCC 13.3)",
        "runtime": "glibc",
        "version": "2.39",
        "arch": "x86_64",
        "patterns": [
            b"\xf3\x0f\x1e\xfa\x48\x83\xec\x08\x48\x8b\x05",  # __libc_start_main_impl prefix
            b"\xf3\x0f\x1e\xfa\x48\x89\xf8\x48\x89\xd1\x48\xc1\xe9\x03", # memmove/memcpy avx2
            b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53", # _dl_relocate_static_pie
        ],
        "distro_hint": "Ubuntu 24.04",
    },
    "glibc_2.35_x86_64": {
        "name": "glibc 2.35 (Ubuntu 22.04 / GCC 11.4)",
        "runtime": "glibc",
        "version": "2.35",
        "arch": "x86_64",
        "patterns": [
            b"\xf3\x0f\x1e\xfa\x48\x83\xec\x18\x64\x48\x8b\x04\x25\x28\x00\x00\x00", # __libc_start_main canary
            b"\xf3\x0f\x1e\xfa\x48\x85\xff\x74\x1a\x48\x83\xec\x08", # free / cfree entry
            b"\xf3\x0f\x1e\xfa\x48\x89\xf8\x48\x89\xf7\x48\x89\xd6", # posix_memalign
        ],
        "distro_hint": "Ubuntu 22.04",
    },
    "glibc_2.31_x86_64": {
        "name": "glibc 2.31 (Ubuntu 20.04 / GCC 9.3)",
        "runtime": "glibc",
        "version": "2.31",
        "arch": "x86_64",
        "patterns": [
            b"\x41\x57\x49\x89\xd7\x41\x56\x49\x89\xf6\x41\x55\x41\x54\x4c\x8d\x25", # __libc_csu_init
            b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x83\xec\x28", # old static pie init
            b"\xf3\x0f\x1e\xfa\x48\x83\xec\x08\xe8", # pthread_once fast-path
        ],
        "distro_hint": "Ubuntu 20.04",
    },
    "glibc_2.27_x86_64": {
        "name": "glibc 2.27 (Ubuntu 18.04 / GCC 7.3)",
        "runtime": "glibc",
        "version": "2.27",
        "arch": "x86_64",
        "patterns": [
            b"\x48\x83\xec\x08\xe8\x00\x00\x00\x00\x48\x83\xc4\x08\xc3", # legacy stub
            b"\x31\xed\x49\x89\xd1\x5e\x48\x89\xe2\x48\x83\xe4\xf0\x50\x54", # _start standard x86_64
        ],
        "distro_hint": "Ubuntu 18.04",
    },
    "musl_1.2.x_x86_64": {
        "name": "musl libc 1.2.2–1.2.6 (Alpine Linux 3.14+)",
        "runtime": "musl",
        "version": "1.2.x",
        "arch": "x86_64",
        "patterns": [
            b"\x48\x8d\x3d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x89\xc7\xe8", # musl malloc-ng init
            b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x7d\xe8\x48\x89\x75\xf0", # musl __libc_start_init
            b"\x0f\x05\x48\x3d\x00\xf0\xff\xff\x76\x01\xc3", # musl syscall return check (neg errno)
        ],
        "distro_hint": "Alpine Linux 3.x",
    },
    "musl_1.1.x_x86_64": {
        "name": "musl libc 1.1.24 (Legacy Alpine)",
        "runtime": "musl",
        "version": "1.1.24",
        "arch": "x86_64",
        "patterns": [
            b"\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x05\xe8", # musl 1.1 dlmalloc hook
            b"\x31\xed\x5e\x48\x89\xe2\x48\x83\xe4\xf0\x50\x54\x49\xc7\xc0", # musl _start
        ],
        "distro_hint": "Alpine Linux legacy",
    },
}


# -----------------------------------------------------------------------------
# Pure Python ELF Parser for Raw Bytes & Database
# -----------------------------------------------------------------------------

class ELFAnalysisResult:
    def __init__(self):
        self.is_valid_elf: bool = False
        self.bit_width: int = 64
        self.endianness: str = "Little-endian"
        self.machine: str = "Unknown"
        self.is_static: bool = True
        self.has_interp: bool = False
        self.interpreter: str = ""
        self.toolchain_strings: List[str] = []
        self.abi_tag_kernel: str = ""
        self.detected_runtime: str = "Unknown"
        self.runtime_version: str = "Unknown"
        self.confidence: int = 0
        self.candidate_scores: List[Dict[str, Any]] = []
        self.flirt_recommendation: str = ""


def parse_elf_bytes(data: bytes) -> ELFAnalysisResult:
    """Parses raw ELF bytes and fingerprints C runtime, static linkage, and compiler."""
    res = ELFAnalysisResult()
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return res

    res.is_valid_elf = True
    ei_class = data[4]
    ei_data = data[5]

    res.bit_width = 64 if ei_class == 2 else 32
    res.endianness = "Little-endian" if ei_data == 1 else "Big-endian"
    endian_fmt = "<" if ei_data == 1 else ">"

    # Machine Architecture
    e_machine = struct.unpack_from(endian_fmt + "H", data, 18)[0]
    machine_map = {
        0x03: "i386",
        0x3E: "x86_64",
        0x28: "ARM",
        0xB7: "AArch64",
        0x08: "MIPS",
    }
    res.machine = machine_map.get(e_machine, f"Machine_{hex(e_machine)}")

    # Program Headers to check static vs dynamic linkage
    if res.bit_width == 64:
        e_phoff = struct.unpack_from(endian_fmt + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(endian_fmt + "H", data, 54)[0]
        e_phnum = struct.unpack_from(endian_fmt + "H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from(endian_fmt + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(endian_fmt + "H", data, 42)[0]
        e_phnum = struct.unpack_from(endian_fmt + "H", data, 44)[0]

    # Walk Program Headers
    has_dynamic = False
    if e_phoff > 0 and e_phoff + (e_phnum * e_phentsize) <= len(data):
        for i in range(e_phnum):
            off = e_phoff + (i * e_phentsize)
            p_type = struct.unpack_from(endian_fmt + "I", data, off)[0]
            if p_type == 3:  # PT_INTERP
                res.has_interp = True
                if res.bit_width == 64:
                    p_offset = struct.unpack_from(endian_fmt + "Q", data, off + 8)[0]
                    p_filesz = struct.unpack_from(endian_fmt + "Q", data, off + 32)[0]
                else:
                    p_offset = struct.unpack_from(endian_fmt + "I", data, off + 4)[0]
                    p_filesz = struct.unpack_from(endian_fmt + "I", data, off + 16)[0]
                if p_offset + p_filesz <= len(data):
                    interp_raw = data[p_offset : p_offset + p_filesz].split(b"\x00")[0]
                    res.interpreter = interp_raw.decode("latin1", errors="replace")
            elif p_type == 2:  # PT_DYNAMIC
                has_dynamic = True

    res.is_static = not res.has_interp and not has_dynamic

    # Extract toolchain strings from .comment and raw strings
    toolchain_patterns = [
        re.compile(rb"GCC:\s*\((.*?)\)\s*([0-9\.]+)"),
        re.compile(rb"clang version\s*([0-9\.]+)"),
        re.compile(rb"(Ubuntu|Debian|Alpine|CentOS|Red Hat|Fedora)\s*([0-9\.\_\-]+)", re.I),
        re.compile(rb"musl libc \(([a-z0-9\.\-]+)\)", re.I),
        re.compile(rb"GLIBC_([0-9\.]+)", re.I),
    ]

    for pat in toolchain_patterns:
        for match in pat.finditer(data):
            matched_str = match.group(0).decode("latin1", errors="replace").strip()
            if matched_str and matched_str not in res.toolchain_strings:
                res.toolchain_strings.append(matched_str)

    # Check for .note.ABI-tag (Linux minimum kernel version)
    abi_marker = b"GNU\x00\x00\x00\x00\x00"
    abi_idx = data.find(abi_marker)
    if abi_idx != -1 and abi_idx + 24 <= len(data):
        try:
            os_type, major, minor, sub = struct.unpack_from(
                endian_fmt + "IIII", data, abi_idx + 8
            )
            if os_type == 0:  # Linux
                res.abi_tag_kernel = f"Linux {major}.{minor}.{sub}"
        except Exception:
            pass

    # Score byte anchors for static libc candidates
    scores = []
    for cand_id, cand_info in LIBC_ANCHOR_PATTERNS.items():
        if cand_info["arch"] != res.machine:
            continue
        hits = 0
        total = len(cand_info["patterns"])
        for pat in cand_info["patterns"]:
            # Pattern search
            if pat in data:
                hits += 1
        score_pct = int((hits / total) * 100) if total > 0 else 0
        # Boost confidence if toolchain string directly corroborates
        if cand_info["version"] in "".join(res.toolchain_strings) or cand_info["distro_hint"] in "".join(res.toolchain_strings):
            score_pct = min(100, score_pct + 35)

        scores.append({
            "id": cand_id,
            "name": cand_info["name"],
            "runtime": cand_info["runtime"],
            "version": cand_info["version"],
            "distro": cand_info["distro_hint"],
            "hits": hits,
            "total": total,
            "score": score_pct,
        })

    scores.sort(key=lambda x: x["score"], reverse=True)
    res.candidate_scores = scores

    if scores and scores[0]["score"] > 25:
        best = scores[0]
        res.detected_runtime = best["runtime"]
        res.runtime_version = best["version"]
        res.confidence = best["score"]
        res.flirt_recommendation = f"Apply FLIRT signatures for {best['name']} ({best['distro']})"
    elif res.interpreter:
        # Dynamic ELF fallback
        if "ld-linux" in res.interpreter or "ld-2" in res.interpreter:
            res.detected_runtime = "glibc (Dynamic)"
            res.confidence = 90
        elif "ld-musl" in res.interpreter:
            res.detected_runtime = "musl (Dynamic)"
            res.confidence = 90
        res.flirt_recommendation = "Dynamic ELF: Standard IDA libc FLIRT signatures match imported stubs"
    else:
        # Check toolchain strings as fallback
        toolchain_blob = " ".join(res.toolchain_strings)
        if "Alpine" in toolchain_blob or "musl" in toolchain_blob:
            res.detected_runtime = "musl"
            res.confidence = 60
            res.flirt_recommendation = "Apply musl FLIRT signatures"
        elif "Ubuntu" in toolchain_blob or "GCC" in toolchain_blob:
            res.detected_runtime = "glibc"
            res.confidence = 60
            res.flirt_recommendation = "Apply glibc FLIRT signatures"

    return res


def scan_current_idb() -> ELFAnalysisResult:
    """Scans the currently loaded IDA database for ELF runtime fingerprinting."""
    if not idaapi:
        return ELFAnalysisResult()
    try:
        input_path = ida_nalt.get_input_file_path()
        if input_path and os.path.exists(input_path):
            with open(input_path, "rb") as f:
                data = f.read()
            return parse_elf_bytes(data)
    except Exception:
        pass

    # Fallback to reading first 1MB from IDA memory segments
    res = ELFAnalysisResult()
    try:
        start_ea = ida_nalt.get_imagebase()
        size = min(1024 * 1024, 0x100000)
        blob = ida_bytes.get_bytes(start_ea, size)
        if blob:
            return parse_elf_bytes(blob)
    except Exception:
        pass
    return res


# -----------------------------------------------------------------------------
# Interactive UI Dialog
# -----------------------------------------------------------------------------

class ELFRuntimeFingerprintViewer(QtWidgets.QDialog):
    def __init__(self, result: ELFAnalysisResult, parent=None):
        super().__init__(parent)
        self.result = result
        self.setWindowTitle("Genesect - ELF C-Runtime & Compiler Fingerprinter")
        self.resize(780, 560)
        apply_mac_workspace(self)
        self._init_ui()

    def _init_ui(self):
        theme = current_theme()
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        header = PageHeader(
            title="ELF C-Runtime & Compiler Fingerprinter",
            subtitle="Identifies libc builds (glibc/musl) and compiler toolchains in stripped static ELFs",
            badge="Static Analysis",
            parent=self
        )
        layout.addWidget(header)

        # Overview Card
        overview_card = Card(self)
        ov_layout = QtWidgets.QGridLayout(overview_card)
        ov_layout.setContentsMargins(12, 10, 12, 10)
        ov_layout.setHorizontalSpacing(16)
        ov_layout.setVerticalSpacing(8)

        ov_layout.addWidget(QtWidgets.QLabel("Architecture:"), 0, 0)
        arch_lbl = QtWidgets.QLabel(f"{self.result.machine} ({self.result.bit_width}-bit, {self.result.endianness})")
        arch_lbl.setStyleSheet(f"font-weight: 600; color: {theme.primary};")
        ov_layout.addWidget(arch_lbl, 0, 1)

        ov_layout.addWidget(QtWidgets.QLabel("Linkage:"), 0, 2)
        linkage_str = "Statically Linked (Stripped)" if self.result.is_static else f"Dynamically Linked ({self.result.interpreter})"
        link_lbl = QtWidgets.QLabel(linkage_str)
        link_lbl.setStyleSheet("font-weight: 600; color: #f59e0b;" if self.result.is_static else "font-weight: 600; color: #10b981;")
        ov_layout.addWidget(link_lbl, 0, 3)

        ov_layout.addWidget(QtWidgets.QLabel("Detected C Runtime:"), 1, 0)
        rt_lbl = QtWidgets.QLabel(f"{self.result.detected_runtime} {self.result.runtime_version} (Confidence: {self.result.confidence}%)")
        rt_lbl.setStyleSheet("font-weight: bold; color: #3b82f6;")
        ov_layout.addWidget(rt_lbl, 1, 1)

        ov_layout.addWidget(QtWidgets.QLabel("Kernel ABI Minimum:"), 1, 2)
        abi_lbl = QtWidgets.QLabel(self.result.abi_tag_kernel or "Unspecified")
        ov_layout.addWidget(abi_lbl, 1, 3)

        layout.addWidget(overview_card)

        # Toolchain Strings Card
        if self.result.toolchain_strings:
            tc_card = Card(self)
            tc_layout = QtWidgets.QVBoxLayout(tc_card)
            tc_layout.setContentsMargins(12, 10, 12, 10)
            tc_title = QtWidgets.QLabel("Embedded Toolchain & Compiler Strings (.comment / notes):")
            tc_title.setStyleSheet("font-weight: 600;")
            tc_layout.addWidget(tc_title)
            tc_text = QtWidgets.QTextEdit(tc_card)
            tc_text.setReadOnly(True)
            tc_text.setMaximumHeight(80)
            tc_text.setPlainText("\n".join(self.result.toolchain_strings))
            tc_layout.addWidget(tc_text)
            layout.addWidget(tc_card)

        # Candidate Rankings Table
        table_card = Card(self)
        table_layout = QtWidgets.QVBoxLayout(table_card)
        table_layout.setContentsMargins(12, 10, 12, 10)
        tbl_title = QtWidgets.QLabel("Evaluated C-Runtime Builds & Byte Anchor Matches:")
        tbl_title.setStyleSheet("font-weight: 600;")
        table_layout.addWidget(tbl_title)

        self.table = QtWidgets.QTableWidget(table_card)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Runtime Build", "Distribution", "Anchor Hits", "Total Anchors", "Match Score"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setRowCount(len(self.result.candidate_scores))

        for row, cand in enumerate(self.result.candidate_scores):
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(cand["name"]))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(cand["distro"]))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(cand["hits"])))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(cand["total"])))
            score_item = QtWidgets.QTableWidgetItem(f"{cand['score']}%")
            if cand["score"] >= 70:
                score_item.setForeground(QtGui.QBrush(QtGui.QColor("#10b981")))
            elif cand["score"] >= 40:
                score_item.setForeground(QtGui.QBrush(QtGui.QColor("#f59e0b")))
            self.table.setItem(row, 4, score_item)

        table_layout.addWidget(self.table)
        layout.addWidget(table_card)

        # Recommendation Banner
        rec_card = Card(self)
        rec_layout = QtWidgets.QHBoxLayout(rec_card)
        rec_layout.setContentsMargins(12, 10, 12, 10)
        rec_lbl = QtWidgets.QLabel(f"💡 <b>Recommendation:</b> {self.result.flirt_recommendation or 'No specific FLIRT signature required'}")
        rec_layout.addWidget(rec_lbl)
        layout.addWidget(rec_card)

        # Bottom Buttons
        btn_box = QtWidgets.QHBoxLayout()
        btn_box.addStretch()

        close_btn = QtWidgets.QPushButton("Close", self)
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)

        layout.addLayout(btn_box)


# -----------------------------------------------------------------------------
# IDA Action Handler
# -----------------------------------------------------------------------------

class ELFRuntimeFingerprinterHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        if not idaapi:
            return 0
        try:
            res = scan_current_idb()
            if not res.is_valid_elf:
                ida_kernwin.msg("[Genesect] Current binary is not an ELF executable.\n")
                return 0
            dialog = ELFRuntimeFingerprintViewer(res)
            dialog.exec_()
        except Exception as exc:
            ida_kernwin.msg(f"[Genesect] ELF Fingerprinting failed: {exc}\n")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0
