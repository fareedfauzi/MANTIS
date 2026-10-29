# -*- coding: utf-8 -*-
"""
Genesect ELF Header Tampering Detector & Repair Utility.

Detects corrupted or anti-analysis tampered ELF header fields (mismatched EI_CLASS,
inverted EI_DATA endianness, non-standard EI_VERSION, and out-of-bounds e_shoff section
table offsets that cause IDA/readelf crashes), sanitizes them in-place, and exports
clean loadable ELF binaries.

Inspired by anti-analysis countermeasures in CTF reversing challenges and FPSZ/ida-better-reverse.
"""

from typing import Dict, List, Optional, Tuple, Any
import os
import struct

try:
    import idaapi
    import ida_kernwin
    import ida_nalt
except ImportError:
    idaapi = None
    ida_kernwin = None
    ida_nalt = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


# Standard ELF Constants
EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8

ELFCLASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2

EV_CURRENT = 1

EM_386 = 0x03
EM_MIPS = 0x08
EM_ARM = 0x28
EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7
EM_RISCV = 0xF3


# -----------------------------------------------------------------------------
# Pure Python Anomaly Detection & Repair Engine
# -----------------------------------------------------------------------------

def detect_elf_header_anomalies(data: bytes) -> List[Dict[str, Any]]:
    """Inspects raw ELF bytes for corrupted or anti-analysis header fields."""
    anomalies = []
    if len(data) < 52:
        anomalies.append({
            "field": "File Size",
            "issue": f"Truncated ELF file (only {len(data)} bytes, minimum is 52 bytes)",
            "severity": "Critical",
            "fix": "File too small to repair automatically",
        })
        return anomalies

    if data[:4] != b"\x7fELF":
        anomalies.append({
            "field": "Magic Bytes",
            "issue": f"Invalid magic bytes: {data[:4].hex()} (expected 7f454c46)",
            "severity": "Critical",
            "fix": "Restore 0x7f, 'E', 'L', 'F' magic header",
        })

    ei_class = data[EI_CLASS]
    ei_data = data[EI_DATA]
    ei_version = data[EI_VERSION]

    # Endianness sanity
    endian_fmt = "<"
    if ei_data == ELFDATA2MSB:
        endian_fmt = ">"
    elif ei_data != ELFDATA2LSB:
        anomalies.append({
            "field": "EI_DATA",
            "issue": f"Tampered endianness indicator: {ei_data} (expected 1 for LSB or 2 for MSB)",
            "severity": "High",
            "fix": "Normalize EI_DATA to ELFDATA2LSB (1)",
        })

    # Machine & Class sanity
    if len(data) >= 20:
        e_machine = struct.unpack_from(endian_fmt + "H", data, 18)[0]
        # Common 64-bit architectures
        if e_machine in (EM_X86_64, EM_AARCH64):
            if ei_class != ELFCLASS64:
                anomalies.append({
                    "field": "EI_CLASS",
                    "issue": f"Architecture is 64-bit ({hex(e_machine)}) but EI_CLASS is {ei_class} (ELFCLASS32 / NONE)",
                    "severity": "Critical",
                    "fix": "Set EI_CLASS to ELFCLASS64 (2)",
                })
        elif e_machine in (EM_386, EM_ARM):
            if ei_class != ELFCLASS32:
                anomalies.append({
                    "field": "EI_CLASS",
                    "issue": f"Architecture is 32-bit ({hex(e_machine)}) but EI_CLASS is {ei_class} (ELFCLASS64)",
                    "severity": "Critical",
                    "fix": "Set EI_CLASS to ELFCLASS32 (1)",
                })

    # Version check
    if ei_version != EV_CURRENT:
        anomalies.append({
            "field": "EI_VERSION",
            "issue": f"Tampered EI_VERSION: {ei_version} (standard is EV_CURRENT=1)",
            "severity": "Medium",
            "fix": "Set EI_VERSION to 1",
        })

    if len(data) >= 24:
        e_version = struct.unpack_from(endian_fmt + "I", data, 20)[0]
        if e_version != EV_CURRENT:
            anomalies.append({
                "field": "e_version",
                "issue": f"Tampered e_version: {e_version} (standard is EV_CURRENT=1)",
                "severity": "Medium",
                "fix": "Set e_version to 1",
            })

    # Section Header Table offset sanity (very common anti-IDA trick in CTFs)
    is_64 = (ei_class == ELFCLASS64) or (len(data) >= 20 and struct.unpack_from(endian_fmt + "H", data, 18)[0] in (EM_X86_64, EM_AARCH64))
    if is_64 and len(data) >= 64:
        e_shoff = struct.unpack_from(endian_fmt + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(endian_fmt + "H", data, 58)[0]
        e_shnum = struct.unpack_from(endian_fmt + "H", data, 60)[0]
        if e_shoff > 0 and e_shoff + (e_shnum * e_shentsize) > len(data):
            anomalies.append({
                "field": "e_shoff",
                "issue": f"Tampered section header table offset {hex(e_shoff)} points beyond EOF ({len(data)} bytes)",
                "severity": "Critical",
                "fix": "Zero out e_shoff and e_shnum to force loader fallback to valid Program Headers",
            })
    elif not is_64 and len(data) >= 52:
        e_shoff = struct.unpack_from(endian_fmt + "I", data, 32)[0]
        e_shentsize = struct.unpack_from(endian_fmt + "H", data, 46)[0]
        e_shnum = struct.unpack_from(endian_fmt + "H", data, 48)[0]
        if e_shoff > 0 and e_shoff + (e_shnum * e_shentsize) > len(data):
            anomalies.append({
                "field": "e_shoff",
                "issue": f"Tampered section header table offset {hex(e_shoff)} points beyond EOF ({len(data)} bytes)",
                "severity": "Critical",
                "fix": "Zero out e_shoff and e_shnum to force loader fallback to valid Program Headers",
            })

    return anomalies


def repair_elf_header(data: bytes) -> Tuple[bytes, List[str]]:
    """
    Applies repairs to corrupted ELF headers and returns sanitized bytes and a log of fixes.
    """
    buf = bytearray(data)
    fixes = []

    if len(buf) < 52:
        return bytes(buf), ["File too small to repair"]

    # 1. Restore magic bytes if damaged
    if buf[:4] != b"\x7fELF":
        buf[0:4] = b"\x7fELF"
        fixes.append("Restored valid 0x7f 'E' 'L' 'F' magic header")

    # 2. Fix endianness if invalid
    if buf[EI_DATA] not in (ELFDATA2LSB, ELFDATA2MSB):
        buf[EI_DATA] = ELFDATA2LSB
        fixes.append("Normalized corrupted EI_DATA endianness to Little-Endian (ELFDATA2LSB)")

    endian_fmt = "<" if buf[EI_DATA] == ELFDATA2LSB else ">"

    # 3. Fix machine vs class mismatch
    e_machine = struct.unpack_from(endian_fmt + "H", buf, 18)[0]
    if e_machine in (EM_X86_64, EM_AARCH64) and buf[EI_CLASS] != ELFCLASS64:
        buf[EI_CLASS] = ELFCLASS64
        fixes.append(f"Corrected EI_CLASS to ELFCLASS64 (2) for 64-bit architecture ({hex(e_machine)})")
    elif e_machine in (EM_386, EM_ARM) and buf[EI_CLASS] != ELFCLASS32:
        buf[EI_CLASS] = ELFCLASS32
        fixes.append(f"Corrected EI_CLASS to ELFCLASS32 (1) for 32-bit architecture ({hex(e_machine)})")

    # 4. Fix EI_VERSION and e_version
    if buf[EI_VERSION] != EV_CURRENT:
        buf[EI_VERSION] = EV_CURRENT
        fixes.append("Corrected EI_VERSION to EV_CURRENT (1)")

    e_version = struct.unpack_from(endian_fmt + "I", buf, 20)[0]
    if e_version != EV_CURRENT:
        struct.pack_into(endian_fmt + "I", buf, 20, EV_CURRENT)
        fixes.append("Corrected e_version to EV_CURRENT (1)")

    # 5. Fix Section Header Table pointing beyond EOF
    is_64 = (buf[EI_CLASS] == ELFCLASS64)
    if is_64 and len(buf) >= 64:
        e_shoff = struct.unpack_from(endian_fmt + "Q", buf, 40)[0]
        e_shentsize = struct.unpack_from(endian_fmt + "H", buf, 58)[0]
        e_shnum = struct.unpack_from(endian_fmt + "H", buf, 60)[0]
        if e_shoff > 0 and e_shoff + (e_shnum * e_shentsize) > len(buf):
            struct.pack_into(endian_fmt + "Q", buf, 40, 0)
            struct.pack_into(endian_fmt + "H", buf, 60, 0)
            struct.pack_into(endian_fmt + "H", buf, 62, 0) # e_shstrndx = 0
            fixes.append(f"Zeroed out out-of-bounds e_shoff ({hex(e_shoff)}) and e_shnum to allow clean loader execution")
    elif not is_64 and len(buf) >= 52:
        e_shoff = struct.unpack_from(endian_fmt + "I", buf, 32)[0]
        e_shentsize = struct.unpack_from(endian_fmt + "H", buf, 46)[0]
        e_shnum = struct.unpack_from(endian_fmt + "H", buf, 48)[0]
        if e_shoff > 0 and e_shoff + (e_shnum * e_shentsize) > len(buf):
            struct.pack_into(endian_fmt + "I", buf, 32, 0)
            struct.pack_into(endian_fmt + "H", buf, 48, 0)
            struct.pack_into(endian_fmt + "H", buf, 50, 0)
            fixes.append(f"Zeroed out out-of-bounds e_shoff ({hex(e_shoff)}) and e_shnum to allow clean loader execution")

    return bytes(buf), fixes


def repair_elf_file(input_path: str, output_path: Optional[str] = None) -> Tuple[str, List[str]]:
    """Reads an ELF file from disk, applies header repairs, and writes the sanitized copy."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not output_path:
        base, ext = os.path.splitext(input_path)
        output_path = f"{base}_repaired{ext or '.elf'}"

    with open(input_path, "rb") as f:
        data = f.read()

    repaired_data, fixes = repair_elf_header(data)
    with open(output_path, "wb") as f:
        f.write(repaired_data)

    return output_path, fixes


# -----------------------------------------------------------------------------
# Interactive UI Dialog
# -----------------------------------------------------------------------------

class ELFHeaderRepairViewer(QtWidgets.QDialog):
    def __init__(self, file_path: str, data: bytes, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.data = data
        self.anomalies = detect_elf_header_anomalies(data)
        self.setWindowTitle("Genesect - ELF Header Tampering & Repair Utility")
        self.resize(760, 520)
        apply_mac_workspace(self)
        self._init_ui()

    def _init_ui(self):
        theme = current_theme()
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = PageHeader(
            title="ELF Header Tampering & Repair Utility",
            subtitle="Detects and rectifies anti-analysis / malformed ELF headers (EI_CLASS, EI_DATA, e_shoff)",
            badge="Binary Sanitizer",
            parent=self
        )
        layout.addWidget(header)

        # Status Summary Card
        status_card = Card(self)
        st_layout = QtWidgets.QHBoxLayout(status_card)
        st_layout.setContentsMargins(12, 10, 12, 10)

        if not self.anomalies:
            status_text = "✅ <b>Header Integrity Verified:</b> No anomalies or anti-analysis tampering detected."
            status_color = "#10b981"
        else:
            status_text = f"⚠️ <b>Tampering Detected:</b> Found {len(self.anomalies)} corrupted or anti-analysis header field(s)."
            status_color = "#ef4444"

        lbl = QtWidgets.QLabel(status_text)
        lbl.setStyleSheet(f"color: {status_color}; font-size: 13px;")
        st_layout.addWidget(lbl)
        layout.addWidget(status_card)

        # Anomalies Table
        table_card = Card(self)
        tbl_layout = QtWidgets.QVBoxLayout(table_card)
        tbl_layout.setContentsMargins(12, 10, 12, 10)

        self.table = QtWidgets.QTableWidget(table_card)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Field", "Severity", "Detected Anomaly", "Proposed Fix"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setRowCount(len(self.anomalies))

        for row, a in enumerate(self.anomalies):
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(a["field"]))
            sev_item = QtWidgets.QTableWidgetItem(a["severity"])
            if a["severity"] == "Critical":
                sev_item.setForeground(QtGui.QBrush(QtGui.QColor("#ef4444")))
            elif a["severity"] == "High":
                sev_item.setForeground(QtGui.QBrush(QtGui.QColor("#f59e0b")))
            self.table.setItem(row, 1, sev_item)
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(a["issue"]))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(a["fix"]))

        tbl_layout.addWidget(self.table)
        layout.addWidget(table_card)

        # Actions
        btn_box = QtWidgets.QHBoxLayout()
        btn_box.addStretch()

        if self.anomalies:
            self.repair_btn = QtWidgets.QPushButton("Repair & Export Sanitized ELF", self)
            self.repair_btn.setStyleSheet("background-color: #3b82f6; color: white; font-weight: bold; padding: 6px 14px;")
            self.repair_btn.clicked.connect(self._do_repair)
            btn_box.addWidget(self.repair_btn)

        close_btn = QtWidgets.QPushButton("Close", self)
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)

        layout.addLayout(btn_box)

    def _do_repair(self):
        try:
            suggested = os.path.splitext(self.file_path)[0] + "_repaired.elf"
            save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Save Sanitized Repaired ELF", suggested, "ELF Executables (*.elf *);;All Files (*.*)"
            )
            if not save_path:
                return

            out_path, fixes = repair_elf_file(self.file_path, save_path)
            QtWidgets.QMessageBox.information(
                self,
                "ELF Repaired Successfully",
                f"Saved repaired binary to:\n{out_path}\n\nApplied {len(fixes)} repair(s):\n- " + "\n- ".join(fixes)
            )
            self.accept()
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, "Repair Error", f"Failed to repair ELF file:\n{exc}")


# -----------------------------------------------------------------------------
# IDA Action Handler
# -----------------------------------------------------------------------------

class ELFHeaderRepairHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        if not idaapi:
            return 0
        try:
            input_path = ida_nalt.get_input_file_path()
            if not input_path or not os.path.exists(input_path):
                ida_kernwin.msg("[Genesect] Input ELF file path unavailable.\n")
                return 0

            with open(input_path, "rb") as f:
                data = f.read()

            dialog = ELFHeaderRepairViewer(input_path, data)
            dialog.exec_()
        except Exception as exc:
            ida_kernwin.msg(f"[Genesect] ELF Header Repair failed: {exc}\n")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0
