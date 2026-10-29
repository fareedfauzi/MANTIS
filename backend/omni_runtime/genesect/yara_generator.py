# -*- coding: utf-8 -*-
"""Interactive YARA Rule and Byte Pattern Generator for Genesect."""

from __future__ import annotations

import re
from typing import List, Optional

try:
    import ida_bytes
    import ida_kernwin
    import idaapi
    import idc
except ImportError:
    ida_bytes = None
    ida_kernwin = None
    idaapi = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.theme import current_theme
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.components import PageHeader, Card
from genesect.ui.typography import mono_font


MASK_MODE_RELOCS = "yara_mask"
MASK_MODE_NO_IMM = "yara_no_imm"
MASK_MODE_OPCODES = "yara_opcodes"
MASK_MODE_RAW = "yara_raw"


_CALL_OR_BRANCH_MNEMONICS = {
    "call", "callq", "jmp", "jmpq", "bl", "blx", "blr", "b",
    "jal", "jalr", "bal", "bctrl",
}


def _extract_bytes_for_copy(ea: int, mask_mode: Optional[str] = None) -> List[Optional[int]]:
    """Decode instruction at ea and return byte list with None for masked positions."""
    try:
        import ida_ua
    except ImportError:
        return []

    insn = ida_ua.insn_t()
    decoded = ida_ua.decode_insn(insn, ea)
    if isinstance(decoded, (int, float)) and decoded <= 0:
        return []
    if isinstance(getattr(insn, "size", None), (int, float)) and insn.size <= 0:
        return []
        return []

    if not ida_bytes:
        return []
    raw = ida_bytes.get_bytes(ea, insn.size)
    if raw is None or len(raw) != insn.size:
        return []

    mask = [False] * insn.size
    operands = [op for op in insn.ops if op.type != ida_ua.o_void and 0 < op.offb < insn.size]
    operand_offsets = sorted(set(op.offb for op in operands))

    def mask_operand(op):
        start = op.offb
        later = [offset for offset in operand_offsets if offset > start]
        end = min(later) if later else insn.size
        for index in range(start, end):
            mask[index] = True

    if mask_mode == "yara_mask":
        mnem = (idc.print_insn_mnem(ea) if idc else "").lower()
        if mnem in _CALL_OR_BRANCH_MNEMONICS and operands:
            mask_operand(operands[0])
        for op in operands:
            if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near, ida_ua.o_displ):
                mask_operand(op)
    elif mask_mode == "yara_no_imm":
        for op in operands:
            if op.type in (ida_ua.o_imm, ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near, ida_ua.o_displ):
                mask_operand(op)
    elif mask_mode == "yara_opcodes":
        first_offb = min(operand_offsets) if operand_offsets else insn.size
        for index in range(first_offb, insn.size):
            mask[index] = True

    res: List[Optional[int]] = []
    for i in range(insn.size):
        res.append(None if mask[i] else raw[i])
    return res


def build_masked_bytes(raw: bytes, start_ea: int, instructions: List[int], mask_mode: str) -> List[Optional[int]]:
    """Apply instruction-aware masking to a byte slice."""
    flat_bytes: List[Optional[int]] = list(raw)
    if mask_mode in (MASK_MODE_RELOCS, MASK_MODE_NO_IMM, MASK_MODE_OPCODES) and instructions:
        for ea in instructions:
            instruction = _extract_bytes_for_copy(ea, mask_mode=mask_mode)
            base = ea - start_ea
            for index, value in enumerate(instruction):
                if 0 <= base + index < len(flat_bytes):
                    flat_bytes[base + index] = value
    return flat_bytes


def build_hex_pattern_text(flat_bytes: List[Optional[int]]) -> str:
    """Format flat byte list into hex string with ?? wildcards."""
    hex_parts = ["??" if b is None else f"{b:02X}" for b in flat_bytes]
    return " ".join(hex_parts)


def build_yara_rule_text(
    rule_name: str,
    flat_bytes: List[Optional[int]],
    start_ea: int,
    string_id: str = "$sequence",
    include_meta: bool = True,
) -> str:
    """Construct a complete, valid YARA rule."""
    clean_name = re.sub(r"\W+", "_", rule_name).strip("_")
    if not clean_name or clean_name[0].isdigit():
        clean_name = f"rule_{clean_name}"
    
    clean_id = string_id.strip()
    if not clean_id.startswith("$"):
        clean_id = f"${clean_id}"

    pattern = build_hex_pattern_text(flat_bytes)
    
    meta_block = ""
    if include_meta:
        meta_block = f"""    meta:
        source = "Genesect"
        start_address = "0x{start_ea:X}"
        author = "Reverse Engineer"
"""

    return f"""rule {clean_name} {{
{meta_block}    strings:
        {clean_id} = {{ {pattern} }}

    condition:
        {clean_id}
}}"""


class YARAGeneratorDialog(QtWidgets.QDialog):
    """Interactive dialog for generating and previewing YARA rules and byte patterns."""

    def __init__(
        self,
        start_ea: int,
        end_ea: int,
        size: int,
        raw_bytes: bytes,
        instructions: List[int],
        parent=None,
    ):
        super().__init__(parent)
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.size = size
        self.raw_bytes = raw_bytes
        self.instructions = instructions

        self.setWindowTitle("Genesect - YARA & Byte Pattern Generator")
        self.resize(760, 620)
        apply_mac_workspace(self)
        self._init_ui()
        self.update_preview()

    def _init_ui(self):
        t = current_theme()

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        # Header
        header = PageHeader(
            "YARA & Byte Pattern Generator",
            "Generate resilient YARA rules and wildcarded hex signatures from selected code or data.",
        )
        layout.addWidget(header)

        # Range information card
        info_card = Card("Selection Scope")
        info_row = QtWidgets.QHBoxLayout()
        insn_count = len(self.instructions)
        insn_text = f" • {insn_count} decoded instructions" if insn_count > 0 else " • raw data block"
        self.scope_label = QtWidgets.QLabel(
            f"<b>Range:</b> 0x{self.start_ea:X} - 0x{self.end_ea:X} (<b>{self.size}</b> bytes{insn_text})"
        )
        self.scope_label.setStyleSheet(f"color: {t.text_muted};")
        info_row.addWidget(self.scope_label, 1)
        info_card.add_layout(info_row)
        layout.addWidget(info_card)

        # Configuration options card
        config_card = Card("Pattern & Rule Configuration")
        form = QtWidgets.QFormLayout()
        form.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)
        form.setSpacing(8)

        # Rule Name default
        base_name = f"sub_{self.start_ea:X}"
        if idc and hasattr(idc, "get_func_name"):
            func_name = idc.get_func_name(self.start_ea)
            if func_name:
                base_name = func_name
        rule_default = re.sub(r"\W+", "_", f"genesect_{base_name}_{self.start_ea:X}").strip("_")[:96]
        
        self.rule_name_edit = QtWidgets.QLineEdit(rule_default)
        self.rule_name_edit.textChanged.connect(self.update_preview)
        form.addRow("Rule Identifier:", self.rule_name_edit)

        self.string_id_edit = QtWidgets.QLineEdit("$sequence")
        self.string_id_edit.textChanged.connect(self.update_preview)
        form.addRow("String Identifier:", self.string_id_edit)

        # Masking mode radio buttons
        mask_box = QtWidgets.QVBoxLayout()
        self.radio_relocs = QtWidgets.QRadioButton("Mask Relocations && Jumps (Recommended)")
        self.radio_relocs.setToolTip("Wildcards target addresses, branches, calls, and memory displacements (e.g. E8 ?? ?? ?? ??).")
        self.radio_relocs.setChecked(True)
        self.radio_relocs.toggled.connect(self.update_preview)
        mask_box.addWidget(self.radio_relocs)

        self.radio_no_imm = QtWidgets.QRadioButton("Mask Immediates && Addresses")
        self.radio_no_imm.setToolTip("Wildcards immediate constants, memory targets, and call/branch operands.")
        self.radio_no_imm.toggled.connect(self.update_preview)
        mask_box.addWidget(self.radio_no_imm)

        self.radio_opcodes = QtWidgets.QRadioButton("Opcodes Only (Most Permissive)")
        self.radio_opcodes.setToolTip("Wildcards everything except instruction opcodes.")
        self.radio_opcodes.toggled.connect(self.update_preview)
        mask_box.addWidget(self.radio_opcodes)

        self.radio_raw = QtWidgets.QRadioButton("Exact Raw Bytes (No Wildcards)")
        self.radio_raw.setToolTip("Exact byte sequence match without any wildcards.")
        self.radio_raw.toggled.connect(self.update_preview)
        mask_box.addWidget(self.radio_raw)

        form.addRow("Wildcarding Mode:", mask_box)
        config_card.add_layout(form)
        layout.addWidget(config_card)

        # Preview Card
        preview_card = Card("Output Preview")
        preview_layout = QtWidgets.QVBoxLayout()

        view_mode_row = QtWidgets.QHBoxLayout()
        self.view_yara_radio = QtWidgets.QRadioButton("YARA Rule Format")
        self.view_yara_radio.setChecked(True)
        self.view_yara_radio.toggled.connect(self.update_preview)
        view_mode_row.addWidget(self.view_yara_radio)

        self.view_hex_radio = QtWidgets.QRadioButton("Raw Hex Pattern Only")
        self.view_hex_radio.toggled.connect(self.update_preview)
        view_mode_row.addWidget(self.view_hex_radio)
        view_mode_row.addStretch()

        self.stats_badge = QtWidgets.QLabel("")
        self.stats_badge.setStyleSheet(f"font-weight: 600; color: {t.accent};")
        view_mode_row.addWidget(self.stats_badge)
        preview_layout.addLayout(view_mode_row)

        self.preview_edit = QtWidgets.QPlainTextEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setFont(mono_font(10))
        self.preview_edit.setStyleSheet(
            f"background-color: {t.code_background}; "
            f"color: {t.text}; "
            f"border: 1px solid {t.border}; "
            "border-radius: 6px; padding: 6px;"
        )
        preview_layout.addWidget(self.preview_edit, 1)
        preview_card.add_layout(preview_layout)
        layout.addWidget(preview_card, 1)

        # Bottom Action Buttons
        btn_row = QtWidgets.QHBoxLayout()
        
        self.copy_rule_btn = QtWidgets.QPushButton("Copy YARA Rule")
        self.copy_rule_btn.setProperty("pnVariant", "primary")
        self.copy_rule_btn.clicked.connect(self.copy_yara_rule)
        btn_row.addWidget(self.copy_rule_btn)

        self.copy_hex_btn = QtWidgets.QPushButton("Copy Hex Pattern")
        self.copy_hex_btn.clicked.connect(self.copy_hex_pattern)
        btn_row.addWidget(self.copy_hex_btn)

        btn_row.addStretch()

        self.close_btn = QtWidgets.QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        btn_row.addWidget(self.close_btn)

        layout.addLayout(btn_row)

    def _selected_mask_mode(self) -> str:
        if self.radio_no_imm.isChecked():
            return MASK_MODE_NO_IMM
        if self.radio_opcodes.isChecked():
            return MASK_MODE_OPCODES
        if self.radio_raw.isChecked():
            return MASK_MODE_RAW
        return MASK_MODE_RELOCS

    def get_flat_bytes(self) -> List[Optional[int]]:
        mask_mode = self._selected_mask_mode()
        return build_masked_bytes(self.raw_bytes, self.start_ea, self.instructions, mask_mode)

    def update_preview(self):
        flat_bytes = self.get_flat_bytes()
        total_len = len(flat_bytes)
        concrete_count = sum(b is not None for b in flat_bytes)
        wildcard_count = total_len - concrete_count

        self.stats_badge.setText(
            f"{total_len} total bytes • {concrete_count} concrete • {wildcard_count} wildcarded (??)"
        )

        if self.view_yara_radio.isChecked():
            rule_name = self.rule_name_edit.text() or "genesect_rule"
            string_id = self.string_id_edit.text() or "$sequence"
            text = build_yara_rule_text(rule_name, flat_bytes, self.start_ea, string_id=string_id)
        else:
            text = build_hex_pattern_text(flat_bytes)

        self.preview_edit.setPlainText(text)

    def copy_yara_rule(self):
        flat_bytes = self.get_flat_bytes()
        concrete = sum(b is not None for b in flat_bytes)
        if concrete < 4:
            if ida_kernwin:
                ida_kernwin.warning("A useful YARA rule requires at least four stable, unmasked bytes.")
            return

        rule_name = self.rule_name_edit.text() or "genesect_rule"
        string_id = self.string_id_edit.text() or "$sequence"
        rule_text = build_yara_rule_text(rule_name, flat_bytes, self.start_ea, string_id=string_id)

        QtWidgets.QApplication.clipboard().setText(rule_text)
        from genesect.handlers import _report_full_copied_output
        _report_full_copied_output(rule_text)
        self.accept()

    def copy_hex_pattern(self):
        flat_bytes = self.get_flat_bytes()
        pattern_text = build_hex_pattern_text(flat_bytes)

        QtWidgets.QApplication.clipboard().setText(pattern_text)
        from genesect.handlers import _report_full_copied_output
        _report_full_copied_output(pattern_text)
        self.accept()


def show_yara_generator_dialog(start_ea: int, end_ea: int, size: int, raw_bytes: bytes, instructions: List[int]):
    """Launch the YARA & Byte Pattern Generator dialog."""
    parent = None
    if ida_kernwin and hasattr(ida_kernwin, "get_main_widget"):
        main_widget = ida_kernwin.get_main_widget()
        if main_widget:
            parent = ida_kernwin.PluginForm.FormToPyQtWidget(main_widget)
    
    dialog = YARAGeneratorDialog(
        start_ea=start_ea,
        end_ea=end_ea,
        size=size,
        raw_bytes=raw_bytes,
        instructions=instructions,
        parent=parent,
    )
    dialog.exec_()
