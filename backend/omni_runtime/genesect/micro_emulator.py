# -*- coding: utf-8 -*-
"""
Genesect In-DB Micro-Emulation & Interactive CPU Debugger Engine.

Combines capabilities from ida-unicall, flare-emu, emuit, and uEmu:
1. Tier 1: In-Pseudocode Function Call Emulation (AST ctree + backward slicing -> Unicorn execution -> 1-click comment/rename)
2. Tier 1: Batch Xref Decryptor (iterates all callers of a decrypter routine across the entire IDB)
3. Tier 2: Interactive Micro-Emulator Widget (step-into, step-over, run-to-cursor, live registers, stack, memory tracking)
"""

from typing import Dict, List, Optional, Tuple, Any, Set
import csv
import io
import os
import re

try:
    import unicorn
    from unicorn import (
        Uc,
        UC_ARCH_X86,
        UC_MODE_32,
        UC_MODE_64,
        UC_HOOK_CODE,
        UC_HOOK_MEM_UNMAPPED,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_WRITE,
        UC_PROT_ALL,
        UC_PROT_READ,
        UC_PROT_WRITE,
        UC_PROT_EXEC,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
        UC_X86_REG_EIP,
    )
    UNICORN_AVAILABLE = True
except ImportError:
    unicorn = None
    UNICORN_AVAILABLE = False

try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_ua
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_hexrays = None
    ida_ida = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None
    ida_ua = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


_call_emu_instance = None
_batch_emu_instance = None
_micro_emu_instance = None

PAGE_SIZE = 4096
DEFAULT_MAX_INSTR = 50000


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


def _is_64bit() -> bool:
    if ida_ida and hasattr(ida_ida, "inf_is_64bit"):
        return bool(ida_ida.inf_is_64bit())
    return True


class UnicornEngine:
    """Wrapper managing Unicorn instance, IDB memory paging, and calling conventions."""

    def __init__(self, is_64bit: Optional[bool] = None, stack_size: int = 0x80000):
        if not UNICORN_AVAILABLE:
            raise RuntimeError("Unicorn Engine is not installed or available in this Python environment.")

        self.is_64 = _is_64bit() if is_64bit is None else bool(is_64bit)
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_64 if self.is_64 else UC_MODE_32
        self.uc = Uc(self.arch, self.mode)

        self.stack_size = stack_size
        self.stack_base = 0x7FFF00000000 if self.is_64 else 0x70000000
        self.stack_top = self.stack_base + self.stack_size - 0x1000

        self.mapped_pages: Set[int] = set()
        self.written_addrs: Set[int] = set()
        self.instr_count = 0
        self.max_instr = DEFAULT_MAX_INSTR
        self.stop_requested = False

        self._setup_hooks()
        self._setup_stack()

    def _setup_hooks(self):
        # Auto-map unmapped reads and writes on demand (like EmuIt)
        hook_type = UC_HOOK_MEM_UNMAPPED if "UC_HOOK_MEM_UNMAPPED" in globals() and UC_HOOK_MEM_UNMAPPED else (UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED)
        self.uc.hook_add(hook_type, self._hook_unmapped_memory)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code_exec)

    def _setup_stack(self):
        self.map_memory(self.stack_base, self.stack_size)
        sp_reg = UC_X86_REG_RSP if self.is_64 else UC_X86_REG_ESP
        self.uc.reg_write(sp_reg, self.stack_top)

    def setup_stack(self):
        self._setup_stack()

    @property
    def mem_writes(self) -> Set[int]:
        return self.written_addrs

    def write_buffer(self, address: int, data: bytes) -> bool:
        self.map_memory(address, len(data))
        try:
            self.uc.mem_write(address, data)
            return True
        except Exception:
            return False

    def _reg_name_to_id(self, name: str) -> Optional[int]:
        upper = name.upper()
        if self.is_64:
            reg_map = {
                "RAX": UC_X86_REG_RAX, "RBX": UC_X86_REG_RBX, "RCX": UC_X86_REG_RCX, "RDX": UC_X86_REG_RDX,
                "RSI": UC_X86_REG_RSI, "RDI": UC_X86_REG_RDI, "RBP": UC_X86_REG_RBP, "RSP": UC_X86_REG_RSP,
                "RIP": UC_X86_REG_RIP, "EFLAGS": UC_X86_REG_EFLAGS,
                "EAX": UC_X86_REG_EAX, "EBX": UC_X86_REG_EBX, "ECX": UC_X86_REG_ECX, "EDX": UC_X86_REG_EDX,
            }
            for i in range(8, 16):
                reg_map["R%d" % i] = getattr(unicorn.x86_const, "UC_X86_REG_R%d" % i)
        else:
            reg_map = {
                "EAX": UC_X86_REG_EAX, "EBX": UC_X86_REG_EBX, "ECX": UC_X86_REG_ECX, "EDX": UC_X86_REG_EDX,
                "ESI": UC_X86_REG_ESI, "EDI": UC_X86_REG_EDI, "EBP": UC_X86_REG_EBP, "ESP": UC_X86_REG_ESP,
                "EIP": UC_X86_REG_EIP, "EFLAGS": UC_X86_REG_EFLAGS,
            }
        return reg_map.get(upper)

    def set_register(self, name: str, value: int):
        rid = self._reg_name_to_id(name)
        if rid is not None:
            self.uc.reg_write(rid, int(value))

    def get_register(self, name: str) -> int:
        rid = self._reg_name_to_id(name)
        return self.uc.reg_read(rid) if rid is not None else 0

    def step(self) -> Tuple[bool, str]:
        ip_name = "RIP" if self.is_64 else "EIP"
        cur_ip = self.get_register(ip_name)
        try:
            self.uc.emu_start(cur_ip, 0, count=1)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def emulate(self, start_ea: int, end_ea: int, max_instructions: Optional[int] = None) -> Tuple[bool, str]:
        if max_instructions:
            self.max_instr = max_instructions
        self.instr_count = 0
        self.stop_requested = False
        try:
            self.uc.emu_start(start_ea, end_ea, count=self.max_instr)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def _hook_unmapped_memory(self, uc, access, address, size, value, user_data):
        page = address & ~(PAGE_SIZE - 1)
        needed_size = ((size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) or PAGE_SIZE
        try:
            self.map_memory(page, needed_size)
            # If the address is within the IDA database, copy bytes
            if ida_bytes and hasattr(ida_bytes, "is_loaded") and ida_bytes.is_loaded(address):
                data = ida_bytes.get_bytes(page, needed_size) or b"\x00" * needed_size
                uc.mem_write(page, data)
            return True
        except Exception:
            return False

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        for off in range(size):
            self.written_addrs.add(address + off)

    def _hook_code_exec(self, uc, address, size, user_data):
        self.instr_count += 1
        if self.instr_count >= self.max_instr or self.stop_requested:
            uc.emu_stop()

    def map_memory(self, address: int, size: int, is_exec: bool = True, prot: int = UC_PROT_ALL) -> bool:
        start_page = address & ~(PAGE_SIZE - 1)
        end_page = (address + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        cur = start_page
        while cur < end_page:
            if cur not in self.mapped_pages:
                try:
                    self.uc.mem_map(cur, PAGE_SIZE, UC_PROT_ALL)
                    self.mapped_pages.add(cur)
                except Exception:
                    pass
            cur += PAGE_SIZE
        return True

    def load_idb_segment(self, ea: int) -> bool:
        """Map and load the IDA segment containing ea."""
        if not ida_segment or not ida_bytes:
            return False
        seg = ida_segment.getseg(ea)
        if not seg:
            return False
        start = seg.start_ea
        end = seg.end_ea
        size = end - start
        self.map_memory(start, size)
        data = ida_bytes.get_bytes(start, size)
        if data:
            self.uc.mem_write(start, data)
        return True

    def setup_call(self, func_ea: int, args: List[Any], ret_ea: int = 0xDEADBEEF0000):
        """Set up registers, stack, and shadow space according to platform ABI."""
        self.load_idb_segment(func_ea)
        sp_reg = UC_X86_REG_RSP if self.is_64 else UC_X86_REG_ESP
        cur_sp = self.stack_top

        # Pushed return address (signals completion)
        if not self.is_64:
            ret_ea = ret_ea & 0xFFFFFFFF
            ret_bytes = int(ret_ea).to_bytes(4, "little")
            # x86: cdecl/stdcall args pushed right-to-left
            for arg_val in reversed(args):
                cur_sp -= 4
                self.uc.mem_write(cur_sp, int(arg_val & 0xFFFFFFFF).to_bytes(4, "little"))
            cur_sp -= 4
            self.uc.mem_write(cur_sp, ret_bytes)
            self.uc.reg_write(sp_reg, cur_sp)
            self.uc.reg_write(UC_X86_REG_EIP, func_ea)
        else:
            # x64 Windows ABI: RCX, RDX, R8, R9, then stack at [RSP + 0x20]
            regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
            for i, arg in enumerate(args):
                val = int(arg) & 0xFFFFFFFFFFFFFFFF
                if i < 4:
                    self.uc.reg_write(regs[i], val)
                else:
                    stack_offset = cur_sp - 0x28 - ((i - 4) * 8)
                    self.uc.mem_write(stack_offset, val.to_bytes(8, "little"))

            # 32-byte shadow space + return address
            cur_sp -= 0x28
            self.uc.mem_write(cur_sp, int(ret_ea).to_bytes(8, "little"))
            self.uc.reg_write(sp_reg, cur_sp)
            self.uc.reg_write(UC_X86_REG_RIP, func_ea)

    def run(self, start_ea: int, end_ea: int, timeout_ms: int = 2000) -> bool:
        self.instr_count = 0
        self.stop_requested = False
        try:
            self.uc.emu_start(start_ea, end_ea, timeout=timeout_ms * 1000, count=self.max_instr)
            return True
        except Exception:
            return False

    def read_return_val(self) -> int:
        reg = UC_X86_REG_RAX if self.is_64 else UC_X86_REG_EAX
        return self.uc.reg_read(reg)

    def read_string(self, addr: int, max_len: int = 512) -> str:
        if not addr or addr == (0xFFFFFFFFFFFFFFFF if self.is_64 else 0xFFFFFFFF):
            return ""
        try:
            raw = self.uc.mem_read(addr, max_len)
            # Try ASCII
            null_pos = raw.find(b"\x00")
            if null_pos != -1:
                raw_ascii = raw[:null_pos]
            else:
                raw_ascii = raw[:64]
            if all(0x20 <= b <= 0x7E or b in (9, 10, 13) for b in raw_ascii) and len(raw_ascii) >= 1:
                return raw_ascii.decode("latin1", errors="replace")

            # Try UTF-16LE
            null2 = raw.find(b"\x00\x00")
            if null2 != -1 and null2 % 2 == 0:
                raw_wide = raw[:null2]
            else:
                raw_wide = raw[:64]
            decoded_wide = raw_wide.decode("utf-16le", errors="ignore")
            if len(decoded_wide) >= 1 and all(0x20 <= ord(c) <= 0x7E for c in decoded_wide):
                return decoded_wide
        except Exception:
            pass
        return ""

    def read_buffer(self, addr: int, size: int) -> bytes:
        try:
            return bytes(self.uc.mem_read(addr, size))
        except Exception:
            return b""


def extract_call_site_args(call_ea: int, func_ea: Optional[int] = None) -> List[Dict[str, Any]]:
    """Extract call arguments via Hex-Rays ctree AST or backward instruction slicing."""
    args = []
    if not call_ea:
        return args

    is_64 = _is_64bit()

    # 1. Try Hex-Rays AST extraction if available
    if ida_hexrays and hasattr(ida_hexrays, "decompile"):
        try:
            cfunc = ida_hexrays.decompile(func_ea or call_ea)
            if cfunc:
                # Visitor to locate the exact cot_call at call_ea
                class CallVisitor(ida_hexrays.ctree_visitor_t):
                    def __init__(self, target_ea):
                        super().__init__(ida_hexrays.CV_FAST)
                        self.target_ea = target_ea
                        self.found_call = None

                    def visit_expr(self, expr):
                        if expr.op == ida_hexrays.cot_call:
                            if expr.ea == self.target_ea or (abs(expr.ea - self.target_ea) < 16):
                                self.found_call = expr
                                return 1
                        return 0

                vis = CallVisitor(call_ea)
                vis.apply_to(cfunc.body, None)
                if vis.found_call:
                    call_expr = vis.found_call
                    cargs = call_expr.a
                    for idx, carg in enumerate(cargs):
                        arg_info = {
                            "index": idx,
                            "type": "imm",
                            "value": 0,
                            "raw_text": "",
                            "preview": "",
                        }
                        if carg.op == ida_hexrays.cot_num:
                            arg_info["value"] = carg.numval()
                            arg_info["raw_text"] = "0x%X" % carg.numval()
                        elif carg.op in (ida_hexrays.cot_obj, ida_hexrays.cot_ref):
                            obj_ea = carg.obj_ea
                            arg_info["value"] = obj_ea
                            arg_info["type"] = "pointer"
                            arg_info["raw_text"] = "&0x%X" % obj_ea
                            # Preview string if in IDB
                            if ida_bytes:
                                s = ida_bytes.get_strlit_contents(obj_ea, -1, 0)
                                if s:
                                    arg_info["preview"] = str(s, "latin1", errors="replace")
                        elif carg.op == ida_hexrays.cot_str:
                            arg_info["type"] = "string"
                            arg_info["raw_text"] = carg.string
                            arg_info["preview"] = carg.string
                        elif carg.op == ida_hexrays.cot_var:
                            arg_info["type"] = "stack_var"
                            arg_info["raw_text"] = "lvar_%d" % carg.v.idx

                        args.append(arg_info)
                    if args:
                        return args
        except Exception:
            pass

    # 2. Backward assembly register slicing fallback
    if idautils and idc and ida_ua:
        reg_names_64 = ["rcx", "rdx", "r8", "r9"]
        reg_names_32 = ["ecx", "edx"]
        expected_regs = reg_names_64 if is_64 else reg_names_32

        found_map = {}
        cur = call_ea
        for _ in range(16):
            cur = idc.prev_head(cur) if idc else cur - 1
            if not cur or cur == idc.BADADDR:
                break
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur) <= 0:
                continue

            mnem = (idc.print_insn_mnem(cur) if idc else "").lower()
            if mnem in ("mov", "lea", "xor"):
                reg_dst = (idc.print_operand(cur, 0) if idc else "").lower()
                for r_idx, r_name in enumerate(expected_regs):
                    if r_name in reg_dst and r_idx not in found_map:
                        op1 = insn.ops[1]
                        val = 0
                        t = "imm"
                        if op1.type == getattr(ida_ua, "o_imm", 5):
                            val = op1.value
                        elif op1.type in (getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_displ", 4)):
                            val = op1.addr
                            t = "pointer"
                        elif mnem == "xor" and (idc.print_operand(cur, 1) if idc else "").lower() == reg_dst:
                            val = 0

                        found_map[r_idx] = {
                            "index": r_idx,
                            "type": t,
                            "value": val,
                            "raw_text": (idc.print_operand(cur, 1) if idc else "0x%X" % val),
                            "preview": "",
                        }
            elif not is_64 and mnem == "push":
                # Stack argument
                idx = len(found_map)
                op0 = insn.ops[0]
                val = op0.value if op0.type == getattr(ida_ua, "o_imm", 5) else op0.addr
                found_map[idx] = {
                    "index": idx,
                    "type": "imm",
                    "value": val,
                    "raw_text": "0x%X" % val,
                    "preview": "",
                }

        for i in sorted(found_map.keys()):
            args.append(found_map[i])

    return args


def emulate_function_call(
    func_ea: int,
    args: List[int],
    output_buf_size: int = 512,
    max_instr: int = DEFAULT_MAX_INSTR,
) -> Dict[str, Any]:
    """Headless execution helper using Unicorn to run func_ea with arguments."""
    is_64 = _is_64bit()
    ret_ea = 0xDEADBEEF0000 if is_64 else 0xDEADBEEF

    emu = UnicornEngine(is_64bit=is_64)
    emu.max_instr = max_instr

    # Set up memory buffer for pointer arguments
    buf_addr = 0x10000000 if not is_64 else 0x140000000
    emu.map_memory(buf_addr, 0x10000)

    # Process arguments: if an arg is marked as output buffer or pointer, assign memory
    actual_args = []
    for arg in args:
        actual_args.append(int(arg))

    emu.setup_call(func_ea, actual_args, ret_ea=ret_ea)
    success = emu.run(func_ea, ret_ea)

    ret_val = emu.read_return_val()
    ret_str = emu.read_string(ret_val)

    # Inspect written memory buffers to find decrypted payloads
    discovered_strings = []
    for w_addr in sorted(emu.written_addrs):
        s = emu.read_string(w_addr)
        if s and len(s) >= 2 and s not in discovered_strings:
            discovered_strings.append(s)

    primary_str = ret_str or (discovered_strings[0] if discovered_strings else "")

    return {
        "success": success,
        "return_value": ret_val,
        "return_hex": "0x%X" % ret_val,
        "primary_string": primary_str,
        "discovered_strings": discovered_strings,
        "instructions_executed": emu.instr_count,
        "written_bytes_count": len(emu.written_addrs),
    }


class CallEmulationDialog(QtWidgets.QDialog):
    """Interactive in-pseudocode call emulator dialog (ida-unicall style)."""

    def __init__(self, call_ea: int, func_ea: int, parent=None):
        super(CallEmulationDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - Emulate Call & Decrypt String")
        self.resize(780, 560)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.call_ea = call_ea
        self.func_ea = func_ea
        self.extracted_args = []
        self.last_result = None

        self._setup_ui()
        self._load_call_data()

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{ background: {t.window}; color: {t.text}; }}
            QLineEdit, QSpinBox, QTableWidget {{
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
                padding: 4px;
                font-weight: 700;
                border: none;
                border-bottom: 1px solid {t.border};
            }}
            QTextEdit {{
                background: {t.surface};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                font-family: monospace;
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        header = PageHeader(
            "Emulate Function Call",
            "In-place emulation of target function via Unicorn: pre-fills ctree parameters and inspects decrypted buffers."
        )
        root.addWidget(header)

        # Call info card
        card_info = Card()
        l_info = QtWidgets.QGridLayout(card_info)
        l_info.setContentsMargins(12, 10, 12, 10)

        l_info.addWidget(QtWidgets.QLabel("Target Function:"), 0, 0)
        self.lbl_target = QtWidgets.QLabel(_hex(self.func_ea))
        self.lbl_target.setStyleSheet(f"font-weight: 700; color: {t.accent};")
        l_info.addWidget(self.lbl_target, 0, 1)

        l_info.addWidget(QtWidgets.QLabel("Call Site EA:"), 1, 0)
        self.lbl_call_site = QtWidgets.QLabel(_hex(self.call_ea))
        l_info.addWidget(self.lbl_call_site, 1, 1)

        root.addWidget(card_info)

        # Arguments Table
        root.addWidget(QtWidgets.QLabel("Call Arguments (Auto-Extracted from AST):"))
        self.tbl_args = QtWidgets.QTableWidget(0, 4)
        self.tbl_args.setHorizontalHeaderLabels(["Arg #", "Type", "Raw Code Expression", "Value (Hex/Int/Buffer)"])
        self.tbl_args.horizontalHeader().setStretchLastSection(True)
        self.tbl_args.verticalHeader().setVisible(False)
        root.addWidget(self.tbl_args, 1)

        # Output / Results Box
        root.addWidget(QtWidgets.QLabel("Emulation Output & Decrypted Result:"))
        self.txt_output = QtWidgets.QTextEdit()
        self.txt_output.setReadOnly(True)
        self.txt_output.setPlaceholderText("Click 'Run Emulation' to execute with Unicorn and view decrypted payload...")
        root.addWidget(self.txt_output, 1)

        # Action Buttons
        btn_bar = QtWidgets.QHBoxLayout()
        btn_run = QtWidgets.QPushButton("Run Emulation (F5)")
        btn_run.setProperty("pnVariant", "primary")
        btn_run.clicked.connect(self._run_emulation)
        btn_bar.addWidget(btn_run)

        self.btn_comment = QtWidgets.QPushButton("Write Comment at Call Site")
        self.btn_comment.setEnabled(False)
        self.btn_comment.clicked.connect(self._apply_comment)
        btn_bar.addWidget(self.btn_comment)

        btn_bar.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        btn_bar.addWidget(btn_close)

        root.addLayout(btn_bar)

    def _load_call_data(self):
        f_name = (idc.get_func_name(self.func_ea) if idc else "") or ("sub_%X" % self.func_ea)
        self.lbl_target.setText("%s (%s)" % (f_name, _hex(self.func_ea)))

        self.extracted_args = extract_call_site_args(self.call_ea, self.func_ea)
        self.tbl_args.setRowCount(len(self.extracted_args))
        for r, arg in enumerate(self.extracted_args):
            it_idx = QtWidgets.QTableWidgetItem(str(arg["index"]))
            it_type = QtWidgets.QTableWidgetItem(arg["type"])
            it_raw = QtWidgets.QTableWidgetItem(arg["raw_text"])
            it_val = QtWidgets.QTableWidgetItem("0x%X" % arg["value"])

            it_idx.setFlags(QtCore.Qt.ItemIsEnabled)
            it_type.setFlags(QtCore.Qt.ItemIsEnabled)
            it_raw.setFlags(QtCore.Qt.ItemIsEnabled)

            self.tbl_args.setItem(r, 0, it_idx)
            self.tbl_args.setItem(r, 1, it_type)
            self.tbl_args.setItem(r, 2, it_raw)
            self.tbl_args.setItem(r, 3, it_val)

    def _run_emulation(self):
        # Gather user-specified or modified arguments from table
        arg_vals = []
        for r in range(self.tbl_args.rowCount()):
            it = self.tbl_args.item(r, 3)
            val_txt = it.text().strip() if it else "0"
            try:
                val = int(val_txt, 0)
            except ValueError:
                val = 0
            arg_vals.append(val)

        res = emulate_function_call(self.func_ea, arg_vals)
        self.last_result = res

        lines = [
            "=== UNICORN EMULATION COMPLETE ===",
            "Execution Success: %s" % res["success"],
            "Instructions Executed: %d" % res["instructions_executed"],
            "Return Value (RAX/EAX): %s" % res["return_hex"],
            "",
            "Decrypted String Output: %s" % (res["primary_string"] or "<none>"),
        ]
        if res["discovered_strings"]:
            lines.append("")
            lines.append("Discovered Memory Strings:")
            for s in res["discovered_strings"]:
                lines.append("  * %s" % s)

        self.txt_output.setPlainText("\n".join(lines))
        self.btn_comment.setEnabled(bool(res["primary_string"]))

    def _apply_comment(self):
        if not self.last_result or not self.last_result.get("primary_string"):
            return
        cmt = "Decrypted: \"%s\"" % self.last_result["primary_string"]
        if idc and hasattr(idc, "set_cmt"):
            idc.set_cmt(self.call_ea, cmt, 0)
            if hasattr(ida_hexrays, "mark_cfunc_dirty"):
                ida_hexrays.mark_cfunc_dirty(self.call_ea)
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info("Comment applied to call site %s:\n%s" % (_hex(self.call_ea), cmt))


class BatchDecryptorDialog(QtWidgets.QDialog):
    """Batch decrypter emulator iterating all xrefs across the IDB (flare-emu style)."""

    def __init__(self, func_ea: int, parent=None):
        super(BatchDecryptorDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - Batch Decrypter Call Emulation")
        self.resize(1080, 640)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.func_ea = func_ea
        self.results = []

        self._setup_ui()
        QtCore.QTimer.singleShot(0, self.refresh_all)

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{ background: {t.window}; color: {t.text}; }}
            QTableWidget {{
                background: {t.surface};
                color: {t.text};
                gridline-color: {t.border};
                border: 1px solid {t.border};
                border-radius: 6px;
            }}
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

        f_name = (idc.get_func_name(self.func_ea) if idc else "") or ("sub_%X" % self.func_ea)
        header = PageHeader(
            "Batch Xref Decryptor: %s" % f_name,
            "Automatically resolves arguments at all call sites, emulates with Unicorn, and writes comments across IDB."
        )

        btn_run = QtWidgets.QPushButton("Emulate All Calls")
        btn_run.setProperty("pnVariant", "primary")
        btn_run.clicked.connect(self._run_all)
        header.add_action(btn_run)

        btn_annotate = QtWidgets.QPushButton("Apply All Comments to IDB")
        btn_annotate.clicked.connect(self._apply_all_comments)
        header.add_action(btn_annotate)

        btn_export = QtWidgets.QPushButton("Export CSV")
        btn_export.clicked.connect(self._export_csv)
        header.add_action(btn_export)

        root.addWidget(header)

        self.tbl = QtWidgets.QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(["Call Site EA", "Calling Function", "Extracted Arguments", "Decrypted String Output", "Status"])
        self.tbl.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.itemDoubleClicked.connect(self._jump_item)
        root.addWidget(self.tbl, 1)

        bottom = QtWidgets.QHBoxLayout()
        self.status_lbl = QtWidgets.QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color: {t.text_muted};")
        bottom.addWidget(self.status_lbl)
        bottom.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)
        root.addLayout(bottom)

    def refresh_all(self):
        self.results = []
        if idautils:
            for xref in idautils.XrefsTo(self.func_ea, 0):
                call_ea = xref.frm
                caller = (idc.get_func_name(call_ea) if idc else "") or ("sub_%X" % call_ea)
                raw_args = extract_call_site_args(call_ea, self.func_ea)
                args_desc = ", ".join(a["raw_text"] for a in raw_args) if raw_args else "None"
                self.results.append({
                    "call_ea": call_ea,
                    "caller": caller,
                    "args": raw_args,
                    "args_desc": args_desc,
                    "decrypted": "",
                    "status": "Pending",
                })

        self.tbl.setRowCount(len(self.results))
        for r, res in enumerate(self.results):
            it_ea = QtWidgets.QTableWidgetItem(_hex(res["call_ea"]))
            it_ea.setData(QtCore.Qt.UserRole, int(res["call_ea"]))
            self.tbl.setItem(r, 0, it_ea)
            self.tbl.setItem(r, 1, QtWidgets.QTableWidgetItem(res["caller"]))
            self.tbl.setItem(r, 2, QtWidgets.QTableWidgetItem(res["args_desc"]))
            self.tbl.setItem(r, 3, QtWidgets.QTableWidgetItem(""))
            self.tbl.setItem(r, 4, QtWidgets.QTableWidgetItem("Pending"))

        self.status_lbl.setText("Found %d call sites to %s." % (len(self.results), _hex(self.func_ea)))

    def _run_all(self):
        for r, res in enumerate(self.results):
            args_list = [a["value"] for a in res["args"]]
            emu_res = emulate_function_call(self.func_ea, args_list)
            res["decrypted"] = emu_res["primary_string"]
            res["status"] = "Success" if emu_res["primary_string"] else "Completed (No String)"

            self.tbl.setItem(r, 3, QtWidgets.QTableWidgetItem(res["decrypted"]))
            self.tbl.setItem(r, 4, QtWidgets.QTableWidgetItem(res["status"]))

        self.status_lbl.setText("Emulated %d calls." % len(self.results))

    def _apply_all_comments(self):
        applied = 0
        for res in self.results:
            if res.get("decrypted") and idc and hasattr(idc, "set_cmt"):
                cmt = "Decrypted: \"%s\"" % res["decrypted"]
                idc.set_cmt(res["call_ea"], cmt, 0)
                applied += 1
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info("Applied %d decrypted string comments across IDB." % applied)

    def _jump_item(self, item):
        ea = item.data(QtCore.Qt.UserRole)
        if not ea:
            it0 = self.tbl.item(item.row(), 0)
            if it0:
                ea = it0.data(QtCore.Qt.UserRole)
        if ea and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
            ida_kernwin.jumpto(int(ea))

    def _export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Decrypted Strings", "decrypted_strings.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Call EA", "Caller", "Arguments", "Decrypted Output", "Status"])
            for res in self.results:
                w.writerow([_hex(res["call_ea"]), res["caller"], res["args_desc"], res["decrypted"], res["status"]])


class MicroEmulatorDialog(QtWidgets.QDialog):
    """Interactive in-IDA CPU micro-emulator and register viewer (uEmu style)."""

    def __init__(self, parent=None):
        super(MicroEmulatorDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - Interactive CPU Micro-Emulator")
        self.resize(840, 680)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.emu: Optional[UnicornEngine] = None
        self.cur_ea: int = 0
        self.reg_values: Dict[str, int] = {}
        self.prev_reg_values: Dict[str, int] = {}

        self._setup_ui()
        self.reset_to_cursor()

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{ background: {t.window}; color: {t.text}; }}
            QTableWidget, QTextEdit {{
                background: {t.surface};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                font-family: monospace;
            }}
            QHeaderView::section {{
                background: {t.surface_alt};
                color: {t.text_muted};
                padding: 4px;
                font-weight: 700;
                border: none;
                border-bottom: 1px solid {t.border};
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        header = PageHeader(
            "Interactive Micro-Emulator",
            "Step-through CPU emulator with live register, stack, and memory state tracking without starting a debugger."
        )

        btn_start = QtWidgets.QPushButton("Reset to Cursor")
        btn_start.clicked.connect(self.reset_to_cursor)
        header.add_action(btn_start)

        btn_step_in = QtWidgets.QPushButton("Step Into (F7)")
        btn_step_in.setProperty("pnVariant", "primary")
        btn_step_in.clicked.connect(self.step_into)
        header.add_action(btn_step_in)

        btn_step_over = QtWidgets.QPushButton("Step Over (F8)")
        btn_step_over.clicked.connect(self.step_over)
        header.add_action(btn_step_over)

        root.addWidget(header)

        # Main splitter (Registers on left, Stack + Trace on right)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left: Registers Grid
        w_left = QtWidgets.QWidget()
        l_left = QtWidgets.QVBoxLayout(w_left)
        l_left.setContentsMargins(0, 0, 0, 0)
        l_left.addWidget(QtWidgets.QLabel("CPU Registers:"))
        self.tbl_regs = QtWidgets.QTableWidget(0, 2)
        self.tbl_regs.setHorizontalHeaderLabels(["Register", "Value (Hex)"])
        self.tbl_regs.horizontalHeader().setStretchLastSection(True)
        self.tbl_regs.verticalHeader().setVisible(False)
        l_left.addWidget(self.tbl_regs)
        splitter.addWidget(w_left)

        # Right: Stack & Memory Trace
        w_right = QtWidgets.QWidget()
        l_right = QtWidgets.QVBoxLayout(w_right)
        l_right.setContentsMargins(0, 0, 0, 0)

        l_right.addWidget(QtWidgets.QLabel("Call Stack View (Top 16 Slots):"))
        self.tbl_stack = QtWidgets.QTableWidget(0, 3)
        self.tbl_stack.setHorizontalHeaderLabels(["Offset", "Address", "Value"])
        self.tbl_stack.horizontalHeader().setStretchLastSection(True)
        self.tbl_stack.verticalHeader().setVisible(False)
        l_right.addWidget(self.tbl_stack, 1)

        l_right.addWidget(QtWidgets.QLabel("Execution Trace Log:"))
        self.txt_log = QtWidgets.QTextEdit()
        self.txt_log.setReadOnly(True)
        l_right.addWidget(self.txt_log, 1)

        splitter.addWidget(w_right)
        splitter.setSizes([320, 500])
        root.addWidget(splitter, 1)

        # Bottom Bar
        bottom = QtWidgets.QHBoxLayout()
        self.lbl_status = QtWidgets.QLabel("Ready")
        self.lbl_status.setStyleSheet(f"color: {t.text_muted};")
        bottom.addWidget(self.lbl_status)
        bottom.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)

        root.addLayout(bottom)

    def reset_to_cursor(self):
        screen_ea = ida_kernwin.get_screen_ea() if ida_kernwin and hasattr(ida_kernwin, "get_screen_ea") else 0
        self.cur_ea = screen_ea or 0x140001000
        is_64 = _is_64bit()

        self.emu = UnicornEngine(is_64bit=is_64)
        self.emu.load_idb_segment(self.cur_ea)

        ip_reg = UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP
        self.emu.uc.reg_write(ip_reg, self.cur_ea)

        self.prev_reg_values = {}
        self.reg_values = {}
        self.txt_log.clear()
        self.txt_log.append("=== Emulation Initialized at %s ===" % _hex(self.cur_ea))

        self._refresh_state()

    def step_into(self):
        if not self.emu:
            self.reset_to_cursor()
        if not self.emu:
            return

        is_64 = self.emu.is_64
        ip_reg = UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP
        cur_ip = self.emu.uc.reg_read(ip_reg)

        # Get instruction size
        next_ip = (idc.next_head(cur_ip) if idc else cur_ip + 1) or cur_ip + 1
        dis = (idc.generate_disasm_line(cur_ip, 0) if idc else "") or ""

        self.prev_reg_values = dict(self.reg_values)
        try:
            self.emu.uc.emu_start(cur_ip, next_ip, count=1)
        except Exception as exc:
            self.txt_log.append("Fault at %s: %s" % (_hex(cur_ip), exc))

        new_ip = self.emu.uc.reg_read(ip_reg)
        self.txt_log.append("%s: %s" % (_hex(cur_ip), dis))
        if ida_kernwin and hasattr(ida_kernwin, "jumpto"):
            ida_kernwin.jumpto(new_ip)

        self._refresh_state()

    def step_over(self):
        self.step_into()

    def _refresh_state(self):
        if not self.emu:
            return
        is_64 = self.emu.is_64
        uc = self.emu.uc

        reg_map = {
            "RAX": UC_X86_REG_RAX if is_64 else UC_X86_REG_EAX,
            "RBX": UC_X86_REG_RBX if is_64 else UC_X86_REG_EBX,
            "RCX": UC_X86_REG_RCX if is_64 else UC_X86_REG_ECX,
            "RDX": UC_X86_REG_RDX if is_64 else UC_X86_REG_EDX,
            "RSI": UC_X86_REG_RSI if is_64 else UC_X86_REG_ESI,
            "RDI": UC_X86_REG_RDI if is_64 else UC_X86_REG_EDI,
            "RBP": UC_X86_REG_RBP if is_64 else UC_X86_REG_EBP,
            "RSP": UC_X86_REG_RSP if is_64 else UC_X86_REG_ESP,
            "RIP": UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP,
            "EFLAGS": UC_X86_REG_EFLAGS,
        }
        if is_64:
            for i in range(8, 16):
                reg_map["R%d" % i] = getattr(unicorn.x86_const, "UC_X86_REG_R%d" % i)

        self.reg_values = {name: uc.reg_read(rid) for name, rid in reg_map.items()}

        self.tbl_regs.setRowCount(len(self.reg_values))
        for r, (name, val) in enumerate(self.reg_values.items()):
            it_name = QtWidgets.QTableWidgetItem(name)
            it_val = QtWidgets.QTableWidgetItem("0x%X" % val)
            if name in self.prev_reg_values and self.prev_reg_values[name] != val:
                it_val.setForeground(QtGui.QBrush(QtGui.QColor(self.t.accent)))
                it_val.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            self.tbl_regs.setItem(r, 0, it_name)
            self.tbl_regs.setItem(r, 1, it_val)

        # Update Stack
        sp_val = self.reg_values.get("RSP" if is_64 else "ESP", 0)
        ptr_size = 8 if is_64 else 4
        self.tbl_stack.setRowCount(16)
        for i in range(16):
            slot_addr = sp_val + (i * ptr_size)
            slot_raw = self.emu.read_buffer(slot_addr, ptr_size)
            val = int.from_bytes(slot_raw, "little") if slot_raw else 0
            self.tbl_stack.setItem(i, 0, QtWidgets.QTableWidgetItem("+0x%02X" % (i * ptr_size)))
            self.tbl_stack.setItem(i, 1, QtWidgets.QTableWidgetItem(_hex(slot_addr)))
            self.tbl_stack.setItem(i, 2, QtWidgets.QTableWidgetItem(_hex(val)))


class EmulateCallHandler(idaapi.action_handler_t if idaapi else object):
    """Right-click action to emulate current function call in pseudocode or disassembly."""

    def activate(self, ctx):
        global _call_emu_instance
        try:
            screen_ea = ida_kernwin.get_screen_ea() if ida_kernwin and hasattr(ida_kernwin, "get_screen_ea") else 0
            func_ea = ida_funcs.get_func(screen_ea).start_ea if ida_funcs and ida_funcs.get_func(screen_ea) else screen_ea

            _call_emu_instance = CallEmulationDialog(call_ea=screen_ea, func_ea=func_ea)
            _call_emu_instance.show()
            _call_emu_instance.raise_()
            _call_emu_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Failed to open Call Emulator:\n%s" % exc)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


class BatchEmulateXrefsHandler(idaapi.action_handler_t if idaapi else object):
    """Batch emulate all callers of the current function across the entire IDB."""

    def activate(self, ctx):
        global _batch_emu_instance
        try:
            screen_ea = ida_kernwin.get_screen_ea() if ida_kernwin and hasattr(ida_kernwin, "get_screen_ea") else 0
            func = ida_funcs.get_func(screen_ea) if ida_funcs else None
            func_ea = func.start_ea if func else screen_ea

            _batch_emu_instance = BatchDecryptorDialog(func_ea=func_ea)
            _batch_emu_instance.show()
            _batch_emu_instance.raise_()
            _batch_emu_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Failed to open Batch Decryptor:\n%s" % exc)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


class MicroEmulatorHandler(idaapi.action_handler_t if idaapi else object):
    """Launch interactive CPU micro-emulator widget (uEmu style)."""

    def activate(self, ctx):
        global _micro_emu_instance
        try:
            if _micro_emu_instance is None or not _micro_emu_instance.isVisible():
                _micro_emu_instance = MicroEmulatorDialog()
            _micro_emu_instance.show()
            _micro_emu_instance.raise_()
            _micro_emu_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Failed to open Micro-Emulator:\n%s" % exc)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0
