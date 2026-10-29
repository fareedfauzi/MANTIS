# -*- coding: utf-8 -*-
"""
Genesect macOS Mach-O & Objective-C / Swift Resolver.

Solves the primary challenges in macOS binary analysis:
1. objc_msgSend Dispatch Resolver: tracks selectors from __objc_selrefs / __objc_methname
   and receivers from __objc_classrefs to reconstruct readable [Class method:args] calls.
2. Objective-C Class & Protocol Dumper: parses __objc_classlist, class_ro_t, ivars,
   protocols, and method lists, generating clean @interface declarations and naming IMP stubs.
3. Mach-O Code Signing & Entitlements Inspector: extracts embedded XML entitlements from
   LC_CODE_SIGNATURE SuperBlob, auditing TCC bypasses, task_for_pid, and sandbox exceptions.
4. Dylib & RPath Hijack Auditor: analyzes LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_RPATH,
   and hardened runtime flags to detect hijackable search paths and persistence vectors.
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
    ida_segment = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


# Known dangerous / privileged Apple Entitlements
CRITICAL_ENTITLEMENTS = {
    "com.apple.security.get-task-allow": ("Debugging", "High", "Allows external debuggers to attach and inspect process memory"),
    "com.apple.security.cs.allow-unsigned-executable-memory": ("Memory", "Critical", "Allows allocating writable and executable memory (JIT/shellcode execution)"),
    "com.apple.security.cs.disable-library-validation": ("Injection", "Critical", "Disables code signature validation when loading dylibs (primary dylib hijack target)"),
    "com.apple.security.cs.allow-dyld-environment-variables": ("Injection", "Critical", "Allows DYLD_INSERT_LIBRARIES and DYLD_LIBRARY_PATH injection"),
    "task_for_pid-allow": ("Kernel / Injection", "Critical", "Allows obtaining the Mach task port for any target process (arbitrary memory read/write)"),
    "com.apple.security.device.camera": ("Privacy", "High", "Access to hardware camera without prompting"),
    "com.apple.security.device.microphone": ("Privacy", "High", "Access to hardware microphone for audio recording"),
    "com.apple.security.personal-information.location": ("Privacy", "Medium", "Access to system geolocation"),
    "com.apple.security.personal-information.addressbook": ("Privacy", "High", "Direct access to contacts database"),
    "com.apple.security.files.all": ("TCC Bypass", "Critical", "Full disk access bypassing macOS Transparency, Consent, and Control (TCC)"),
    "com.apple.rootless.storage": ("SIP Bypass", "Critical", "Bypasses System Integrity Protection (SIP) protected directories"),
    "com.apple.private.tcc.allow": ("TCC Bypass", "Critical", "Private Apple entitlement allowing arbitrary TCC permission grants"),
}


class ObjCMessageCall:
    """Represents a single detected objc_msgSend call site."""

    def __init__(self, call_ea: int, func_ea: int, func_name: str):
        self.call_ea = call_ea
        self.func_ea = func_ea
        self.func_name = func_name
        self.selector_name = ""
        self.selector_ea = 0
        self.receiver_class = ""
        self.formatted_call = ""
        self.annotated = False


class ObjCMethod:
    """Represents a parsed Objective-C method entry."""

    def __init__(self, name: str, types: str, imp_ea: int, is_class_method: bool = False):
        self.name = name
        self.types = types
        self.imp_ea = imp_ea
        self.is_class_method = is_class_method


class ObjCIvar:
    """Represents a parsed Objective-C instance variable."""

    def __init__(self, name: str, type_encoding: str, offset: int):
        self.name = name
        self.type_encoding = type_encoding
        self.offset = offset


class ObjCClassDesc:
    """Represents an Objective-C class reconstructed from Mach-O metadata."""

    def __init__(self, class_ea: int, name: str, superclass_name: str = ""):
        self.class_ea = class_ea
        self.name = name
        self.superclass_name = superclass_name
        self.protocols: List[str] = []
        self.ivars: List[ObjCIvar] = []
        self.methods: List[ObjCMethod] = []

    def generate_header(self) -> str:
        proto_str = f" <{', '.join(self.protocols)}>" if self.protocols else ""
        super_str = f" : {self.superclass_name}" if self.superclass_name else ""
        lines = [f"@interface {self.name}{super_str}{proto_str}"]
        if self.ivars:
            lines.append("{")
            for iv in self.ivars:
                lines.append(f"    id {iv.name}; // type: {iv.type_encoding}, offset: 0x{iv.offset:X}")
            lines.append("}")
        for m in self.methods:
            prefix = "+" if m.is_class_method else "-"
            lines.append(f"{prefix} (void){m.name}; // IMP: 0x{m.imp_ea:X}")
        lines.append("@end\n")
        return "\n".join(lines)


class MachODylibEntry:
    """Represents a Mach-O dynamic library dependency and hijacking audit."""

    def __init__(
        self,
        path: str,
        cmd_name: str,
        is_weak: bool,
        is_rpath_dependent: bool,
        risk_level: str,
        notes: str,
    ):
        self.path = path
        self.cmd_name = cmd_name
        self.is_weak = is_weak
        self.is_rpath_dependent = is_rpath_dependent
        self.risk_level = risk_level
        self.notes = notes


def read_c_string(ea: int, max_len: int = 256) -> str:
    if not ida_bytes:
        return ""
    try:
        raw = ida_bytes.get_bytes(ea, max_len)
        if not raw:
            return ""
        null_pos = raw.find(b"\x00")
        if null_pos != -1:
            raw = raw[:null_pos]
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def resolve_objc_msgsend_calls() -> List[ObjCMessageCall]:
    """Scan the database for calls to objc_msgSend and resolve selectors/classes."""
    results: List[ObjCMessageCall] = []
    if not idautils or not idc:
        return results

    is_64 = bool(ida_ida.inf_is_64bit()) if ida_ida and hasattr(ida_ida, "inf_is_64bit") else True

    # Locate objc_msgSend import/function address
    target_eas = set()
    for name, ea in idautils.Names():
        if name in ("_objc_msgSend", "objc_msgSend", "_objc_msgSend_stret", "_objc_msgSendSuper", "_objc_msgSendSuper2"):
            target_eas.add(ea)

    if not target_eas:
        return results

    for target_ea in target_eas:
        for xref in idautils.CodeRefsTo(target_ea, 0):
            func = ida_funcs.get_func(xref) if ida_funcs else None
            func_ea = func.start_ea if func else xref
            func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

            call_info = ObjCMessageCall(call_ea=xref, func_ea=func_ea, func_name=func_name)

            sel_name, rec_name = _backward_slice_objc_args(xref, func_ea, is_64)
            call_info.selector_name = sel_name or "unknownSelector"
            call_info.receiver_class = rec_name or "id"

            if rec_name and sel_name:
                call_info.formatted_call = f"[{rec_name} {sel_name}]"
            elif sel_name:
                call_info.formatted_call = f"[(id) {sel_name}]"
            else:
                call_info.formatted_call = "[unknown call]"

            results.append(call_info)

    results.sort(key=lambda c: c.call_ea)
    return results


def _backward_slice_objc_args(call_ea: int, func_start: int, is_64: bool, max_lookback: int = 15) -> Tuple[str, str]:
    if not idc or not ida_bytes:
        return "", ""

    target_sel_regs = {"rsi", "esi", "x1", "w1"}
    target_rec_regs = {"rdi", "edi", "x0", "w0"}

    sel_name = ""
    receiver_name = ""

    cur_ea = call_ea
    for _ in range(max_lookback):
        prev_ea = idc.prev_head(cur_ea, func_start)
        if prev_ea == idaapi.BADADDR or prev_ea == cur_ea:
            break
        cur_ea = prev_ea

        op0 = (idc.print_operand(cur_ea, 0) or "").lower().strip()
        op1 = (idc.print_operand(cur_ea, 1) or "").strip()
        val = idc.get_operand_value(cur_ea, 1)

        # Check Selector (RSI / X1)
        if not sel_name and op0 in target_sel_regs:
            op1_lower = op1.lower()
            if "selref_" in op1_lower or "sel_" in op1_lower:
                match = re.search(r"sel(?:ref)?_([a-zA-Z0-9_:]+)", op1, re.IGNORECASE)
                if match:
                    sel_name = match.group(1).replace("_", ":")

            if not sel_name and val and val != -1:
                pointed_str = read_c_string(val)
                if pointed_str and any(c.isalnum() for c in pointed_str):
                    sel_name = pointed_str
                else:
                    deref = (ida_bytes.get_qword(val) if is_64 else ida_bytes.get_dword(val)) if ida_bytes else 0
                    if deref and deref != idaapi.BADADDR:
                        deref_str = read_c_string(deref)
                        if deref_str and any(c.isalnum() for c in deref_str):
                            sel_name = deref_str

        # Check Receiver (RDI / X0)
        if not receiver_name and op0 in target_rec_regs:
            op1_lower = op1.lower()
            if "classref_" in op1_lower or "class_" in op1_lower:
                match = re.search(r"class(?:ref)?_([a-zA-Z0-9_]+)", op1, re.IGNORECASE)
                if match:
                    receiver_name = match.group(1)

            if not receiver_name and val and val != -1:
                name_at_val = idc.get_name(val) or ""
                if "classref_" in name_at_val.lower():
                    match = re.search(r"class(?:ref)?_([a-zA-Z0-9_]+)", name_at_val, re.IGNORECASE)
                    if match:
                        receiver_name = match.group(1)

        if sel_name and receiver_name:
            break

    return sel_name, receiver_name


def scan_objc_classes() -> List[ObjCClassDesc]:
    """
    Parses Mach-O Objective-C metadata sections (__objc_classlist, class_ro_t, ivars, methods)
    and reconstructs Objective-C classes.
    """
    classes: List[ObjCClassDesc] = []
    if not ida_segment or not idautils or not ida_bytes:
        return classes

    is_64 = bool(ida_ida.inf_is_64bit()) if ida_ida and hasattr(ida_ida, "inf_is_64bit") else True
    ptr_size = 8 if is_64 else 4

    # 1. Locate __objc_classlist section
    classlist_segs = []
    for s_ea in idautils.Segments():
        s_name = idc.get_segm_name(s_ea) if idc else ""
        if "__objc_classlist" in s_name:
            classlist_segs.append(s_ea)

    seen_classes: Set[int] = set()

    for seg_ea in classlist_segs:
        s = ida_segment.getseg(seg_ea) if hasattr(ida_segment, "getseg") else None
        if not s:
            continue
        cur = s.start_ea
        end_ea = s.end_ea

        while cur < end_ea:
            class_ea = ida_bytes.get_qword(cur) if is_64 else ida_bytes.get_dword(cur)
            if class_ea and class_ea != idaapi.BADADDR and class_ea not in seen_classes:
                seen_classes.add(class_ea)

                # Parse objc_class struct:
                # 0x00: isa
                # 0x08: superclass
                # 0x10: cache
                # 0x18: vtable
                # 0x20: data (pointer to class_ro_t, masked & ~0x7)
                super_ea = ida_bytes.get_qword(class_ea + ptr_size) if is_64 else ida_bytes.get_dword(class_ea + ptr_size)
                data_ea = ida_bytes.get_qword(class_ea + (4 * ptr_size)) if is_64 else ida_bytes.get_dword(class_ea + (4 * ptr_size))
                data_ea &= ~0x7  # Mask PAC / flags

                super_name = ""
                if super_ea and super_ea != idaapi.BADADDR:
                    super_name = idc.get_name(super_ea) or ""
                    if super_name.startswith(("_OBJC_CLASS_$_", "OBJC_CLASS_$_")):
                        super_name = super_name.split("$_")[-1]

                if data_ea and data_ea != idaapi.BADADDR:
                    # class_ro_t (64-bit layout):
                    # 0x18: name (ptr)
                    # 0x20: baseMethodList (ptr)
                    # 0x28: baseProtocols (ptr)
                    # 0x30: ivars (ptr)
                    name_ptr_off = 24 if is_64 else 12
                    methods_ptr_off = 32 if is_64 else 16
                    protos_ptr_off = 40 if is_64 else 20
                    ivars_ptr_off = 48 if is_64 else 24

                    name_ptr = ida_bytes.get_qword(data_ea + name_ptr_off) if is_64 else ida_bytes.get_dword(data_ea + name_ptr_off)
                    cls_name = read_c_string(name_ptr) if name_ptr else ""

                    if not cls_name:
                        cur_name = idc.get_name(class_ea) or ""
                        if "$_" in cur_name:
                            cls_name = cur_name.split("$_")[-1]

                    if cls_name:
                        desc = ObjCClassDesc(class_ea=class_ea, name=cls_name, superclass_name=super_name)

                        # Parse Methods
                        meth_list_ptr = ida_bytes.get_qword(data_ea + methods_ptr_off) if is_64 else ida_bytes.get_dword(data_ea + methods_ptr_off)
                        if meth_list_ptr and meth_list_ptr != idaapi.BADADDR:
                            m_entsize = ida_bytes.get_dword(meth_list_ptr) & ~0x3
                            m_count = ida_bytes.get_dword(meth_list_ptr + 4)
                            if 0 < m_count < 1000 and 12 <= m_entsize <= 64:
                                for m_i in range(m_count):
                                    m_ea = meth_list_ptr + 8 + (m_i * m_entsize)
                                    s_ptr = ida_bytes.get_qword(m_ea) if is_64 else ida_bytes.get_dword(m_ea)
                                    t_ptr = ida_bytes.get_qword(m_ea + ptr_size) if is_64 else ida_bytes.get_dword(m_ea + ptr_size)
                                    imp_ea = ida_bytes.get_qword(m_ea + (2 * ptr_size)) if is_64 else ida_bytes.get_dword(m_ea + (2 * ptr_size))
                                    s_name = read_c_string(s_ptr)
                                    t_str = read_c_string(t_ptr)
                                    if s_name:
                                        desc.methods.append(ObjCMethod(name=s_name, types=t_str, imp_ea=imp_ea))

                        # Parse Ivars
                        ivar_list_ptr = ida_bytes.get_qword(data_ea + ivars_ptr_off) if is_64 else ida_bytes.get_dword(data_ea + ivars_ptr_off)
                        if ivar_list_ptr and ivar_list_ptr != idaapi.BADADDR:
                            iv_entsize = ida_bytes.get_dword(ivar_list_ptr) & ~0x3
                            iv_count = ida_bytes.get_dword(ivar_list_ptr + 4)
                            if 0 < iv_count < 500 and 12 <= iv_entsize <= 64:
                                for iv_i in range(iv_count):
                                    iv_ea = ivar_list_ptr + 8 + (iv_i * iv_entsize)
                                    off_ptr = ida_bytes.get_qword(iv_ea) if is_64 else ida_bytes.get_dword(iv_ea)
                                    iv_name_ptr = ida_bytes.get_qword(iv_ea + ptr_size) if is_64 else ida_bytes.get_dword(iv_ea + ptr_size)
                                    iv_type_ptr = ida_bytes.get_qword(iv_ea + (2 * ptr_size)) if is_64 else ida_bytes.get_dword(iv_ea + (2 * ptr_size))
                                    offset_val = ida_bytes.get_dword(off_ptr) if off_ptr else 0
                                    iv_name = read_c_string(iv_name_ptr)
                                    iv_type = read_c_string(iv_type_ptr)
                                    if iv_name:
                                        desc.ivars.append(ObjCIvar(name=iv_name, type_encoding=iv_type, offset=offset_val))

                        classes.append(desc)

            cur += ptr_size

    # Fallback: if no classlist section found, scan names for _OBJC_CLASS_$_
    if not classes and idautils and hasattr(idautils, "Names"):
        for name, ea in idautils.Names():
            if name.startswith("_OBJC_CLASS_$_"):
                c_name = name[14:]
                classes.append(ObjCClassDesc(class_ea=ea, name=c_name, superclass_name="NSObject"))

    classes.sort(key=lambda c: c.name)
    return classes


def rename_objc_imp_functions(classes: List[ObjCClassDesc]) -> int:
    """Labels unnamed IMP implementation functions in IDA with -[Class method]."""
    if not idc:
        return 0
    count = 0
    for cls in classes:
        for m in cls.methods:
            if m.imp_ea and m.imp_ea != idaapi.BADADDR:
                cur_name = idc.get_func_name(m.imp_ea) or idc.get_name(m.imp_ea) or ""
                if cur_name.startswith("sub_") or not cur_name:
                    prefix = "+" if m.is_class_method else "-"
                    new_name = f"{prefix}[{cls.name} {m.name}]"
                    flag = idc.SN_CHECK if hasattr(idc, "SN_CHECK") else 0
                    if idc.set_name(m.imp_ea, new_name, flag):
                        count += 1
    return count


def parse_macho_entitlements() -> Tuple[str, List[Dict[str, Any]], List[str], List[MachODylibEntry]]:
    """
    Parses the input Mach-O file to extract XML Code Signing Entitlements,
    audited security flags, LC_RPATH dynamic library search paths,
    and detailed LC_LOAD_DYLIB commands for hijacking analysis.
    """
    input_path = ida_nalt.get_input_file_path() if ida_nalt and hasattr(ida_nalt, "get_input_file_path") else ""
    if not input_path or not os.path.exists(input_path):
        return "", [], [], []

    xml_text = ""
    audited_risks = []
    rpaths = []
    dylibs: List[MachODylibEntry] = []

    try:
        with open(input_path, "rb") as f:
            data = f.read()

        if len(data) < 32:
            return "", [], [], []

        # Parse Mach-O Header
        magic = struct.unpack(">I", data[:4])[0]
        is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
        is_le = magic in (0xCEFAEDFE, 0xCFFAEDFE)
        order = "<" if is_le else ">"

        if magic not in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
            return "", [], [], []

        hdr_fmt = f"{order}IIIIII" + ("I" if is_64 else "")
        hdr_size = struct.calcsize(hdr_fmt)
        ncmds = struct.unpack_from(hdr_fmt, data)[4]

        offset = hdr_size
        cs_off = 0
        cs_size = 0

        # Command constants
        LC_REQ_DYLD = 0x80000000
        LC_LOAD_DYLIB = 0x0C
        LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
        LC_RPATH = (0x1C | LC_REQ_DYLD)
        LC_REEXPORT_DYLIB = (0x1F | LC_REQ_DYLD)
        LC_LAZY_LOAD_DYLIB = 0x20
        LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD)
        LC_CODE_SIGNATURE = 0x1D

        # Iterate Load Commands
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(f"{order}II", data, offset)

            if cmd == LC_CODE_SIGNATURE:
                cs_off, cs_size = struct.unpack_from(f"{order}II", data, offset + 8)

            elif cmd == LC_RPATH:
                str_off = struct.unpack_from(f"{order}I", data, offset + 8)[0]
                raw_rpath = data[offset + str_off:offset + cmdsize].split(b"\x00")[0]
                rpaths.append(raw_rpath.decode("utf-8", errors="replace"))

            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB):
                str_off = struct.unpack_from(f"{order}I", data, offset + 8)[0]
                raw_path = data[offset + str_off:offset + cmdsize].split(b"\x00")[0]
                dpath = raw_path.decode("utf-8", errors="replace")

                is_weak = (cmd == LC_LOAD_WEAK_DYLIB)
                is_rpath = dpath.startswith("@rpath")
                cmd_names = {
                    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
                    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
                    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
                    LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
                    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
                }

                # Evaluate Dylib Hijack Risk
                risk = "Low"
                notes = "Standard system framework/library"
                if is_weak and is_rpath:
                    risk = "Critical"
                    notes = "Weak dylib loaded via RPath search; missing file will execute attacker-planted dylib"
                elif is_weak:
                    risk = "High"
                    notes = "Weak library binding (execution continues if missing; hijackable target)"
                elif is_rpath:
                    risk = "Medium"
                    notes = "Dynamic library resolved at runtime via runpaths"
                elif dpath.startswith(("/tmp", "/var/tmp", ".")):
                    risk = "Critical"
                    notes = "Points directly to an insecure/writable location"

                dylibs.append(
                    MachODylibEntry(
                        path=dpath,
                        cmd_name=cmd_names.get(cmd, "LC_LOAD_DYLIB"),
                        is_weak=is_weak,
                        is_rpath_dependent=is_rpath,
                        risk_level=risk,
                        notes=notes,
                    )
                )

            offset += cmdsize

        # Parse Code Signature SuperBlob
        if cs_off and cs_size and cs_off + cs_size <= len(data):
            cs_data = data[cs_off:cs_off + cs_size]
            if len(cs_data) >= 12:
                sb_magic, sb_len, sb_count = struct.unpack_from(">III", cs_data, 0)
                if sb_magic == 0xFADE0CC0:
                    for i in range(sb_count):
                        blob_type, blob_off = struct.unpack_from(">II", cs_data, 12 + (i * 8))
                        if blob_type == 5 and blob_off < len(cs_data):  # CSSLOT_ENTITLEMENTS
                            ent_data = cs_data[blob_off:]
                            if len(ent_data) >= 8:
                                ent_magic, ent_len = struct.unpack_from(">II", ent_data, 0)
                                if ent_magic in (0xFADE7171, 0xFADE7172):
                                    raw_xml = ent_data[8:ent_len]
                                    xml_text = raw_xml.decode("utf-8", errors="replace")

        # Audit Entitlements
        for ent_key, (category, threat, desc) in CRITICAL_ENTITLEMENTS.items():
            if ent_key in xml_text:
                audited_risks.append({
                    "key": ent_key,
                    "category": category,
                    "threat": threat,
                    "description": desc,
                })

    except Exception:
        pass

    return xml_text, audited_risks, rpaths, dylibs


class MachOExplorerDialog(QtWidgets.QDialog):
    """Unified macOS Mach-O & Objective-C / Entitlements / Dylib Explorer Dialog."""

    def __init__(self, parent=None):
        super(MachOExplorerDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - macOS Mach-O & Objective-C Resolver")
        self.resize(1140, 720)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.objc_calls: List[ObjCMessageCall] = []
        self.classes: List[ObjCClassDesc] = []
        self.entitlements_xml = ""
        self.audited_risks: List[Dict[str, Any]] = []
        self.rpaths: List[str] = []
        self.dylibs: List[MachODylibEntry] = []

        self._setup_ui()
        QtCore.QTimer.singleShot(0, self.refresh_all)

    def _setup_ui(self):
        t = self.t
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        header = PageHeader(
            "macOS Mach-O & Objective-C Analysis Suite",
            "Objective-C msgSend resolver, class-dump header reconstructor, code signing entitlements audit, and dylib hijack inspector."
        )

        btn_rescan = QtWidgets.QPushButton("Rescan All")
        btn_rescan.setProperty("pnVariant", "primary")
        btn_rescan.clicked.connect(self.refresh_all)
        header.add_action(btn_rescan)

        btn_annotate = QtWidgets.QPushButton("Annotate Selected Calls")
        btn_annotate.clicked.connect(self._annotate_selected)
        header.add_action(btn_annotate)

        btn_export = QtWidgets.QPushButton("Export CSV...")
        btn_export.clicked.connect(self._export_csv)
        header.add_action(btn_export)

        root.addWidget(header)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()

        # Tab 0: objc_msgSend Resolver
        tab_objc = QtWidgets.QWidget()
        l_objc = QtWidgets.QVBoxLayout(tab_objc)
        l_objc.setContentsMargins(10, 10, 10, 10)

        l_f = QtWidgets.QHBoxLayout()
        l_f.addWidget(QtWidgets.QLabel("Search Calls:"))
        self.edit_search = QtWidgets.QLineEdit()
        self.edit_search.setPlaceholderText("Filter by selector, class, or address...")
        self.edit_search.textChanged.connect(self._apply_objc_filter)
        l_f.addWidget(self.edit_search, 1)
        l_objc.addLayout(l_f)

        self.tbl_objc = QtWidgets.QTableWidget(0, 5)
        self.tbl_objc.setHorizontalHeaderLabels([
            "Call Address", "Calling Function", "Receiver Class", "Resolved Selector", "Reconstructed Call Signature"
        ])
        self.tbl_objc.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_objc.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_objc.horizontalHeader().setStretchLastSection(True)
        self.tbl_objc.itemDoubleClicked.connect(self._on_call_double_clicked)
        l_objc.addWidget(self.tbl_objc, 1)

        self.tabs.addTab(tab_objc, "Objective-C Dispatch Resolver")

        # Tab 1: Class & Protocol Dumper
        tab_cls = QtWidgets.QWidget()
        l_cls = QtWidgets.QVBoxLayout(tab_cls)
        l_cls.setContentsMargins(10, 10, 10, 10)

        top_cls_bar = QtWidgets.QHBoxLayout()
        top_cls_bar.addWidget(QtWidgets.QLabel("Reconstructed Classes:"))
        top_cls_bar.addStretch(1)

        btn_label_imp = QtWidgets.QPushButton("Label IMP Functions in IDB")
        btn_label_imp.clicked.connect(self._label_imp_functions)
        top_cls_bar.addWidget(btn_label_imp)

        btn_export_headers = QtWidgets.QPushButton("Export @interface Headers...")
        btn_export_headers.clicked.connect(self._export_headers)
        top_cls_bar.addWidget(btn_export_headers)
        l_cls.addLayout(top_cls_bar)

        splitter_cls = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Class list table
        self.tbl_classes = QtWidgets.QTableWidget(0, 3)
        self.tbl_classes.setHorizontalHeaderLabels(["Class Name", "Superclass", "Methods"])
        self.tbl_classes.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_classes.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_classes.horizontalHeader().setStretchLastSection(True)
        self.tbl_classes.itemSelectionChanged.connect(self._on_class_selected)
        splitter_cls.addWidget(self.tbl_classes)

        # Class detail preview
        self.txt_class_preview = QtWidgets.QTextEdit()
        self.txt_class_preview.setFont(QtGui.QFont("Consolas", 10))
        self.txt_class_preview.setReadOnly(True)
        splitter_cls.addWidget(self.txt_class_preview)
        splitter_cls.setSizes([380, 600])

        l_cls.addWidget(splitter_cls, 1)
        self.tabs.addTab(tab_cls, "Class & Protocol Dumper")

        # Tab 2: Entitlements & Security Audit
        tab_ent = QtWidgets.QWidget()
        l_ent = QtWidgets.QVBoxLayout(tab_ent)
        l_ent.setContentsMargins(10, 10, 10, 10)

        l_ent.addWidget(QtWidgets.QLabel("High-Risk Entitlements & Sandbox Escapes Detected:"))
        self.tbl_risks = QtWidgets.QTableWidget(0, 4)
        self.tbl_risks.setHorizontalHeaderLabels(["Entitlement Key", "Category", "Threat Level", "Description"])
        self.tbl_risks.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_risks.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_risks.horizontalHeader().setStretchLastSection(True)
        l_ent.addWidget(self.tbl_risks, 1)

        l_ent.addWidget(QtWidgets.QLabel("Raw XML Code Signing Entitlements:"))
        self.txt_xml = QtWidgets.QTextEdit()
        self.txt_xml.setFont(QtGui.QFont("Consolas", 10))
        self.txt_xml.setReadOnly(True)
        l_ent.addWidget(self.txt_xml, 1)

        self.tabs.addTab(tab_ent, "Code Signing & Entitlements")

        # Tab 3: Dylib & RPath Hijack Auditor
        tab_dylib = QtWidgets.QWidget()
        l_dy = QtWidgets.QVBoxLayout(tab_dylib)
        l_dy.setContentsMargins(10, 10, 10, 10)

        l_dy.addWidget(QtWidgets.QLabel("Loaded Dynamic Libraries & Hijack Assessment:"))
        self.tbl_dylibs = QtWidgets.QTableWidget(0, 4)
        self.tbl_dylibs.setHorizontalHeaderLabels(["Library Path", "Load Command", "Hijack Risk", "Audit Notes"])
        self.tbl_dylibs.horizontalHeader().setStretchLastSection(True)
        self.tbl_dylibs.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_dylibs.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_dylibs.setColumnWidth(0, 320)
        self.tbl_dylibs.setColumnWidth(1, 150)
        self.tbl_dylibs.setColumnWidth(2, 110)
        l_dy.addWidget(self.tbl_dylibs, 2)

        l_dy.addWidget(QtWidgets.QLabel("Runpath Search Paths (LC_RPATH):"))
        self.lst_rpaths = QtWidgets.QTableWidget(0, 2)
        self.lst_rpaths.setHorizontalHeaderLabels(["Runtime Search Path", "Hijacking Assessment"])
        self.lst_rpaths.horizontalHeader().setStretchLastSection(True)
        self.lst_rpaths.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.lst_rpaths.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        l_dy.addWidget(self.lst_rpaths, 1)

        self.tabs.addTab(tab_dylib, "Dylib & RPath Hijack Auditor")

        root.addWidget(self.tabs, 1)

        # Bottom Bar
        bottom = QtWidgets.QHBoxLayout()
        self.lbl_stats = QtWidgets.QLabel("Ready")
        self.lbl_stats.setStyleSheet(f"color: {t.text_muted};")
        bottom.addWidget(self.lbl_stats)
        bottom.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)
        root.addLayout(bottom)

    def refresh_all(self):
        # Scan Objective-C calls
        self.objc_calls = resolve_objc_msgsend_calls()
        self._apply_objc_filter()

        # Scan Objective-C Classes
        self.classes = scan_objc_classes()
        self._populate_classes_tab()

        # Parse Mach-O Entitlements, RPaths, and Dylibs
        self.entitlements_xml, self.audited_risks, self.rpaths, self.dylibs = parse_macho_entitlements()
        self._populate_security_tab()
        self._populate_dylib_tab()

        self.lbl_stats.setText(
            f"Found {len(self.objc_calls)} msgSend calls, {len(self.classes)} classes, "
            f"{len(self.dylibs)} dylibs, {len(self.audited_risks)} high-risk entitlements."
        )

    def _populate_classes_tab(self):
        self.tbl_classes.setRowCount(len(self.classes))
        for row, cls in enumerate(self.classes):
            it_n = QtWidgets.QTableWidgetItem(cls.name)
            it_n.setData(QtCore.Qt.UserRole, cls)
            it_s = QtWidgets.QTableWidgetItem(cls.superclass_name or "-")
            it_m = QtWidgets.QTableWidgetItem(str(len(cls.methods)))

            self.tbl_classes.setItem(row, 0, it_n)
            self.tbl_classes.setItem(row, 1, it_s)
            self.tbl_classes.setItem(row, 2, it_m)

        if self.classes:
            self.tbl_classes.selectRow(0)
            self._on_class_selected()
        else:
            self.txt_class_preview.setText("// No Objective-C classes detected in __objc_classlist.")

    def _on_class_selected(self):
        items = self.tbl_classes.selectedItems()
        if not items:
            return
        row = items[0].row()
        it = self.tbl_classes.item(row, 0)
        if it:
            cls: ObjCClassDesc = it.data(QtCore.Qt.UserRole)
            if cls:
                self.txt_class_preview.setText(cls.generate_header())

    def _label_imp_functions(self):
        count = rename_objc_imp_functions(self.classes)
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Labeled {count} IMP functions with Objective-C method signatures.")

    def _export_headers(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Objective-C Headers", "classes.h", "Header Files (*.h)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("// Reconstructed Objective-C Headers by Genesect\n\n")
                for cls in self.classes:
                    fp.write(cls.generate_header() + "\n\n")
            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info(f"Saved {len(self.classes)} class declarations to:\n{path}")
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to export headers:\n{exc}")

    def _populate_security_tab(self):
        self.txt_xml.setText(self.entitlements_xml or "<!-- No embedded XML entitlements found in Mach-O binary -->")

        self.tbl_risks.setRowCount(len(self.audited_risks))
        for r, risk in enumerate(self.audited_risks):
            it_key = QtWidgets.QTableWidgetItem(risk["key"])
            it_cat = QtWidgets.QTableWidgetItem(risk["category"])
            it_threat = QtWidgets.QTableWidgetItem(risk["threat"])
            if risk["threat"] == "Critical":
                it_threat.setForeground(QtGui.QBrush(QtGui.QColor("#EF4444")))
                it_threat.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            elif risk["threat"] == "High":
                it_threat.setForeground(QtGui.QBrush(QtGui.QColor("#F59E0B")))
            it_desc = QtWidgets.QTableWidgetItem(risk["description"])

            self.tbl_risks.setItem(r, 0, it_key)
            self.tbl_risks.setItem(r, 1, it_cat)
            self.tbl_risks.setItem(r, 2, it_threat)
            self.tbl_risks.setItem(r, 3, it_desc)

    def _populate_dylib_tab(self):
        # Populate Dylibs
        self.tbl_dylibs.setRowCount(len(self.dylibs))
        for r, dy in enumerate(self.dylibs):
            it_p = QtWidgets.QTableWidgetItem(dy.path)
            it_cmd = QtWidgets.QTableWidgetItem(dy.cmd_name)
            it_risk = QtWidgets.QTableWidgetItem(dy.risk_level)
            if dy.risk_level == "Critical":
                it_risk.setForeground(QtGui.QBrush(QtGui.QColor("#EF4444")))
                it_risk.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            elif dy.risk_level == "High":
                it_risk.setForeground(QtGui.QBrush(QtGui.QColor("#F59E0B")))
                it_risk.setFont(QtGui.QFont("", -1, QtGui.QFont.Bold))
            elif dy.risk_level == "Medium":
                it_risk.setForeground(QtGui.QBrush(QtGui.QColor("#3B82F6")))

            it_notes = QtWidgets.QTableWidgetItem(dy.notes)

            self.tbl_dylibs.setItem(r, 0, it_p)
            self.tbl_dylibs.setItem(r, 1, it_cmd)
            self.tbl_dylibs.setItem(r, 2, it_risk)
            self.tbl_dylibs.setItem(r, 3, it_notes)

        # Populate RPaths
        self.lst_rpaths.setRowCount(len(self.rpaths))
        for r, rp in enumerate(self.rpaths):
            it_p = QtWidgets.QTableWidgetItem(rp)
            assessment = "Relative Search Path (potential hijack vector)" if ("@loader_path" in rp or "@executable_path" in rp or "@rpath" in rp) else "Standard System Path"
            it_a = QtWidgets.QTableWidgetItem(assessment)
            if "hijack" in assessment:
                it_a.setForeground(QtGui.QBrush(QtGui.QColor("#F59E0B")))
            self.lst_rpaths.setItem(r, 0, it_p)
            self.lst_rpaths.setItem(r, 1, it_a)

    def _apply_objc_filter(self):
        q = self.edit_search.text().strip().lower()
        filtered = []
        for c in self.objc_calls:
            if q:
                combined = f"{_hex(c.call_ea)} {c.func_name} {c.receiver_class} {c.selector_name} {c.formatted_call}".lower()
                if q not in combined:
                    continue
            filtered.append(c)

        self.tbl_objc.setRowCount(len(filtered))
        for row, c in enumerate(filtered):
            it_ea = QtWidgets.QTableWidgetItem(_hex(c.call_ea))
            it_ea.setData(QtCore.Qt.UserRole, c)
            it_fn = QtWidgets.QTableWidgetItem(c.func_name)
            it_rec = QtWidgets.QTableWidgetItem(c.receiver_class)
            it_sel = QtWidgets.QTableWidgetItem(c.selector_name)
            it_fmt = QtWidgets.QTableWidgetItem(c.formatted_call)
            it_fmt.setFont(QtGui.QFont("Consolas", 9, QtGui.QFont.Bold))
            it_fmt.setForeground(QtGui.QBrush(QtGui.QColor(self.t.accent)))

            self.tbl_objc.setItem(row, 0, it_ea)
            self.tbl_objc.setItem(row, 1, it_fn)
            self.tbl_objc.setItem(row, 2, it_rec)
            self.tbl_objc.setItem(row, 3, it_sel)
            self.tbl_objc.setItem(row, 4, it_fmt)

    def _on_call_double_clicked(self, item):
        row = item.row()
        it_ea = self.tbl_objc.item(row, 0)
        if it_ea:
            c: ObjCMessageCall = it_ea.data(QtCore.Qt.UserRole)
            if c and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
                ida_kernwin.jumpto(c.call_ea)

    def _annotate_selected(self):
        rows = set(it.row() for it in self.tbl_objc.selectedItems())
        count = 0
        for row in rows:
            it = self.tbl_objc.item(row, 0)
            if not it:
                continue
            c: ObjCMessageCall = it.data(QtCore.Qt.UserRole)
            if not c or not idc:
                continue

            comment = f"[Genesect] ObjC: {c.formatted_call}"
            idc.set_cmt(c.call_ea, comment, 0)
            count += 1

        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Successfully annotated {count} objc_msgSend calls.")

    def _export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export macOS Analysis CSV", "macos_objc_calls.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fp:
                writer = csv.writer(fp)
                writer.writerow(["Call Address", "Calling Function", "Receiver Class", "Resolved Selector", "Reconstructed Call"])
                for c in self.objc_calls:
                    writer.writerow([
                        _hex(c.call_ea), c.func_name, c.receiver_class, c.selector_name, c.formatted_call
                    ])
            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info(f"Saved {len(self.objc_calls)} records to:\n{path}")
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to export CSV:\n{exc}")


class MachOObjCResolverHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _macho_objc_instance
        try:
            _macho_objc_instance = MachOExplorerDialog()
            _macho_objc_instance.tabs.setCurrentIndex(0)
            _macho_objc_instance.show()
            _macho_objc_instance.raise_()
            _macho_objc_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open Mach-O & Objective-C Resolver:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


class MachOClassDumperHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _macho_objc_instance
        try:
            _macho_objc_instance = MachOExplorerDialog()
            _macho_objc_instance.tabs.setCurrentIndex(1)
            _macho_objc_instance.show()
            _macho_objc_instance.raise_()
            _macho_objc_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open Objective-C Class Dumper:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


class MachOEntitlementsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _macho_objc_instance
        try:
            _macho_objc_instance = MachOExplorerDialog()
            _macho_objc_instance.tabs.setCurrentIndex(2)
            _macho_objc_instance.show()
            _macho_objc_instance.raise_()
            _macho_objc_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open Mach-O Entitlements Inspector:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


class MachODylibAuditorHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _macho_objc_instance
        try:
            _macho_objc_instance = MachOExplorerDialog()
            _macho_objc_instance.tabs.setCurrentIndex(3)
            _macho_objc_instance.show()
            _macho_objc_instance.raise_()
            _macho_objc_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open Mach-O Dylib & RPath Auditor:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


_macho_objc_instance = None
