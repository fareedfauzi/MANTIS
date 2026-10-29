# -*- coding: utf-8 -*-
"""
Windows Driver & Rootkit Explorer.

Dedicated reverse engineering and capability triage engine for Windows kernel
drivers (.sys), rootkits, and BYOVD (Bring Your Own Vulnerable Driver) samples.

Provides:
1. Driver Framework & Subsystem Detection (WDM, KMDF/WDF, Minifilter, NDIS, WFP, PortCls)
2. Major Function Dispatch Table Mapping (IRP_MJ_* & DriverUnload with IDA enum annotation)
3. IOCTL Command & Dispatch Table Mapping (CTL_CODE decoding, AST/switch recovery, dangerous sinks)
4. Inbound vs Outbound IOCTL Separation (handled vs downstream forwarded requests)
5. Device Objects & Symbolic Link Identification (communication handles & SDDL ACL audit)
6. Kernel PoolTag Extraction & Dump (WinDbg-compatible pooltags.txt generator)
7. Rootkit & Privileged Primitives (DKOM, ObRegisterCallbacks, PreviousMode, port I/O, MSR/CR0)
8. Driver PE Exports Audit (identifying zero-xref exposed kernel interface functions)
9. Kernel Structure Auto-Typing (DRIVER_OBJECT, IRP, IO_STACK_LOCATION, WDFFUNCTIONS)
"""

from typing import Dict, List, Optional, Tuple, Any, Set
import csv
import io
import os
import re

try:
    import idaapi
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_typeinf
    import ida_ua
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_entry = None
    ida_funcs = None
    ida_ida = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None
    ida_typeinf = None
    ida_ua = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


_explorer_instance = None

# Known Windows Device Types (from devioctl.h)
DEVICE_TYPES = {
    0x0001: "FILE_DEVICE_BEEP",
    0x0002: "FILE_DEVICE_CD_ROM",
    0x0003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    0x0004: "FILE_DEVICE_CONTROLLER",
    0x0005: "FILE_DEVICE_DATALINK",
    0x0006: "FILE_DEVICE_DFS",
    0x0007: "FILE_DEVICE_DISK",
    0x0008: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x0009: "FILE_DEVICE_FILE_SYSTEM",
    0x000A: "FILE_DEVICE_INPORT_PORT",
    0x000B: "FILE_DEVICE_KEYBOARD",
    0x000C: "FILE_DEVICE_MAILSLOT",
    0x000D: "FILE_DEVICE_MIDI_IN",
    0x000E: "FILE_DEVICE_MIDI_OUT",
    0x000F: "FILE_DEVICE_MOUSE",
    0x0010: "FILE_DEVICE_MULTI_UNC_PROVIDER",
    0x0011: "FILE_DEVICE_NAMED_PIPE",
    0x0012: "FILE_DEVICE_NETWORK",
    0x0013: "FILE_DEVICE_NETWORK_BROWSER",
    0x0014: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    0x0015: "FILE_DEVICE_NULL",
    0x0016: "FILE_DEVICE_PARALLEL_PORT",
    0x0017: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x0018: "FILE_DEVICE_PRINTER",
    0x0019: "FILE_DEVICE_SCANNER",
    0x001A: "FILE_DEVICE_SERIAL_MOUSE_PORT",
    0x001B: "FILE_DEVICE_SERIAL_PORT",
    0x001C: "FILE_DEVICE_SCREEN",
    0x001D: "FILE_DEVICE_SOUND",
    0x001E: "FILE_DEVICE_STREAMS",
    0x001F: "FILE_DEVICE_TAPE",
    0x0020: "FILE_DEVICE_TAPE_FILE_SYSTEM",
    0x0021: "FILE_DEVICE_TRANSPORT",
    0x0022: "FILE_DEVICE_UNKNOWN",
    0x0023: "FILE_DEVICE_VIDEO",
    0x0024: "FILE_DEVICE_VIRTUAL_DISK",
    0x0025: "FILE_DEVICE_WAVE_IN",
    0x0026: "FILE_DEVICE_WAVE_OUT",
    0x0027: "FILE_DEVICE_8042_PORT",
    0x0028: "FILE_DEVICE_NETWORK_REDIRECTOR",
    0x0029: "FILE_DEVICE_BATTERY",
    0x002A: "FILE_DEVICE_BUS_EXTENDER",
    0x002B: "FILE_DEVICE_MODEM",
    0x002C: "FILE_DEVICE_VDM",
    0x002D: "FILE_DEVICE_MASS_STORAGE",
    0x002E: "FILE_DEVICE_SMB",
    0x002F: "FILE_DEVICE_KS",
    0x0030: "FILE_DEVICE_CHANGER",
    0x0031: "FILE_DEVICE_SMARTCARD",
    0x0032: "FILE_DEVICE_ACPI",
    0x0033: "FILE_DEVICE_DVD",
    0x0034: "FILE_DEVICE_FULLSCREEN_VIDEO",
    0x0035: "FILE_DEVICE_DFS_FILE_SYSTEM",
    0x0036: "FILE_DEVICE_DFS_VOLUME",
    0x0037: "FILE_DEVICE_SERENUM",
    0x0038: "FILE_DEVICE_TERMSRV",
    0x0039: "FILE_DEVICE_KSEC",
    0x003A: "FILE_DEVICE_FIPS",
    0x003B: "FILE_DEVICE_INFINIBAND",
}

TRANSFER_METHODS = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

REQUIRED_ACCESS = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_DATA",
    2: "FILE_WRITE_DATA",
    3: "FILE_READ_DATA | FILE_WRITE_DATA",
}

MAJOR_FUNCTIONS = {
    0x00: "IRP_MJ_CREATE",
    0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0C: "IRP_MJ_DIRECTORY_CONTROL",
    0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN",
    0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA",
    0x1A: "IRP_MJ_SET_QUOTA",
    0x1B: "IRP_MJ_PNP",
    0xFF: "DriverUnload",
}

# Dangerous kernel sinks reachable from IOCTL handlers
DANGEROUS_KERNEL_SINKS = {
    "MmMapIoSpace": "Physical memory mapping",
    "MmMapIoSpaceEx": "Physical memory mapping (Win10+)",
    "MmMapLockedPages": "MDL memory mapping",
    "MmMapLockedPagesSpecifyCache": "MDL memory mapping",
    "ZwMapViewOfSection": "Section view mapping",
    "ZwOpenSection": "Section handle open",
    "__writemsr": "Model Specific Register write",
    "__writecr0": "Control register CR0 write (WP disable)",
    "__writecr3": "Control register CR3 write (Page directory)",
    "__writecr4": "Control register CR4 write (SMEP/SMAP disable)",
    "HalGetBusDataByOffset": "PCI configuration read",
    "HalSetBusDataByOffset": "PCI configuration write",
    "ZwOpenProcess": "Process handle acquisition",
    "ZwTerminateProcess": "Process termination",
    "PsLookupProcessByProcessId": "EPROCESS pointer lookup",
    "ObRegisterCallbacks": "Handle rights stripping callback",
    "PsSetCreateProcessNotifyRoutine": "Process creation callback",
    "PsSetCreateThreadNotifyRoutine": "Thread creation callback",
    "PsSetLoadImageNotifyRoutine": "Image load callback",
    "FltRegisterFilter": "Minifilter registration",
}

# Outbound IOCTL dispatch APIs
OUTBOUND_IOCTL_APIS = {
    "IoBuildDeviceIoControlRequest",
    "ZwDeviceIoControlFile",
    "IoCallDriver",
    "IofCallDriver",
}

# Pool allocation APIs carrying tag arguments
POOL_TAG_APIS = {
    "ExAllocatePoolWithTag",
    "ExFreePoolWithTag",
    "ExAllocatePool2",
    "ExFreePool2",
    "ExAllocatePool3",
    "ExAllocatePoolWithTagPriority",
    "ExAllocatePoolWithQuotaTag",
    "ExAllocatePoolZero",
    "ExAllocatePoolQuotaZero",
    "ExAllocatePoolQuotaUninitialized",
    "ExAllocatePoolPriorityZero",
    "ExAllocatePoolPriorityUninitialized",
    "ExAllocatePoolUninitialized",
}


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


def _is_64bit() -> bool:
    return bool(ida_ida and hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit())


def decode_ioctl_code(code: int) -> Dict[str, Any]:
    """Deconstruct a 32-bit Windows CTL_CODE into standard driver bitfields."""
    code = int(code) & 0xFFFFFFFF
    method = code & 0x03
    function = (code >> 2) & 0x0FFF
    access = (code >> 14) & 0x03
    device = (code >> 16) & 0xFFFF

    dev_name = DEVICE_TYPES.get(device, "CUSTOM_DEVICE (0x%X)" % device if device >= 0x8000 else "DEVICE_0x%X" % device)
    method_name = TRANSFER_METHODS.get(method, "UNKNOWN_METHOD (%d)" % method)
    access_name = REQUIRED_ACCESS.get(access, "ACCESS_0x%X" % access)
    is_custom = bool(function >= 0x800)

    macro_str = "CTL_CODE(0x%X, 0x%X, %s, %s)" % (device, function, method_name, access_name)

    return {
        "code": code,
        "hex": "0x%08X" % code,
        "device": device,
        "device_name": dev_name,
        "function": function,
        "is_custom": is_custom,
        "method": method,
        "method_name": method_name,
        "access": access,
        "access_name": access_name,
        "macro": macro_str,
    }


def is_valid_ioctl_code(code: int) -> bool:
    """Check if a 32-bit integer conforms to a credible Windows IOCTL pattern."""
    code = int(code) & 0xFFFFFFFF
    if code < 0x10000 or code == 0xFFFFFFFF:
        return False
    dev = (code >> 16) & 0xFFFF
    func = (code >> 2) & 0x0FFF
    method = code & 0x03

    # Must have a recognized device type or vendor-defined range (0x8000 - 0xFFFF)
    if dev not in DEVICE_TYPES and not (0x8000 <= dev <= 0xFFFF):
        return False
    # Method must be 0..3
    if method not in (0, 1, 2, 3):
        return False
    # Custom driver IOCTLs predominantly use function code >= 0x800
    if func >= 0x800:
        return True
    # Standard MS IOCTLs
    if dev in (0x7, 0x22, 0x12, 0x9, 0x11, 0x14, 0x28):
        return True
    return False


def detect_driver_framework() -> Dict[str, Any]:
    """Detect Windows Driver architecture (KMDF/WDF, Minifilter, NDIS, WFP, PortCls, or WDM)."""
    detected_type = "WDM (Standard / Legacy)"
    indicators = []
    kmdf_version = ""

    if idautils:
        # Check imported APIs
        imported_names = set()
        for _, name in idautils.Names():
            clean = name.lstrip("_").split("@")[0]
            imported_names.add(clean)

        if "WdfVersionBind" in imported_names or "WdfVersionUnbind" in imported_names:
            detected_type = "KMDF / WDF Driver"
            indicators.append("Imports WdfVersionBind / WdfVersionUnbind")
        elif "FltRegisterFilter" in imported_names or "FltStartFiltering" in imported_names:
            detected_type = "File System Minifilter (FLTMGR)"
            indicators.append("Imports FltRegisterFilter")
        elif "NdisRegisterMiniportDriver" in imported_names or "NdisMRegisterMiniportDriver" in imported_names:
            detected_type = "NDIS Network Miniport Driver"
            indicators.append("Imports NdisMRegisterMiniportDriver")
        elif any(n.startswith("FwpsCalloutRegister") for n in imported_names):
            detected_type = "WFP Network Callout Driver"
            indicators.append("Imports FwpsCalloutRegister")
        elif "PcRegisterSubdevice" in imported_names or "StreamClassRegisterMinidriver" in imported_names:
            detected_type = "AVStream / PortCls Audio Driver"
            indicators.append("Imports PcRegisterSubdevice / StreamClassRegisterMinidriver")

        # Scan strings for KMDF version string
        strings = idautils.Strings()
        for s in strings:
            st = str(s).strip()
            if "KmdfLibrary" in st or "UmdfLibrary" in st:
                m = re.search(r"(?:Kmdf|Umdf)Library\s*(\d+\.\d+)?", st, re.I)
                if m and m.group(1):
                    kmdf_version = m.group(1)
                    detected_type = "KMDF / WDF Driver (v%s)" % kmdf_version
                    indicators.append("Found library string: %s" % st)
                    break

    # Entry point resolution (GsDriverEntry wrapper detection)
    entry_ea = None
    real_entry_ea = None
    if ida_nalt and hasattr(ida_nalt, "inf_get_start_ip"):
        entry_ea = ida_nalt.inf_get_start_ip()
    elif ida_ida and hasattr(ida_ida, "inf_get_start_ip"):
        entry_ea = ida_ida.inf_get_start_ip()

    if entry_ea and entry_ea != (idaapi.BADADDR if idaapi else -1):
        real_entry_ea = entry_ea
        entry_name = (idc.get_func_name(entry_ea) if idc else "") or ""
        # Check if entry is GsDriverEntry calling real entry
        if idautils and idc:
            calls = []
            for item_ea in idautils.FuncItems(entry_ea):
                if idc.print_insn_mnem(item_ea).lower() == "call":
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        if xref != item_ea and xref != entry_ea:
                            calls.append(xref)
            # Second call or call after security init is typically Real DriverEntry
            for c_ea in calls:
                target_name = (idc.get_func_name(c_ea) if idc else "").lower()
                if "__security" not in target_name and "cookie" not in target_name:
                    real_entry_ea = c_ea
                    break

    return {
        "framework": detected_type,
        "indicators": indicators,
        "kmdf_version": kmdf_version,
        "entry_ea": entry_ea,
        "real_entry_ea": real_entry_ea,
        "is_64bit": _is_64bit(),
    }


def trace_dangerous_sinks(func_ea: int, max_depth: int = 4) -> List[Dict[str, str]]:
    """BFS traversal from an IOCTL handler to identify reachable dangerous kernel sinks."""
    findings = []
    if not idautils or not func_ea:
        return findings

    queue = [(func_ea, [func_ea], 0)]
    visited = {func_ea}

    while queue:
        cur_ea, path, depth = queue.pop(0)
        cur_name = (idc.get_func_name(cur_ea) if idc else "") or ("sub_%X" % cur_ea)
        clean_name = cur_name.lstrip("_").split("@")[0]

        if clean_name in DANGEROUS_KERNEL_SINKS and cur_ea != func_ea:
            chain_str = " -> ".join((idc.get_func_name(p) if idc else ("sub_%X" % p)) for p in path)
            findings.append({
                "sink": clean_name,
                "description": DANGEROUS_KERNEL_SINKS[clean_name],
                "chain": chain_str,
                "target_ea": cur_ea,
            })
            if len(findings) >= 5:
                break

        if depth >= max_depth:
            continue

        for item_ea in idautils.FuncItems(cur_ea):
            for xref in idautils.CodeRefsFrom(item_ea, 0):
                if xref not in visited and ida_funcs and ida_funcs.get_func(xref):
                    visited.add(xref)
                    queue.append((xref, path + [xref], depth + 1))

    return findings


def scan_major_functions() -> List[Dict[str, Any]]:
    """Scan DriverEntry and helper routines for DriverObject->MajorFunction assignments."""
    results = []
    if not idautils or not ida_funcs:
        return results

    is_64 = _is_64bit()
    ptr_size = 8 if is_64 else 4
    # DriverObject structure offsets:
    # x64: DriverUnload = 0x68, MajorFunction[0] = 0x70
    # x86: DriverUnload = 0x34, MajorFunction[0] = 0x38
    mf_base = 0x70 if is_64 else 0x38
    unload_off = 0x68 if is_64 else 0x34

    # Determine driver entry functions to scan
    fw = detect_driver_framework()
    candidate_funcs = set()
    if fw["entry_ea"]:
        candidate_funcs.add(fw["entry_ea"])
    if fw["real_entry_ea"]:
        candidate_funcs.add(fw["real_entry_ea"])

    for func_ea in idautils.Functions():
        name = (idc.get_func_name(func_ea) if idc else "").lower()
        if any(k in name for k in ("driverentry", "real_driver", "gsdriver", "start", "init")):
            candidate_funcs.add(func_ea)

    seen_slots = set()

    for func_ea in candidate_funcs:
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        func_name = (idc.get_func_name(func_ea) if idc else "") or ("sub_%X" % func_ea)

        for item_ea in idautils.FuncItems(func_ea):
            if not ida_ua:
                continue
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, item_ea) <= 0:
                continue

            mnem = (idc.print_insn_mnem(item_ea) if idc else "").lower()
            if mnem != "mov":
                continue

            op0 = insn.ops[0]
            op1 = insn.ops[1]

            # Store to memory: mov [reg + disp], reg/imm
            disp = getattr(op0, "addr", 0)
            if op0.type in (getattr(ida_ua, "o_displ", 4), getattr(ida_ua, "o_phrase", 3)):
                slot_code = None
                slot_name = None

                if disp == unload_off:
                    slot_code = 0xFF
                    slot_name = "DriverUnload"
                elif mf_base <= disp < (mf_base + 28 * ptr_size):
                    idx = (disp - mf_base) // ptr_size
                    if idx in MAJOR_FUNCTIONS:
                        slot_code = idx
                        slot_name = MAJOR_FUNCTIONS[idx]

                if slot_code is not None and slot_code not in seen_slots:
                    # Find handler address
                    handler_ea = 0
                    if op1.type == getattr(ida_ua, "o_imm", 5):
                        handler_ea = op1.value
                    else:
                        # Check previous instruction for lea reg, target
                        prev_ea = idc.prev_head(item_ea) if idc else item_ea
                        p_insn = ida_ua.insn_t()
                        if p_insn and ida_ua.decode_insn(p_insn, prev_ea) > 0:
                            if p_insn.ops[1].type in (getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_imm", 5)):
                                handler_ea = p_insn.ops[1].addr or p_insn.ops[1].value

                    if handler_ea and ida_funcs.get_func(handler_ea):
                        seen_slots.add(slot_code)
                        h_name = (idc.get_func_name(handler_ea) if idc else "") or ("sub_%X" % handler_ea)
                        results.append({
                            "code": slot_code,
                            "name": slot_name,
                            "offset": "0x%X" % disp,
                            "handler_ea": int(handler_ea),
                            "handler_name": h_name,
                            "site_ea": int(item_ea),
                            "function": func_name,
                        })

    return sorted(results, key=lambda x: (x["code"] == 0xFF, x["code"]))


def annotate_irp_major_functions() -> Tuple[bool, str]:
    """Create IRP_MJ_FUNCTION IDA enum, set comments, and suggest renaming unnamed handlers."""
    if not idc:
        return False, "IDC module unavailable."

    enum_name = "IRP_MJ_FUNCTION"
    # Create enum
    eid = idc.get_enum(enum_name) if hasattr(idc, "get_enum") else idc.BADADDR
    if eid == idc.BADADDR or eid == -1:
        if hasattr(idc, "add_enum"):
            eid = idc.add_enum(-1, enum_name, 0)
            if eid != idc.BADADDR and hasattr(idc, "add_enum_member"):
                for val, name in MAJOR_FUNCTIONS.items():
                    if val != 0xFF:
                        idc.add_enum_member(eid, name, val, -1)

    annotated = 0
    major_funcs = scan_major_functions()
    for mf in major_funcs:
        site_ea = mf["site_ea"]
        handler_ea = mf["handler_ea"]
        name = mf["name"]

        # Set repeatable comment at assignment site
        comment = "%s -> %s" % (name, mf["handler_name"])
        if hasattr(idc, "set_cmt"):
            idc.set_cmt(site_ea, comment, 1)
            annotated += 1

        # Rename unnamed handler
        cur_h_name = idc.get_func_name(handler_ea) or ""
        if cur_h_name.startswith("sub_") and hasattr(idc, "set_name"):
            short_name = name.replace("IRP_MJ_", "Dispatch_")
            new_name = "%s_%X" % (short_name, handler_ea)
            idc.set_name(handler_ea, new_name, idc.SN_NOWARN)

    return True, "Applied IRP_MJ_FUNCTION enum and annotated %d dispatch slot(s)." % annotated


def scan_pool_tags() -> List[Dict[str, Any]]:
    """Scan pool allocation APIs to extract 4-byte pool tags and calling functions."""
    tags = []
    seen = set()
    if not idautils:
        return tags

    for api_ea, api_name in idautils.Names():
        clean_name = api_name.lstrip("_").split("@")[0]
        if clean_name in POOL_TAG_APIS:
            for xref in idautils.XrefsTo(api_ea, 0):
                call_ea = xref.frm
                caller_name = (idc.get_func_name(call_ea) if idc else "") or ("sub_%X" % call_ea)

                # Look back up to 15 instructions for tag argument
                cur = call_ea
                for _ in range(15):
                    cur = idc.prev_head(cur) if idc else cur - 1
                    if not cur or cur == idc.BADADDR:
                        break
                    if not ida_ua:
                        break
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, cur) <= 0:
                        continue

                    # Look for immediate value
                    for op in insn.ops:
                        if op.type == getattr(ida_ua, "o_imm", 5):
                            val = op.value & 0xFFFFFFFF
                            # Pool tags are 4 bytes with printable ASCII
                            b = [(val >> (8 * i)) & 0xFF for i in range(4)]
                            if all(0x20 <= x <= 0x7E for x in b):
                                # Little endian tag string representation
                                tag_ascii = "".join(chr(x) for x in b)
                                key = (tag_ascii, caller_name)
                                if key not in seen:
                                    seen.add(key)
                                    tags.append({
                                        "tag": tag_ascii,
                                        "tag_hex": "0x%08X" % val,
                                        "api": clean_name,
                                        "call_ea": int(call_ea),
                                        "site_ea": int(cur),
                                        "caller": caller_name,
                                    })
                                break

    return sorted(tags, key=lambda x: x["tag"])


def scan_privileged_opcodes() -> List[Dict[str, Any]]:
    """Scan executable segments for privileged CPU instructions (port I/O, MSR, CR*, DR*)."""
    findings = []
    if not idautils or not ida_segment or not ida_funcs:
        return findings

    OPCODE_RULES = [
        (re.compile(r"^\s*(?:in|out)\s+", re.I), "CRITICAL", "Hardware Port I/O (in / out)", "Direct port I/O instruction for hardware/chipset registers"),
        (re.compile(r"^\s*wrmsr\b", re.I), "CRITICAL", "MSR Tampering (wrmsr)", "Model Specific Register write instruction (syscall hooking / LSTAR)"),
        (re.compile(r"^\s*rdmsr\b", re.I), "HIGH", "MSR Read (rdmsr)", "Model Specific Register read instruction"),
        (re.compile(r"^\s*mov\s+cr\d\b", re.I), "CRITICAL", "Control Register Write (mov cr*)", "Modifying CR0/CR3/CR4 (write protection or page tables)"),
        (re.compile(r"^\s*mov\s+dr\d\b", re.I), "HIGH", "Debug Register Tampering (mov dr*)", "Reading or setting hardware debug registers"),
        (re.compile(r"^\s*(?:lgdt|lidt|sgdt|sidt)\b", re.I), "HIGH", "Descriptor Table Instruction", "Manipulating Global/Interrupt Descriptor Tables (GDT/IDT)"),
        (re.compile(r"^\s*(?:cli|sti|hlt|invd|wbinvd)\b", re.I), "MEDIUM", "Privileged CPU State Control", "Interrupt toggling or CPU cache invalidate/halt"),
    ]

    for func_ea in idautils.Functions():
        func_name = (idc.get_func_name(func_ea) if idc else "") or ("sub_%X" % func_ea)
        for item_ea in idautils.FuncItems(func_ea):
            disasm = (idc.generate_disasm_line(item_ea, 0) if idc else "") or (idc.GetDisasm(item_ea) if idc else "")
            for pattern, sev, name, desc in OPCODE_RULES:
                if pattern.search(disasm):
                    findings.append({
                        "severity": sev,
                        "category": "Privileged CPU Instructions",
                        "name": name,
                        "site_ea": int(item_ea),
                        "function": func_name,
                        "evidence": disasm.strip(),
                        "detail": desc,
                    })

    return findings


def scan_driver_exports_audit() -> List[Dict[str, Any]]:
    """Identify exported functions with zero internal cross-references."""
    exports = []
    if not idautils or not ida_entry:
        return exports

    qty = ida_entry.get_entry_qty() if hasattr(ida_entry, "get_entry_qty") else 0
    for i in range(qty):
        ordinal = ida_entry.get_entry_ordinal(i) if hasattr(ida_entry, "get_entry_ordinal") else i
        ea = ida_entry.get_entry(ordinal) if hasattr(ida_entry, "get_entry") else idaapi.BADADDR
        name = ida_entry.get_entry_name(ordinal) if hasattr(ida_entry, "get_entry_name") else ""
        if not name or ea == idaapi.BADADDR:
            continue

        # Check internal xrefs
        code_refs = list(idautils.CodeRefsTo(ea))
        data_refs = list(idautils.DataRefsTo(ea))
        total_refs = len(code_refs) + len(data_refs)

        is_unreferenced = (total_refs == 0 and name.lower() not in ("driverentry", "gsdriverentry", "start"))
        exports.append({
            "ordinal": ordinal,
            "name": name,
            "ea": int(ea),
            "refs_count": total_refs,
            "is_unreferenced": is_unreferenced,
            "status": "Exposed (0 internal xrefs)" if is_unreferenced else "Referenced internally",
        })

    return sorted(exports, key=lambda x: (not x["is_unreferenced"], x["ordinal"]))


def scan_ioctl_dispatch_map() -> List[Dict[str, Any]]:
    """Scan the binary for IOCTL codes, jump tables, switch statements, and handlers."""
    results = []
    seen_codes = set()
    if not idautils or not ida_funcs:
        return results

    # 1. Inspect switches and jump tables across all functions
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        func_name = (idc.get_func_name(func_ea) if idc else "") or ("sub_%X" % func_ea)

        for item_ea in idautils.FuncItems(func_ea):
            switch_info = ida_nalt.get_switch_info(item_ea) if ida_nalt else None
            if switch_info:
                cases_calc = getattr(ida_nalt, "calc_switch_cases", None) or getattr(idaapi, "calc_switch_cases", None)
                if cases_calc:
                    try:
                        case_res = cases_calc(item_ea, switch_info)
                        targets = list(getattr(case_res, "targets", []) or [])
                        cases = list(getattr(case_res, "cases", []) or [])
                        for idx, target in enumerate(targets):
                            case_vals = list(cases[idx]) if idx < len(cases) else []
                            for c_val in case_vals:
                                if is_valid_ioctl_code(c_val) and c_val not in seen_codes:
                                    seen_codes.add(c_val)
                                    decoded = decode_ioctl_code(c_val)
                                    sinks = trace_dangerous_sinks(target)
                                    sink_desc = ", ".join(s["sink"] for s in sinks[:2]) if sinks else "None"
                                    results.append({
                                        "code": decoded["code"],
                                        "hex": decoded["hex"],
                                        "macro": decoded["macro"],
                                        "device": decoded["device_name"],
                                        "function": "0x%X (%s)" % (decoded["function"], "Vendor" if decoded["is_custom"] else "System"),
                                        "method": decoded["method_name"],
                                        "access": decoded["access_name"],
                                        "direction": "Inbound (Handled)",
                                        "handler_ea": int(target),
                                        "handler_name": (idc.get_func_name(target) if idc else "") or ("sub_%X" % target),
                                        "containing_func": func_name,
                                        "site_ea": int(item_ea),
                                        "sinks": sink_desc,
                                        "source": "Switch Jump Table",
                                    })
                    except Exception:
                        pass

            # 2. Inspect comparison / immediate instructions
            if ida_ua:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, item_ea) > 0:
                    mnem = (idc.print_insn_mnem(item_ea) if idc else "").lower()
                    if mnem in ("cmp", "sub", "xor", "mov", "lea", "push"):
                        for op_idx in range(len(insn.ops)):
                            op = insn.ops[op_idx]
                            if op.type == getattr(ida_ua, "o_imm", 5):
                                imm_val = op.value
                                if is_valid_ioctl_code(imm_val) and imm_val not in seen_codes:
                                    seen_codes.add(imm_val)
                                    decoded = decode_ioctl_code(imm_val)
                                    # Check if outbound
                                    direction = "Inbound (Handled)"
                                    next_head = idc.next_head(item_ea) if idc else item_ea
                                    for xref in idautils.CodeRefsFrom(next_head, 0):
                                        target_name = idc.get_func_name(xref) if idc else ""
                                        if any(out_api in target_name for out_api in OUTBOUND_IOCTL_APIS):
                                            direction = "Outbound (Downstream Request)"
                                            break

                                    sinks = trace_dangerous_sinks(func_ea)
                                    sink_desc = ", ".join(s["sink"] for s in sinks[:2]) if sinks else "None"

                                    results.append({
                                        "code": decoded["code"],
                                        "hex": decoded["hex"],
                                        "macro": decoded["macro"],
                                        "device": decoded["device_name"],
                                        "function": "0x%X (%s)" % (decoded["function"], "Vendor" if decoded["is_custom"] else "System"),
                                        "method": decoded["method_name"],
                                        "access": decoded["access_name"],
                                        "direction": direction,
                                        "handler_ea": int(next_head),
                                        "handler_name": func_name,
                                        "containing_func": func_name,
                                        "site_ea": int(item_ea),
                                        "sinks": sink_desc,
                                        "source": "Immediate Comparison (%s)" % mnem.upper(),
                                    })

    return sorted(results, key=lambda x: x["code"])


def scan_device_objects_and_symlinks() -> List[Dict[str, Any]]:
    """Scan strings and API references for created device objects, symlinks, and ACL indicators."""
    devices = []
    seen = set()

    if idautils:
        strings = idautils.Strings()
        for s in strings:
            text = str(s).strip()
            if not text:
                continue
            lower = text.lower()
            if any(lower.startswith(p) for p in ("\\device\\", "\\dosdevices\\", "\\??\\", "\\\\.\\")):
                key = (text, int(s.ea))
                if key not in seen:
                    seen.add(key)
                    is_symlink = any(lower.startswith(p) for p in ("\\dosdevices\\", "\\??\\", "\\\\.\\"))
                    kind = "Symbolic Link (Userland Handle)" if is_symlink else "Device Object"

                    xrefs = list(idautils.DataRefsTo(s.ea))
                    caller_func = ""
                    call_site = s.ea
                    acl_info = "Default (Admin or System)"
                    if xrefs:
                        call_site = xrefs[0]
                        caller_func = idc.get_func_name(call_site) if idc else ""
                        # Inspect nearby API calls to determine ACL
                        func = ida_funcs.get_func(call_site) if ida_funcs else None
                        if func:
                            for item_ea in idautils.FuncItems(func.start_ea):
                                dis = (idc.generate_disasm_line(item_ea, 0) if idc else "").lower()
                                if "iocreatedevice" in dis and "secure" not in dis:
                                    acl_info = "IoCreateDevice (Potential World-Accessible)"
                                    break
                                elif "iocreatedevicesecure" in dis:
                                    acl_info = "IoCreateDeviceSecure (SDDL Protected)"
                                    break

                    devices.append({
                        "kind": kind,
                        "name": text,
                        "string_ea": int(s.ea),
                        "site_ea": int(call_site),
                        "function": caller_func or "<data reference>",
                        "acl": acl_info,
                    })

    return sorted(devices, key=lambda d: (d["kind"], d["name"]))


ROOTKIT_PRIMITIVE_RULES = [
    {
        "category": "DKOM & Process Token Manipulation",
        "name": "EPROCESS ActiveProcessLinks / Token Unlinking",
        "description": "Manipulating ActiveProcessLinks or Token pointer to conceal processes or elevate to SYSTEM",
        "patterns": [
            re.compile(r"\b(?:ActiveProcessLinks|Token|UniqueProcessId)\b", re.I),
            re.compile(r"\[(?:r..|e..)\s*\+\s*(?:188h|2e8h|448h|208h|358h|4b8h)\]", re.I),
        ],
        "apis": ["PsLookupProcessByProcessId", "PsLookupThreadByThreadId", "IoGetCurrentProcess"],
        "severity": "CRITICAL",
    },
    {
        "category": "DKOM / PreviousMode Bypass",
        "name": "KTHREAD PreviousMode Manipulation",
        "description": "Overwriting PreviousMode to KernelMode (0) to force Zw* APIs to bypass UserMode access checks",
        "patterns": [
            re.compile(r"PreviousMode", re.I),
            re.compile(r"\[(?:r..|e..)\s*\+\s*232h\]\s*,\s*0", re.I),
        ],
        "apis": ["KeGetCurrentThread"],
        "severity": "CRITICAL",
    },
    {
        "category": "EDR / Monitoring Evasion",
        "name": "Process/Thread/Image Kernel Notification Callbacks",
        "description": "Registering, enumerating, or unhooking process, thread, and image notification callbacks",
        "patterns": [],
        "apis": [
            "PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx", "PsSetCreateProcessNotifyRoutineEx2",
            "PsRemoveCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine", "PsRemoveCreateThreadNotifyRoutine",
            "PsSetLoadImageNotifyRoutine", "PsRemoveLoadImageNotifyRoutine",
        ],
        "severity": "HIGH",
    },
    {
        "category": "EDR / Security Neutralization",
        "name": "Object Callbacks (Handle Rights Stripping)",
        "description": "Registering ObRegisterCallbacks to intercept and strip PROCESS_TERMINATE rights from EDR/AV",
        "patterns": [],
        "apis": ["ObRegisterCallbacks", "ObUnRegisterCallbacks"],
        "severity": "HIGH",
    },
    {
        "category": "Privileged Registers & Syscall Hooks",
        "name": "MSR & Control Register Tampering (LSTAR / CR0 WP Disable)",
        "description": "Writing MSR 0xC0000082 (IA32_LSTAR) or clearing CR0.WP to overwrite read-only kernel code",
        "patterns": [
            re.compile(r"\bwrmsr\b", re.I),
            re.compile(r"mov\s+cr0\b", re.I),
            re.compile(r"mov\s+cr4\b", re.I),
            re.compile(r"mov\s+cr3\b", re.I),
            re.compile(r"C0000082h", re.I),
        ],
        "apis": ["__writemsr", "__writecr0", "__writecr3", "__writecr4"],
        "severity": "CRITICAL",
    },
    {
        "category": "Driver Signature Enforcement (DSE)",
        "name": "g_CiOptions & CI.dll Tampering",
        "description": "Scanning or patching g_CiOptions to disable Windows Driver Signature Enforcement (DSE)",
        "patterns": [
            re.compile(r"\b(?:g_CiOptions|CiValidateImageHeader|CI\.dll)\b", re.I),
        ],
        "apis": [],
        "severity": "CRITICAL",
    },
    {
        "category": "Physical Memory Mapping",
        "name": "Physical Memory / IO Space Mapping",
        "description": "Mapping raw physical RAM to read/write arbitrary kernel pages or bypass virtual protections",
        "patterns": [
            re.compile(r"\\Device\\PhysicalMemory", re.I),
        ],
        "apis": ["MmMapIoSpace", "MmMapIoSpaceEx", "ZwOpenSection"],
        "severity": "HIGH",
    },
    {
        "category": "File & Registry Stealth",
        "name": "Minifilter File System / Registry Interception",
        "description": "Registering file minifilter or registry callbacks to hide rootkit artifacts from userland",
        "patterns": [],
        "apis": [
            "FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter",
            "CmRegisterCallback", "CmRegisterCallbackEx", "CmUnRegisterCallback",
        ],
        "severity": "MEDIUM",
    },
]


def scan_rootkit_primitives() -> List[Dict[str, Any]]:
    """Scan IDB for kernel rootkit, DKOM, MSR, and privileged opcode primitives."""
    findings = []
    if not idautils:
        return findings

    # 1. Check imported APIs and calls
    for api_ea, api_name in idautils.Names():
        clean_name = api_name.lstrip("_").split("@")[0]
        for rule in ROOTKIT_PRIMITIVE_RULES:
            if clean_name in rule["apis"]:
                for xref in idautils.XrefsTo(api_ea, 0):
                    call_site = xref.frm
                    func_name = (idc.get_func_name(call_site) if idc else "") or ("sub_%X" % call_site)
                    findings.append({
                        "category": rule["category"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "site_ea": int(call_site),
                        "function": func_name,
                        "evidence": "API invocation: %s" % api_name,
                        "detail": rule["description"],
                    })

    # 2. Check rule patterns in disasm
    for func_ea in idautils.Functions():
        func_name = (idc.get_func_name(func_ea) if idc else "") or ("sub_%X" % func_ea)
        for item_ea in idautils.FuncItems(func_ea):
            disasm = (idc.generate_disasm_line(item_ea, 0) if idc else "") or (idc.GetDisasm(item_ea) if idc else "")
            for rule in ROOTKIT_PRIMITIVE_RULES:
                for pattern in rule["patterns"]:
                    if pattern.search(disasm):
                        findings.append({
                            "category": rule["category"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "site_ea": int(item_ea),
                            "function": func_name,
                            "evidence": "Instruction match: %s" % disasm.strip(),
                            "detail": rule["description"],
                        })

    # 3. Add privileged CPU control opcodes (in/out/cr*/dr*/lgdt/lidt)
    opcodes = scan_privileged_opcodes()
    findings.extend(opcodes)

    return sorted(findings, key=lambda f: (f["severity"] != "CRITICAL", f["severity"] != "HIGH", f["category"]))


def auto_type_kernel_structures() -> Tuple[bool, str]:
    """Load Windows Kernel Type Library and apply DRIVER_OBJECT prototypes."""
    if not ida_typeinf or not hasattr(ida_typeinf, "load_til"):
        return False, "IDA Type Information library (ida_typeinf) unavailable."

    til_loaded = False
    for til_name in ("ntkrnlmp.til", "ntospkr.til", "mssdk.til", "mssdk_win7.til"):
        try:
            til = ida_typeinf.load_til(til_name)
            if til:
                til_loaded = True
                break
        except Exception:
            pass

    applied_count = 0
    # Try typing DriverEntry if found
    if idautils and idc:
        fw = detect_driver_framework()
        targets = [fw["entry_ea"], fw["real_entry_ea"]]
        for ea in idautils.Functions():
            name = idc.get_func_name(ea) or ""
            if ea in targets or name.lower() in ("driverentry", "gsdriverentry", "_driverentry@8", "start"):
                proto = "NTSTATUS __stdcall %s(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);" % name
                if hasattr(idc, "SetType") and idc.SetType(ea, proto):
                    applied_count += 1

    msg = "Kernel types initialized (TIL loaded: %s). Auto-typed %d driver entrypoint(s)." % (til_loaded, applied_count)
    return True, msg


class DriverRootkitExplorerDialog(QtWidgets.QDialog):
    """Interactive multi-tab dialog for Driver and Rootkit analysis."""

    def __init__(self, parent=None):
        super(DriverRootkitExplorerDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - Windows Driver & Rootkit Explorer")
        self.resize(1240, 760)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.framework_info = {}
        self.major_funcs = []
        self.ioctls = []
        self.devices = []
        self.pooltags = []
        self.primitives = []
        self.exports = []

        self._setup_ui()
        QtCore.QTimer.singleShot(0, self.refresh_all)

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{
                background: {t.window};
                color: {t.text};
            }}
            QTabWidget::pane {{
                border: 1px solid {t.border};
                background: {t.surface};
                border-radius: 6px;
            }}
            QTabBar::tab {{
                background: {t.surface_alt};
                color: {t.text_muted};
                padding: 8px 16px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: 600;
            }}
            QTabBar::tab:selected {{
                background: {t.surface};
                color: {t.text};
                border-bottom: 2px solid {t.accent};
            }}
            QTableWidget {{
                background: {t.surface};
                color: {t.text};
                gridline-color: {t.border};
                border: none;
                selection-background-color: {t.accent};
                selection-color: white;
            }}
            QHeaderView::section {{
                background: {t.surface_alt};
                color: {t.text_muted};
                padding: 6px;
                font-weight: 700;
                border: none;
                border-bottom: 1px solid {t.border};
            }}
            QLineEdit {{
                background: {t.surface};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                padding: 6px 10px;
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        # Header
        header = PageHeader(
            "Windows Driver & Rootkit Explorer",
            "Kernel driver reverse engineering triage: dispatch tables, IOCTL maps, pool tags, and rootkit primitives."
        )

        btn_auto_type = QtWidgets.QPushButton("Auto-Type Kernel Structs")
        btn_auto_type.setToolTip("Load ntkrnlmp.til and apply DRIVER_OBJECT / IRP types in Hex-Rays")
        btn_auto_type.clicked.connect(self._run_auto_type)
        header.add_action(btn_auto_type)

        btn_annotate_mf = QtWidgets.QPushButton("Apply IRP_MJ Enum")
        btn_annotate_mf.setToolTip("Create IRP_MJ_FUNCTION enum, set comments, and label dispatch routines")
        btn_annotate_mf.clicked.connect(self._run_annotate_mf)
        header.add_action(btn_annotate_mf)

        btn_refresh = QtWidgets.QPushButton("Refresh All")
        btn_refresh.setProperty("pnVariant", "primary")
        btn_refresh.clicked.connect(self.refresh_all)
        header.add_action(btn_refresh)

        btn_export = QtWidgets.QPushButton("Export CSV")
        btn_export.clicked.connect(self._export_csv)
        header.add_action(btn_export)

        btn_pooltag_txt = QtWidgets.QPushButton("Export pooltags.txt")
        btn_pooltag_txt.setToolTip("Export dumped pool tags in standard WinDbg pooltags.txt format")
        btn_pooltag_txt.clicked.connect(self._export_pooltags_file)
        header.add_action(btn_pooltag_txt)

        root.addWidget(header)

        # Architecture & Framework Banner
        self.banner = Card()
        b_layout = QtWidgets.QHBoxLayout(self.banner)
        b_layout.setContentsMargins(12, 8, 12, 8)
        self.lbl_framework = QtWidgets.QLabel("Driver Framework: Detecting...")
        self.lbl_framework.setStyleSheet(f"font-weight: 700; color: {t.accent}; font-size: 10.5pt;")
        self.lbl_arch = QtWidgets.QLabel("Arch: Unknown")
        self.lbl_arch.setStyleSheet(f"color: {t.text_muted}; font-size: 9.5pt;")
        self.lbl_entry = QtWidgets.QLabel("Entrypoint: Unknown")
        self.lbl_entry.setStyleSheet(f"color: {t.text_muted}; font-size: 9.5pt;")

        b_layout.addWidget(self.lbl_framework)
        b_layout.addSpacing(20)
        b_layout.addWidget(self.lbl_arch)
        b_layout.addSpacing(20)
        b_layout.addWidget(self.lbl_entry)
        b_layout.addStretch(1)
        root.addWidget(self.banner)

        # Search Bar
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Filter across Major Functions, IOCTLs, pool tags, devices, or rootkit capabilities...")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._apply_filter)
        root.addWidget(self.search_edit)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()

        # Tab 1: Major Functions (IRP_MJ_* & DriverUnload)
        tab1 = QtWidgets.QWidget()
        l1 = QtWidgets.QVBoxLayout(tab1)
        l1.setContentsMargins(8, 8, 8, 8)
        self.tbl_major_funcs = self._create_table([
            "Slot / Index", "Major Function Name", "Offset in Object", "Handler EA", "Handler Function Name", "Assigned In"
        ])
        self.tbl_major_funcs.itemDoubleClicked.connect(self._jump_table_item)
        l1.addWidget(self.tbl_major_funcs)
        self.tabs.addTab(tab1, "Major Function Dispatch (IRP_MJ)")

        # Tab 2: IOCTLs & Dispatch Map
        tab2 = QtWidgets.QWidget()
        l2 = QtWidgets.QVBoxLayout(tab2)
        l2.setContentsMargins(8, 8, 8, 8)
        self.tbl_ioctls = self._create_table([
            "IOCTL Code", "Macro / CTL_CODE", "Direction", "Device Type", "Function Code", "Transfer Method", "Required Access", "Reachable Sinks", "Handler EA", "Handler Name"
        ])
        self.tbl_ioctls.itemDoubleClicked.connect(self._jump_table_item)
        l2.addWidget(self.tbl_ioctls)
        self.tabs.addTab(tab2, "IOCTL & Dispatch Map")

        # Tab 3: Devices & Symlinks
        tab3 = QtWidgets.QWidget()
        l3 = QtWidgets.QVBoxLayout(tab3)
        l3.setContentsMargins(8, 8, 8, 8)
        self.tbl_devices = self._create_table([
            "Kind", "Object / Symlink Name", "Security / ACL Audit", "String EA", "Reference EA", "Containing Function"
        ])
        self.tbl_devices.itemDoubleClicked.connect(self._jump_table_item)
        l3.addWidget(self.tbl_devices)
        self.tabs.addTab(tab3, "Device Objects & Symlinks")

        # Tab 4: Kernel Pool Tags
        tab4 = QtWidgets.QWidget()
        l4 = QtWidgets.QVBoxLayout(tab4)
        l4.setContentsMargins(8, 8, 8, 8)
        self.tbl_pooltags = self._create_table([
            "Pool Tag (ASCII)", "Tag (Hex)", "Allocation API", "Call Site EA", "Caller Function"
        ])
        self.tbl_pooltags.itemDoubleClicked.connect(self._jump_table_item)
        l4.addWidget(self.tbl_pooltags)
        self.tabs.addTab(tab4, "Kernel Pool Tags")

        # Tab 5: Rootkit & Privileged Primitives
        tab5 = QtWidgets.QWidget()
        l5 = QtWidgets.QVBoxLayout(tab5)
        l5.setContentsMargins(8, 8, 8, 8)
        self.tbl_primitives = self._create_table([
            "Severity", "Category", "Capability Name", "Address", "Function", "Evidence", "Description"
        ])
        self.tbl_primitives.itemDoubleClicked.connect(self._jump_table_item)
        l5.addWidget(self.tbl_primitives)
        self.tabs.addTab(tab5, "Rootkit & Privileged Primitives")

        # Tab 6: Driver Exports Audit
        tab6 = QtWidgets.QWidget()
        l6 = QtWidgets.QVBoxLayout(tab6)
        l6.setContentsMargins(8, 8, 8, 8)
        self.tbl_exports = self._create_table([
            "Ordinal", "Export Name", "Address", "Internal Cross-References", "Status"
        ])
        self.tbl_exports.itemDoubleClicked.connect(self._jump_table_item)
        l6.addWidget(self.tbl_exports)
        self.tabs.addTab(tab6, "Exported Attack Surface")

        root.addWidget(self.tabs, 1)

        # Bottom Bar
        bottom = QtWidgets.QHBoxLayout()
        self.status_lbl = QtWidgets.QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color: {t.text_muted}; font-size: 9.5pt;")
        bottom.addWidget(self.status_lbl)
        bottom.addStretch(1)

        btn_jump = QtWidgets.QPushButton("Jump in IDA")
        btn_jump.clicked.connect(self._jump_current_selected)
        bottom.addWidget(btn_jump)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)

        root.addLayout(bottom)

    def _create_table(self, headers: List[str]) -> QtWidgets.QTableWidget:
        tbl = QtWidgets.QTableWidget(0, len(headers))
        tbl.setHorizontalHeaderLabels(headers)
        tbl.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        tbl.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        tbl.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        tbl.setAlternatingRowColors(True)
        tbl.verticalHeader().setVisible(False)
        tbl.horizontalHeader().setStretchLastSection(True)
        return tbl

    def refresh_all(self):
        if ida_kernwin and hasattr(ida_kernwin, "show_wait_box"):
            ida_kernwin.show_wait_box("Analyzing Windows driver architecture & kernel dispatchers...\nPress Cancel to stop.")
        try:
            self.framework_info = detect_driver_framework()
            self.major_funcs = scan_major_functions()
            self.ioctls = scan_ioctl_dispatch_map()
            self.devices = scan_device_objects_and_symlinks()
            self.pooltags = scan_pool_tags()
            self.primitives = scan_rootkit_primitives()
            self.exports = scan_driver_exports_audit()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Driver Explorer error:\n%s" % exc)
        finally:
            if ida_kernwin and hasattr(ida_kernwin, "hide_wait_box"):
                ida_kernwin.hide_wait_box()

        # Update Banner
        self.lbl_framework.setText("Driver Framework: %s" % self.framework_info.get("framework", "Unknown"))
        self.lbl_arch.setText("Architecture: %s" % ("x64 (64-bit)" if self.framework_info.get("is_64bit") else "x86 (32-bit)"))
        entry_txt = "Entrypoint: " + (_hex(self.framework_info["entry_ea"]) if self.framework_info.get("entry_ea") else "Unknown")
        if self.framework_info.get("real_entry_ea") and self.framework_info["real_entry_ea"] != self.framework_info.get("entry_ea"):
            entry_txt += " -> Real: " + _hex(self.framework_info["real_entry_ea"])
        self.lbl_entry.setText(entry_txt)

        self._populate_major_funcs()
        self._populate_ioctls()
        self._populate_devices()
        self._populate_pooltags()
        self._populate_primitives()
        self._populate_exports()

        self.status_lbl.setText("Found %d major dispatchers, %d IOCTLs, %d devices, %d pool tags, %d rootkit indicators, %d exports." % (
            len(self.major_funcs), len(self.ioctls), len(self.devices), len(self.pooltags), len(self.primitives), len(self.exports)
        ))

    def _populate_major_funcs(self):
        self.tbl_major_funcs.setSortingEnabled(False)
        self.tbl_major_funcs.setRowCount(len(self.major_funcs))
        for r, item in enumerate(self.major_funcs):
            slot_str = "0x%02X" % item["code"] if item["code"] != 0xFF else "Unload"
            cols = [
                slot_str,
                item["name"],
                item["offset"],
                _hex(item["handler_ea"]),
                item["handler_name"],
                item["function"],
            ]
            for c, val in enumerate(cols):
                it = QtWidgets.QTableWidgetItem(str(val))
                if c == 3:
                    it.setData(QtCore.Qt.UserRole, int(item["handler_ea"]))
                self.tbl_major_funcs.setItem(r, c, it)
        self.tbl_major_funcs.setSortingEnabled(True)

    def _populate_ioctls(self):
        self.tbl_ioctls.setSortingEnabled(False)
        self.tbl_ioctls.setRowCount(len(self.ioctls))
        for r, item in enumerate(self.ioctls):
            cols = [
                item["hex"],
                item["macro"],
                item.get("direction", "Inbound (Handled)"),
                item["device"],
                item["function"],
                item["method"],
                item["access"],
                item.get("sinks", "None"),
                _hex(item["handler_ea"]),
                item["handler_name"],
            ]
            for c, val in enumerate(cols):
                it = QtWidgets.QTableWidgetItem(str(val))
                if c == 8:
                    it.setData(QtCore.Qt.UserRole, int(item["handler_ea"]))
                if "METHOD_NEITHER" in str(val) or "Inbound" in str(val):
                    it.setForeground(QtGui.QBrush(QtGui.QColor(self.t.accent)))
                self.tbl_ioctls.setItem(r, c, it)
        self.tbl_ioctls.setSortingEnabled(True)

    def _populate_devices(self):
        self.tbl_devices.setSortingEnabled(False)
        self.tbl_devices.setRowCount(len(self.devices))
        for r, item in enumerate(self.devices):
            cols = [
                item["kind"],
                item["name"],
                item.get("acl", "Default"),
                _hex(item["string_ea"]),
                _hex(item["site_ea"]),
                item["function"],
            ]
            for c, val in enumerate(cols):
                it = QtWidgets.QTableWidgetItem(str(val))
                if c in (3, 4):
                    it.setData(QtCore.Qt.UserRole, int(item["site_ea"]))
                self.tbl_devices.setItem(r, c, it)
        self.tbl_devices.setSortingEnabled(True)

    def _populate_pooltags(self):
        self.tbl_pooltags.setSortingEnabled(False)
        self.tbl_pooltags.setRowCount(len(self.pooltags))
        for r, item in enumerate(self.pooltags):
            cols = [
                item["tag"],
                item["tag_hex"],
                item["api"],
                _hex(item["call_ea"]),
                item["caller"],
            ]
            for c, val in enumerate(cols):
                it = QtWidgets.QTableWidgetItem(str(val))
                if c == 3:
                    it.setData(QtCore.Qt.UserRole, int(item["call_ea"]))
                self.tbl_pooltags.setItem(r, c, it)
        self.tbl_pooltags.setSortingEnabled(True)

    def _populate_primitives(self):
        self.tbl_primitives.setSortingEnabled(False)
        self.tbl_primitives.setRowCount(len(self.primitives))
        for r, item in enumerate(self.primitives):
            cols = [
                item["severity"],
                item["category"],
                item["name"],
                _hex(item["site_ea"]),
                item["function"],
                item["evidence"],
                item["detail"],
            ]
            for c, val in enumerate(cols):
                it = QtWidgets.QTableWidgetItem(str(val))
                if c == 0:
                    sev = item["severity"].upper()
                    if sev == "CRITICAL":
                        it.setForeground(QtGui.QBrush(QtGui.QColor(self.t.error)))
                    elif sev == "HIGH":
                        it.setForeground(QtGui.QBrush(QtGui.QColor(self.t.accent)))
                elif c == 3:
                    it.setData(QtCore.Qt.UserRole, int(item["site_ea"]))
                self.tbl_primitives.setItem(r, c, it)
        self.tbl_primitives.setSortingEnabled(True)

    def _populate_exports(self):
        self.tbl_exports.setSortingEnabled(False)
        self.tbl_exports.setRowCount(len(self.exports))
        for r, item in enumerate(self.exports):
            cols = [
                str(item["ordinal"]),
                item["name"],
                _hex(item["ea"]),
                str(item["refs_count"]),
                item["status"],
            ]
            for c, val in enumerate(cols):
                it = QtWidgets.QTableWidgetItem(str(val))
                if c == 2:
                    it.setData(QtCore.Qt.UserRole, int(item["ea"]))
                if item.get("is_unreferenced") and c == 4:
                    it.setForeground(QtGui.QBrush(QtGui.QColor(self.t.accent)))
                self.tbl_exports.setItem(r, c, it)
        self.tbl_exports.setSortingEnabled(True)

    def _apply_filter(self, text: str):
        text = text.lower().strip()
        tables = [
            self.tbl_major_funcs,
            self.tbl_ioctls,
            self.tbl_devices,
            self.tbl_pooltags,
            self.tbl_primitives,
            self.tbl_exports,
        ]
        for tbl in tables:
            for r in range(tbl.rowCount()):
                row_match = False
                for c in range(tbl.columnCount()):
                    it = tbl.item(r, c)
                    if it and text in it.text().lower():
                        row_match = True
                        break
                tbl.setRowHidden(r, not row_match if text else False)

    def _jump_table_item(self, item: QtWidgets.QTableWidgetItem):
        ea = item.data(QtCore.Qt.UserRole)
        if not ea:
            tbl = item.tableWidget()
            for c in range(tbl.columnCount()):
                cand = tbl.item(item.row(), c)
                if cand and cand.data(QtCore.Qt.UserRole):
                    ea = cand.data(QtCore.Qt.UserRole)
                    break
        if ea and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
            ida_kernwin.jumpto(int(ea))

    def _jump_current_selected(self):
        cur_tbl = self.tabs.currentWidget().findChild(QtWidgets.QTableWidget)
        if not cur_tbl:
            return
        sel = cur_tbl.selectedItems()
        if sel:
            self._jump_table_item(sel[0])

    def _run_auto_type(self):
        ok, msg = auto_type_kernel_structures()
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(msg)
        self.refresh_all()

    def _run_annotate_mf(self):
        ok, msg = annotate_irp_major_functions()
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(msg)
        self.refresh_all()

    def _export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save Driver Analysis Report", "driver_analysis.csv", "CSV Files (*.csv)"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["=== WINDOWS DRIVER & ROOTKIT REPORT ==="])
                writer.writerow(["Framework", self.framework_info.get("framework", "")])
                writer.writerow(["Architecture", "x64" if self.framework_info.get("is_64bit") else "x86"])
                writer.writerow([])

                writer.writerow(["--- MAJOR FUNCTION DISPATCH TABLE ---"])
                writer.writerow(["Index", "Major Function", "Offset", "Handler EA", "Handler Name", "Assigned In"])
                for mf in self.major_funcs:
                    writer.writerow([mf["code"], mf["name"], mf["offset"], _hex(mf["handler_ea"]), mf["handler_name"], mf["function"]])
                writer.writerow([])

                writer.writerow(["--- IOCTL & DISPATCH MAP ---"])
                writer.writerow(["Code", "Macro", "Direction", "Device", "Function", "Method", "Access", "Sinks", "Handler EA", "Handler Name"])
                for item in self.ioctls:
                    writer.writerow([
                        item["hex"], item["macro"], item.get("direction", ""), item["device"], item["function"],
                        item["method"], item["access"], item.get("sinks", ""), _hex(item["handler_ea"]), item["handler_name"]
                    ])
                writer.writerow([])

                writer.writerow(["--- DEVICE OBJECTS & SYMLINKS ---"])
                writer.writerow(["Kind", "Name", "ACL Audit", "String EA", "Site EA", "Function"])
                for item in self.devices:
                    writer.writerow([item["kind"], item["name"], item.get("acl", ""), _hex(item["string_ea"]), _hex(item["site_ea"]), item["function"]])
                writer.writerow([])

                writer.writerow(["--- KERNEL POOL TAGS ---"])
                writer.writerow(["Tag (ASCII)", "Tag (Hex)", "API", "Call EA", "Caller"])
                for item in self.pooltags:
                    writer.writerow([item["tag"], item["tag_hex"], item["api"], _hex(item["call_ea"]), item["caller"]])
                writer.writerow([])

                writer.writerow(["--- ROOTKIT & PRIVILEGED PRIMITIVES ---"])
                writer.writerow(["Severity", "Category", "Capability", "Address", "Function", "Evidence", "Description"])
                for item in self.primitives:
                    writer.writerow([item["severity"], item["category"], item["name"], _hex(item["site_ea"]), item["function"], item["evidence"], item["detail"]])
                writer.writerow([])

                writer.writerow(["--- EXPORTED ATTACK SURFACE ---"])
                writer.writerow(["Ordinal", "Name", "Address", "Internal Refs", "Status"])
                for item in self.exports:
                    writer.writerow([item["ordinal"], item["name"], _hex(item["ea"]), item["refs_count"], item["status"]])

            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info("Report exported successfully to:\n%s" % path)
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Failed to export report:\n%s" % exc)

    def _export_pooltags_file(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save WinDbg pooltags.txt", "pooltags.txt", "Text Files (*.txt)"
        )
        if not path:
            return

        try:
            bin_name = (ida_nalt.get_root_filename() if ida_nalt else "driver.sys") or "driver.sys"
            with open(path, "w", encoding="utf-8") as f:
                f.write("// Pooltags extracted by Genesect Windows Driver Explorer\n")
                f.write("// Format: Tag  - Binary - Description\n")
                for pt in self.pooltags:
                    f.write("%-4s - %s - %s (via %s)\n" % (pt["tag"], bin_name, pt["caller"], pt["api"]))

            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info("pooltags.txt exported successfully to:\n%s" % path)
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Failed to export pooltags.txt:\n%s" % exc)


class DriverRootkitExplorerHandler(idaapi.action_handler_t if idaapi else object):
    """Action handler launching the Windows Driver & Rootkit Explorer."""

    def activate(self, ctx):
        global _explorer_instance
        try:
            if _explorer_instance is None or not _explorer_instance.isVisible():
                _explorer_instance = DriverRootkitExplorerDialog()
            _explorer_instance.show()
            _explorer_instance.raise_()
            _explorer_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Failed to open Windows Driver & Rootkit Explorer:\n%s" % exc)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0
