# -*- coding: utf-8 -*-
"""
Genesect Decompiler Call Explainer.

Inspects decompiled function calls in Hex-Rays pseudocode, evaluates constant
arguments, decomposes bitmasks and enum values (open flags, mmap/mprotect RWX
protections, socket domains/types, ptrace requests, prctl options, signals),
and resolves raw Linux syscall(n, ...) invocations across x86-64, i386, and ARM64.

Rendered dynamically in Hex-Rays pseudocode comments during print without
polluting the IDA database. Inspired by FPSZ/ida-better-reverse.
"""

from typing import Dict, List, Optional, Tuple, Any
import re

try:
    import idaapi
    import ida_hexrays
    import ida_kernwin
    import ida_lines
    import ida_name
except ImportError:
    idaapi = None
    ida_hexrays = None
    ida_kernwin = None
    ida_lines = None
    ida_name = None

from genesect.linux_syscall_resolver import (
    SYSCALLS_X86_64,
    SYSCALLS_X86,
    SYSCALLS_ARM64,
)


ACTION_ID = "genesect:toggle_call_explanations"
_enabled = False
_hooks_instance = None


# -----------------------------------------------------------------------------
# Bitmask & Enum Dictionaries for Linux / POSIX APIs
# -----------------------------------------------------------------------------

OPEN_FLAGS = {
    0x00000000: "O_RDONLY",
    0x00000001: "O_WRONLY",
    0x00000002: "O_RDWR",
    0x00000040: "O_CREAT",
    0x00000080: "O_EXCL",
    0x00000100: "O_NOCTTY",
    0x00000200: "O_TRUNC",
    0x00000400: "O_APPEND",
    0x00000800: "O_NONBLOCK",
    0x00001000: "O_DSYNC",
    0x00002000: "FASYNC",
    0x00004000: "O_DIRECT",
    0x00008000: "O_LARGEFILE",
    0x00010000: "O_DIRECTORY",
    0x00020000: "O_NOFOLLOW",
    0x00040000: "O_NOATIME",
    0x00080000: "O_CLOEXEC",
    0x00101000: "O_SYNC",
    0x00200000: "O_PATH",
    0x00410000: "O_TMPFILE",
}

MMAP_PROT = {
    0x0: "PROT_NONE",
    0x1: "PROT_READ",
    0x2: "PROT_WRITE",
    0x4: "PROT_EXEC",
    0x01000000: "PROT_GROWSDOWN",
    0x02000000: "PROT_GROWSUP",
}

MMAP_FLAGS = {
    0x01: "MAP_SHARED",
    0x02: "MAP_PRIVATE",
    0x10: "MAP_FIXED",
    0x20: "MAP_ANONYMOUS",
    0x100: "MAP_GROWSDOWN",
    0x800: "MAP_DENYWRITE",
    0x1000: "MAP_EXECUTABLE",
    0x2000: "MAP_LOCKED",
    0x4000: "MAP_NORESERVE",
    0x8000: "MAP_POPULATE",
    0x10000: "MAP_NONBLOCK",
    0x20000: "MAP_STACK",
    0x40000: "MAP_HUGETLB",
    0x80000: "MAP_SYNC",
}

SOCKET_DOMAINS = {
    0: "AF_UNSPEC",
    1: "AF_UNIX/AF_LOCAL",
    2: "AF_INET (IPv4)",
    10: "AF_INET6 (IPv6)",
    16: "AF_NETLINK",
    17: "AF_PACKET",
    31: "AF_BLUETOOTH",
}

SOCKET_TYPES = {
    1: "SOCK_STREAM (TCP)",
    2: "SOCK_DGRAM (UDP)",
    3: "SOCK_RAW",
    4: "SOCK_RDM",
    5: "SOCK_SEQPACKET",
    6: "SOCK_DCCP",
    10: "SOCK_PACKET",
}

PTRACE_REQUESTS = {
    0: "PTRACE_TRACEME [Anti-Debug Check]",
    1: "PTRACE_PEEKTEXT",
    2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER",
    4: "PTRACE_POKETEXT",
    5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSER",
    7: "PTRACE_CONT",
    8: "PTRACE_KILL",
    9: "PTRACE_SINGLESTEP",
    16: "PTRACE_ATTACH [Process Injection]",
    17: "PTRACE_DETACH",
    24: "PTRACE_SYSCALL",
    0x4200: "PTRACE_SETOPTIONS",
    0x4201: "PTRACE_GETEVENTMSG",
    0x4202: "PTRACE_GETSIGINFO",
    0x4203: "PTRACE_SETSIGINFO",
    0x4204: "PTRACE_GETREGSET",
    0x4205: "PTRACE_SETREGSET",
    0x4206: "PTRACE_SEIZE",
}

PRCTL_OPTIONS = {
    1: "PR_SET_PDEATHSIG",
    2: "PR_GET_PDEATHSIG",
    3: "PR_GET_DUMPABLE",
    4: "PR_SET_DUMPABLE [Anti-Dump / Anti-Forensic]",
    15: "PR_SET_NAME",
    16: "PR_GET_NAME",
    22: "PR_SET_SECCOMP [Seccomp Sandbox]",
    28: "PR_SET_TIMERSLACK",
    35: "PR_SET_PTRACER",
    38: "PR_SET_NO_NEW_PRIVS [Priv-Esc Prevention]",
    55: "PR_SPEC_RESTRICT",
}

ACCESS_MODES = {
    0: "F_OK (File exists)",
    1: "X_OK (Executable)",
    2: "W_OK (Writable)",
    4: "R_OK (Readable)",
}

SIGNALS = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP [Debugger Trap]",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL [Forced Kill]",
    10: "SIGUSR1",
    11: "SIGSEGV [Segmentation Fault]",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM [Termination]",
    17: "SIGCHLD",
    18: "SIGCONT",
    19: "SIGSTOP",
    20: "SIGTSTP",
}


# -----------------------------------------------------------------------------
# Bitmask Decomposers
# -----------------------------------------------------------------------------

def decompose_bitmask(val: int, flag_map: Dict[int, str], zero_val: str = "") -> str:
    """Decomposes an integer into bitwise OR flags."""
    if val == 0 and zero_val:
        return zero_val
    matched = []
    # Check 0-value exact match first if present in map
    if val == 0 and 0 in flag_map:
        return flag_map[0]

    remaining = val
    # Sort flags descending by value to match compound bits first
    for flag_val in sorted(flag_map.keys(), reverse=True):
        if flag_val == 0:
            continue
        if (remaining & flag_val) == flag_val:
            matched.append(flag_map[flag_val])
            remaining &= ~flag_val

    if not matched:
        return hex(val)
    if remaining != 0:
        matched.append(hex(remaining))
    return " | ".join(matched)


def decompose_open_flags(flags: int) -> str:
    acc_mode = flags & 3
    acc_str = OPEN_FLAGS.get(acc_mode, hex(acc_mode))
    other_flags = flags & ~3
    if other_flags == 0:
        return acc_str
    other_str = decompose_bitmask(other_flags, {k: v for k, v in OPEN_FLAGS.items() if k > 3})
    return f"{acc_str} | {other_str}" if other_str else acc_str


def decompose_mmap_prot(prot: int) -> str:
    parts = []
    if prot == 0:
        return "PROT_NONE"
    if prot & 1:
        parts.append("PROT_READ")
    if prot & 2:
        parts.append("PROT_WRITE")
    if prot & 4:
        parts.append("PROT_EXEC")
    rem = prot & ~7
    if rem:
        parts.append(hex(rem))
    res = "|".join(parts)
    # Highlight dangerous RWX memory permissions
    if (prot & 7) == 7:
        res += " [CRITICAL: RWX INJECTION ALERT!]"
    elif (prot & 6) == 6:
        res += " [ALERT: W+X Execution]"
    return res


def decompose_socket_type(sock_type: int) -> str:
    base = sock_type & 0xFF
    base_str = SOCKET_TYPES.get(base, f"TYPE_{base}")
    flags = []
    if sock_type & 0x80000:
        flags.append("SOCK_CLOEXEC")
    if sock_type & 0x800:
        flags.append("SOCK_NONBLOCK")
    if flags:
        return f"{base_str} | {' | '.join(flags)}"
    return base_str


# -----------------------------------------------------------------------------
# Function Call Explanation Logic
# -----------------------------------------------------------------------------

def explain_call(
    func_name: str,
    args: List[Any],
    arch: str = "x86_64"
) -> Optional[str]:
    """
    Evaluates constant arguments of a function call and produces an explanation string.
    Works independently of IDA for pure unit testing.
    """
    clean_name = func_name.lower().lstrip("_").split("@")[0]

    # 1. Linux syscall(SYS_xxx, ...)
    if clean_name in ("syscall", "__syscall", "sys_call"):
        if not args:
            return None
        sys_num = args[0]
        if not isinstance(sys_num, int):
            return None

        # Resolve architecture syscall table
        table = SYSCALLS_X86_64
        if arch in ("x86", "i386", "i686"):
            table = SYSCALLS_X86
        elif arch in ("arm64", "aarch64", "arm", "arm32"):
            table = SYSCALLS_ARM64

        info = table.get(sys_num)
        if not info:
            return f"syscall({sys_num}) -> Unknown Linux Syscall"

        sys_name, category, danger, sig = info
        note = f"syscall({sys_num}) -> {sys_name}"
        if danger in ("Critical", "High"):
            note += f" [{danger}: {category}]"

        # Check if the invoked syscall has specialized argument decomposition
        sub_args = args[1:]
        if sys_name in ("sys_open", "sys_openat") and len(sub_args) >= 2:
            flag_idx = 1 if sys_name == "sys_open" else 2
            if flag_idx < len(sub_args) and isinstance(sub_args[flag_idx], int):
                note += f" (flags: {decompose_open_flags(sub_args[flag_idx])})"
        elif sys_name in ("sys_mmap", "sys_mprotect") and len(sub_args) >= 3:
            prot_val = sub_args[2] if sys_name == "sys_mmap" else sub_args[2]
            if isinstance(prot_val, int):
                note += f" (prot: {decompose_mmap_prot(prot_val)})"
        elif sys_name == "sys_ptrace" and sub_args and isinstance(sub_args[0], int):
            req_name = PTRACE_REQUESTS.get(sub_args[0], hex(sub_args[0]))
            note += f" (request: {req_name})"
        elif sys_name == "sys_prctl" and sub_args and isinstance(sub_args[0], int):
            opt_name = PRCTL_OPTIONS.get(sub_args[0], hex(sub_args[0]))
            note += f" (option: {opt_name})"

        return note

    # 2. open / openat
    if clean_name == "open" and len(args) >= 2:
        flags_val = args[1]
        if isinstance(flags_val, int):
            return f"flags: {decompose_open_flags(flags_val)}"
    elif clean_name == "openat" and len(args) >= 3:
        flags_val = args[2]
        if isinstance(flags_val, int):
            return f"flags: {decompose_open_flags(flags_val)}"

    # 3. mmap / mmap2
    if clean_name in ("mmap", "mmap2") and len(args) >= 4:
        prot_val = args[2]
        flags_val = args[3]
        parts = []
        if isinstance(prot_val, int):
            parts.append(f"prot: {decompose_mmap_prot(prot_val)}")
        if isinstance(flags_val, int):
            parts.append(f"flags: {decompose_bitmask(flags_val, MMAP_FLAGS)}")
        if parts:
            return ", ".join(parts)

    # 4. mprotect
    if clean_name == "mprotect" and len(args) >= 3:
        prot_val = args[2]
        if isinstance(prot_val, int):
            return f"prot: {decompose_mmap_prot(prot_val)}"

    # 5. socket
    if clean_name == "socket" and len(args) >= 2:
        domain_val = args[0]
        type_val = args[1]
        parts = []
        if isinstance(domain_val, int):
            dom_str = SOCKET_DOMAINS.get(domain_val, f"AF_{domain_val}")
            parts.append(f"domain: {dom_str}")
        if isinstance(type_val, int):
            parts.append(f"type: {decompose_socket_type(type_val)}")
        if parts:
            return ", ".join(parts)

    # 6. ptrace
    if clean_name == "ptrace" and len(args) >= 1:
        req_val = args[0]
        if isinstance(req_val, int):
            req_str = PTRACE_REQUESTS.get(req_val, f"PTRACE_{req_val}")
            return f"request: {req_str}"

    # 7. prctl
    if clean_name == "prctl" and len(args) >= 1:
        opt_val = args[0]
        if isinstance(opt_val, int):
            opt_str = PRCTL_OPTIONS.get(opt_val, f"PR_{opt_val}")
            return f"option: {opt_str}"

    # 8. access / faccessat
    if clean_name == "access" and len(args) >= 2:
        mode_val = args[1]
        if isinstance(mode_val, int):
            mode_str = ACCESS_MODES.get(mode_val, hex(mode_val))
            return f"mode: {mode_str}"
    elif clean_name == "faccessat" and len(args) >= 3:
        mode_val = args[2]
        if isinstance(mode_val, int):
            mode_str = ACCESS_MODES.get(mode_val, hex(mode_val))
            return f"mode: {mode_str}"

    # 9. kill / tkill / tgkill / signal
    if clean_name in ("kill", "tkill") and len(args) >= 2:
        sig_val = args[1]
        if isinstance(sig_val, int):
            sig_str = SIGNALS.get(sig_val, f"SIG_{sig_val}")
            return f"sig: {sig_str}"
    elif clean_name == "tgkill" and len(args) >= 3:
        sig_val = args[2]
        if isinstance(sig_val, int):
            sig_str = SIGNALS.get(sig_val, f"SIG_{sig_val}")
            return f"sig: {sig_str}"
    elif clean_name == "signal" and len(args) >= 1:
        sig_val = args[0]
        if isinstance(sig_val, int):
            sig_str = SIGNALS.get(sig_val, f"SIG_{sig_val}")
            return f"sig: {sig_str}"

    return None


# -----------------------------------------------------------------------------
# IDA Hex-Rays Decompiler Hooks & Annotation Injector
# -----------------------------------------------------------------------------

def _extract_cfunc_arch():
    """Detect current IDA binary architecture."""
    if not idaapi:
        return "x86_64"
    try:
        proc = idaapi.get_inf_structure().procname.lower()
        if "arm" in proc or "aarch" in proc:
            return "arm64" if idaapi.get_inf_structure().is_64bit() else "arm"
        if idaapi.get_inf_structure().is_64bit():
            return "x86_64"
        return "x86"
    except Exception:
        return "x86_64"


def _constant_num_val(expr) -> Optional[int]:
    """Extract constant integer from a Hex-Rays cexpr_t node."""
    if not expr:
        return None
    try:
        node = expr
        while node.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref) and node.x is not None:
            node = node.x
        if node.op == ida_hexrays.cot_num:
            return int(node.n._val)
        if node.op == ida_hexrays.cot_obj:
            return None
    except Exception:
        pass
    return None


class CallExplainerHooks(ida_hexrays.Hexrays_Hooks if ida_hexrays else object):
    def __init__(self):
        if ida_hexrays and hasattr(ida_hexrays, "Hexrays_Hooks"):
            ida_hexrays.Hexrays_Hooks.__init__(self)

    def func_printed(self, cfunc):
        if not _enabled or not cfunc or not ida_hexrays:
            return 0
        try:
            arch = _extract_cfunc_arch()
            explanations_by_ea = {}

            # Walk ctree to find cot_call expressions with constant parameters
            for item in cfunc.treeitems:
                if item.op != ida_hexrays.cot_call:
                    continue
                call = item.cexpr
                if not call or not call.x:
                    continue

                # Get called function name
                func_name = ""
                if call.x.op == ida_hexrays.cot_obj:
                    func_name = ida_name.get_name(call.x.obj_ea)
                elif call.x.op == ida_hexrays.cot_helper:
                    func_name = str(call.x.helper or "")
                if not func_name:
                    func_name = str(call.x.dstr() or "")

                if not func_name:
                    continue

                # Extract constant arguments
                arg_values = []
                for a in call.a:
                    val = _constant_num_val(a)
                    arg_values.append(val if val is not None else str(a.dstr() or ""))

                note = explain_call(func_name, arg_values, arch=arch)
                if note and call.ea != idaapi.BADADDR:
                    explanations_by_ea[call.ea] = note

            if not explanations_by_ea:
                return 0

            # Inject end-of-line explanations into printed pseudocode
            pseudocode = cfunc.get_pseudocode()
            for line_idx in range(len(pseudocode)):
                simple_line = pseudocode[line_idx]
                # Look for matching call address in line's tagged addresses
                for ea, note in explanations_by_ea.items():
                    ea_hex = f"{ea:X}"
                    if ea_hex in simple_line.line or ea in getattr(simple_line, "sl_eas", []):
                        tag = idaapi.COLSTR(f"  /* {note} */", idaapi.SCOLOR_AUTOCMT)
                        if tag not in simple_line.line:
                            simple_line.line += tag
                            pseudocode[line_idx] = simple_line
                        break
        except Exception as exc:
            if ida_kernwin:
                ida_kernwin.msg(f"[Genesect] Call Explainer skipped: {exc}\n")
        return 0


def set_call_explanations_enabled(enabled: bool, persist: bool = True, refresh: bool = True) -> bool:
    global _enabled
    _enabled = bool(enabled)
    try:
        from genesect.config import CONFIG
        CONFIG.call_explanations_enabled = _enabled
        if persist:
            CONFIG.save()
    except Exception:
        pass

    if ida_kernwin:
        setter = getattr(ida_kernwin, "set_action_checked", None)
        if callable(setter):
            try:
                setter(ACTION_ID, bool(_enabled))
            except Exception:
                pass

    if refresh and ida_kernwin:
        from genesect.argument_hints import refresh_open_pseudocode_views
        refresh_open_pseudocode_views()

    return _enabled


def is_call_explanations_enabled() -> bool:
    return bool(_enabled)


def create_call_explainer_hooks():
    global _hooks_instance
    if _hooks_instance is not None:
        return _hooks_instance
    if not ida_hexrays or not ida_hexrays.init_hexrays_plugin():
        return None
    hooks = CallExplainerHooks()
    if not hooks.hook():
        return None
    _hooks_instance = hooks
    try:
        from genesect.config import CONFIG
        init_enabled = getattr(CONFIG, "call_explanations_enabled", True)
    except Exception:
        init_enabled = True
    set_call_explanations_enabled(init_enabled, persist=False, refresh=False)
    return hooks


def destroy_call_explainer_hooks():
    global _hooks_instance, _enabled
    _enabled = False
    if _hooks_instance is not None:
        try:
            _hooks_instance.unhook()
        except Exception:
            pass
    _hooks_instance = None


class ToggleCallExplanationsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        create_call_explainer_hooks()
        enabled = set_call_explanations_enabled(not _enabled)
        if ida_kernwin:
            ida_kernwin.msg(
                f"[Genesect] Dynamic Call Explanations & Bitmasks {'enabled' if enabled else 'disabled'}\n"
            )
        return 1

    def update(self, ctx):
        if ida_kernwin:
            setter = getattr(ida_kernwin, "set_action_checked", None)
            if callable(setter):
                setter(ACTION_ID, bool(_enabled))
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0
