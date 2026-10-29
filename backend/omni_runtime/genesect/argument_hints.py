# -*- coding: utf-8 -*-
"""Hex-Rays function argument-name inlay hints with Windows API fallback.

The display behavior is inspired by milankovo/hexinlay (MIT), reimplemented
here with Genesect lifecycle, persistence, and bundled Windows API metadata.
"""
import os
import re
import xml.etree.ElementTree as ET

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


ACTION_ID = "genesect:argument_name_hints"
_hooks_instance = None
_enabled = False
_import_modules = None
_api_file_map = None
_api_module_cache = {}
_COLOR_ADDR = re.compile("\x01\\(([A-Fa-f0-9]{8,})")
_IMPORT_PREFIX = re.compile(r"^(?:__imp_|_imp__|imp_)", re.I)


def _config():
    from genesect.config import CONFIG
    return CONFIG


def _set_checked(enabled):
    setter = getattr(ida_kernwin, "set_action_checked", None)
    if callable(setter):
        try:
            setter(ACTION_ID, bool(enabled))
        except Exception:
            pass


def _function_arg_names(tinfo):
    """Read parameter names from IDA's effective function type."""
    if tinfo is None:
        return []
    try:
        value = idaapi.tinfo_t(tinfo)
    except Exception:
        value = tinfo
    try:
        value.remove_ptr_or_array()
        details = idaapi.func_type_data_t()
        if not value.get_func_details(details):
            return []
        return [str(argument.name or "") for argument in details]
    except Exception:
        return []


def _normalized_function_name(name):
    value = _IMPORT_PREFIX.sub("", str(name or "")).lstrip("_")
    return value.split("@", 1)[0]


def _build_import_module_map():
    global _import_modules
    if _import_modules is not None:
        return _import_modules
    result = {}
    try:
        for index in range(int(idaapi.get_import_module_qty())):
            module = str(idaapi.get_import_module_name(index) or "")

            def collect(ea, name, ordinal, module_name=module):
                result[int(ea)] = module_name
                return True

            idaapi.enum_import_names(index, collect)
    except Exception:
        pass
    _import_modules = result
    return result


def _api_files():
    global _api_file_map
    if _api_file_map is None:
        root = os.path.join(os.path.dirname(__file__), "API", "Windows")
        try:
            _api_file_map = {
                os.path.splitext(name)[0].lower(): os.path.join(root, name)
                for name in os.listdir(root) if name.lower().endswith(".xml")
            }
        except OSError:
            _api_file_map = {}
    return _api_file_map


def _load_api_module(module_name):
    """Lazily parse only the API XML corresponding to an imported DLL."""
    normalized = os.path.basename(str(module_name or "")).lower()
    normalized = normalized[:-4] if normalized.endswith(".dll") else normalized
    if normalized in _api_module_cache:
        return _api_module_cache[normalized]
    path = _api_files().get(normalized)
    functions = {}
    if path:
        try:
            root = ET.parse(path).getroot()
            for api in root.iter("Api"):
                name = str(api.get("Name") or "")
                if not name:
                    continue
                params = [str(node.get("Name") or "") for node in api.findall("Param")]
                functions[name.lower()] = params
                if str(api.get("BothCharset") or "").lower() == "true":
                    functions[(name + "A").lower()] = params
                    functions[(name + "W").lower()] = params
        except (OSError, ET.ParseError):
            functions = {}
    _api_module_cache[normalized] = functions
    return functions


# Fallback dictionary for common POSIX libc, Linux system calls, and macOS Foundation/Security APIs
POSIX_MACOS_API_HINTS = {
    # POSIX File I/O & Memory
    "open": ["pathname", "flags", "mode"],
    "creat": ["pathname", "mode"],
    "read": ["fd", "buf", "count"],
    "write": ["fd", "buf", "count"],
    "lseek": ["fd", "offset", "whence"],
    "close": ["fd"],
    "mmap": ["addr", "length", "prot", "flags", "fd", "offset"],
    "munmap": ["addr", "length"],
    "mprotect": ["addr", "len", "prot"],
    "brk": ["addr"],

    # Network / Sockets
    "socket": ["domain", "type", "protocol"],
    "bind": ["sockfd", "addr", "addrlen"],
    "connect": ["sockfd", "addr", "addrlen"],
    "listen": ["sockfd", "backlog"],
    "accept": ["sockfd", "addr", "addrlen"],
    "send": ["sockfd", "buf", "len", "flags"],
    "recv": ["sockfd", "buf", "len", "flags"],
    "sendto": ["sockfd", "buf", "len", "flags", "dest_addr", "addrlen"],
    "recvfrom": ["sockfd", "buf", "len", "flags", "src_addr", "addrlen"],
    "setsockopt": ["sockfd", "level", "optname", "optval", "optlen"],
    "getsockopt": ["sockfd", "level", "optname", "optval", "optlen"],

    # Process & Linux Kernel
    "clone": ["fn", "stack", "flags", "arg"],
    "fork": [],
    "execve": ["filename", "argv", "envp"],
    "execveat": ["dirfd", "pathname", "argv", "envp", "flags"],
    "kill": ["pid", "sig"],
    "ptrace": ["request", "pid", "addr", "data"],
    "prctl": ["option", "arg2", "arg3", "arg4", "arg5"],
    "memfd_create": ["name", "flags"],
    "process_vm_readv": ["pid", "local_iov", "liovcnt", "remote_iov", "riovcnt", "flags"],
    "process_vm_writev": ["pid", "local_iov", "liovcnt", "remote_iov", "riovcnt", "flags"],

    # Threads & Event Polling
    "pthread_create": ["thread", "attr", "start_routine", "arg"],
    "pthread_join": ["thread", "retval"],
    "pthread_mutex_lock": ["mutex"],
    "pthread_mutex_unlock": ["mutex"],
    "epoll_create": ["size"],
    "epoll_create1": ["flags"],
    "epoll_ctl": ["epfd", "op", "fd", "event"],
    "epoll_wait": ["epfd", "events", "maxevents", "timeout"],
    "poll": ["fds", "nfds", "timeout"],
    "select": ["nfds", "readfds", "writefds", "exceptfds", "timeout"],
    "dlopen": ["filename", "flags"],
    "dlsym": ["handle", "symbol"],
    "dlclose": ["handle"],

    # macOS CoreFoundation & Security
    "cfstringcreatewithcstring": ["alloc", "cStr", "encoding"],
    "cfstringgetcstring": ["theString", "buffer", "bufferSize", "encoding"],
    "cfrelease": ["cf"],
    "cfretain": ["cf"],
    "cfdictionarygetvalue": ["theDict", "key"],
    "cfdictionarysetvalue": ["theDict", "key", "value"],
    "secitemadd": ["attributes", "result"],
    "secitemcopymatching": ["query", "result"],
    "secitemupdate": ["query", "attributesToUpdate"],
    "secitemdelete": ["query"],
    "seckeychainopen": ["pathName", "keychain"],
    "smloginitemsetenabled": ["identifier", "enabled"],
    "smjobbless": ["domain", "executableLabel", "auth", "error"],
    "smjobsubmit": ["domain", "job", "auth", "error"],
    "cgeventcreatemouseevent": ["source", "mouseType", "mouseCursorPosition", "mouseButton"],
    "cgeventpost": ["tap", "event"],
    "axisprocesstrusted": [],
    "axisprocesstrustedwithoptions": ["options"],
    "dispatch_async": ["queue", "block"],
    "dispatch_sync": ["queue", "block"],
    "dispatch_once": ["predicate", "block"],
    "dispatch_queue_create": ["label", "attr"],
}


def _api_argument_names(target_ea, function_name):
    normalized = _normalized_function_name(function_name).lower()

    # 1. Check POSIX and macOS standard API hints dictionary
    if normalized in POSIX_MACOS_API_HINTS:
        return list(POSIX_MACOS_API_HINTS[normalized])

    # 2. Check Windows DLL XML definitions
    module = _build_import_module_map().get(int(target_ea), "")
    if not module:
        return []
    functions = _load_api_module(module)
    names = functions.get(normalized)
    if names is None and normalized.endswith(("a", "w")):
        names = functions.get(normalized[:-1])
    return list(names or [])


def _call_identity(call):
    target = call.x
    while target is not None and target.op == ida_hexrays.cot_cast:
        target = target.x
    if target is None or target.op != ida_hexrays.cot_obj:
        return idaapi.BADADDR, ""
    ea = int(target.obj_ea)
    return ea, _normalized_function_name(ida_name.get_name(ea) or "")


def _leftmost_argument_node(argument):
    node = argument
    while node is not None:
        if idaapi.is_binary(node.op):
            node = node.x
            continue
        if node.op in (ida_hexrays.cot_call, ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
            node = node.x
            continue
        return node
    return argument


def _redundant_hint(name, argument):
    try:
        node = argument
        while node.op in (ida_hexrays.cot_ref, ida_hexrays.cot_cast) and node.x is not None:
            node = node.x
        rendered = str(node.dstr() or "").strip()
        return bool(rendered and rendered == name)
    except Exception:
        return False


def _inject_hints(cfunc, index_to_name):
    pseudocode = cfunc.get_pseudocode()
    for i in range(len(pseudocode)):
        simple_line = pseudocode[i]
        used = set()

        def insert(match):
            index = int(match.group(1), 16)
            name = index_to_name.get(index)
            if not name or index in used:
                return match.group(0)
            used.add(index)
            tagged_hint = idaapi.COLSTR(name + ": ", idaapi.SCOLOR_AUTOCMT)
            if tagged_hint in simple_line.line:
                return match.group(0)
            return match.group(0) + tagged_hint

        new_line = _COLOR_ADDR.sub(insert, simple_line.line)
        if new_line != simple_line.line:
            simple_line.line = new_line
            pseudocode[i] = simple_line


class ArgumentNameHintHooks(ida_hexrays.Hexrays_Hooks if ida_hexrays else object):
    def __init__(self):
        if ida_hexrays and hasattr(ida_hexrays, "Hexrays_Hooks"):
            ida_hexrays.Hexrays_Hooks.__init__(self)

    def func_printed(self, cfunc):
        if not _enabled or not cfunc:
            return 0
        try:
            position_by_object = {item.obj_id: index for index, item in enumerate(cfunc.treeitems)}
            name_by_object = {}
            for item in cfunc.treeitems:
                if item.op != ida_hexrays.cot_call:
                    continue
                call = item.cexpr
                names = _function_arg_names(call.x.type)
                target_ea, function_name = _call_identity(call)
                if not any(names) and target_ea != idaapi.BADADDR:
                    names = _api_argument_names(target_ea, function_name)
                for index, argument in enumerate(call.a):
                    if index >= len(names) or not names[index] or _redundant_hint(names[index], argument):
                        continue
                    node = _leftmost_argument_node(argument)
                    name_by_object[node.obj_id] = names[index]
            index_to_name = {}
            for obj_id, name in name_by_object.items():
                index_to_name[obj_id] = name
                if obj_id in position_by_object:
                    index_to_name[position_by_object[obj_id]] = name
            if index_to_name:
                _inject_hints(cfunc, index_to_name)
        except Exception as exc:
            ida_kernwin.msg("[Genesect] Function argument hints skipped: %s\n" % exc)
        return 0


def refresh_open_pseudocode_views():
    get_count = getattr(ida_kernwin, "get_widget_qty", None)
    get_widget = getattr(ida_kernwin, "getn_widget", None)
    if not callable(get_count) or not callable(get_widget):
        idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)
        return
    try:
        for index in range(int(get_count())):
            widget = get_widget(index)
            if widget and idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                vu = ida_hexrays.get_widget_vdui(widget)
                if vu:
                    vu.refresh_view(True)
    except Exception as exc:
        ida_kernwin.msg("[Genesect] Could not refresh argument hints: %s\n" % exc)


def set_argument_name_hints_enabled(enabled, persist=True, refresh=True):
    global _enabled
    _enabled = bool(enabled)
    if persist:
        config = _config()
        config.argument_name_hints_enabled = _enabled
        config.save()
    _set_checked(_enabled)
    if refresh:
        refresh_open_pseudocode_views()
    return _enabled


def is_argument_name_hints_enabled():
    return bool(_enabled)


def create_argument_name_hint_hooks():
    global _hooks_instance
    if _hooks_instance is not None:
        return _hooks_instance
    if not ida_hexrays.init_hexrays_plugin():
        return None
    candidate = ArgumentNameHintHooks()
    if not candidate.hook():
        return None
    _hooks_instance = candidate
    set_argument_name_hints_enabled(
        getattr(_config(), "argument_name_hints_enabled", False), persist=False, refresh=False
    )
    return candidate


def destroy_argument_name_hint_hooks():
    global _hooks_instance, _enabled, _import_modules
    _enabled = False
    if _hooks_instance is not None:
        try:
            _hooks_instance.unhook()
        except Exception:
            pass
    _hooks_instance = None
    _import_modules = None


class ToggleArgumentNameHintsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        create_argument_name_hint_hooks()
        enabled = set_argument_name_hints_enabled(not _enabled)
        ida_kernwin.msg("[Genesect] Display function argument names %s\n" % ("enabled" if enabled else "disabled"))
        return 1

    def update(self, ctx):
        _set_checked(_enabled)
        return idaapi.AST_ENABLE_ALWAYS
