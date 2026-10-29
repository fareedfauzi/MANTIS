"""Classification, triage and layout helpers for the Genesect workspace exporter.

Nothing in here imports IDA, so everything can be unit tested with plain Python.
The IDA-facing collection code lives in :mod:`genesect.ai_workspace_export`.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Iterable, Optional

# --------------------------------------------------------------------------
# Modules (folders under ``modules/``)
# --------------------------------------------------------------------------

MODULE_ENTRY = "00_entry_runtime"
MODULE_NETWORK = "01_network_c2"
MODULE_CRYPTO = "02_crypto_encoding"
MODULE_EVASION = "03_evasion_injection"
MODULE_SYSTEM = "04_system_files"
MODULE_STEALER = "05_stealer_credentials"
MODULE_PERSISTENCE = "06_persistence_autorun"
MODULE_DISCOVERY = "07_discovery_recon"
MODULE_LATERAL = "08_lateral_movement"
MODULE_COMPRESSION = "09_compression_archive"
MODULE_DRIVER = "10_driver_kernel_ipc"
MODULE_GUI = "11_gui_interface"
MODULE_LIBRARY = "98_library_thunks"
MODULE_UTILITY = "99_utilities"

MODULE_ORDER = [
    MODULE_ENTRY, MODULE_NETWORK, MODULE_CRYPTO, MODULE_EVASION,
    MODULE_SYSTEM, MODULE_STEALER, MODULE_PERSISTENCE, MODULE_DISCOVERY,
    MODULE_LATERAL, MODULE_COMPRESSION, MODULE_DRIVER, MODULE_GUI,
    MODULE_LIBRARY, MODULE_UTILITY,
]

MODULE_DESCRIPTIONS = {
    MODULE_ENTRY: "Entry points, DllMain/main, TLS callbacks and C runtime start-up.",
    MODULE_NETWORK: "Sockets, WinINet/WinHTTP, DNS, URLs and anything that looks like C2 or beaconing.",
    MODULE_CRYPTO: "Ciphers, hashes, encoders (Base64, XOR loops) and key handling.",
    MODULE_EVASION: "Process injection, dynamic API resolution, anti-debugging and memory tricks.",
    MODULE_SYSTEM: "File system, registry, processes, and general operating system helpers.",
    MODULE_STEALER: "Keyloggers, clipboard monitors, browser vault theft, DPAPI and credential harvesting.",
    MODULE_PERSISTENCE: "Windows services, scheduled tasks, Run/RunOnce keys, and auto-start handlers.",
    MODULE_DISCOVERY: "Host profiling, network/share enumeration, user discovery and environment recon.",
    MODULE_LATERAL: "Named pipes, remote RPC, remote service control, and lateral movement.",
    MODULE_COMPRESSION: "Zlib, LZMA, Cabinet (CAB), ZIP extraction and data packing/unpacking.",
    MODULE_DRIVER: "DeviceIoControl, driver loading, raw disk access, and kernel IPC.",
    MODULE_GUI: "Windows message loops, dialog boxes, window creation, menus and UI controls.",
    MODULE_LIBRARY: "Library code recognised by FLIRT and import thunks. Rarely interesting.",
    MODULE_UTILITY: "Everything else: helpers with no strong behavioural signal.",
}

# Tie-break order when multiple modules score.
_MODULE_PRIORITY = [
    MODULE_STEALER,
    MODULE_PERSISTENCE,
    MODULE_LATERAL,
    MODULE_DRIVER,
    MODULE_NETWORK,
    MODULE_CRYPTO,
    MODULE_EVASION,
    MODULE_COMPRESSION,
    MODULE_DISCOVERY,
    MODULE_SYSTEM,
    MODULE_GUI,
]

ENTRY_NAME_RE = re.compile(
    r"^(?:_?start|_?main|_?wmain|_?winmain|_?wwinmain|dllmain|_?dllentrypoint|_?dllmaincrtstartup|"
    r"_?maincrtstartup|_?winmaincrtstartup|_?wmaincrtstartup|_?wwinmaincrtstartup|_?tmaincrtstartup|"
    r"__?tmaincrtstartup|tlscallback_\w+|_?_?scrt_\w+|_?initterm\w*|_?cinit|_?_?security_init_cookie|"
    r"_?crt_init|_?_?crtexitprocess|_?_?crtdllmain\w*|_?rtc_\w+|_?_?native_startup_state|"
    r"_?_?acrt_\w+|_?_?vcrt_\w+)$",
    re.I,
)


# --------------------------------------------------------------------------
# Import capabilities
# --------------------------------------------------------------------------

_IMPORT_PREFIX_RE = re.compile(r"^(?:__imp_|_imp__|_imp_|imp_|j_)+", re.I)
_STDCALL_SUFFIX_RE = re.compile(r"@\d+$")


def normalize_import(name: str) -> str:
    """Strip IDA/MSVC decoration: ``__imp__send@16`` -> ``send``."""
    text = _IMPORT_PREFIX_RE.sub("", str(name or "").strip())
    text = _STDCALL_SUFFIX_RE.sub("", text)
    return text.lstrip("_")


def _compile(names: Iterable[str], prefixes: Iterable[str] = ()) -> "re.Pattern[str]":
    parts = []
    exact = "|".join(re.escape(n) for n in names)
    if exact:
        # Win32 A/W/Ex variants are folded into the base name.
        parts.append(r"(?:%s)(?:ex)?[aw]?" % exact)
    parts.extend(prefixes)
    return re.compile(r"^(?:%s)$" % "|".join(parts), re.I)


_CAPABILITY_PATTERNS = {
    "network": _compile(
        ["socket", "connect", "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept",
         "closesocket", "getaddrinfo", "getnameinfo", "gethostname", "select", "setsockopt", "ioctlsocket",
         "getsockname", "shutdown", "dnsquery", "urldownloadtofile", "urldownloadtocachefile",
         "internetopen", "internetopenurl", "internetconnect", "internetreadfile",
         "internetwritefile", "internetclosehandle", "httpopenrequest", "httpsendrequest",
         "httpqueryinfo", "ftpputfile", "ftpgetfile", "ftpopen", "recvmsg", "sendmsg",
         "epoll_create", "epoll_ctl", "epoll_wait", "kqueue", "kevent", "pcap_open_live",
         "res_query", "inet_ntop", "inet_pton"],
        [r"wsa\w+", r"gethostby\w+", r"inet_\w+", r"winhttp\w+", r"curl_\w+", r"dns\w+query\w*",
         r"internet\w+", r"http\w*request\w*", r"wininet\w*", r"urlmon\w*"],
    ),
    "crypto": _compile(
        ["cryptacquirecontext", "cryptreleasecontext", "cryptcreatehash", "crypthashdata",
         "cryptderivekey", "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptimportkey",
         "cryptexportkey", "cryptgenrandom", "cryptdestroykey", "cryptdestroyhash",
         "cryptstringtobinary", "cryptbinarytostring", "cryptprotectdata",
         "rtlgenrandom", "systemfunction032", "systemfunction033",
         "cc_sha256_init", "cccrypt", "cccryptorcreate", "seckeyencrypt", "seckeydecrypt",
         "secitemcopymatching", "crypto_secretbox", "crypto_box"],
        [r"bcrypt\w+", r"ncrypt\w+", r"evp_\w+", r"aes_\w+", r"rsa_\w+", r"sha\d*_\w+",
         r"md5_\w+", r"rc4\w*", r"crypt\w+"],
    ),
    "injection": _compile(
        ["virtualallocex", "writeprocessmemory", "readprocessmemory", "createremotethread",
         "createremotethreadex", "ntcreatethreadex", "zwcreatethreadex", "rtlcreateuserthread",
         "queueuserapc", "ntqueueapcthread", "ntqueueapcthreadex", "zwqueueapcthread",
         "setthreadcontext", "wow64setthreadcontext", "ntsetcontextthread", "zwsetcontextthread",
         "ntgetcontextthread", "zwgetcontextthread", "ntunmapviewofsection",
         "zwunmapviewofsection", "ntmapviewofsection", "zwmapviewofsection", "ntwritevirtualmemory",
         "zwwritevirtualmemory", "ntallocatevirtualmemory", "zwallocatevirtualmemory",
         "ntprotectvirtualmemory", "zwprotectvirtualmemory", "openprocess", "ntopenprocess",
         "zwopenprocess", "suspendthread", "resumethread", "ntresumethread", "zwresumethread",
         "createprocessinternal", "createprocessinternalw", "createprocessinternala",
         "ntcreatesection", "zwcreatesection", "ntcreateuserprocess", "zwcreateuserprocess",
         "ntcreatetransaction", "ptrace", "process_vm_readv", "process_vm_writev", "memfd_create",
         "task_for_pid", "mach_vm_write", "mach_vm_read", "mach_vm_allocate", "mach_vm_protect",
         "thread_create_running", "task_threads", "thread_set_state", "thread_get_state",
         "task_get_special_port", "posix_spawn", "posix_spawnp"],
        [r"nt.*thread\w*", r"zw.*thread\w*", r"nt.*section\w*", r"zw.*section\w*", r"mach_vm_\w+"],
    ),
    "anti_debug": _compile(
        ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
         "zwqueryinformationprocess", "ntsetinformationthread", "zwsetinformationthread",
         "debugactiveprocess", "outputdebugstring", "ntquerysysteminformation",
         "zwquerysysteminformation", "blockinput", "ntdelayexecution", "zwdelayexecution",
         "ptrace", "sysctl", "sysctlbyname", "proc_pidinfo", "ami_being_debugged"],
    ),
    "dynamic_resolve": _compile(
        ["getprocaddress", "ldrgetprocedureaddress", "loadlibrary", "loadlibraryex",
         "ldrloaddll", "getmodulehandle", "getmodulehandleex", "dlsym", "dlopen", "freelibrary",
         "dlclose", "dlinfo"],
    ),
    "memory": _compile(
        ["virtualalloc", "virtualalloc2", "virtualprotect", "virtualprotectex",
         "virtualprotectfromapp", "virtualfree", "ntfreevirtualmemory", "zwfreevirtualmemory",
         "heapcreate", "heapalloc", "mmap", "mprotect", "munmap", "posix_memalign",
         "mach_vm_allocate", "vm_allocate"],
    ),
    "resource": _compile(
        ["findresource", "findresourceex", "loadresource", "lockresource", "sizeofresource"],
        [r"findresource\w*"],
    ),
    "stealer": _compile(
        ["cryptunprotectdata", "openclipboard", "getclipboarddata", "getasynckeystate",
         "getkeystate", "getkeyboardstate", "setwindowshook", "bitblt", "getdibits",
         "getdc", "vaultcli", "vaultgetinformation", "pstorecreateinstance",
         "seckeychainsearchcopynext", "secitemcopymatching", "seckeychaincopydefault",
         "getspnam", "getpwnam", "pam_authenticate"],
    ),
    "persistence": _compile(
        ["openscmanager", "createservice", "startservice", "controlservice", "deleteservice",
         "openservice", "changeserviceconfig", "startservicectrldispatcher",
         "registerservicectrlhandler", "queryserviceconfig", "systemctl", "launchctl", "crontab",
         "init_module", "finit_module", "delete_module", "kextload", "kextunload"],
        [r"schtasks\w*"],
    ),
    "discovery": _compile(
        ["getcomputername", "getusername", "getsysteminfo", "getnativesysteminfo",
         "getversion", "rtlgetversion", "getadaptersinfo", "getadaptersaddresses",
         "getsystemdirectory", "getwindowsdirectory", "getvolumeinformation",
         "globalmemorystatus", "globalmemorystatusex", "getlogicaldrives", "uname",
         "getdisktype", "netshareenum", "netserverenum", "netuserenum", "netlocalgroupenum",
         "wnetopenenum", "netgetjoininformation", "gethostid", "getdomainname",
         "getifaddrs", "getlogin", "getpwuid", "statfs", "fstatfs", "statvfs"],
    ),
    "lateral": _compile(
        ["createnamedpipe", "connectnamedpipe", "callnamedpipe", "transactnamedpipe",
         "waitnamedpipe", "disconnectnamedpipe", "peeknamedpipe",
         "rpcbindingfromstringbinding", "rpcserveruseprotseq", "rpcserverregisterif",
         "wnetaddconnection"],
        [r"rpc\w+"],
    ),
    "compression": _compile(
        ["deflate", "inflate", "compress", "decompress", "uncompress",
         "setupiteratecabinet", "fdicreate", "fdiopen", "fdiread", "fdicopy", "fdidestroy",
         "lzmadecode", "lzmaencode", "rtlcompressbuffer", "rtldecompressbuffer"],
    ),
    "driver": _compile(
        ["deviceiocontrol", "zwloaddriver", "ntloaddriver", "zwunloaddriver", "ntunloaddriver",
         "ioctl", "init_module", "finit_module", "delete_module", "kextload", "kextunload",
         "ioserviceopen", "ioconnectcallmethod", "ioconnectcallscalarmethod"],
    ),
    "gui": _compile(
        ["createwindow", "createwindowex", "registerclass", "registerclassex", "getmessage",
         "dispatchmessage", "translatemessage", "defwindowproc", "dialogboxparam",
         "createdialogparam", "messagebox", "shell_notifyicon", "loadmenu", "loadicon",
         "loadcursor", "showwindow", "updatewindow", "postquitmessage"],
    ),
    "file": _compile(
        ["createfile", "readfile", "writefile", "deletefile", "copyfile", "movefile",
         "findfirstfile", "findnextfile", "gettemppath", "gettempfilename", "createdirectory",
         "removedirectory", "setfileattributes", "getfileattributes", "ntcreatefile",
         "fopen", "fread", "fwrite", "unlink", "getfilesize", "setfilepointer",
         "createfilemapping", "mapviewoffile", "shfileoperation",
         "open", "creat", "read", "write", "close", "stat", "lstat", "fstat",
         "chmod", "fchmod", "chown", "fchown", "mknod", "symlink", "readlink"],
    ),
    "registry": _compile(
        ["ntopenkey", "ntsetvaluekey", "ntcreatekey", "shgetvalue", "shsetvalue", "shdeletekey",
         "shdeletevalue"],
        [r"reg\w+"],
    ),
    "process": _compile(
        ["createprocess", "createprocessasuser", "createprocesswithlogon", "winexec",
         "shellexecute", "system", "popen", "execve", "execl", "fork", "vfork", "execvp",
         "execv", "terminateprocess", "createtoolhelp32snapshot", "process32first",
         "process32next", "thread32first", "thread32next", "enumprocesses", "enumprocessmodules",
         "openprocesstoken", "adjusttokenprivileges", "lookupprivilegevalue",
         "impersonateloggedonuser", "duplicatetoken", "duplicatehandle", "ntduplicateobject",
         "createmutex", "openmutex", "posix_spawn", "waitpid", "sigaction", "pipe", "dup2"],
    ),
    "system_info": _compile(
        ["getcomputername", "getusername", "getsysteminfo", "getnativesysteminfo",
         "getversion", "rtlgetversion", "getadaptersinfo", "getadaptersaddresses",
         "getsystemdirectory", "getwindowsdirectory", "getvolumeinformation",
         "globalmemorystatus", "globalmemorystatusex", "getlogicaldrives", "uname",
         "getdisktype", "getcurrentdirectory", "sysctl", "sysctlbyname"],
    ),
    "input_capture": _compile(
        ["getasynckeystate", "getkeystate", "getkeyboardstate", "getclipboarddata",
         "openclipboard", "bitblt", "getdibits", "getforegroundwindow", "getwindowtext"],
    ),
    "service": _compile(
        ["openscmanager", "createservice", "startservice", "controlservice", "deleteservice",
         "openservice", "changeserviceconfig", "startservicectrldispatcher",
         "registerservicectrlhandler", "queryserviceconfig"],
    ),
}

# capability -> (module, weight)
CAPABILITY_MODULE = {
    "network": (MODULE_NETWORK, 3.0),
    "crypto": (MODULE_CRYPTO, 3.0),
    "injection": (MODULE_EVASION, 3.0),
    "anti_debug": (MODULE_EVASION, 2.0),
    "dynamic_resolve": (MODULE_EVASION, 2.0),
    "memory": (MODULE_EVASION, 0.5),
    "resource": (MODULE_EVASION, 2.0),
    "stealer": (MODULE_STEALER, 3.0),
    "input_capture": (MODULE_STEALER, 3.0),
    "persistence": (MODULE_PERSISTENCE, 3.0),
    "service": (MODULE_PERSISTENCE, 3.0),
    "lateral": (MODULE_LATERAL, 3.0),
    "driver": (MODULE_DRIVER, 3.0),
    "compression": (MODULE_COMPRESSION, 3.0),
    "discovery": (MODULE_DISCOVERY, 2.5),
    "system_info": (MODULE_DISCOVERY, 2.5),
    "gui": (MODULE_GUI, 2.0),
    "file": (MODULE_SYSTEM, 1.0),
    "registry": (MODULE_SYSTEM, 1.5),
    "process": (MODULE_SYSTEM, 1.5),
}

CAPABILITY_ORDER = list(_CAPABILITY_PATTERNS)


def capabilities_of_import(name: str) -> list[str]:
    base = normalize_import(name)
    if not base:
        return []
    return [cap for cap, pattern in _CAPABILITY_PATTERNS.items() if pattern.match(base)]


def group_imports_by_capability(imports: Iterable[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in imports:
        caps = capabilities_of_import(item.get("name", "")) or ["other"]
        for cap in caps:
            grouped[cap].append(item)
    return {cap: grouped[cap] for cap in [*CAPABILITY_ORDER, "other"] if cap in grouped}


# --------------------------------------------------------------------------
# String classification
# --------------------------------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>]+", re.I)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(
    r"\b[a-z0-9-]{2,}(?:\.[a-z0-9-]{2,})*\.(?:com|net|org|info|ru|cn|xyz|top|io|biz|co|onion|tk|cc|me|club|site|online)\b",
    re.I,
)
_REGISTRY_RE = re.compile(
    r"(?:HKEY_[A-Z_]+|\bHK(?:LM|CU|CR|U)\b)\\?|\\CurrentVersion\\Run|\\CurrentControlSet\\|^Software\\Microsoft\\",
    re.I,
)
_PATH_RE = re.compile(
    r"(?:\b[A-Za-z]:\\|%[A-Za-z_]+%\\?|\\\\[\w.$-]+\\|(?:^|\s)/(?:etc|tmp|var|usr|bin|home|Library|Applications|System|dev|proc|sys)/)"
)
_COMMAND_RE = re.compile(
    r"\bcmd(?:\.exe)?\s*/[ck]\b|\bpowershell(?:\.exe)?\b|\bpwsh\b|\bwscript\b|\bcscript\b|\bmshta\b|"
    r"\brundll32\b|\bregsvr32\b|\bcertutil\b|\bbitsadmin\b|\bschtasks\b|\bwmic\b|"
    r"-enc(?:odedcommand)?\b|/bin/(?:ba)?sh\b|\blaunchctl\b|\bsystemctl\b|\bcrontab\b|"
    r"\biptables\b|\bufw\b|\bosascript\b|\bcurl\s+-[fsSLkO]|\bwget\s+|\b(?:nc|ncat|netcat|socat)\b",
    re.I,
)
_USERAGENT_RE = re.compile(r"Mozilla/\d|User-Agent:|\bcurl/\d|\bWinHTTP\b", re.I)
_HTTP_RE = re.compile(r"^(?:GET|POST|PUT|HEAD|DELETE)\s|\bHTTP/1\.[01]\b|\bContent-Type:", re.I)
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_PIPE_RE = re.compile(r"\\\\(?:\.|\w+)\\pipe\\[\w.$-]+", re.I)
_DEVICE_RE = re.compile(r"\\\\(?:\.|\?)\\(?:PhysicalDrive\d+|Volume\{[0-9a-f-]+\}|[A-Za-z]:|[\w._-]+)", re.I)
_STEALER_TARGET_RE = re.compile(
    r"\b(?:Login Data|Web Data|cookies\.sqlite|key4\.db|logins\.json|wallet\.dat|Discord[\\/]Tokens|Telegram Desktop|Foxmail)\b|"
    r"(?:\.ssh/(?:id_rsa|id_ed25519|known_hosts)|\.aws/credentials|/etc/(?:shadow|passwd)|login\.keychain(?:-db)?|"
    r"\.config/(?:google-chrome|chromium)/|\.mozilla/firefox/)",
    re.I,
)
_PERSIST_RE = re.compile(
    r"\\CurrentVersion\\(?:Run|RunOnce|Winlogon|Explorer\\Shell Folders)|\\Startup\\|schtasks(?:\.exe)?\s*/create|"
    r"/(?:etc|lib)/systemd/system/|/(?:Library|System/Library)/Launch(?:Agents|Daemons)/|"
    r"~/Library/LaunchAgents/|launchctl\s+(?:load|bootstrap|submit)|/etc/cron\.|/var/spool/cron|"
    r"/etc/init\.d/|/etc/rc\.local",
    re.I,
)

# string category -> (module, weight)
_STRING_MODULE = {
    "url": (MODULE_NETWORK, 2.0),
    "ip": (MODULE_NETWORK, 2.0),
    "domain": (MODULE_NETWORK, 1.5),
    "useragent": (MODULE_NETWORK, 2.0),
    "http": (MODULE_NETWORK, 2.0),
    "base64_alphabet": (MODULE_CRYPTO, 3.0),
    "stealer_target": (MODULE_STEALER, 3.0),
    "persistence": (MODULE_PERSISTENCE, 3.0),
    "named_pipe": (MODULE_LATERAL, 3.0),
    "device_driver": (MODULE_DRIVER, 3.0),
    "registry": (MODULE_SYSTEM, 2.0),
    "path": (MODULE_SYSTEM, 1.0),
    "command": (MODULE_SYSTEM, 2.0),
}


def classify_string(text: str) -> list[str]:
    value = str(text or "")
    if not value:
        return []
    found = []
    if _URL_RE.search(value):
        found.append("url")
    if _IPV4_RE.search(value):
        found.append("ip")
    if "url" not in found and _DOMAIN_RE.search(value):
        found.append("domain")
    if _USERAGENT_RE.search(value):
        found.append("useragent")
    if _HTTP_RE.search(value):
        found.append("http")
    if _PIPE_RE.search(value):
        found.append("named_pipe")
    if _DEVICE_RE.search(value):
        found.append("device_driver")
    if _STEALER_TARGET_RE.search(value):
        found.append("stealer_target")
    if _PERSIST_RE.search(value):
        found.append("persistence")
    if _REGISTRY_RE.search(value):
        found.append("registry")
    if _PATH_RE.search(value):
        found.append("path")
    if _COMMAND_RE.search(value):
        found.append("command")
    if _B64_ALPHABET[:40] in value or ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" in value and "0123456789+/" in value):
        found.append("base64_alphabet")
    return found


# --------------------------------------------------------------------------
# Pseudocode scanning
# --------------------------------------------------------------------------

_CRYPTO_CONSTANTS = {
    "0x67452301": "MD5/SHA-1 initial state",
    "0xefcdab89": "MD5/SHA-1 initial state",
    "0x5a827999": "SHA-1 round constant",
    "0x6a09e667": "SHA-256 initial state",
    "0x428a2f98": "SHA-256 round constant",
    "0x9e3779b9": "TEA/XTEA/RC5 delta",
    "0x61707865": "ChaCha/Salsa20 'expand' constant",
    "0xedb88320": "CRC-32 polynomial",
    "0x243f6a88": "Blowfish pi constant",
    "0xd76aa478": "MD5 round constant",
    "0x63, 0x7c, 0x77, 0x7b": "AES S-box",
    "0x637c777b": "AES S-box",
}
_LOOP_RE = re.compile(r"\b(?:for|while|do)\b")
_XOR_RE = re.compile(r"\^=|[^\^]\^[^\^=]")
_RC4_RE = re.compile(r"%\s*256\b|&\s*0xFFu?\b", re.I)
_GPA_TARGET_RE = re.compile(r"GetProcAddress\w*\s*\([^,()]+,\s*\"([^\"]{1,64})\"")
_DYN_API_RE = re.compile(r"\b(?:GetProcAddress|LdrGetProcedureAddress|LoadLibrary\w*|LdrLoadDll|dlsym|dlopen)\b")
_STACK_BUFFER_RE = re.compile(
    r"^\s*(?:(?:const|volatile|unsigned|signed|struct|union)\s+)*"
    r"(?P<type>[A-Za-z_]\w*(?:\s*\*)*)\s+\**(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<count>\d+)\s*\]\s*;",
    re.M,
)
_ELEMENT_SIZES = {
    "char": 1, "_byte": 1, "byte": 1, "__int8": 1, "bool": 1, "_bool": 1, "uchar": 1, "int8": 1,
    "_word": 2, "word": 2, "wchar": 2, "wchar_t": 2, "__int16": 2, "short": 2, "int16": 2,
    "_dword": 4, "dword": 4, "int": 4, "__int32": 4, "float": 4, "long": 4, "int32": 4, "uint": 4,
    "_qword": 8, "qword": 8, "__int64": 8, "double": 8, "int64": 8, "size_t": 8, "ulonglong": 8,
}
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def stack_buffers(text: str, min_bytes: int = 256) -> list[dict]:
    found = []
    for match in _STACK_BUFFER_RE.finditer(text):
        raw_type = match.group("type")
        count = int(match.group("count"))
        base = re.sub(r"\s+", "", raw_type.replace("*", "")).lower()
        element = 8 if "*" in raw_type else _ELEMENT_SIZES.get(base, 1)
        size = count * element
        if size >= min_bytes:
            found.append({"name": match.group("name"), "type": raw_type.strip(), "elements": count, "bytes": size})
    return found


def scan_function_text(text: str) -> dict:
    """Pull crypto / obfuscation / dynamic-resolution hints out of Hex-Rays output."""
    code = _COMMENT_RE.sub("", text or "")
    lowered = code.lower()
    crypto = sorted({label for needle, label in _CRYPTO_CONSTANTS.items() if needle in lowered})
    has_loop = bool(_LOOP_RE.search(code))
    has_xor = bool(_XOR_RE.search(code))
    indexed = "[" in code or "*(" in code
    xor_loop = has_loop and has_xor and indexed
    rc4 = bool(has_loop and has_xor and _RC4_RE.search(code) and re.search(r"\b256\b", code))
    targets = sorted({m.group(1) for m in _GPA_TARGET_RE.finditer(code)})
    return {
        "crypto_constants": crypto,
        "xor_loop": xor_loop,
        "rc4_like": rc4,
        "dynamic_resolution": bool(_DYN_API_RE.search(code)),
        "resolved_apis": targets,
        "stack_buffers": stack_buffers(code),
    }


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def score_modules(imports: Iterable[str], strings: Iterable[str], signals: dict) -> tuple[dict[str, float], dict[str, list[str]]]:
    """Return ``(scores, reasons)`` keyed by module for one function."""
    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)

    for name in imports:
        for cap in capabilities_of_import(name):
            weights = CAPABILITY_MODULE.get(cap)
            if weights:
                scores[weights[0]] += weights[1]
                reasons[weights[0]].append("import %s (%s)" % (normalize_import(name), cap))

    seen_categories: set[tuple[str, str]] = set()
    for text in strings:
        for category in classify_string(text):
            weights = _STRING_MODULE.get(category)
            if weights and (weights[0], category) not in seen_categories:
                seen_categories.add((weights[0], category))
                scores[weights[0]] += weights[1]
                reasons[weights[0]].append("%s string" % category)

    if signals.get("crypto_constants"):
        scores[MODULE_CRYPTO] += 3.0
        reasons[MODULE_CRYPTO].append("crypto constant: " + signals["crypto_constants"][0])
    if signals.get("rc4_like"):
        scores[MODULE_CRYPTO] += 2.0
        reasons[MODULE_CRYPTO].append("RC4-like key schedule loop")
    elif signals.get("xor_loop"):
        scores[MODULE_CRYPTO] += 1.5
        reasons[MODULE_CRYPTO].append("XOR loop over a buffer")
    if signals.get("dynamic_resolution") and not any("dynamic_resolve" in r for r in reasons[MODULE_EVASION]):
        scores[MODULE_EVASION] += 2.0
        reasons[MODULE_EVASION].append("dynamic API resolution")
    return dict(scores), dict(reasons)


def choose_module(scores: dict[str, float], threshold: float = 1.0) -> Optional[str]:
    best, best_score = None, 0.0
    for module in _MODULE_PRIORITY:
        score = scores.get(module, 0.0)
        if score > best_score:
            best, best_score = module, score
    return best if best_score >= threshold else None


def propagate_modules(
    modules: dict[int, Optional[str]],
    callers: dict[int, set],
    callees: dict[int, set],
    rounds: int = 3,
    fixed: Optional[set] = None,
) -> dict[int, Optional[str]]:
    """Give unclassified functions the module of their call-graph neighbours.

    A helper that is only ever called from network code is, in practice, network
    code. Callees count slightly more than callers because a function mostly
    inherits meaning from what it calls.
    """
    fixed = fixed or set()
    current = dict(modules)
    for _ in range(max(0, rounds)):
        updates = {}
        for ea, module in current.items():
            if module is not None or ea in fixed:
                continue
            votes: Counter = Counter()
            for neighbour in callees.get(ea, ()):
                m = current.get(neighbour)
                if m in _MODULE_PRIORITY:
                    votes[m] += 1.0
            for neighbour in callers.get(ea, ()):
                m = current.get(neighbour)
                if m in _MODULE_PRIORITY:
                    votes[m] += 0.5
            if not votes:
                continue
            ranked = votes.most_common(2)
            top_module, top_votes = ranked[0]
            runner_up = ranked[1][1] if len(ranked) > 1 else 0.0
            if top_votes >= 1.0 and top_votes > runner_up:
                updates[ea] = top_module
        if not updates:
            break
        current.update(updates)
    return current


def triage_signals(capabilities: Iterable[str], signals: dict, string_categories: Iterable[str]) -> tuple[int, list[dict]]:
    """Return ``(score, signals)`` used to rank functions for a human or agent."""
    caps = set(capabilities)
    out: list[dict] = []
    score = 0

    def add(kind: str, detail: str, weight: int) -> None:
        nonlocal score
        out.append({"type": kind, "detail": detail})
        score += weight

    if "injection" in caps:
        add("process_injection_apis", "calls process/thread/memory manipulation APIs", 4)
    if "anti_debug" in caps:
        add("anti_debugging", "calls debugger-detection APIs", 2)
    if signals.get("dynamic_resolution"):
        detail = "resolves APIs at runtime"
        if signals.get("resolved_apis"):
            detail += ": " + ", ".join(signals["resolved_apis"][:8])
        add("dynamic_api_resolution", detail, 3)
    if "resource" in caps:
        add("payload_resource_apis", "calls PE resource extraction APIs (crypter / payload staging)", 2)
    if "network" in caps:
        add("network_apis", "calls networking APIs", 2)
    if "crypto" in caps:
        add("crypto_apis", "calls cryptographic APIs", 2)
    if "stealer" in caps or "input_capture" in caps:
        add("credential_access_apis", "calls credential / keystroke / clipboard capture APIs", 3)
    if "persistence" in caps or "service" in caps:
        add("persistence_apis", "creates services or registers auto-start persistence", 3)
    if "lateral" in caps:
        add("lateral_movement_apis", "calls named pipe / remote RPC APIs", 3)
    if "driver" in caps:
        add("driver_kernel_apis", "calls DeviceIoControl or driver loading APIs", 3)
    if signals.get("crypto_constants"):
        add("crypto_constants", ", ".join(signals["crypto_constants"]), 3)
    if signals.get("rc4_like"):
        add("rc4_like_loop", "256-entry state with XOR/modulo loop", 3)
    elif signals.get("xor_loop"):
        add("xor_loop", "XOR inside a loop over a buffer", 2)
    for buf in signals.get("stack_buffers", [])[:3]:
        add("large_stack_buffer", "%s %s[%d] = %d bytes" % (buf["type"], buf["name"], buf["elements"], buf["bytes"]),
            3 if buf["bytes"] >= 1024 else 1)
    cats = set(string_categories)
    if "command" in cats:
        add("command_string", "references a command-line / LOLBin string", 3)
    if "stealer_target" in cats:
        add("stealer_target_string", "references browser vault / credential file target", 3)
    if "named_pipe" in cats:
        add("named_pipe_string", "references a named pipe path", 2)
    if "device_driver" in cats:
        add("device_driver_string", "references raw disk / hardware device", 3)
    if "persistence" in cats:
        add("persistence_string", "references auto-start or task scheduler command", 3)
    if cats & {"url", "ip", "domain"}:
        add("network_indicator_string", "references a URL / IP / domain", 2)
    if "registry" in cats:
        add("registry_string", "references a registry path", 1)
    if "base64_alphabet" in cats:
        add("base64_alphabet", "contains a Base64 alphabet", 2)
    return score, out


# --------------------------------------------------------------------------
# File layout
# --------------------------------------------------------------------------

_INVALID_CHARS_RE = re.compile(r"[<>:\"/\\|?*\x00-\x1f]+")


def safe_filename(value: str, fallback: str = "item", limit: int = 60) -> str:
    text = _INVALID_CHARS_RE.sub("_", str(value or "").strip())
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._ ")
    text = text[:limit].rstrip("._ ")
    return text or fallback


def assign_layout(functions: list[dict], per_part: int = 200) -> None:
    """Add ``dir`` and ``stem`` to each function dict (``ea``, ``name``, ``module``).

    A readable name is used when it is unique; otherwise the address is appended so
    files never collide, even on case-insensitive file systems.
    """
    by_module: dict[str, list[dict]] = defaultdict(list)
    for fn in functions:
        by_module[fn["module"]].append(fn)

    name_counts: Counter = Counter()
    for fn in functions:
        name_counts[safe_filename(fn["name"], "fn").lower()] += 1

    for module, items in by_module.items():
        items.sort(key=lambda f: f["ea"])
        for index, fn in enumerate(items):
            base = safe_filename(fn["name"], "fn")
            unique = name_counts[base.lower()] == 1
            has_address = re.search(r"[0-9A-Fa-f]{6,}", base) is not None
            fn["stem"] = base if unique or has_address else "%s_%X" % (base, fn["ea"])
            if len(items) > per_part:
                fn["dir"] = "%s/part_%02d" % (module, index // per_part + 1)
            else:
                fn["dir"] = module


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------

def _fmt_fn(ea: int, name: str) -> str:
    return "`0x%X %s`" % (ea, name)


def _limited(items: list[str], limit: int) -> str:
    if not items:
        return "_none_"
    shown = ", ".join(items[:limit])
    return shown + (" _(+%d more)_" % (len(items) - limit) if len(items) > limit else "")


def render_brief(fn: dict, names: dict[int, str]) -> str:
    """Compact per-function summary an agent can read instead of the full source."""
    lines = ["# %s" % fn["name"], ""]
    lines.append("- **Address**: `0x%X` - `0x%X` (%d bytes)" % (fn["ea"], fn["end_ea"], fn["size"]))
    module_line = "- **Module**: `%s`" % fn["module"]
    if fn.get("module_reasons"):
        module_line += " - " + "; ".join(fn["module_reasons"][:4])
    lines.append(module_line)
    if fn.get("original_name") and fn["original_name"] != fn["name"]:
        lines.append("- **Original IDA name**: `%s`" % fn["original_name"])
    if fn.get("prototype"):
        lines.append("- **Prototype**: `%s`" % fn["prototype"])
    if fn.get("flags"):
        lines.append("- **Flags**: " + ", ".join(fn["flags"]))
    if fn.get("capabilities"):
        lines.append("- **Capabilities**: " + ", ".join(fn["capabilities"]))
    lines.append("- **APIs called**: " + _limited(["`%s`" % n for n in fn.get("imports_called", [])], 25))
    lines.append("- **Referenced strings**: " + _limited(
        ["`%s`" % s.replace("`", "'").replace("\n", " ")[:80] for s in fn.get("strings", [])], 12))
    lines.append("- **Callers**: " + _limited([_fmt_fn(ea, names.get(ea, "?")) for ea in fn.get("callers", [])], 20))
    lines.append("- **Callees**: " + _limited([_fmt_fn(ea, names.get(ea, "?")) for ea in fn.get("callees", [])], 20))
    if fn.get("triage"):
        lines.append("- **Triage score**: %d" % fn.get("triage_score", 0))
        for sig in fn["triage"][:8]:
            lines.append("  - `%s`: %s" % (sig["type"], sig["detail"]))
    lines.append("")
    stem = fn["stem"]
    lines.append("Files: [`%s.c`](%s.c) / [`%s.asm`](%s.asm)" % (stem, stem, stem, stem))
    lines.append("")
    return "\n".join(lines)
