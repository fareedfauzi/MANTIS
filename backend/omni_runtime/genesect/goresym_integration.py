import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_typeinf
import idaapi
import idc

from genesect.config import CONFIG
from genesect.qt_compat import QtCore, QtWidgets


GORESYM_RELEASE_API = "https://api.github.com/repos/mandiant/GoReSym/releases/latest"
goresym_thread = None


def _tool_dir():
    root = os.path.join(os.path.expanduser("~"), ".genesect", "tools", "goresym")
    legacy_root = os.path.join(os.path.expanduser("~"), ".pseudo" + "note-extended", "tools", "goresym")
    if not os.path.isdir(root) and os.path.isdir(legacy_root):
        return legacy_root
    os.makedirs(root, exist_ok=True)
    return root


def _is_windows():
    return os.name == "nt" or sys.platform.startswith("win")


def _goresym_names():
    return ["GoReSym.exe", "goresym.exe", "GoReSym"] if _is_windows() else ["GoReSym", "goresym", "GoReSym.exe"]


def resolve_goresym_executable(configured_path=""):
    candidates = []
    configured_path = str(configured_path or "").strip().strip('"')
    if configured_path:
        candidates.append(configured_path)
        found = shutil.which(configured_path)
        if found:
            candidates.append(found)
    for name in _goresym_names():
        candidates.append(os.path.join(_tool_dir(), name))
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        path = os.path.abspath(os.path.expanduser(candidate))
        if os.path.isfile(path) and (_is_windows() or os.access(path, os.X_OK)):
            return path
    return ""


def validate_goresym_executable(path):
    if not path or not os.path.isfile(path):
        return False, "The GoReSym executable does not exist."
    try:
        completed = subprocess.run(
            [path, "-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if _is_windows() else 0,
        )
    except subprocess.TimeoutExpired:
        return False, "The selected GoReSym executable did not respond to '-h'."
    except OSError as exc:
        return False, f"The selected GoReSym executable could not be started: {exc}"
    help_text = ((completed.stdout or b"") + b"\n" + (completed.stderr or b"")).decode("utf-8", "replace")
    identity = help_text.lower()
    if "goresym" not in identity or not any(marker in identity for marker in ("-p", "pclntab", "moduledata")):
        excerpt = " ".join(help_text.split())[:300]
        return False, "The selected program does not look like GoReSym." + (f" Output: {excerpt}" if excerpt else "")
    return True, ""


def _platform_keywords():
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system.startswith("darwin"):
        os_keys = ("darwin", "mac", "osx")
    elif system.startswith("linux"):
        os_keys = ("linux",)
    elif system.startswith("windows"):
        os_keys = ("windows", "win")
    else:
        os_keys = (system,)
    if machine in ("amd64", "x86_64"):
        arch_keys = ("amd64", "x86_64", "x64")
    elif machine in ("arm64", "aarch64"):
        arch_keys = ("arm64", "aarch64")
    elif machine in ("i386", "i686", "x86"):
        arch_keys = ("386", "x86")
    else:
        arch_keys = (machine,)
    return os_keys, arch_keys


def _select_release_asset(release):
    os_keys, arch_keys = _platform_keywords()
    assets = release.get("assets", []) or []
    scored = []
    for asset in assets:
        name = str(asset.get("name", ""))
        lower = name.lower()
        if not asset.get("browser_download_url"):
            continue
        score = 0
        if any(key in lower for key in os_keys):
            score += 10
        if any(key in lower for key in arch_keys):
            score += 5
        if "goresym" in lower:
            score += 3
        if lower.endswith((".zip", ".tar.gz", ".tgz")):
            score += 1
        if score >= 14:
            scored.append((score, asset))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored[0][1]


def _download(url, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "Genesect"})
    with urllib.request.urlopen(request, timeout=60) as response, open(destination, "wb") as stream:
        shutil.copyfileobj(response, stream)


def _extract_archive(archive_path, destination):
    def _safe_target(name):
        dest_root = os.path.abspath(destination)
        target = os.path.abspath(os.path.join(destination, name))
        if os.path.commonpath([dest_root, target]) != dest_root:
            raise RuntimeError("GoReSym archive contains an unsafe path: %s" % name)
        return target

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                _safe_target(member.filename)
            archive.extractall(destination)
        return
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers():
                _safe_target(member.name)
            archive.extractall(destination)
        return
    target = os.path.join(destination, os.path.basename(archive_path))
    shutil.copy2(archive_path, target)


def _find_downloaded_binary(root):
    for current, _dirs, files in os.walk(root):
        for filename in files:
            if filename.lower() in {name.lower() for name in _goresym_names()}:
                path = os.path.join(current, filename)
                if not _is_windows():
                    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
                return path
    return ""


def download_goresym_release():
    with tempfile.TemporaryDirectory() as tmp:
        release_json = os.path.join(tmp, "release.json")
        _download(GORESYM_RELEASE_API, release_json)
        with open(release_json, "r", encoding="utf-8") as stream:
            release = json.load(stream)
        asset = _select_release_asset(release)
        if not asset:
            raise RuntimeError("No GoReSym release asset matched this platform.")
        asset_name = asset.get("name") or "goresym-release"
        archive_path = os.path.join(tmp, asset_name)
        _download(asset["browser_download_url"], archive_path)
        extract_dir = os.path.join(tmp, "extract")
        os.makedirs(extract_dir, exist_ok=True)
        _extract_archive(archive_path, extract_dir)
        binary = _find_downloaded_binary(extract_dir)
        if not binary:
            raise RuntimeError("Downloaded GoReSym release did not contain a recognized executable.")
        destination = os.path.join(_tool_dir(), os.path.basename(binary))
        shutil.copy2(binary, destination)
        if not _is_windows():
            os.chmod(destination, os.stat(destination).st_mode | stat.S_IXUSR)
        return destination


def get_input_binary_path():
    input_file = idc.get_input_file_path()
    if input_file and os.path.exists(input_file):
        return input_file
    idb_path = idc.get_idb_path()
    if idb_path:
        base = os.path.splitext(idb_path)[0]
        for suffix in ("", ".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".dylib"):
            candidate = base + suffix
            if os.path.exists(candidate):
                return candidate
    return ""


def get_goresym_output_path(input_file):
    idb_path = idc.get_idb_path()
    base = os.path.splitext(idb_path or input_file)[0]
    return base + ".goresym.json"


def run_goresym(goresym_path, input_file, output_path):
    cmd = [goresym_path, "-t", "-d", "-p", input_file]
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30 * 60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if _is_windows() else 0,
    )
    stdout = (completed.stdout or b"").decode("utf-8-sig", "replace")
    stderr = (completed.stderr or b"").decode("utf-8", "replace")
    if completed.returncode != 0:
        raise RuntimeError("GoReSym failed with exit code %d: %s" % (completed.returncode, stderr[:1000]))
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        excerpt = " ".join(stdout.split())[:1000]
        raise RuntimeError("GoReSym did not return valid JSON (%s at %d). Output: %s" % (exc.msg, exc.pos, excerpt))
    with open(output_path, "w", encoding="utf-8") as stream:
        json.dump(parsed, stream, ensure_ascii=False, indent=2)
    return parsed, stderr


class GoReSymWorker(QtCore.QThread):
    finished_signal = QtCore.Signal(str, str)
    error_signal = QtCore.Signal(str)

    def __init__(self, goresym_path, input_file, output_path):
        super().__init__()
        self.goresym_path = goresym_path
        self.input_file = input_file
        self.output_path = output_path

    def run(self):
        try:
            _parsed, stderr = run_goresym(self.goresym_path, self.input_file, self.output_path)
            self.finished_signal.emit(self.output_path, stderr)
        except Exception as exc:
            self.error_signal.emit(str(exc))


def _iterable(obj):
    try:
        iter(obj)
        return obj is not None
    except Exception:
        return False


def _get_type_by_name(name):
    t = idaapi.tinfo_t()
    t.get_named_type(None, name)
    return t


def _name_flags():
    return (
        getattr(idaapi, "SN_NOWARN", getattr(ida_name, "SN_NOWARN", 0))
        | getattr(idaapi, "SN_NOCHECK", getattr(ida_name, "SN_NOCHECK", 0))
        | getattr(ida_name, "SN_FORCE", 0)
    )


def _set_name(ea, name):
    if ea is None or not name:
        return False
    return idaapi.set_name(ea, name, _name_flags())


def _import_primitives():
    type_map = {
        "BUILTIN_STRING": "string",
        "uint8_t": "uint8",
        "uint16_t": "uint16",
        "uint32_t": "uint32",
        "uint64_t": "uint64",
        "int8_t": "int8",
        "int16_t": "int16",
        "int32_t": "int32",
        "double": "float64",
        "float": "float32",
        "complex64_t": "complex64",
        "complex128_t": "complex128",
        "void*": "uintptr",
        "uint8": "byte",
        "int32": "rune",
    }
    ida_typeinf.idc_parse_types("struct BUILTIN_INTERFACE{void *tab;void *data;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    ida_typeinf.idc_parse_types("struct BUILTIN_STRING{char *ptr;size_t len;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    ida_typeinf.idc_parse_types("struct complex64_t{float real;float imag;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    ida_typeinf.idc_parse_types("struct complex128_t{double real;double imag;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    for ida_type, go_type in type_map.items():
        ida_typeinf.idc_parse_types(f"typedef {ida_type} {go_type};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)


def _parse_reconstructed_types_enabled():
    legacy_key = "PSEUDO" + "NOTE_GORESYM_PARSE_TYPES"
    value = os.environ.get("GENESECT_GORESYM_PARSE_TYPES", os.environ.get(legacy_key, ""))
    return value.strip().lower() in ("1", "true", "yes", "on")


def _safe_c_identifier(name):
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(name or "")))


def _parse_reconstructed_types(types):
    parsed = 0
    skipped = 0
    for typ in types:
        if typ.get("Kind") == "Struct" and _safe_c_identifier(typ.get("CStr")):
            try:
                parsed += int(ida_typeinf.idc_parse_types("struct %s;" % typ["CStr"], ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL) == 0)
            except Exception:
                skipped += 1
        elif typ.get("Kind") == "Struct":
            skipped += 1
    for typ in (types or [])[::-1]:
        decl = typ.get("CReconstructed")
        if not decl:
            continue
        try:
            if ida_typeinf.idc_parse_types(decl + ";", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL) == 0:
                parsed += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return parsed, skipped


def apply_goresym_json(json_path):
    with open(json_path, "r", encoding="utf-8") as stream:
        hints = json.load(stream)
    renamed_functions = 0
    renamed_types = 0
    parsed_type_decls = 0
    skipped_type_decls = 0
    for key in ("UserFunctions", "StdFunctions"):
        if _iterable(hints.get(key)):
            for func in hints.get(key) or []:
                ida_bytes.del_items(func["Start"])
                ida_funcs.add_func(func["Start"])
                idaapi.add_func(func["Start"], func["End"])
                if _set_name(func.get("Start"), func.get("FullName")):
                    renamed_functions += 1
    if _iterable(hints.get("Types")):
        _import_primitives()
        if _parse_reconstructed_types_enabled():
            parsed_type_decls, skipped_type_decls = _parse_reconstructed_types(hints.get("Types") or [])
        else:
            skipped_type_decls = sum(1 for typ in hints.get("Types") or [] if typ.get("CReconstructed") or typ.get("Kind") == "Struct")
        for typ in hints.get("Types") or []:
            if _set_name(typ.get("VA"), typ.get("Str")):
                renamed_types += 1
            ida_bytes.del_items(typ["VA"], 0, 4)
            idaapi.apply_tinfo(typ["VA"], _get_type_by_name("abi_Type"), idaapi.TINFO_DEFINITE)
    if _iterable(hints.get("Interfaces")):
        for typ in hints.get("Interfaces") or []:
            if _set_name(typ.get("VA"), typ.get("Str")):
                renamed_types += 1
            ida_bytes.del_items(typ["VA"], 0, 4)
            idaapi.apply_tinfo(typ["VA"], _get_type_by_name("abi_Type"), idaapi.TINFO_DEFINITE)
    tabmeta = hints.get("TabMeta")
    if tabmeta and tabmeta.get("VA"):
        _set_name(tabmeta["VA"], "runtime_pclntab")
    modmeta = hints.get("ModuleMeta")
    if modmeta and modmeta.get("VA"):
        _set_name(modmeta["VA"], "runtime_firstmoduledata")
    return renamed_functions, renamed_types, parsed_type_decls, skipped_type_decls


def _choose_goresym_path():
    path = resolve_goresym_executable(CONFIG.goresym_path)
    if path:
        return path
    choice = ida_kernwin.ask_buttons(
        "Locate",
        "Download",
        "Cancel",
        1,
        "GoReSym was not found in Settings, bundled tools, or PATH.\n\nLocate an existing GoReSym binary or download the latest release from GitHub?",
    )
    if choice == 1:
        selected = ida_kernwin.ask_file(0, "GoReSym*", "Locate GoReSym binary")
        path = resolve_goresym_executable(selected)
    elif choice == 0:
        try:
            ida_kernwin.msg("Downloading latest GoReSym release from GitHub...\n")
            path = download_goresym_release()
        except Exception as exc:
            ida_kernwin.warning(f"Could not download GoReSym: {exc}")
            return ""
    else:
        return ""
    valid, error = validate_goresym_executable(path)
    if not valid:
        if CONFIG.goresym_path:
            CONFIG.goresym_path = ""
            CONFIG.save()
        ida_kernwin.warning(error)
        return ""
    if CONFIG.goresym_path != path:
        CONFIG.goresym_path = path
        CONFIG.save()
    return path


def show_goresym_ui():
    global goresym_thread
    if goresym_thread is not None and goresym_thread.isRunning():
        ida_kernwin.warning("A GoReSym analysis is already running.")
        return
    goresym_path = _choose_goresym_path()
    if not goresym_path:
        return
    input_file = get_input_binary_path()
    if not input_file:
        input_file = ida_kernwin.ask_file(0, "*.*", "Select sample binary for GoReSym")
    if not input_file or not os.path.exists(input_file):
        ida_kernwin.warning("Could not locate the opened sample binary.")
        return
    output_path = get_goresym_output_path(input_file)
    ida_kernwin.msg(f"Starting GoReSym in background on {input_file}...\n")
    goresym_thread = GoReSymWorker(goresym_path, input_file, output_path)
    goresym_thread.finished_signal.connect(on_goresym_finished)
    goresym_thread.error_signal.connect(on_goresym_error)
    goresym_thread.finished.connect(_clear_goresym_thread)
    goresym_thread.start()


def on_goresym_finished(output_path, stderr):
    def _main_thread_handler():
        try:
            renamed_functions, renamed_types, parsed_type_decls, skipped_type_decls = apply_goresym_json(output_path)
            if stderr.strip():
                ida_kernwin.msg("GoReSym diagnostics: %s\n" % stderr.strip()[:1000])
            idaapi.request_refresh(idaapi.IWID_DISASM)
            QtWidgets.QMessageBox.information(
                QtWidgets.QApplication.activeWindow(),
                "GoReSym Complete",
                "GoReSym JSON saved to:\n%s\n\nRenamed %d functions and %d type/interface records.\nSkipped %d reconstructed C type declarations."
                % (output_path, renamed_functions, renamed_types, skipped_type_decls),
            )
        except Exception as exc:
            ida_kernwin.warning(f"GoReSym rename failed: {exc}")

    ida_kernwin.execute_sync(_main_thread_handler, ida_kernwin.MFF_WRITE)


def on_goresym_error(error):
    ida_kernwin.msg(f"GoReSym failed: {error}\n")


def _clear_goresym_thread():
    global goresym_thread
    goresym_thread = None


class GoReSymHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_goresym_ui()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
