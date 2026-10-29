# -*- coding: utf-8 -*-
"""Microsoft RIFT server integration for Rust library signature generation."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import ida_funcs
import ida_kernwin
import ida_loader
import idaapi
import idautils

from genesect.config import CONFIG
from genesect.qt_compat import QtCore, QtWidgets


DEFAULT_RIFT_SERVER_URL = "http://127.0.0.1:5001"
rift_thread = None


class RiftIntegrationError(RuntimeError):
    pass


def _normalize_server_url(url):
    value = str(url or "").strip().rstrip("/")
    if not value:
        value = DEFAULT_RIFT_SERVER_URL
    if "://" not in value:
        value = "http://" + value
    return value


def _request_json(method, server_url, path, payload=None, timeout=15):
    url = _normalize_server_url(server_url) + path
    data = None
    headers = {"User-Agent": "Genesect"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        raise RiftIntegrationError("RIFT server returned HTTP %d: %s" % (exc.code, raw[:500]))
    except urllib.error.URLError as exc:
        raise RiftIntegrationError("Could not reach RIFT server at %s: %s" % (url, exc))
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RiftIntegrationError("RIFT server returned invalid JSON: %s" % exc)


def health_check(server_url):
    return _request_json("GET", server_url, "/health", timeout=8)


def _iter_strings():
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        try:
            yield str(item)
        except Exception:
            continue


def _guess_arch():
    try:
        import ida_ida
        proc = str(ida_ida.inf_get_procname() or "")
        if proc == "metapc":
            return "i686" if ida_ida.inf_is_32bit_exactly() else "x86_64"
        if proc == "ARM":
            return "arm" if ida_ida.inf_is_32bit_exactly() else "aarch64"
    except Exception:
        pass
    try:
        bits = idaapi.get_inf_structure().is_64bit()
        return "x86_64" if bits else "i686"
    except Exception:
        return "x86_64"


def _guess_filetype():
    try:
        name = str(ida_loader.get_file_type_name() or "")
    except Exception:
        name = ""
    lower = name.lower()
    if "portable executable" in lower or "pe" in lower:
        return "PE"
    if "elf" in lower:
        return "ELF"
    if "mach-o" in lower or "macho" in lower:
        return "MachO"
    return "PE"


def _crate_from_component(component):
    match = re.match(r"(?P<name>.+)-(?P<version>\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9_.-]+)?)$", component)
    if not match:
        return None
    name = match.group("name").strip()
    version = match.group("version").strip()
    if not name or not version:
        return None
    return {"name": name, "version": version}


def _extract_crates(strings):
    crates = {}
    cargo_path = re.compile(r"[\\/]\.cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([^\\/]+)")
    cargo_home = re.compile(r"[\\/]cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([^\\/]+)")
    for value in strings:
        for regex in (cargo_path, cargo_home):
            match = regex.search(value)
            if not match:
                continue
            crate = _crate_from_component(match.group(1))
            if crate:
                crates[(crate["name"], crate["version"])] = crate
    return sorted(crates.values(), key=lambda item: (item["name"].casefold(), item["version"]))


def _extract_commithash(strings):
    patterns = (
        re.compile(r"[\\/]rustc[\\/]([0-9a-fA-F]{7,40})(?:[\\/]|$)"),
        re.compile(r"rustc[-_/ ]([0-9a-fA-F]{7,40})"),
        re.compile(r"commit[-_ ]hash[:= ]+([0-9a-fA-F]{7,40})", re.I),
    )
    for value in strings:
        for pattern in patterns:
            match = pattern.search(value)
            if match:
                return match.group(1).lower()
    return ""


def _extract_target_triple(strings, arch, filetype):
    archs = r"(?:x86_64|i686|aarch64|armv7|arm)"
    vendors = r"(?:pc|unknown|apple|uwp|fortanix)"
    systems = r"(?:windows|linux|darwin|none|sgx|uefi)"
    abis = r"(?:msvc|gnu|gnueabihf|musl|eabi|elf|macabi)"
    triple_re = re.compile(r"\b(%s-%s-%s(?:-%s)?)\b" % (archs, vendors, systems, abis), re.I)
    for value in strings:
        match = triple_re.search(value)
        if match:
            return match.group(1).lower()
    if filetype == "PE":
        return "%s-pc-windows-msvc" % arch
    if filetype == "ELF":
        return "%s-unknown-linux-gnu" % arch
    if filetype == "MachO":
        return "%s-apple-darwin" % arch
    return "%s-pc-windows-msvc" % arch


def collect_rift_metadata():
    strings = list(_iter_strings())
    arch = _guess_arch()
    filetype = _guess_filetype()
    return {
        "commithash": _extract_commithash(strings),
        "arch": arch,
        "filetype": filetype,
        "crates": _extract_crates(strings),
        "target_triple": _extract_target_triple(strings, arch, filetype),
    }


def _metadata_summary(metadata):
    crates = metadata.get("crates") or []
    crate_text = ", ".join("%s@%s" % (item["name"], item["version"]) for item in crates[:8])
    if len(crates) > 8:
        crate_text += ", ... %d more" % (len(crates) - 8)
    return (
        "Compiler commit: %(commithash)s\n"
        "Architecture: %(arch)s\n"
        "File type: %(filetype)s\n"
        "Target triple: %(target_triple)s\n"
        "Crates: %(crate_count)d%(crate_text)s"
    ) % {
        "commithash": metadata.get("commithash") or "(missing)",
        "arch": metadata.get("arch") or "(missing)",
        "filetype": metadata.get("filetype") or "(missing)",
        "target_triple": metadata.get("target_triple") or "(missing)",
        "crate_count": len(crates),
        "crate_text": ("\n  " + crate_text) if crate_text else "",
    }


def _validate_metadata(metadata):
    missing = [key for key in ("commithash", "arch", "filetype", "target_triple") if not metadata.get(key)]
    if missing:
        raise RiftIntegrationError("Missing RIFT metadata fields: %s" % ", ".join(missing))
    if not isinstance(metadata.get("crates"), list):
        metadata["crates"] = []
    return metadata


def _prompt_metadata(metadata):
    metadata = dict(metadata)
    text = _metadata_summary(metadata)
    choice = ida_kernwin.ask_buttons(
        "Run",
        "Edit",
        "Cancel",
        1,
        "RIFT will generate Rust library FLIRT signatures using this metadata:\n\n%s\n\n"
        "Run with this metadata or edit the JSON request?" % text,
    )
    if choice == -1:
        return None
    if choice == 0:
        raw = ida_kernwin.ask_text(4096, json.dumps(metadata, indent=2), "Edit RIFT /flirt JSON request")
        if not raw:
            return None
        try:
            metadata = json.loads(raw)
        except json.JSONDecodeError as exc:
            ida_kernwin.warning("Invalid RIFT JSON: %s" % exc)
            return None
    if not metadata.get("commithash"):
        value = ida_kernwin.ask_str("", 0, "Rust compiler commit hash for RIFT")
        if not value:
            return None
        metadata["commithash"] = value.strip()
    try:
        return _validate_metadata(metadata)
    except Exception as exc:
        ida_kernwin.warning(str(exc))
        return None


def _choose_output_folder():
    configured = str(getattr(CONFIG, "rift_output_folder", "") or "").strip()
    selected = ""
    if QtWidgets:
        selected = QtWidgets.QFileDialog.getExistingDirectory(
            QtWidgets.QApplication.activeWindow(),
            "Select RIFT output folder",
            configured or os.path.expanduser("~"),
        )
    if not selected:
        selected = ida_kernwin.ask_str(configured, 0, "RIFT output folder")
    if not selected:
        return ""
    path = os.path.abspath(os.path.expanduser(selected))
    os.makedirs(path, exist_ok=True)
    if getattr(CONFIG, "rift_output_folder", "") != path:
        CONFIG.rift_output_folder = path
        CONFIG.save()
    return path


def _ask_apply_generated_signatures():
    return ida_kernwin.ask_yn(
        1,
        "Apply generated RIFT .sig files to the current IDB when the job completes?",
    ) == 1


def _apply_signature(path):
    if not path or not os.path.isfile(path) or not path.lower().endswith(".sig"):
        return False

    def _apply():
        ida_funcs.plan_to_apply_idasgn(path)
        return 1

    idaapi.execute_sync(_apply, idaapi.MFF_WRITE)
    return True


def submit_flirt_job(server_url, payload):
    return _request_json("POST", server_url, "/flirt", payload=payload, timeout=30)


def get_job(server_url, job_id):
    query = urllib.parse.urlencode({"id": job_id})
    return _request_json("GET", server_url, "/job?%s" % query, timeout=15)


class RiftWorker(QtCore.QThread):
    finished_signal = QtCore.Signal(dict)
    error_signal = QtCore.Signal(str)

    def __init__(self, server_url, metadata, output_folder, apply_signatures=False):
        super().__init__()
        self.server_url = server_url
        self.metadata = dict(metadata)
        self.output_folder = output_folder
        self.apply_signatures = bool(apply_signatures)

    def run(self):
        try:
            health = health_check(self.server_url)
            if health.get("status") != "healthy":
                raise RiftIntegrationError("RIFT server is not healthy: %s" % health)
            payload = dict(self.metadata)
            payload["output_folder"] = self.output_folder
            submitted = submit_flirt_job(self.server_url, payload)
            if submitted.get("status") == "error" or submitted.get("error"):
                raise RiftIntegrationError("RIFT job submission failed: %s" % submitted)
            job_id = submitted.get("job_id")
            if not job_id:
                raise RiftIntegrationError("RIFT server did not return a job_id: %s" % submitted)
            last = submitted
            for _ in range(720):
                time.sleep(5)
                last = get_job(self.server_url, job_id)
                status = str(last.get("status") or "").lower()
                if status in ("completed", "failed", "error"):
                    break
            if str(last.get("status") or "").lower() != "completed":
                raise RiftIntegrationError("RIFT job did not complete successfully: %s" % last)
            applied = []
            if self.apply_signatures:
                for path in last.get("result_files") or []:
                    if _apply_signature(path):
                        applied.append(path)
            last["applied_files"] = applied
            self.finished_signal.emit(last)
        except Exception as exc:
            self.error_signal.emit(str(exc))


def _choose_server_url():
    current = _normalize_server_url(getattr(CONFIG, "rift_server_url", DEFAULT_RIFT_SERVER_URL))
    value = ida_kernwin.ask_str(current, 0, "RIFT server URL")
    if not value:
        return ""
    value = _normalize_server_url(value)
    if getattr(CONFIG, "rift_server_url", "") != value:
        CONFIG.rift_server_url = value
        CONFIG.save()
    return value


def run_rift_ui():
    global rift_thread
    if rift_thread is not None and rift_thread.isRunning():
        ida_kernwin.warning("A RIFT job is already running.")
        return
    server_url = _choose_server_url()
    if not server_url:
        return
    output_folder = _choose_output_folder()
    if not output_folder:
        return
    metadata = _prompt_metadata(collect_rift_metadata())
    if not metadata:
        return
    apply_signatures = _ask_apply_generated_signatures()
    ida_kernwin.msg("[Genesect] Submitting RIFT FLIRT generation job to %s...\n" % server_url)
    rift_thread = RiftWorker(server_url, metadata, output_folder, apply_signatures)
    rift_thread.finished_signal.connect(on_rift_finished)
    rift_thread.error_signal.connect(on_rift_error)
    rift_thread.finished.connect(_clear_rift_thread)
    rift_thread.start()


def on_rift_finished(result):
    def _main_thread_handler():
        files = result.get("result_files") or []
        applied = result.get("applied_files") or []
        message = "RIFT job completed.\n\nGenerated %d signature file(s)." % len(files)
        if files:
            message += "\n\n" + "\n".join(str(path) for path in files[:12])
            if len(files) > 12:
                message += "\n... %d more" % (len(files) - 12)
        if applied:
            message += "\n\nQueued %d signature file(s) for IDA application." % len(applied)
        ida_kernwin.msg("[Genesect] %s\n" % message.replace("\n", " "))
        QtWidgets.QMessageBox.information(QtWidgets.QApplication.activeWindow(), "RIFT Complete", message)
        try:
            idaapi.request_refresh(idaapi.IWID_DISASM)
        except Exception:
            pass

    ida_kernwin.execute_sync(_main_thread_handler, ida_kernwin.MFF_WRITE)


def on_rift_error(error):
    ida_kernwin.msg("[Genesect] RIFT failed: %s\n" % error)
    QtWidgets.QMessageBox.warning(QtWidgets.QApplication.activeWindow(), "RIFT Failed", error)


def _clear_rift_thread():
    global rift_thread
    rift_thread = None


class RiftLibraryRecognitionHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        run_rift_ui()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
