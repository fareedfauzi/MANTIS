import os
import __main__
import builtins
import sys
import ida_kernwin
import idaapi
import idc
import idautils
import subprocess
import json
import re
import threading
import ctypes
import shutil
import tempfile
import time
import signal
from .qt_compat import QtCore, Signal, QtWidgets, QtGui, Qt
from .config import CONFIG
from .ui.mac_workspace import apply_mac_workspace
from .ui.components import configure_content_tabs

# --- IDB PERSISTENCE ---
FLOSS_NETNODE_NAME = "$ genesect:floss_results"

def save_results_to_idb(results):
    def _do_save():
        try:
            import ida_netnode
            node = ida_netnode.netnode(FLOSS_NETNODE_NAME, 0, True)
            data = json.dumps(results)
            node.setblob(data.encode('utf-8'), 0, ord('F'))
        except Exception as e:
            print(f"FLOSS Viewer: Failed to save results to IDB: {e}")
    ida_kernwin.execute_sync(_do_save, ida_kernwin.MFF_WRITE)

def load_results_from_idb():
    res = [None]
    def _do_load():
        try:
            import ida_netnode
            node = ida_netnode.netnode(FLOSS_NETNODE_NAME, 0, False)
            if node and node != ida_netnode.BADNODE:
                data = node.getblob(0, ord('F'))
                if data:
                    res[0] = json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"FLOSS Viewer: Failed to load results from IDB: {e}")
    ida_kernwin.execute_sync(_do_load, ida_kernwin.MFF_READ)
    return res[0]

# --- ROBUST SHIBOKEN DISCOVERY FOR IDA 9.3 ---
def _find_shiboken():
    # 1. Search sys.modules (best for already-loaded IDA environment)
    for name, mod in sys.modules.items():
        if mod is None or not isinstance(name, str): continue
        if 'shiboken' in name.lower():
            if hasattr(mod, 'wrapInstance'): return mod
            if hasattr(mod, 'shiboken') and hasattr(mod.shiboken, 'wrapInstance'): return mod.shiboken
    
    # 2. Try explicit names (priority on PySide6)
    for name in ['shiboken6', 'shiboken2', 'shiboken']:
        try:
            m = __import__(name)
            if hasattr(m, 'wrapInstance'): return m
            if hasattr(m, 'shiboken') and hasattr(m.shiboken, 'wrapInstance'): return m.shiboken
        except: continue
    return None

shiboken = _find_shiboken()

# Inject into all possible namespaces to satisfy IDA's internal C++ evaluations
for mod_name in ['shiboken', 'Shiboken']:
    if shiboken:
        globals()[mod_name] = shiboken
        setattr(builtins, mod_name, shiboken)
        setattr(__main__, mod_name, shiboken)

# Ensure Qt modules are also visible to IDA's bridge
for mod_name, mod in [('QtCore', QtCore), ('QtWidgets', QtWidgets), ('QtGui', QtGui)]:
    if mod:
        setattr(builtins, mod_name, mod)
        setattr(__main__, mod_name, mod)

# Final Bridge Shim for QWidget.FromCapsule (IDA 9.3 specific)
if QtGui:
    if not hasattr(QtGui, 'QWidget') or not hasattr(getattr(QtGui, 'QWidget', object), 'FromCapsule'):
        class QWidgetShim(QtWidgets.QWidget):
            @staticmethod
            def FromCapsule(tw):
                if not shiboken or not hasattr(shiboken, 'wrapInstance'):
                    return None
                
                # IDA 9.3/PySide6 specific: convert PyCapsule to raw pointer address (int)
                ptr = tw
                if str(type(tw)).find('PyCapsule') != -1:
                    try:
                        # IDA uses b'$valid$' for its capsules
                        ctypes.pythonapi.PyCapsule_GetPointer.restype = ctypes.c_void_p
                        ctypes.pythonapi.PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
                        
                        # Try with IDA's default name first
                        ptr = ctypes.pythonapi.PyCapsule_GetPointer(tw, b'$valid$')
                        if not ptr:
                            # Fallback to None (unnamed)
                            ptr = ctypes.pythonapi.PyCapsule_GetPointer(tw, None)
                    except Exception:
                        # Final resort: if it's a capsule but we can't get pointer, let wrapInstance try it directly
                        ptr = tw
                
                try:
                    return shiboken.wrapInstance(ptr, QtWidgets.QWidget)
                except Exception as e:
                    # Final attempt: try with original 'tw' in case wrapInstance was updated
                    try:
                        return shiboken.wrapInstance(tw, QtWidgets.QWidget)
                    except Exception:
                        print(f"FLOSS Viewer: Failed to wrap widget: {e}")
                        return None
        
        # Patch QtGui with the shim if it's missing or broken
        if not hasattr(QtGui, 'QWidget'):
            QtGui.QWidget = QWidgetShim
        else:
            try:
                QtGui.QWidget.FromCapsule = QWidgetShim.FromCapsule
            except:
                # If QWidget is read-only, we swap the class out
                QtGui.QWidget = QWidgetShim

# Global reference to prevent UI garbage collection
floss_strings_chooser = None
floss_thread = None
MAX_FLOSS_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_FLOSS_ENTRIES = 200000
FLOSS_TIMEOUT_SECONDS = 30 * 60


def resolve_floss_executable(configured_path=""):
    """Resolve an explicit path, command name, bundled tool, or PATH install."""
    names = ["floss.exe", "floss"] if sys.platform.startswith("win") else ["floss", "floss.exe"]
    candidates = []
    configured_path = str(configured_path or "").strip().strip('"')
    if configured_path:
        candidates.append(configured_path)
        located = shutil.which(configured_path)
        if located:
            candidates.append(located)
    module_dir = os.path.dirname(os.path.abspath(__file__))
    for name in names:
        candidates.extend([
            os.path.join(module_dir, "tools", name),
            os.path.join(os.path.dirname(module_dir), "tools", name),
        ])
        located = shutil.which(name)
        if located:
            candidates.append(located)
    for candidate in candidates:
        path = os.path.abspath(os.path.expanduser(candidate))
        if os.path.isfile(path):
            if sys.platform.startswith("win") or os.access(path, os.X_OK):
                return path
    return ""


def validate_floss_executable(path, timeout=12):
    """Confirm that a selected binary is Mandiant FLARE-FLOSS, not a namesake tool."""
    if not path or not os.path.isfile(path):
        return False, "The FLOSS executable does not exist."
    try:
        startupinfo = None
        if hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        completed = subprocess.run(
            [path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, startupinfo=startupinfo,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform.startswith("win") else 0,
        )
    except subprocess.TimeoutExpired:
        return False, "The selected executable did not respond to 'floss -h'."
    except OSError as exc:
        return False, f"The selected executable could not be started: {exc}"
    output = (completed.stdout or b"") + b"\n" + (completed.stderr or b"")
    help_text = output.decode("utf-8", "replace")
    identity = help_text.lower()
    if "floss" not in identity or not any(flag in identity for flag in ("--json", "obfuscated string", "flare")):
        excerpt = " ".join(help_text.split())[:300]
        detail = f" Output: {excerpt}" if excerpt else " It produced no help output."
        return False, "The selected program is not Mandiant FLARE-FLOSS." + detail
    return True, ""


def decode_floss_json(stdout, stderr=b""):
    """Decode FLOSS JSON while preserving actionable process diagnostics."""
    out_text = stdout.decode("utf-8-sig", "replace") if isinstance(stdout, bytes) else str(stdout or "")
    err_text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr or "")
    stripped = out_text.strip()
    if not stripped:
        detail = " ".join(err_text.split())[:1000]
        raise ValueError(
            "FLOSS exited successfully but returned no JSON output."
            + (f" FLOSS diagnostic: {detail}" if detail else " Verify that the selected file is the official FLARE-FLOSS binary and that the input is supported.")
        )
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        # Some launchers may print a short banner before the JSON document.
        starts = [index for index in (stripped.find("{"), stripped.find("[")) if index >= 0]
        if starts:
            candidate = stripped[min(starts):]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass
        excerpt = " ".join(stripped.split())[:1000]
        diagnostics = " ".join(err_text.split())[:1000]
        message = f"FLOSS did not return valid JSON ({exc.msg} at character {exc.pos}). Output: {excerpt}"
        if diagnostics:
            message += f" Diagnostic: {diagnostics}"
        raise ValueError(message) from exc


def decode_floss_text(stdout):
    """Parse the sectioned output emitted by older FLARE-FLOSS builds.

    New FLOSS releases support JSON, but older standalone executables have
    been observed accepting the option while still rendering text. Keep that
    useful result and let the main thread map static strings back into IDA.
    """
    text = stdout.decode("utf-8-sig", "replace") if isinstance(stdout, bytes) else str(stdout or "")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    category = ""
    entries = []
    headings = (
        ("static ascii", "static/ascii"),
        ("static unicode", "static/unicode"),
        ("utf-16", "static/unicode"),
        ("stack string", "stack"),
        ("tight string", "tight"),
        ("decoded string", "decoded"),
    )
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        matched_heading = next((name for marker, name in headings if marker in lowered and "floss" in lowered), None)
        if matched_heading:
            category = matched_heading
            continue
        if not category or set(line) <= {"-", "=", "_"}:
            continue
        if lowered.startswith(("warning:", "error:", "floss version", "finished ")):
            continue

        address = 0
        value = line
        match = re.match(r"^(?:0x)?([0-9a-fA-F]{6,16})(?:\s*[:|]\s*|\s{2,})(.+)$", line)
        if match:
            address = int(match.group(1), 16)
            value = match.group(2).strip()
        if value:
            entries.append({"string": value, "address": address, "_parent_key": category, "_text_fallback": True})
        if len(entries) >= MAX_FLOSS_ENTRIES:
            break
    if not entries:
        raise ValueError("FLOSS returned text output, but no recognized string sections were found.")
    return entries


def _coerce_address(value):
    if isinstance(value, bool):
        return 0
    try:
        return int(value, 0) if isinstance(value, str) else int(value or 0)
    except (TypeError, ValueError):
        return 0

class FlossStringsChooser(ida_kernwin.Choose):
    def __init__(self, title, items, embedded=False):
        # In newer IDA versions, these constants are global in ida_kernwin
        flags = getattr(ida_kernwin, "CH_KEEP", 0)
        if embedded:
            flags |= getattr(ida_kernwin, "CH_EMBEDDED", 0x400)
            
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", 10 | getattr(ida_kernwin, "CHCOL_HEX", 0x2)],
                ["Type", 10],
                ["String", 50],
            ],
            flags=flags,
            embedded=embedded
        )
        self.items = items

    def OnGetLine(self, n):
        item = self.items[n]
        return [hex(item[0]), item[2], item[1]]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnRefresh(self, n):
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

class FlossTabbedViewer(ida_kernwin.PluginForm):
    def __init__(self, results):
        super(FlossTabbedViewer, self).__init__()
        self.results = results
        self.title = "Genesect - Discover Strings with FLOSS"
        self.choosers = []

    def _to_widget(self, form):
        for method_name in ("FormToPyQtWidget", "FormToPySideWidget"):
            method = getattr(self, method_name, None)
            if method:
                try:
                    widget = method(form)
                    if widget:
                        return widget
                except Exception:
                    pass
        return None

    def OnCreate(self, form):
        try:
            parent = self._to_widget(form)
            if not parent:
                print("FLOSS Viewer: Failed to get parent widget from form")
                return
            apply_mac_workspace(parent)
                
            self.main_layout = QtWidgets.QVBoxLayout(parent)
            self.tabs = QtWidgets.QTabWidget()
            configure_content_tabs(self.tabs)
            
            print(f"FLOSS Viewer: Creating tabs for {len(self.results)} results...")
            
            # Categorize results
            categories = ["ASCII", "Unicode", "Stack", "Tight", "Decoded"]
            tabs_added = 0
            for cat in categories:
                cat_items = [item for item in self.results if item[2] == cat]
                # Always show ASCII/Unicode tabs even if empty, others only if they have data
                if not cat_items and cat not in ["ASCII", "Unicode"]:
                    continue
                
                # Sort by address for each tab
                cat_items = sorted(cat_items, key=lambda x: x[0])
                
                chooser = FlossStringsChooser(f"FLOSS {cat}", cat_items, embedded=True)
                self.choosers.append(chooser) # Keep reference
                
                ret = chooser.Embedded()
                if ret == 0:
                    widget_raw = chooser.GetWidget()
                    widget = self._to_widget(widget_raw)
                    if widget:
                        self.tabs.addTab(widget, f"FLOSS {cat} ({len(cat_items)})")
                        tabs_added += 1
                    else:
                        print(f"FLOSS Viewer: Failed to convert chooser widget for {cat}")
                else:
                    print(f"FLOSS Viewer: Failed to embed chooser for {cat} (error {ret})")
            
            self.main_layout.addWidget(self.tabs)
            parent.setLayout(self.main_layout)
            print(f"FLOSS Viewer: UI created with {tabs_added} tabs.")
        except Exception as e:
            print(f"FLOSS Viewer: Error in OnCreate: {e}")
            import traceback
            traceback.print_exc()

    def Show(self):
        return super(FlossTabbedViewer, self).Show(self.title, options=ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WOPN_RESTORE | ida_kernwin.PluginForm.WOPN_PERSIST)

    def OnClose(self, form):
        global floss_strings_chooser
        self.choosers = []
        if floss_strings_chooser is self:
            floss_strings_chooser = None

class FlossWorker(QtCore.QThread):
    finished_signal = QtCore.Signal(str) # Pass results as JSON string to avoid OverflowError
    error_signal = QtCore.Signal(str)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self._proc = None

    def cancel(self):
        self.requestInterruption()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                if sys.platform.startswith("win"):
                    proc.terminate()
                else:
                    os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                pass

    def run(self):
        try:
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 0)
            
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform.startswith("win") else 0
            with tempfile.TemporaryFile() as stdout_file:
                proc = subprocess.Popen(
                    self.cmd, stdout=stdout_file, stderr=subprocess.PIPE,
                    startupinfo=startupinfo, creationflags=creationflags,
                    start_new_session=not sys.platform.startswith("win"),
                )
                self._proc = proc
                try:
                    _, stderr = proc.communicate(timeout=FLOSS_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    if sys.platform.startswith("win"):
                        proc.kill()
                    else:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
                    self.error_signal.emit("FLOSS timed out after 30 minutes.")
                    return
                finally:
                    self._proc = None

                if self.isInterruptionRequested():
                    self.error_signal.emit("FLOSS scan cancelled.")
                    return

                output_size = stdout_file.tell()
                if output_size > MAX_FLOSS_OUTPUT_BYTES:
                    self.error_signal.emit("FLOSS JSON output exceeded the 256 MiB safety limit.")
                    return
                stdout_file.seek(0)
                stdout = stdout_file.read()
            
            if proc.returncode != 0:
                err_msg = stderr.decode('utf-8', 'ignore') if isinstance(stderr, bytes) else str(stderr)
                self.error_signal.emit(err_msg)
                return

            try:
                data = decode_floss_json(stdout, stderr)
                raw_entries = []
                stack = [(data, "")]
                while stack and len(raw_entries) < MAX_FLOSS_ENTRIES:
                    obj, parent_path = stack.pop()
                    if isinstance(obj, dict):
                        if "string" in obj:
                            item = obj.copy()
                            item["_parent_key"] = parent_path
                            raw_entries.append(item)
                        for key, value in obj.items():
                            stack.append((value, f"{parent_path}/{key}"))
                    elif isinstance(obj, list):
                        stack.extend((item, parent_path) for item in reversed(obj))
            except ValueError:
                raw_entries = decode_floss_text(stdout)
            self.finished_signal.emit(json.dumps(raw_entries))
        except Exception as e:
            self.error_signal.emit(str(e))

def on_floss_finished(results_json):
    # CRITICAL: Move processing to the main thread immediately.
    # We use a wrapper to ensure all UI and IDA API calls happen safely.
    def _main_thread_handler():
        try:
            raw_entries = json.loads(results_json)
            ida_kernwin.msg("FLOSS scanning finished.\n")
            
            if not raw_entries:
                ida_kernwin.msg("No strings found by FLOSS in the JSON output.\n")
                return

            results = []
            counts = {"ASCII": 0, "Unicode": 0, "Stack": 0, "Tight": 0, "Decoded": 0}
            failed_to_map = 0
            used_text_fallback = any(bool(entry.get("_text_fallback")) for entry in raw_entries)
            ida_string_addresses = None

            def find_ida_string_address(value):
                nonlocal ida_string_addresses
                if ida_string_addresses is None:
                    ida_string_addresses = {}
                    try:
                        for ida_string in idautils.Strings():
                            rendered = str(ida_string)
                            if rendered and rendered not in ida_string_addresses:
                                ida_string_addresses[rendered] = int(ida_string.ea)
                    except Exception:
                        pass
                return ida_string_addresses.get(value, 0)
            
            for entry in raw_entries:
                s_val = str(entry.get("string", ""))
                if not s_val: continue
                if len(s_val) > 1024 * 1024:
                    continue
                
                parent_key = entry.get("_parent_key", "").lower()
                base_cat = "Static"
                if "stack" in parent_key: base_cat = "Stack"
                elif "tight" in parent_key: base_cat = "Tight"
                elif "decoded" in parent_key: base_cat = "Decoded"

                final_ea = 0
                instances = entry.get("instances", [])
                if instances and isinstance(instances, list):
                    for inst in instances:
                        if not isinstance(inst, dict): continue
                        for k in ["location", "va", "address"]:
                            ea = _coerce_address(inst.get(k, 0))
                            if ea and idaapi.is_mapped(ea):
                                final_ea = ea; break
                        if final_ea: break
                        
                        # Fallback: check offset in inst
                        offset = _coerce_address(inst.get("offset", 0))
                        if offset:
                            ea = idaapi.get_fileregion_ea(offset)
                            if ea != idaapi.BADADDR and idaapi.is_mapped(ea):
                                final_ea = ea; break
                        if final_ea: break
                
                if not final_ea:
                    for k in ["va", "address", "location", "function", "decoding_routine"]:
                        ea = _coerce_address(entry.get(k, 0))
                        if ea and idaapi.is_mapped(ea):
                            final_ea = ea; break
                
                if not final_ea:
                    offset = _coerce_address(entry.get("offset", 0))
                    if offset:
                        ea = idaapi.get_fileregion_ea(offset)
                        if ea != idaapi.BADADDR and idaapi.is_mapped(ea):
                            final_ea = ea

                if not final_ea and entry.get("_text_fallback"):
                    final_ea = find_ida_string_address(s_val)

                if final_ea:
                    label = base_cat
                    if label == "Static":
                        enc = entry.get("encoding", "").upper()
                        label = "Unicode" if ("UTF-16" in enc or "UNICODE" in enc) else "ASCII"
                    
                    if label in ["ASCII", "Unicode"]:
                        if len(s_val) < 4: continue
                        
                        noise_patterns = [
                            r'^[a-zA-Z\\\|]\$[0-9A-Za-z@`]{1,3}$',
                            r'^[a-zA-Z]\$[0-9A-Za-z]{1,3}[A-Z]?$',
                            r'^(AVH|TAVH|VATAVH|VATH|AVD|AV|SVWH|UVWH|SUVWH|A\^A\\A_)$',
                            r'^(A_A\^A\]A\\_|HA\\A\^|HA\\_\^|\^A\^|_\^|\[|\])$',
                            r'^[A-Z_\^\[\]\\]{4,}$',
                            r'^[DTL]\$[0-9A-Za-z]{1,4}$',
                            r'^(U{3,}|f{4,}|A{3,}|_{3,}|\*{3,}|\.{3,}|>{3,})$',
                            r"^[A-Za-z]'[HI];$",
                            r'^[0-9A-Fa-f]{1,2}$',
                            r'^[A-Za-z@\$\\]$',
                            r'^\([a-z]\$[0-9]{1,3}\)$',
                            r'^[\+\-\*/\)][>\<][0-9A-Za-z]{1,3}$',
                            r'^[#=:][A-Za-z]{1,3}[\?]?$',
                            r'^\\t+$',
                            r'^\s+$',
                            r'^[@#\$%\^&\*\(\)\[\]\{\}\\\/\|~`]$',
                            r'^\d+\.\d{10,}$',
                            r'^0x[0-9A-Fa-f]{1,4}$',
                            r'^\.[a-z]+\$[a-z0-9]*$',
                        ]
                        
                        is_noise = False
                        for p in noise_patterns:
                            if re.search(p, s_val):
                                is_noise = True
                                break
                        if is_noise: continue

                        seg = idaapi.getseg(final_ea)
                        if seg:
                            seg_name = idaapi.get_segm_name(seg).lower()
                            if "text" in seg_name or "code" in seg_name:
                                symbol_count = sum(1 for c in s_val if not c.isalnum() and not c.isspace())
                                if symbol_count / len(s_val) > 0.3 or len(s_val) < 10:
                                    continue
                        
                        if sum(1 for c in s_val if not (32 <= ord(c) <= 126)) / len(s_val) > 0.1:
                            continue

                    if label in counts: counts[label] += 1
                    results.append((final_ea, s_val, label))
                else:
                    failed_to_map += 1

            summary_parts = [f"{v} {k}" for k, v in counts.items() if v > 0]
            if summary_parts:
                ida_kernwin.msg(f"Mapped to IDA: {', '.join(summary_parts)}\n")
            if used_text_fallback:
                ida_kernwin.msg(
                    "FLOSS returned legacy text output; Genesect parsed it and matched "
                    "the recovered strings against the current IDB.\n"
                )
            
            if failed_to_map > 0:
                ida_kernwin.msg(f"Note: {failed_to_map} strings found in JSON could not be mapped to binary segments.\n")

            if not results:
                ida_kernwin.msg("FLOSS found results, but none could be mapped to your current segments.\n")
                return

            seen = set()
            unique_results = []
            for ea, s, t in results:
                if (ea, s) not in seen:
                    unique_results.append((ea, s, t))
                    seen.add((ea, s))
            results = sorted(unique_results, key=lambda x: x[0])

            # Save to IDB for persistence
            save_results_to_idb(results)

            global floss_strings_chooser
            floss_strings_chooser = FlossTabbedViewer(results)
            floss_strings_chooser.Show()
        except Exception as e:
            ida_kernwin.msg(f"Error in FLOSS finish handler: {str(e)}\n")

    ida_kernwin.execute_sync(_main_thread_handler, ida_kernwin.MFF_WRITE)

def on_floss_error(err):
    ida_kernwin.msg(f"FLOSS failed with error: {err}\n")


def _clear_floss_thread():
    global floss_thread
    floss_thread = None

def show_floss_strings_ui():
    global floss_thread
    if floss_thread is not None and floss_thread.isRunning():
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "A FLOSS scan is already running. Cancel it?") == ida_kernwin.ASKBTN_YES:
            floss_thread.cancel()
        return
    # Check for existing results in IDB first
    cached_results = load_results_from_idb()
    if cached_results:
        choice = ida_kernwin.ask_buttons("Reload Results", "New Scan", "Cancel", 1, "Cached FLOSS results ({} strings) found in IDB.\nWould you like to reload them or start a fresh scan?".format(len(cached_results)))
        if choice == 1: # Reload
            global floss_strings_chooser
            floss_strings_chooser = FlossTabbedViewer(cached_results)
            floss_strings_chooser.Show()
            return
        elif choice == -1: # Cancel or Close
            return
        # choice == 0 means New Scan and continues below.

    # Handle cross-platform binary names
    is_windows = os.name == 'nt' or sys.platform.startswith('win')
    ext = ".exe" if is_windows else ""
    binary_name = f"floss{ext}"

    floss_path = resolve_floss_executable(CONFIG.floss_path)
    if not floss_path:
        ida_kernwin.msg(f"FLOSS was not found in Settings, bundled tools, or PATH. Please select {binary_name}.\n")
        floss_path = ida_kernwin.ask_file(0, binary_name, f"Locate FLOSS binary ({binary_name}). Download from https://github.com/mandiant/flare-floss/releases")
        floss_path = resolve_floss_executable(floss_path)
        if not floss_path:
            suffix = " On Linux/macOS, ensure the file is executable (chmod +x)." if os.name != "nt" else ""
            ida_kernwin.warning("The selected FLOSS executable is unavailable or not executable." + suffix)
            return
    valid_floss, validation_error = validate_floss_executable(floss_path)
    if not valid_floss:
        if str(CONFIG.floss_path or "").strip():
            CONFIG.floss_path = ""
            CONFIG.save()
        ida_kernwin.warning(validation_error + "\n\nSelect the standalone FLOSS executable from the official Mandiant FLARE-FLOSS release.")
        return
    if CONFIG.floss_path != floss_path:
        CONFIG.floss_path = floss_path
        CONFIG.save()

    # Try to find the original binary
    input_file = idc.get_input_file_path()
    if not input_file or not os.path.exists(input_file):
        # Fallback to IDB based discovery
        idb_path = idc.get_idb_path()
        if idb_path:
            base_name = os.path.splitext(idb_path)[0]
            for ext in ["", ".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".dylib"]:
                p = base_name + ext
                if os.path.exists(p):
                    input_file = p; break

    if not input_file or not os.path.exists(input_file):
        ida_kernwin.msg("Could not automatically locate the binary. Please select the file you are analyzing.\n")
        input_file = ida_kernwin.ask_file(0, "*.*", "Select Binary for FLOSS Scan")
        if not input_file or not os.path.exists(input_file): return
        
    # Detect file type and architecture to check if it's shellcode
    file_type = idc.get_inf_attr(idc.INF_FILETYPE)
    file_type_name = idaapi.get_file_type_name().lower()
    is_pe = "portable executable" in file_type_name or re.search(r"\bpe\b", file_type_name) or file_type == getattr(idc, "FT_PE", 11)
    is_elf = "elf" in file_type_name
    is_macho = "mach-o" in file_type_name or "mach o" in file_type_name
    
    floss_format = None
    if not (is_pe or is_elf or is_macho):
        import ida_ida
        is_64 = ida_ida.inf_is_64bit()
        formats = [
            "32-bit Shellcode (sc32)",
            "64-bit Shellcode (sc64)",
            "PE (Portable Executable / Auto-detect)"
        ]
        default_idx = 1 if is_64 else 0
        
        parent = QtWidgets.QApplication.activeWindow()
        item, ok = QtWidgets.QInputDialog.getItem(
            parent,
            "Select FLOSS Format",
            "The database file is not detected as a standard PE.\n"
            "FLOSS requires a format specification for shellcode.\n"
            "Please select the analysis format:",
            formats,
            default_idx,
            False
        )
        if not ok:
            ida_kernwin.msg("FLOSS Scan cancelled.\n")
            return
            
        if "sc32" in item:
            floss_format = "sc32"
        elif "sc64" in item:
            floss_format = "sc64"

    # Determine if this FLOSS executable supports the JSON output flag.
    # Older v1.x standalone builds do not support -j or --json and output text by default.
    supports_json = False
    json_flag = "-j"
    try:
        completed = subprocess.run(
            [floss_path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if is_windows else 0
        )
        help_text = (completed.stdout + completed.stderr).decode('utf-8', 'replace').lower()
        if "--json" in help_text:
            supports_json = True
            json_flag = "--json"
        elif "-j" in help_text:
            supports_json = True
    except Exception:
        pass

    cmd = [floss_path]
    if supports_json:
        cmd.append(json_flag)
    if floss_format:
        cmd.extend(["--format", floss_format])
    cmd.extend(["--", input_file])
    
    floss_thread = FlossWorker(cmd)
    floss_thread.finished_signal.connect(on_floss_finished)
    floss_thread.error_signal.connect(on_floss_error)
    floss_thread.finished.connect(_clear_floss_thread)
    
    ida_kernwin.msg("Starting FLOSS in background....\n")
    floss_thread.start()

if __name__ == "__main__":
    show_floss_strings_ui()
