# -*- coding: utf-8 -*-
"""Go package function-folder organizer."""

from collections import Counter
import re

import ida_funcs
import ida_kernwin
import idaapi
import idautils

from genesect.qt_compat import QtWidgets


STANDARD_ROOTS = {
    "archive", "bufio", "builtin", "bytes", "cmp", "compress", "container",
    "context", "crypto", "database", "debug", "embed", "encoding", "errors",
    "expvar", "flag", "fmt", "go", "hash", "html", "image", "index", "io",
    "iter", "log", "maps", "math", "mime", "net", "os", "path", "plugin",
    "reflect", "regexp", "runtime", "slices", "sort", "strconv", "strings",
    "sync", "syscall", "testing", "text", "time", "unicode", "unsafe",
}

RUNTIME_ROOTS = {
    "abi", "asan", "atomic", "cgo", "cpu", "gc", "godebug", "goexperiment",
    "internal", "msan", "race", "runtime", "setg", "sys", "type",
}

THIRD_PARTY_ROOTS = {
    "bitbucket.org", "cloud.google.com", "github.com", "gitlab.com", "go.etcd.io",
    "go.opencensus.io", "go.opentelemetry.io", "go.uber.org", "golang.org",
    "gonum.org", "google.golang.org", "gopkg.in", "honnef.co", "k8s.io",
    "modernc.org", "rsc.io",
}

IDA_PREFIXES = (
    "sub_", "loc_", "j_", "nullsub_", "byte_", "word_", "dword_", "qword_",
    "off_", "unk_",
)


def _clean_name(name):
    name = str(name or "")
    if name.startswith("j_") and len(name) > 2:
        return name[2:]
    return name


def _package_from_name(name):
    name = _clean_name(name)
    if not name or name.startswith(IDA_PREFIXES) or "." not in name:
        return ""
    package, _func = name.rsplit(".", 1)
    return package.strip("._/")


def _package_root(package):
    if not package:
        return ""
    normalized = package.replace("\\", "/")
    if "/" in normalized:
        return normalized.split("/", 1)[0]
    if "_" in normalized:
        for host in THIRD_PARTY_ROOTS:
            prefix = host.replace(".", "_") + "_"
            if normalized.startswith(prefix):
                return host
    return normalized.split(".", 1)[0]


def _is_third_party(package):
    value = package.replace("\\", "/")
    underscored = value.replace(".", "_")
    for root in THIRD_PARTY_ROOTS:
        if value == root or value.startswith(root + "/"):
            return True
        if underscored == root.replace(".", "_") or underscored.startswith(root.replace(".", "_") + "_"):
            return True
    return False


def _classify_package(package, name):
    if not package or name.startswith(IDA_PREFIXES):
        return "Uncategorized"
    root = _package_root(package)
    if root in RUNTIME_ROOTS or package.startswith("runtime."):
        return "Runtime"
    if _is_third_party(package):
        return "ThirdParty"
    if root in STANDARD_ROOTS:
        return "Standard"
    return "User"


def _safe_component(value, fallback="unnamed"):
    value = str(value or "").strip().strip("/\\").replace("\\", "/")
    value = re.sub(r"[:*?\"<>|]+", "_", value)
    value = re.sub(r"/+", "/", value)
    value = value.strip(" ./")
    return value or fallback


def _folder_for_row(row):
    category = row["category"]
    package = row["package"]
    if category == "Runtime":
        return "Go/Runtime"
    if category == "Standard":
        return "Go/Standard/%s" % _safe_component(_package_root(package) or "misc")
    if category == "ThirdParty":
        value = package.replace("\\", "/")
        if "/" not in value:
            value = value.replace("_", "/")
        parts = [part for part in value.split("/") if part][:3]
        return "Go/ThirdParty/%s" % "/".join(_safe_component(part) for part in (parts or ["misc"]))
    if category == "User":
        return "Go/User/%s" % _safe_component(package.replace("\\", "/").replace("_", "/"))
    return "Go/Uncategorized"


def collect_go_functions():
    rows = []
    for func_ea in idautils.Functions():
        if ida_kernwin.user_cancelled():
            break
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        name = ida_funcs.get_func_name(func.start_ea) or ""
        package = _package_from_name(name)
        rows.append({
            "ea": int(func.start_ea),
            "name": name,
            "package": package or "(none)",
            "category": _classify_package(package, name),
        })
    return sorted(rows, key=lambda row: (row["category"], row["package"].casefold(), row["name"].casefold(), row["ea"]))


def _mkdir_recursive(func_dir, path):
    current = ""
    for part in [part for part in path.split("/") if part]:
        current = part if not current else current + "/" + part
        try:
            if not func_dir.isdir(current):
                func_dir.mkdir(current)
        except Exception:
            pass


def organize_go_package_folders(rows=None):
    try:
        import ida_dirtree
    except Exception as exc:
        raise RuntimeError("IDA function folders require ida_dirtree support: %s" % exc)

    rows = rows if rows is not None else collect_go_functions()
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    moved = 0
    skipped = 0
    folders = set()
    for row in rows:
        if not row["name"]:
            skipped += 1
            continue
        folder = _folder_for_row(row)
        folders.add(folder)
        _mkdir_recursive(func_dir, folder)
        try:
            func_dir.rename(row["name"], "%s/%s" % (folder, row["name"]))
            moved += 1
        except Exception:
            skipped += 1
    return {
        "moved": moved,
        "skipped": skipped,
        "folders": len(folders),
        "rows": len(rows),
        "counts": Counter(row["category"] for row in rows),
    }


def show_organize_summary(parent=None):
    try:
        rows = collect_go_functions()
        summary = organize_go_package_folders(rows)
    except Exception as exc:
        ida_kernwin.warning("Go package organization failed:\n%s" % exc)
        return None
    message = (
        "Processed %(rows)d functions.\n"
        "Moved %(moved)d functions into %(folders)d Go folders.\n"
        "Skipped %(skipped)d functions that were already moved or unsupported.\n\n"
        "Likely user code: %(user)d\n"
        "Third-party: %(third)d\n"
        "Standard library: %(std)d\n"
        "Runtime/internal: %(runtime)d"
    ) % {
        "rows": summary["rows"],
        "moved": summary["moved"],
        "folders": summary["folders"],
        "skipped": summary["skipped"],
        "user": summary["counts"].get("User", 0),
        "third": summary["counts"].get("ThirdParty", 0),
        "std": summary["counts"].get("Standard", 0),
        "runtime": summary["counts"].get("Runtime", 0),
    }
    QtWidgets.QMessageBox.information(parent or QtWidgets.QApplication.activeWindow(), "Go Package Organizer", message)
    return summary


class GoPackageOrganizerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_organize_summary()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
