#!/usr/bin/env python3
"""Locate an IDA batch executable without assuming an installation version."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path


NAMES = ("idat64.exe", "ida64.exe", "ida.exe", "idat.exe", "idat64", "ida64", "ida", "idat")


def find_ida() -> Path | None:
    explicit = os.environ.get("IDA_PATH", "").strip().strip('"')
    if explicit and Path(explicit).is_file():
        return Path(explicit).resolve()
    for name in NAMES:
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve()
    if sys.platform == "darwin":
        mac_roots = [Path("/Applications"), Path.home() / "Applications"]
        for base in mac_roots:
            for bundle in sorted(base.glob("IDA*.app"), reverse=True):
                for name in NAMES:
                    candidate = bundle / "Contents" / "MacOS" / name
                    if candidate.is_file():
                        return candidate.resolve()
    elif os.name != "nt":
        linux_roots = [Path("/opt"), Path("/usr/local"), Path.home() / ".local" / "opt", Path.home() / "opt"]
        for base in linux_roots:
            if not base.is_dir():
                continue
            for folder in [base, *sorted(base.glob("ida*"), reverse=True), *sorted(base.glob("IDA*"), reverse=True)]:
                for name in NAMES:
                    candidate = folder / name
                    if candidate.is_file():
                        return candidate.resolve()
        return None
    roots = [os.environ.get(key, "") for key in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA")]
    for root in filter(None, roots):
        base = Path(root)
        if not base.is_dir():
            continue
        for folder in sorted(base.glob("IDA*"), reverse=True):
            if not folder.is_dir():
                continue
            for name in NAMES:
                candidate = folder / name
                if candidate.is_file():
                    return candidate.resolve()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Find IDA's idat/idat64 batch executable.")
    parser.add_argument("--json", action="store_true", help="Print a JSON result")
    parser.add_argument("--write", type=Path, help="Write the selected path to this file")
    args = parser.parse_args()
    found = find_ida()
    if args.write:
        args.write.write_text((str(found) if found else "") + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps({"ida_path": str(found) if found else ""}))
    elif found:
        print(str(found))
    else:
        print("IDA batch executable not found. Set IDA_PATH or pass --ida explicitly.")
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
