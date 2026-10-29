#!/usr/bin/env python3
"""Locate ILSpyCmd without assuming it is installed in one fixed location."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path


def find_ilspycmd() -> list[str] | None:
    explicit = os.environ.get("ILSPYCMD_PATH", "").strip().strip('"')
    if explicit and Path(explicit).is_file():
        return [explicit]
    direct = shutil.which("ilspycmd") or shutil.which("ilspycmd.exe")
    if direct:
        return [direct]
    tool = Path.home() / ".dotnet" / "tools" / ("ilspycmd.exe" if sys.platform == "win32" else "ilspycmd")
    if tool.is_file():
        return [str(tool)]
    dotnet = shutil.which("dotnet") or shutil.which("dotnet.exe")
    if dotnet:
        if sys.platform == "darwin":
            cache_base = Path.home() / "Library" / "Caches"
        elif os.name == "nt":
            cache_base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        else:
            cache_base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        cache = cache_base / "OmniIDB" / "tools" / "ilspycmd" / "9.1.0.7988" / "tools" / "net8.0" / "any" / "ilspycmd.dll"
        if cache.is_file():
            return [dotnet, str(cache)]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Find ILSpyCmd or a cached ILSpyCmd package.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    command = find_ilspycmd()
    print(json.dumps({"command": command or []}) if args.json else (" ".join(command) if command else "ILSpyCmd was not found. Install .NET 8, then run: dotnet tool install --global ilspycmd"))
    return 0 if command else 1


if __name__ == "__main__":
    raise SystemExit(main())
