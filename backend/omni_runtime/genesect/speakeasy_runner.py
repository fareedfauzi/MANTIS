# -*- coding: utf-8 -*-
"""Local Speakeasy subprocess runner."""

from __future__ import annotations

import os
import subprocess
import tempfile


def build_speakeasy_command(config, target_path, output_path, arch=""):
    exe = str(getattr(config, "speakeasy_path", "") or "speakeasy")
    command = [exe, "--target", str(target_path), "--output", str(output_path)]
    arch = arch or getattr(config, "speakeasy_default_arch", "")
    if arch:
        command.extend(["--arch", str(arch)])
    timeout = int(getattr(config, "speakeasy_timeout", 60) or 60)
    if timeout > 0:
        command.extend(["--timeout", str(timeout)])
    max_api_count = int(getattr(config, "speakeasy_max_api_count", 10000) or 0)
    if max_api_count > 0:
        command.extend(["--max-api-count", str(max_api_count)])
    command.append("--analysis-coverage")
    if bool(getattr(config, "speakeasy_snapshot_memory", True)):
        command.append("--snapshot-memory-regions")
    if bool(getattr(config, "speakeasy_dropped_files", True)):
        command.extend(["--dropped-files-path", str(output_path) + ".dropped.zip"])
    return command


def run_speakeasy(config, target_path, output_path=None, arch="", timeout=None):
    if not target_path or not os.path.exists(target_path):
        raise ValueError("target path does not exist")
    if output_path is None:
        fd, output_path = tempfile.mkstemp(prefix="genesect-speakeasy-", suffix=".json")
        os.close(fd)
    command = build_speakeasy_command(config, target_path, output_path, arch=arch)
    run_timeout = timeout or max(30, int(getattr(config, "speakeasy_timeout", 60) or 60) + 30)
    completed = subprocess.run(
        command,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=run_timeout,
    )
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "command": command,
        "output_path": output_path,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-12000:],
    }
