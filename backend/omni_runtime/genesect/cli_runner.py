# -*- coding: utf-8 -*-
"""Small, IDA-independent process runner for signed-in CLI providers."""

import os
import signal
import subprocess
import time


class CLICancelled(RuntimeError):
    """Raised when a caller cancels an active CLI request."""


def _terminate_process_tree(process):
    """Best-effort termination of the exact process tree started by Genesect."""
    if process.poll() is not None:
        return

    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
                creationflags=flags,
            )
        except Exception:
            try:
                process.terminate()
            except Exception:
                pass
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            try:
                process.terminate()
            except Exception:
                pass

    try:
        process.wait(timeout=2)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def run_cli_command(
    command,
    input_text,
    timeout,
    cancel_checker=None,
    status_callback=None,
    status_interval=5.0,
):
    """Run a captured CLI while retaining cancellation and heartbeat updates."""
    timeout = max(0.1, float(timeout))
    popen_kwargs = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
    else:
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(list(command), **popen_kwargs)
    started = time.monotonic()
    next_status = max(0.1, float(status_interval))
    pending_input = str(input_text or "")

    while True:
        if cancel_checker and cancel_checker():
            _terminate_process_tree(process)
            raise CLICancelled("Signed-in CLI request cancelled.")

        elapsed = time.monotonic() - started
        if elapsed >= timeout:
            _terminate_process_tree(process)
            raise subprocess.TimeoutExpired(list(command), timeout)

        wait_for = min(0.5, max(0.05, timeout - elapsed))
        try:
            stdout, stderr = process.communicate(
                input=pending_input,
                timeout=wait_for,
            )
            return subprocess.CompletedProcess(
                list(command), process.returncode, stdout, stderr,
            )
        except subprocess.TimeoutExpired:
            # communicate() preserves its buffered output across retries. Input
            # must only be supplied on the first call.
            pending_input = None
            elapsed = time.monotonic() - started
            if status_callback and elapsed >= next_status:
                try:
                    status_callback(elapsed)
                except Exception:
                    pass
                next_status += max(0.1, float(status_interval))

