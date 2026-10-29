"""Isolated headless-ida runner for MANTIS Similarity.

This process loads IDA/idalib, runs the shared similarity extractor, writes the
feature JSON, and exits. Keeping it outside the FastAPI process avoids loading
IDA DLLs into the web server.
"""
from __future__ import annotations

import json
import sys
import traceback


def _write_failure(output_path: str, reason: str) -> None:
    payload = {
        "status": "failed",
        "reason": reason,
        "analysis_engine": "headless-ida",
        "profile": {"status": "failed", "reason": reason, "analysis_engine": "headless-ida"},
        "functions": [],
    }
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))


def main() -> int:
    if len(sys.argv) < 5:
        print("usage: similarity_headless_ida_runner.py <ida-or-idalib> <sample> <output.json> <config.json>", file=sys.stderr)
        return 2
    ida_backend, sample_path, output_path, config_path = sys.argv[1:5]
    headlessida = None
    result = None
    try:
        from headless_ida import HeadlessIda

        headlessida = HeadlessIda(ida_backend, sample_path)
        import similarity_ida_extract as extractor

        config = extractor.load_config(config_path)
        result = extractor.run_extraction(config)
        result["analysis_engine"] = "headless-ida"
        if isinstance(result.get("profile"), dict):
            result["profile"]["analysis_engine"] = "headless-ida"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, separators=(",", ":"))
        return 0 if result.get("status") in {"success", "partial"} else 1
    except Exception as exc:
        reason = f"{exc}\n{traceback.format_exc(limit=8)}"
        _write_failure(output_path, reason[:4000])
        print(reason, file=sys.stderr)
        return 1
    finally:
        if headlessida is not None:
            try:
                headlessida.clean_up()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
