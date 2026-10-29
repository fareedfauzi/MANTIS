# -*- coding: utf-8 -*-
"""Shared Markdown/JSON chat-log export for Genesect conversations."""
import datetime
import json
import os

from genesect.qt_compat import QtWidgets


def _serializable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _serializable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serializable(item) for item in value]
    return str(value)


def _clean_messages(messages, include_system=False):
    output = []
    for message in messages or []:
        if not isinstance(message, dict):
            message = {"role": "message", "content": str(message)}
        role = str(message.get("role", "message") or "message")
        if role == "system" and not include_system:
            continue
        output.append({
            "index": len(output) + 1, "timestamp": message.get("timestamp"),
            "role": role, "content": _serializable(message.get("content", "")),
        })
    return output


def build_chat_log(metadata, messages, extras=None):
    return {
        "schema": "genesect.chat-log.v1",
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "metadata": _serializable(metadata or {}),
        "messages": _clean_messages(messages),
        "extras": _serializable(extras or {}),
    }


def _markdown_value(value):
    return value if isinstance(value, str) else "```json\n%s\n```" % json.dumps(value, indent=2, ensure_ascii=False)


def chat_log_markdown(log):
    metadata = log["metadata"]
    lines = ["# %s" % metadata.get("title", "Genesect Chat Log"), "", "Exported: %s" % log["exported_at"]]
    for key, value in metadata.items():
        if key != "title" and value not in (None, "", [], {}):
            lines.append("%s: %s" % (str(key).replace("_", " ").title(), value))
    lines.extend(["", "## Conversation"])
    for message in log["messages"]:
        timestamp = " · %s" % message["timestamp"] if message.get("timestamp") else ""
        lines.extend(["", "### %s%s" % (message["role"].replace("_", " ").title(), timestamp), "", _markdown_value(message["content"])])
    for key, value in log["extras"].items():
        if value not in (None, "", [], {}):
            lines.extend(["", "## %s" % str(key).replace("_", " ").title(), "", _markdown_value(value)])
    return "\n".join(lines).rstrip() + "\n"


def export_chat_log(parent, dialog_title, default_name, metadata, messages, extras=None):
    path, selected_filter = QtWidgets.QFileDialog.getSaveFileName(parent, dialog_title, default_name, "Markdown log (*.md);;JSON log (*.json)")
    if not path:
        return ""
    wants_json = path.lower().endswith(".json") or selected_filter.startswith("JSON")
    if not os.path.splitext(path)[1]:
        path += ".json" if wants_json else ".md"
    log = build_chat_log(metadata, messages, extras)
    content = json.dumps(log, indent=2, ensure_ascii=False) + "\n" if wants_json else chat_log_markdown(log)
    try:
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(content)
    except OSError as exc:
        QtWidgets.QMessageBox.warning(parent, "Export Failed", str(exc))
        return ""
    return path
