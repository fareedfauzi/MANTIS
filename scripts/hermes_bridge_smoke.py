import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
TOKEN = os.environ.get("MANTIS_AGENT_TOKEN") or "local-smoke-token"


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"{name} failed{': ' + detail if detail else ''}")
    print(f"PASS {name}")


def run_cli():
    proc = subprocess.run(
        [
            sys.executable,
            str(BACKEND / "mantis_agent_cli.py"),
            "mantis.v1.extract_iocs",
            "--args",
            '{"text":"Observed hxxps://example[.]com/a and CVE-2024-12345"}',
        ],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        env={**os.environ, "MANTIS_AGENT_TOKEN": TOKEN},
    )
    check("cli_returncode", proc.returncode == 0, proc.stderr[:500])
    body = json.loads(proc.stdout)
    check("cli_extract_iocs", body.get("ok") and body.get("data", {}).get("total") == 2)


def run_http():
    sys.path.insert(0, str(BACKEND))
    os.environ["MANTIS_AGENT_TOKEN"] = TOKEN
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    tools = client.get("/api/agent/tools", headers=headers)
    tool_names = {tool.get("name") for tool in tools.json().get("tools", [])}
    check("http_tools", tools.status_code == 200 and len(tool_names) >= 19)
    for required in {
        "mantis.v1.ioc_lookup_auto",
        "mantis.v1.misp_lookup_ioc",
        "mantis.v1.breach_feed_search",
        "mantis.v1.yara_rule_search",
        "mantis.v1.similarity_dashboard",
        "mantis.v1.case_list",
        "mantis.v1.permission_policy",
    }:
        check(f"http_tool_{required}", required in tool_names)
    extract = client.post(
        "/api/agent/tools/mantis.v1.extract_iocs",
        headers=headers,
        json={"arguments": {"text": "Observed hxxps://example[.]com/a and CVE-2024-12345"}},
    )
    body = extract.json()
    check("http_extract_iocs", extract.status_code == 200 and body.get("ok") and body.get("data", {}).get("total") == 2)


def run_mcp():
    proc = subprocess.Popen(
        [sys.executable, str(BACKEND / "mantis_mcp_server.py")],
        cwd=str(ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "MANTIS_AGENT_TOKEN": TOKEN},
    )
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "mantis.v1.extract_iocs", "arguments": {"text": "hxxps://example[.]org CVE-2024-22222"}},
        },
        {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}},
        {"jsonrpc": "2.0", "id": 5, "method": "prompts/get", "params": {"name": "ioc_triage", "arguments": {"indicator": "example.com"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "resources/list", "params": {}},
        {"jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": {"uri": "mantis://schemas/analyst-output-v1"}},
    ]
    for message in messages:
        proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.close()
    lines = [line.strip() for line in proc.stdout if line.strip()]
    stderr = proc.stderr.read()
    code = proc.wait(timeout=15)
    check("mcp_returncode", code == 0, stderr[:500])
    responses = [json.loads(line) for line in lines]
    by_id = {item.get("id"): item for item in responses}
    check("mcp_tools", len(by_id[2]["result"]["tools"]) >= 19)
    check("mcp_tool_call", by_id[3]["result"]["structuredContent"].get("ok"))
    check("mcp_prompts", len(by_id[4]["result"]["prompts"]) >= 7)
    check("mcp_prompt_get", "Runtime Inputs" in by_id[5]["result"]["messages"][0]["content"]["text"])
    check("mcp_resources", len(by_id[6]["result"]["resources"]) >= 3)
    check("mcp_resource_read", "mantis://schemas/analyst-output-v1" in by_id[7]["result"]["contents"][0]["text"])


def main():
    run_cli()
    run_http()
    run_mcp()
    print("Hermes bridge smoke checks passed.")


if __name__ == "__main__":
    main()
