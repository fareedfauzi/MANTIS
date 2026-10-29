# Hermes Bridge

This bridge lets Hermes call MANTIS as a controlled CTI tool server. Hermes should use the API/MCP surface, not the web GUI, for core workflows.

## Current Milestone

Implemented:

- Read-only HTTP tool API
- Local stdio MCP server
- Local CLI fallback

Endpoints:

```text
GET  /api/agent/tools
POST /api/agent/tools/{tool_name}
GET  /api/agent/audit/recent
```

Authentication:

```text
Authorization: Bearer <MANTIS_AGENT_TOKEN>
```

or:

```text
X-MANTIS-Agent-Token: <MANTIS_AGENT_TOKEN>
```

## Environment

Copy `.env.example` to `.env` and set:

```env
MANTIS_AGENT_TOKEN=change-me
MANTIS_AGENT_PERMISSIONS=read_only
MANTIS_AGENT_RATE_WINDOW_SECONDS=60
MANTIS_AGENT_RATE_MAX_CALLS=60
```

Agent endpoints are disabled unless `MANTIS_AGENT_TOKEN` is set. For temporary local testing only, set `MANTIS_AGENT_DEV_ALLOW_NO_TOKEN=1`.

## Tools

Initial read-only tools:

- `mantis.v1.provider_metadata`
- `mantis.v1.permission_policy`
- `mantis.v1.ioc_lookup_auto`
- `mantis.v1.misp_lookup_ioc`
- `mantis.v1.cti_search`
- `mantis.v1.cti_article_get`
- `mantis.v1.extract_iocs`
- `mantis.v1.breach_feed_search`
- `mantis.v1.breach_stats`
- `mantis.v1.yara_status`
- `mantis.v1.yara_rule_search`
- `mantis.v1.yara_rule_get`
- `mantis.v1.similarity_dashboard`
- `mantis.v1.similarity_entities`
- `mantis.v1.similarity_entity_get`
- `mantis.v1.case_list`
- `mantis.v1.case_get`
- `mantis.v1.case_related`
- `mantis.v1.case_report`

The YARA and similarity tools exposed here are read-only. They do not upload samples, scan files, save rules, create entities, delete entities, run IDA, or mutate similarity settings.
The case tools exposed here are read-only. They do not sync new evidence, run agents, execute providers, or modify case state.

Hermes can call `mantis.v1.permission_policy` to discover current permissions, rate limits, audit settings, and blocked action classes.

## Tool Argument Shapes

`mantis.v1.ioc_lookup_auto`

```json
{
  "indicator": "example.com",
  "indicator_type": "auto",
  "sources": ["cti_articles", "misp"],
  "provider_keys": {
    "virustotal": "",
    "otx": ""
  },
  "misp": {
    "url": "https://misp.local",
    "key": "",
    "verify_ssl": true
  }
}
```

`mantis.v1.misp_lookup_ioc`

```json
{
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "limit": 50,
  "misp": {
    "url": "https://misp.local",
    "key": "",
    "verify_ssl": true
  }
}
```

`mantis.v1.cti_search`

```json
{
  "query": "Akira ransomware",
  "limit": 5,
  "category": "Analyst"
}
```

`mantis.v1.cti_article_get`

```json
{
  "article_id": 123,
  "include_html": false,
  "max_content_chars": 20000
}
```

`mantis.v1.extract_iocs`

```json
{
  "text": "Observed callback to hxxps://example[.]com/a and CVE-2024-12345"
}
```

or:

```json
{
  "article_id": 123
}
```

`mantis.v1.breach_feed_search`

```json
{
  "query": "example",
  "source": "RecentBreaches",
  "page_size": 10
}
```

`mantis.v1.yara_rule_search`

```json
{
  "query": "stealer",
  "repos": ["elastic", "malpedia"],
  "limit": 20
}
```

`mantis.v1.yara_rule_get`

```json
{
  "repo": "elastic",
  "name": "Windows_Trojan_RevStealer"
}
```

`mantis.v1.similarity_entity_get`

```json
{
  "entity_id": 1,
  "include_functions": true,
  "function_limit": 50
}
```

`mantis.v1.case_get`

```json
{
  "case_id": "domain-example.com"
}
```

## MCP Server

Hermes should launch the local stdio MCP server:

```bash
cd /path/to/IOC-Intel
MANTIS_AGENT_TOKEN=change-me python backend/mantis_mcp_server.py
```

Example MCP server config shape:

```json
{
  "mcpServers": {
    "mantis": {
      "command": "python",
      "args": ["backend/mantis_mcp_server.py"],
      "cwd": "C:\\Work\\RESEARCH_AREA\\Tools_Scripts\\IOC-Intel",
      "env": {
        "MANTIS_AGENT_TOKEN": "change-me",
        "MANTIS_AGENT_PERMISSIONS": "read_only"
      }
    }
  }
}
```

The MCP server implements:

- `initialize`
- `ping`
- `tools/list`
- `tools/call`
- `prompts/list`
- `prompts/get`
- `resources/list`
- `resources/read`

Tool call results include a text JSON payload and `structuredContent` for clients that support it.
Tool arguments are validated server-side against the advertised input schema before the handler runs. Unsupported arguments, missing required fields, type mismatches, enum mismatches, and numeric/string bound violations return an error envelope.

## Prompt Pack

Hermes can fetch MANTIS-specific analyst playbooks through MCP:

- `mantis_cti_analyst`
- `ioc_triage`
- `misp_context_expansion`
- `cti_article_analysis`
- `yara_rule_hunting`
- `similarity_triage`
- `case_review`

The Markdown source files live in `docs/hermes_bridge/prompts/`.

## Resources And Output Contract

Hermes can fetch bridge documentation and response contracts through MCP resources:

- `mantis://docs/hermes-bridge`
- `mantis://docs/analyst-output-contract`
- `mantis://schemas/analyst-output-v1`

Analyst answers should follow `docs/hermes_bridge/output_contract.md` and, when structured output is supported, emit JSON matching `docs/hermes_bridge/schemas/analyst_output.schema.json`.

## Example Calls

List tools:

```bash
curl -H "Authorization: Bearer $MANTIS_AGENT_TOKEN" \
  http://127.0.0.1:9999/api/agent/tools
```

IOC lookup:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANTIS_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:9999/api/agent/tools/mantis.v1.ioc_lookup_auto \
  -d '{"arguments":{"indicator":"example.com","indicator_type":"domain","sources":["cti_articles","misp"]},"reason":"Hermes IOC triage"}'
```

CTI search:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANTIS_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:9999/api/agent/tools/mantis.v1.cti_search \
  -d '{"arguments":{"query":"Akira ransomware","limit":5}}'
```

Extract IOCs:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANTIS_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:9999/api/agent/tools/mantis.v1.extract_iocs \
  -d '{"arguments":{"text":"Observed callback to hxxps://example[.]com/a and 8.8.8.8"}}'
```

## CLI Fallback

Hermes can also call the local CLI wrapper when HTTP/MCP is not available:

```bash
python backend/mantis_agent_cli.py list --pretty
python backend/mantis_agent_cli.py mantis.v1.extract_iocs --pretty \
  --args '{"text":"Observed callback to hxxps://example[.]com/a and CVE-2024-12345"}'
```

## Smoke Test

Run the local bridge regression check:

```bash
python scripts/hermes_bridge_smoke.py
```

This validates CLI, HTTP, MCP tools, MCP prompts, and MCP resources without requiring a running web server.

## Safety

- Current bridge is read-only.
- MISP access uses the existing passive MANTIS MISP integration.
- Audit entries are written to `backend/data/agent_audit.jsonl` by default.
- Inputs and audit logs are redacted for common secret/token patterns.
- No arbitrary shell, filesystem, direct database, or MISP write actions are exposed.
