# MANTIS Hermes Bridge Implementation Plan

## Objective

Build a Hermes -> MANTIS bridge where Hermes acts as the agentic analyst runtime and MANTIS exposes trusted CTI, OSINT, MISP, YARA, case, and sample-analysis capabilities as controlled tools.

Hermes should not operate the MANTIS web GUI for core workflows. The bridge should use API, MCP, and optional CLI surfaces.

## Current Implementation Status

Implemented in the local workspace:

- Read-only HTTP tool API under `/api/agent/*`.
- Stdio MCP server for Hermes.
- Local CLI fallback.
- Token authentication, permissions, per-tool rate limiting, audit logging, and redaction.
- Server-side tool argument validation against advertised input schemas.
- MCP prompt pack, MCP resources, and structured analyst output schema.
- Read-only tools for IOC lookup, MISP lookup, CTI articles, IOC extraction, Breach Watcher, YARA metadata/rules, sample similarity metadata, and case workspace review.
- Smoke harness: `python scripts/hermes_bridge_smoke.py`.

Not implemented yet:

- Write-capable case tools, approval queues, sample upload/scanning, IDA execution, bulk enrichment, deployment packaging, and CI wiring. These remain outside the bridge until the approval layer and operational controls are explicitly enabled.

## Core Principles

- MANTIS remains the source of truth for CTI data, provider integrations, cases, and reports.
- Hermes plans and reasons, but MANTIS controls tool permissions and evidence access.
- Default bridge mode is passive/read-only.
- Every tool call is authenticated, authorized, rate-limited, and audited.
- Risky or expensive actions require explicit human approval.
- Tool outputs must be structured JSON, not UI-shaped HTML.
- No arbitrary shell, filesystem, direct database, or unrestricted MISP write access is exposed to Hermes.

## Permission Model

| Level | Purpose | Example Tools |
| --- | --- | --- |
| `read_only` | Passive lookup and retrieval | IOC lookup, MISP lookup, CTI search |
| `case_write` | Write to analyst workspace | Add note, attach finding, add pivot |
| `expensive_action` | Long-running or provider-costly work | Bulk lookup, sample similarity, IDA feature extraction |
| `admin` | Configuration and maintenance | Refresh feeds, provider status, bridge config |
| `blocked` | Never exposed to Hermes | Delete files, write MISP events, submit samples, arbitrary shell |

## Phase 0: Scope And Threat Model

Define exactly what Hermes can do through MANTIS.

Tasks:
- Write an allowed/blocked action matrix.
- Decide which MANTIS features are safe for `read_only`.
- Identify actions requiring approval.
- Define data sensitivity categories: public CTI, API keys, private cases, samples, credentials, reports.
- Decide default deployment mode: localhost-only.

Deliverables:
- `docs/hermes_bridge/threat_model.md`
- Permission matrix
- Initial blocked-action list

## Phase 1: Tool Inventory

Map existing MANTIS capabilities into agent-callable tools.

Candidate tool groups:
- IOC intelligence
- MISP context
- CTI articles
- Breach Watcher
- YARA
- Sample similarity
- Telegram toolkit
- Ransomware monitor
- X Monitor
- Today's Intelligence
- Case/report workspace
- Provider metadata and health

Deliverables:
- `docs/hermes_bridge/tool_inventory.md`
- Tool priority list: v1, v2, later

## Phase 2: Tool Schema Design

Design stable schemas before implementation.

Tasks:
- Define input/output JSON schema for each tool.
- Normalize errors.
- Normalize confidence, severity, provider status, source references.
- Add `tool_version` to every response.
- Add `evidence` arrays where relevant.

Example response envelope:

```json
{
  "ok": true,
  "tool": "mantis.v1.ioc_lookup",
  "tool_version": "1.0",
  "data": {},
  "evidence": [],
  "warnings": [],
  "errors": []
}
```

Deliverables:
- `backend/agent_tools/schemas.py`
- `docs/hermes_bridge/tool_schemas.md`

## Phase 3: Auth, Permissions, And Audit

Add the bridge control layer.

Tasks:
- Add `MANTIS_AGENT_TOKEN`.
- Add optional named tokens later.
- Implement token validation.
- Implement per-tool permission checks.
- Create audit log table/file.
- Redact secrets before logging.

Audit fields:
- timestamp
- token identity
- tool name
- workflow id
- input hash
- input summary
- output status
- duration
- approval id, if any

Deliverables:
- `backend/agent_auth.py`
- `backend/agent_audit.py`
- `.env.example` entries

## Phase 4: Read-Only HTTP Tool API

Expose a stable HTTP API first, then wrap it with MCP.

Endpoint pattern:

```text
POST /api/agent/tools/{tool_name}
GET  /api/agent/tools
GET  /api/agent/audit/recent
```

Initial tools:
- `mantis.v1.provider_metadata`
- `mantis.v1.ioc_lookup`
- `mantis.v1.misp_lookup`
- `mantis.v1.cti_search`
- `mantis.v1.cti_article_get`
- `mantis.v1.extract_iocs`

Deliverables:
- `backend/agent_tools/__init__.py`
- `backend/agent_tools/router.py`
- FastAPI route registration in `backend/main.py`

## Phase 5: MCP Server v1

Expose the read-only tools to Hermes through MCP.

Tasks:
- Build MCP server wrapper around HTTP tool handlers or direct Python functions.
- Keep MCP tool descriptions concise and agent-friendly.
- Support localhost transport first.
- Include Hermes config examples.

Deliverables:
- `backend/mantis_mcp_server.py`
- `docs/hermes_bridge/hermes_setup.md`
- Example Hermes MCP config snippet

## Phase 6: Hermes Analyst Prompt Pack

Provide Hermes with MANTIS-specific operating instructions.

Playbook rules:
- Use MANTIS tools first.
- Cite evidence from tool results.
- Separate facts from inference.
- Prefer passive pivots.
- Do not request blocked actions.
- Ask for approval when needed.

Deliverables:
- `docs/hermes_bridge/prompts/mantis_cti_analyst.md`
- `docs/hermes_bridge/prompts/ioc_triage.md`
- `docs/hermes_bridge/prompts/misp_expansion.md`

## Phase 7: IOC Lookup Tools

Expose MANTIS IOC intelligence as read-only tools.

Tools:
- `mantis.v1.ioc_lookup_domain`
- `mantis.v1.ioc_lookup_ip`
- `mantis.v1.ioc_lookup_url`
- `mantis.v1.ioc_lookup_hash`
- `mantis.v1.ioc_lookup_keyword`
- `mantis.v1.ioc_lookup_auto`

Tasks:
- Reuse existing `intel_query.py` functions.
- Enforce provider allowlists from request.
- Limit response size.
- Include provider errors without crashing the workflow.

Deliverables:
- `backend/agent_tools/ioc_tools.py`
- Tests for representative IOC types

## Phase 8: MISP Tools

Expose passive MISP knowledge to Hermes.

Tools:
- `mantis.v1.misp_lookup_ioc`
- `mantis.v1.misp_event_get`
- `mantis.v1.misp_event_reports`
- `mantis.v1.misp_related_iocs`
- `mantis.v1.misp_galaxy_context`
- `mantis.v1.misp_warninglist_check`
- `mantis.v1.misp_sightings`

Rules:
- Read-only only.
- No event creation.
- No attribute submission.
- No enrichment trigger.
- No tag or galaxy modification.

Deliverables:
- `backend/agent_tools/misp_tools.py`
- Read-only guard tests

## Phase 9: CTI Article Tools

Expose CTI Articles as a knowledge source.

Tools:
- `mantis.v1.cti_search`
- `mantis.v1.cti_article_get`
- `mantis.v1.cti_article_summarize`
- `mantis.v1.cti_article_extract_iocs`
- `mantis.v1.cti_article_related`

Tasks:
- Reuse existing CTI DB and extractor.
- Return article metadata, source, date, title, content excerpt, and IOCs.
- Support article-to-MISP pivot workflow.

Deliverables:
- `backend/agent_tools/cti_tools.py`
- CTI article triage playbook

## Phase 10: Breach Watcher Tools

Expose safe breach intelligence.

Tools:
- `mantis.v1.breach_feed_search`
- `mantis.v1.hibp_breach_catalog_search`
- `mantis.v1.hibp_breach_get`
- `mantis.v1.leak_lookup_search`

Rules:
- Leak-Lookup requires user-provided key.
- No bundled API keys.
- Redact exposed credential values in agent responses unless explicitly approved.

Deliverables:
- `backend/agent_tools/breach_tools.py`

## Phase 11: YARA Tools

Expose rule search and non-destructive scanning.

Tools:
- `mantis.v1.yara_repo_status`
- `mantis.v1.yara_rule_search`
- `mantis.v1.yara_rule_get`
- `mantis.v1.yara_scan_uploaded_sample`
- `mantis.v1.yara_workbench_validate`

Approval:
- Scanning uploaded samples may require `expensive_action`.

Deliverables:
- `backend/agent_tools/yara_tools.py`

## Phase 12: Sample Similarity Tools

Expose malware-analysis and similarity results.

Tools:
- `mantis.v1.sample_similarity_status`
- `mantis.v1.sample_static_metadata`
- `mantis.v1.sample_yara_matches`
- `mantis.v1.sample_ida_features`
- `mantis.v1.sample_compare`
- `mantis.v1.sample_similarity_run`

Approval:
- `sample_similarity_run`
- IDA/headless extraction
- Large file analysis

Deliverables:
- `backend/agent_tools/sample_tools.py`
- Similarity explanation playbook

## Phase 13: Case Workspace Tools

Let Hermes interact with MANTIS cases under permission control.

Tools:
- `mantis.v1.case_create`
- `mantis.v1.case_get`
- `mantis.v1.case_add_note`
- `mantis.v1.case_attach_finding`
- `mantis.v1.case_add_pivot`
- `mantis.v1.case_generate_report`

Rules:
- Reads can be `read_only`.
- Writes require `case_write`.
- Report generation may require approval.

Deliverables:
- `backend/agent_tools/case_tools.py`
- Case write approval tests

## Phase 14: Human Approval Layer

Implement approvals for risky actions.

Approval-required examples:
- Case writes
- Report generation
- Bulk external lookups
- Sample similarity run
- IDA headless analysis
- Feed refresh jobs

Tasks:
- Add approval queue.
- Add approval statuses: pending, approved, denied, expired.
- Add UI surface later for approval management.
- Return approval-required response to Hermes.

Deliverables:
- `backend/agent_approvals.py`
- Approval API endpoints
- Audit integration

## Phase 15: Structured Analyst Output

Standardize how Hermes should return investigation output.

Schema:

```json
{
  "summary": "",
  "verdict": "benign|suspicious|malicious|unknown",
  "confidence": "low|medium|high",
  "evidence": [],
  "recommended_pivots": [],
  "gaps": [],
  "caveats": [],
  "next_steps": []
}
```

Deliverables:
- `docs/hermes_bridge/analyst_output_schema.md`
- JSON schema for validation

## Phase 16: Evidence And Citation Layer

Require every conclusion to cite MANTIS evidence.

Tasks:
- Add stable evidence IDs to tool results.
- Include provider name, timestamp, source URL/event ID/article ID.
- Make Hermes prompt require evidence references.

Deliverables:
- Evidence ID format
- Evidence validation helper

## Phase 17: Rate Limits And Quotas

Prevent accidental provider/API abuse.

Limits:
- Per token
- Per tool
- Per workflow
- Per external provider
- Per time window

Deliverables:
- `backend/agent_rate_limit.py`
- Configurable defaults in `.env.example`

## Phase 18: Redaction Layer

Protect secrets and sensitive artifacts.

Redact:
- API keys
- tokens
- cookies
- passwords
- Telegram bot tokens
- session strings
- private case notes unless authorized

Deliverables:
- `backend/agent_redaction.py`
- Unit tests with representative secret shapes

## Phase 19: Workflow State Store

Store multi-step agent workflows.

Fields:
- workflow id
- tool calls
- approvals
- intermediate outputs
- final report
- status
- created/updated timestamps

Deliverables:
- `backend/agent_workflows.py`
- SQLite schema or existing case DB integration

## Phase 20: Evaluation Harness

Test agent quality and safety.

Benchmark cases:
- Benign domain
- Malicious domain
- Hash with MISP hit
- Hash with conflicting provider results
- CTI article with embedded IOCs
- MISP event with galaxies
- Ransomware victim triage

Score:
- Correct tool selection
- Factuality
- Citation quality
- Pivot usefulness
- Hallucination rate
- Policy compliance

Deliverables:
- `tests/agent_eval_cases/`
- `backend/agent_eval.py`
- Evaluation report template

## Phase 21: CLI Wrapper

Add optional command-line access to the same tools.

Examples:

```bash
mantis-agent ioc-lookup --type domain example.com
mantis-agent misp-lookup --ioc 1.2.3.4
mantis-agent cti-search --query "akira ransomware"
```

Deliverables:
- `backend/mantis_agent_cli.py`
- CLI docs

## Phase 22: Documentation

Write public-facing docs.

Docs:
- Setup
- Security model
- Tool reference
- Hermes MCP config
- Example playbooks
- Troubleshooting
- Local-only warning

Deliverables:
- `docs/hermes_bridge/README.md`
- `docs/hermes_bridge/security.md`
- `docs/hermes_bridge/tools.md`

## Phase 23: Packaging

Package the bridge cleanly.

Options:
- Built-in MANTIS module
- Optional `mantis-hermes-bridge` package
- Docker compose service

Deliverables:
- Packaging decision
- Install instructions
- Versioning policy

## Phase 24: Deployment Hardening

Prepare safe deployment defaults.

Tasks:
- Localhost-only by default.
- Require token for agent endpoints.
- Restrict CORS.
- Add reverse-proxy guidance.
- Document TLS expectations.
- Document that MANTIS is not internet-safe without auth/proxy.

Deliverables:
- Hardened defaults
- Deployment checklist

## Phase 25: Public Release Preparation

Prepare for GitHub release.

Tasks:
- Remove generated databases and reports from git.
- Remove private `.env`.
- Add license.
- Add `SECURITY.md`.
- Add clean `.env.example`.
- Ensure no hard-coded API keys.
- Run secret scan.
- Run syntax/tests.

Deliverables:
- Release checklist
- Clean public branch

## Recommended Build Order

1. Phase 0 to Phase 3: safety, schemas, auth, audit.
2. Phase 4: read-only HTTP API.
3. Phase 5: MCP server v1.
4. Phase 7 to Phase 9: IOC, MISP, CTI tools.
5. Phase 6 and Phase 15: Hermes playbooks and output format.
6. Phase 16 to Phase 18: evidence, quotas, redaction.
7. Phase 13 to Phase 14: case writing and approvals.
8. Phase 12: sample similarity bridge.
9. Phase 20: evaluation harness.
10. Phase 21 to Phase 25: CLI, docs, packaging, hardening, release.

## First Milestone

The first useful milestone should be:

```text
Hermes can use MANTIS read-only tools to perform IOC triage with evidence-backed output.
```

Minimum tools:
- `mantis.v1.provider_metadata`
- `mantis.v1.ioc_lookup_auto`
- `mantis.v1.misp_lookup_ioc`
- `mantis.v1.cti_search`
- `mantis.v1.cti_article_get`
- `mantis.v1.extract_iocs`

Minimum controls:
- Agent token
- Tool allowlist
- Audit logging
- Redaction
- Rate limit
