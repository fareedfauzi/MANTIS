# API Reference

MANTIS exposes a REST API under `/api/`. The web interface uses the same endpoints. This page lists how the API works. Each feature guide has its own endpoint table.

## Interactive docs

FastAPI generates interactive docs at `/docs` (Swagger UI) and the schema at `/openapi.json`. Use them to try endpoints.

## Authentication

- Sign in with `POST /api/auth/login`. The session is kept in a cookie.
- `GET /api/auth/me` returns the signed-in user.
- Most endpoints require a session. Requests without one return `401`.
- Roles control what a user can change. See [Getting Started](getting-started.md#roles).

## Conventions

- JSON in and out. Search and list endpoints accept query parameters for filters, paging and limits.
- Long-running jobs return a progress id; poll the matching `progress` or `jobs` endpoint.
- Errors use standard HTTP codes. `400` is a bad request, `401` means not signed in, `403` means the role does not allow the action, `404` means not found, `429` means a rate limit or quota.

## Feature endpoints

| Area | Guide | Prefix |
| --- | --- | --- |
| IOC lookup and feeds | [IOC Search](ioc-search.md) | `/api/query`, `/api/feeds` |
| MANTIS AI | [MANTIS AI](mantis-ai.md) | `/api/ai`, `/api/ai/case` |
| Infrastructure | [Infrastructure Hunting](infrastructure-hunting.md) | `/api/infra-hunts`, `/api/infra-pivoting`, `/api/exposure-monitor` |
| Threat intelligence | [Threat Intelligence](threat-intelligence.md) | `/api/todays-intelligence`, `/api/ransomware-monitor`, `/api/cti`, `/api/intel-reports`, `/api/poc`, `/api/osv` |
| Threat knowledge | [Threat Knowledge](threat-knowledge.md) | `/api/misp-galaxy`, `/api/ktip`, `/api/vt/hunting`, `/api/malware-db` |
| Sigma | [Sigma Rules](sigma-rules.md) | `/api/sigma` |
| YARA | [YARA](yara.md) | `/api/yara`, `/api/ai/yara` |
| Similarity | [Similarity](similarity.md) | `/api/similarity` |
| Monitoring | [Monitoring](monitoring.md) | `/api/x-monitor`, `/api/breach-watcher`, `/api/credential-stealer` |
| Telegram | [Telegram Toolkit](telegram-toolkit.md) | `/api/tg` |
| Binary analysis | [AI Binary Analysis Lab](ai_binary_lab.md) | `/api/binary-lab` |
| VirusTotal | [VT Samples Downloader](vt_bulk_downloader.md) | `/api/vt` |
| Settings and users | [Getting Started](getting-started.md) | `/api/auth/users`, `/api/ai/settings`, `/api/config` |

## Example

```bash
# Sign in and keep the cookie
curl -c jar.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your password>"}' \
  http://127.0.0.1:9999/api/auth/login

# List Sigma stats
curl -b jar.txt http://127.0.0.1:9999/api/sigma/stats
```

Replace the password with your own and do not paste it into shared logs.
