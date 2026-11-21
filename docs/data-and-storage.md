# Data and Storage

MANTIS keeps everything local: a set of SQLite databases and folders under `backend/data/`. Nothing is stored in a hosted service unless a feature calls an external API you configured.

## Where data lives

| Path | Holds |
| --- | --- |
| `backend/data/users.db` | Users, roles and password hashes. |
| `backend/data/cti_articles.db` | CTI articles and sources. |
| `backend/data/poc_fts.db` | Vulnerability PoC index (full-text search). |
| `backend/data/infra_hunts.db`, `infra_pivoting.db` | Infra hunts and pivots. |
| `backend/data/opendir_hunt.db` | Open directory hunts. |
| `backend/data/exposure_monitor.db` | C2 & tool exposure queries and results. |
| `backend/data/telegram_intel.db` | Telegram channels, targets, bots and messages. |
| `backend/data/x_monitor.db` | X accounts and posts. |
| `backend/data/credential_stealer.db` | Stealer sources, parsers and credentials. |
| `backend/data/sample_similarity.db` | Similarity families, sample features and past comparisons. Uploaded samples are not kept. |
| `backend/data/malware_db.db` | Malware repository index. |
| `backend/data/threat_hunting.db` | Threat hunting library data. |
| `backend/data/mantis_ai.db` | MANTIS AI chat history and settings. |
| `backend/data/mantis_ai_cases.db` | AI case records. |
| `backend/data/yara-rules/` | YARA rule corpus. |
| `backend/data/c2_hunting_rules/` | C2 hunting rule files. |
| `backend/data/binary_lab/` | AI Binary Analysis Lab working files. |
| `backend/data/reports/` | Generated reports. |
| `backend/data/temp/` | Temporary files; safe to clear when no job is running. |

Set `MANTIS_AI_DB` to move the AI database elsewhere. The Telegram path can be set with `TG_DB_PATH`.

## Backups

Stop the server, then copy `backend/data/` as a whole. Copying a database while the server writes to it can produce an inconsistent copy.

```bash
cd /workspace/MANTIS
# stop the server first (Ctrl+C in its terminal, or cancel the process that runs it)
tar -czf mantis-data-$(date +%F).tgz backend/data
```

Back up `.env` too if you use one. It holds your keys.

## Sensitive data

- `users.db` stores password hashes, not passwords. Restrict access to the file.
- The Credential Stealer and Telegram stores hold personal or sensitive data. Restrict who can read them and delete sources you no longer need.
- API keys live in **Settings -> API Keys** and in `.env`. See [Getting Started](getting-started.md#personal-key-vault).

## Resetting data

- To reset one feature, delete its database file while the server is stopped. MANTIS recreates an empty one on next start.
- Do not delete `users.db` unless you intend to recreate the admin account. Setting `MANTIS_ADMIN_PASSWORD` does not change an admin that already exists in the database.
