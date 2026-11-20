# Getting Started

This guide covers installing MANTIS, choosing a deployment mode, signing in, and adding API keys.

## 1. Requirements

- Python 3.10 or newer (3.11+ recommended).
- A modern browser.
- Optional, feature-specific:
  - `ssdeep` needs libfuzzy headers and is **not** installed by default.
  - IDA Pro (`idat64`) or Ghidra (`analyzeHeadless`) for the Binary Lab and richer Similarity features.
  - Telegram API credentials for Telegram monitoring.
  - Provider API keys for the sources you want (see [API keys](#5-add-api-keys)).

## 2. Install and launch

### Windows (workstation)

```cmd
run.bat
```

The first run asks for a **Deployment Mode** and saves it to `.env`. The default address is `http://127.0.0.1:9999`.

```cmd
set MANTIS_PORT=8000
run.bat --server          # Team Server mode
run.bat --workstation     # Workstation mode
run.bat --reconfigure     # Ask for the deployment mode again
```

### Windows Server (team)

```cmd
start_windows_server.bat  :: binds 0.0.0.0, shows the network IP, opens login
test_server_auth.bat      :: runs the auth and multi-user checks
```

### Linux

```bash
chmod +x start_linux.sh
./start_linux.sh                 # first run prompts for the mode
./start_linux.sh --server        # Team Server mode
./start_linux.sh --workstation
```

The script creates `backend/venv`, installs dependencies, and starts the backend in the foreground.

### Manual (development)

```bash
pip install -r requirements.txt
python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 9999
```

### Launch flags and variables

| Setting | Effect |
| --- | --- |
| `--server` / `-s` | Force Team Server mode. |
| `--workstation` / `-w` | Force Workstation mode. |
| `--reconfigure` / `--setup` | Ask for the deployment mode again. |
| `MANTIS_MODE=workstation\|server` | Deployment mode, read from `.env` or the shell. |
| `MANTIS_PORT` | Port (default `9999`). |
| `MANTIS_SKIP_DEPS=1` | Skip dependency checks at launch. |
| `MANTIS_FORCE_DEPS=1` | Run `pip install -r requirements.txt` again. |
| `MANTIS_RELOAD=1` | Uvicorn reload, for development. |
| `MANTIS_YARA_STARTUP_BUILD=1` | Build YARA repositories during startup. |

## 3. Choose a deployment mode

| | Workstation (default) | Team Server |
| --- | --- | --- |
| Use for | One analyst's laptop or desktop | A shared internal server (Linux or Windows) |
| Bind address | `127.0.0.1` | `0.0.0.0` |
| Sign-in | Bypassed; a local analyst profile is used | Required; admin and analyst roles |
| File pickers | Native Windows dialogs | Disabled; use drop zones |
| RE tools | Enter the path, or browse | Auto-detected from `backend/data/tools/` or `PATH` |
| Samples and stealer logs | Browse locally or drag and drop | `backend/data/staging/` drop zones |

You can switch modes later in **Settings -> Deployment Mode** without restarting the server, and check tool discovery and staging counts there.

## 4. First sign-in (Team Server)

Team Server mode requires an admin account.

1. Start the server. The console prints an administrator password on first start.
2. Open the URL shown in the console and sign in as `admin`.
3. Open **Settings -> Team Management** and click **Change My Password**. The new password is written to `.env` so restarts keep it.

To set the password yourself before the first start, set `MANTIS_ADMIN_PASSWORD` (minimum 8 characters; use 12 or more for a shared server). Setting it does not change an admin that already exists in the database.

From the server shell, you can reset the admin password:

```bash
python backend/auth_service.py --reset-admin [new_password]
```

> **Note:** the server generates a new admin password on every start unless `MANTIS_ADMIN_PASSWORD` is set. Restarting invalidates existing sessions, so set the variable in `.env` for any server that restarts.

### Roles

- **Admin**: all analyst features, user provisioning, deployment configuration.
- **Analyst**: all investigation workbenches and a personal key vault.

### Personal key vault

Each analyst stores their own provider keys in **Settings -> API Keys**. Keys are encrypted at rest with AES-256-GCM using the server secret `MANTIS_SECRET_KEY`. One analyst cannot read another's keys or spend another's quota.

## 5. Add API keys

Open **Settings -> API Keys** and paste the keys for the providers you use. Badges show which sources are ready. The Data Feeds page shows the same readiness under **API Key Configuration**.

You can also set server-side environment variables, for example:

```bash
export SHODAN_API_KEY=...
export RANSOMWARE_LIVE_API_KEY=...
export GREYNOISE_API_KEY=...
```

Supported names include `GITHUB_TOKEN`, `CENSYS_PAT`, `CENSYS_API_KEY`, `DRIFTNET_API_TOKEN`, `SILENT_PUSH_API_KEY`, `VALIDIN_API_KEY`, `ETUGEN_API_KEY`, `NETLAS_API_KEY`, `ZOOMEYE_API_KEY`, `PULSEDIVE_API_KEY`, and `IOCINTEL_*` / `MANTIS_*` variants read by `intel_query.py`. The VirusTotal downloader accepts `IOCINTEL_VT_KEY`.

Keyless sources (crt.sh, RIPEstat, OpenPhish, ThreatMiner, the local CTI and PoC databases, and others) work without any key.

## 6. Configure MANTIS AI

Open **Settings -> AI** (or the MANTIS AI panel) and choose a provider, model, timeout and max output. Click **Test** to check connectivity before a long run.

Reasoning models spend output tokens on hidden reasoning. If you see "The AI provider used its whole output budget before writing any answer", raise **Max Output To**. The Intel Reports and Binary Lab paths now use a higher floor (8192 tokens) by default.

## 7. Configure GitHub sources

Under **Settings -> GitHub**, list the repositories the GitHub Threat Intel Repo search should query. These are used by IOC lookups with the GitHub source.

## 8. Data locations

Runtime data lives under `backend/data/`. Keep it out of version control. See [Data and Storage](data-and-storage.md).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Port already in use | Set `MANTIS_PORT` to a free port and relaunch. |
| Login rejected after restart | The admin password rotated. Set `MANTIS_ADMIN_PASSWORD` or reset it from the shell. |
| Source shows "API key required" | Add the key under **Settings -> API Keys**, or set its environment variable, then restart. |
| A page shows "Loading" forever | Check the server console for a traceback and confirm the backend answers `/` with HTTP 200. |
| Module stuck on first use after a fresh install | Some engines build local indexes on first use. Wait, then refresh; check **Data Feeds** for sync status. |
