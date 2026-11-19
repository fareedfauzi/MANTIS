# MANTIS — Full Application Audit, Repair and Regression Testing

Started: 2026-11-19. Working tree: `/workspace/MANTIS-audit` (checkout of `fareedfauzi/MANTIS@5ee2116`).
No commits, pushes or deployments were made. All changes are uncommitted working-tree edits.

## Status legend
Discovered / Reproduced / Fixed / Verified / Blocked. Severity: P0 critical, P1 high, P2 medium, P3 low.

## Phase 1 — Inventory (facts, not estimates)

| Item | Value |
|---|---|
| Backend Python files | 266 (186,261 lines) |
| Largest backend modules | `intel_query.py` 14,743 · `main.py` 7,711 · `ai_service.py` 4,655 · `infra_pivoting_service.py` 4,146 |
| Frontend JS files | 30 (app.js 1.6 MB, index.html 315 KB) |
| Registered API endpoints | 467 across 420 paths (`app.openapi()["paths"]`) |
| Databases | SQLite: `users.db`, `cti_articles.db`, `mantis_ai.db`, `malware.db`/`samples.db`, `credential_stealer.db`, `opendir_hunt.db`, `similarity.db`, `ransomware.db`, `x_monitor.db`, `binary_lab` state |
| Background workers | CTI collector loop, auto-tagger thread, weekly data updater, OpenDir watch scheduler, X monitor collection lock, ransomware monitor, telegram intel |
| Auth | PBKDF2-HMAC-SHA256 (120k), HttpOnly SameSite=Lax cookie `mantis_session`, HMAC-signed session tokens, admin/analyst roles |
| Tests present (pre-audit) | `scripts/test_auth_workflow.py`, `scripts/test_opendir_hunt.py`, `scripts/test_x_providers.py` |
| Tooling | Python 3.14 venv, `node --check`, pyflakes, Playwright + Chromium 1255 |

Enumerated programs used: `pyflakes` over the whole backend, `py_compile` over all 266 modules,
`node --check` over all 30 frontend files, AST scans for blocking calls in async functions,
GET handlers that write, and dynamic SQL.

## Bug log

### BUG-01 — P1 — `sigma_ai_converter.py` cannot be imported (SyntaxError)
- **Root cause:** a duplicated `try:` with a mis-indented `from backend.ai_service import _settings_available`, followed by a duplicated `except ImportError`. `py_compile` fails: `IndentationError: expected an indented block after 'try' statement on line 756`.
- **Impact:** `sigma_converter.ai_convert_sigma` / `ai_repair_sigma` / `validate_conversion` all raise on import, so the AI Sigma conversion feature is dead.
- **Fix:** restored the single `try/except ImportError` fallback import.
- **Test:** module compiles; import + `_settings_available` resolution checked.
- **Status:** Fixed / Verified.

### BUG-02 — P2 — SANS ISC lookups raise `NameError` on any non-200
- **File:** `intel_query.py:14678`, `_sans_get`.
- **Root cause:** `_b3_http_error(...)` does not exist (typo for `_b1_http_error`), so a 404/429/500 from SANS ISC raises `NameError` instead of returning the error card.
- **Fix:** call `_b1_http_error(label, resp.status_code)`.
- **Test:** offline test with monkeypatched `requests.get` returning 429/404.
- **Status:** Fixed / Verified.

### BUG-03 — P2 — `Tuple` used but not imported in `omni_idb/workspace_analysis.py`
- **Root cause:** `from typing import Callable, Optional` but `_extract_or_generate_yara` is annotated `-> Tuple[str, str]`.
- **Impact:** `NameError` at function-definition time (no `from __future__ import annotations`), so the module cannot be imported.
- **Fix:** added `Tuple` to the typing import.
- **Status:** Fixed / Verified.

### BUG-04 — P2 — Undefined `target` in `omni_idb/app.py::_on_sample_selected`
- **Root cause:** the handler computes `folder = sample_output_folder(sample.path)` then reads `target / "result.json"`; `target` is undefined, so selecting a sample raises `NameError`.
- **Fix:** use `folder` for both the result and failure paths (`folder / "logs" / "failure.txt"` restored).
- **Status:** Fixed / Verified (compile + pyflakes clean).

### BUG-05 — P2 — `credential_stealer.sync_all_async` raises `NameError: settings`
- **Root cause:** the worker closure reads `settings.get("delete_after_parse", False)`, but `settings` is only a parameter of other functions.
- **Impact:** every full credential-stealer sync aborts on its first local folder.
- **Fix:** `settings = get_settings()` at the start of the worker.
- **Status:** Fixed / Verified.

### BUG-06 — P1 (security) — arbitrary code execution via Sigma `condition`
- **File:** `sigma_engine.py::_eval_condition_expr`.
- **Root cause:** `eval(expr, {"__builtins__": None}, allowed)`. `condition` comes from downloaded rule packs and user-uploaded rules; clearing `__builtins__` is not a sandbox (`().__class__.__bases__[0].__subclasses__()` reaches `os`).
- **Fix:** replaced `eval` with an AST whitelist evaluator (`_safe_bool_expr`) supporting only bool/int constants, `and`/`or`/`not`; anything else falls back to the pre-existing heuristic.
- **Test:** normal Sigma conditions unchanged; `__import__('os').system('id')`, `().__class__...`, `sel1.__class__` all rejected without execution.
- **Status:** Fixed / Verified.

### BUG-07 — P3 — `return` inside `finally` swallows AI errors (`genesect/view.py::on_convert`)
- **Root cause:** `finally:` block returned when `raw_code` was empty, which suppresses any exception raised by decompilation/disassembly.
- **Fix:** `finally` only hides the progress dialog; the early return happens after the block.
- **Status:** Fixed / compile-verified. GUI behaviour not executed (no IDA in this environment) — **unverified**.

### BUG-08 — P1 — `MANTIS_ADMIN_PASSWORD` is validated and then discarded
- **File:** `auth_service.py::init_users_db` (server mode branch).
- **Root cause:** `explicit_pw` is read from the environment and length-checked, then the server-mode path unconditionally does `admin_pass = secrets.token_urlsafe(16); is_random = True`. The document string promises "generates a fresh secure random administrator password **unless MANTIS_ADMIN_PASSWORD is set**". The explicit password was never used, and the random one was printed to the terminal.
- **Impact:** an operator who sets `MANTIS_ADMIN_PASSWORD` (the documented, scriptable path) cannot sign in with it; the account is silently rotated to a random password on every start. Reproduced live: `POST /api/auth/login` returned `401 Invalid username or password.` for the configured password.
- **Fix:** honour the environment value (`admin_pass = explicit_pw; is_random = False`) and print `Password: set from MANTIS_ADMIN_PASSWORD` instead of echoing it.
- **Test:** `TestAdminPasswordFromEnv` — env password authenticates after `init_users_db(rotate_admin=True)`; a wrong password is still rejected. Live: the bundled `scripts/test_auth_workflow.py` (12 steps) now passes 12/12 against the server using `MANTIS_ADMIN_PASSWORD`; before the fix step 3 could not log in.
- **Status:** Fixed / Verified (unit + live).

### BUG-09 — P1 (security) — logout and password changes do not invalidate sessions
- **File:** `auth_service.py` (`create_session_token`, `verify_session_token`), `main.py::auth_logout`.
- **Root cause:** sessions are stateless HMAC tokens valid for 7 days. `POST /api/auth/logout` only deleted the cookie, and `set_user_password` only rewrote the hash, so a copied token kept working after logout and after a password reset. The auth workflow suite reported "session invalidation PASS" because it only checked that the cookie was cleared.
- **Also:** two logins in the same second produced **byte-identical tokens** (payload had no unique id), so revoking one session revoked the other.
- **Fix:** `revoked_sessions` (token denylist, pruned on write) + `session_revocations` (per-user `revoked_before` epoch, bumped by `set_user_password`), both checked inside the existing verification query; random `jti` per token; `auth_logout` now revokes the presented token (cookie or bearer).
- **Test:** `TestSessionRevocation` — token valid before logout, rejected after; other sessions survive; password change invalidates earlier tokens but not the new one; garbage tokens rejected without raising. Live: login → `GET /api/auth/me` 200 → `POST /api/auth/logout` → the same bearer token now returns 401.
- **Status:** Fixed / Verified (unit + live).

### BUG-10 — P2 (security) — no failed-login limit on `/api/auth/login`
- **Root cause:** there was no throttle anywhere on the sign-in path (the only rate limiter in the tree is for agent tool calls), so passwords could be guessed indefinitely.
- **Fix:** new `backend/login_throttle.py`, wired into `auth_login`: 5 failures per (username, client) per 10 min, then a cooldown starting at 60 s and doubling per failure (cap 15 min); a per-username-wide limit (10x) also covers distributed attempts. Memory-bounded (key cap + window eviction), no writes on the success path, generic 429 message so account existence is not disclosed. Tunable via `MANTIS_LOGIN_MAX_FAILURES`, `MANTIS_LOGIN_WINDOW_S`, `MANTIS_LOGIN_MAX_KEYS`.
- **Test:** live — 5 wrong passwords return 401, the 6th returns `429` with `Retry-After: 60`; a valid admin login from the same address still succeeds.
- **Status:** Fixed / Verified (live). Unit tests not added (behaviour is time-based; live check is authoritative).

### BUG-11 — P1 (availability) — `GET /api/yara/status` compiles the whole YARA corpus to answer a status poll
- **File:** `yara_repos.py::engine_status`, `main.py::yara_status`.
- **Root cause:** `engine_status` called `ensure_indexed()` for every repository, which builds the full rule index (parsing and compiling every file) to read four counters. Measured: **+829 MB RSS and a 5 s timeout** on a single GET, on a host where the whole process must fit in 2.9 GB. Together with the two endpoints below it OOM-killed the server twice during the sweep (`dmesg`: `Killed process ... anon-rss:2586708kB`).
- **Fix:** status is now cache-only (`index_snapshot`), reports `indexed_repositories` / `indexing_in_progress`, and starts a **single** background build (kill-switch `MANTIS_YARA_BG_BUILD=0`, 10-minute retry cooldown). All builds now pass through a module-level `_BUILD_GATE` semaphore so a status fill-in and a search cannot allocate concurrently, and `ensure_built` re-checks the cache after acquiring the gate.
- **Test:** live — `GET /api/yara/status` returns 200 in **0.14 s** and **+7 MB** (previously +829 MB / timeout), with `indexing_in_progress: true`.
- **Status:** Fixed / Verified (live). Trade-off: the hero counters read `0` until the background build finishes; the UI caches the first response, so a reload is needed to see final counts.

### BUG-12 — P1 (availability) — `POST /api/todays-intelligence` allocates ~800 MB per call, unbounded
- **File:** `main.py::todays_intelligence`, `todays_intelligence.build_dashboard`.
- **Root cause:** one call fans out ~20 network lanes with a `ThreadPoolExecutor` and builds 500 article summaries; measured **+805 MB** per request. Nothing serialised or cached it, so a handful of parallel requests (or a page reload loop) exceeds the host.
- **Fix:** single-flight semaphore (one build at a time, 25 s wait then `503` + `Retry-After`), 120 s result cache keyed by filters with provider keys hashed (never stored raw), 8-entry cap. Handler split into `_build_todays_intelligence` so the guarded path is obvious.
- **Test:** live — repeat calls are served from cache; a concurrent call is serialised instead of stacking allocations. `ai-brief` (+131 MB) and `ai-report` (+59 MB) remain unguarded (they are reachable only with a configured AI provider) — **open**.

### BUG-13 — P2 (performance) — article feeds pull full article bodies for every row
- **File:** `cti_db.py::recent_articles` — `SELECT a.*` includes `content_text` and `content_html`.
- **Impact:** every caller (`todays_intelligence.today_articles` with `limit>=500`, and the CTI Articles list via `cti_query.feed`) materialises full article bodies that are never read: both call sites only build summaries, and `get_article()` is what serves bodies.
- **Fix:** explicit column projection (id, source, title, url, canonical_url, url_norm, author, published_at, modified_at, fetched_at, excerpt, content_hash, image_url + the joined `source_name` / `source_category` / `indicator_count`).
- **Status:** Fixed / compile-verified. Benchmarked only on an empty dataset in this checkout (the real `cti_articles.db` is not in the audit tree) — **unverified at scale**.

### BUG-14 — P3 (UX) — first-run loader blocked the whole UI until every download finished
- **File:** `frontend/startup-loader.js`, `main.py::_register_startup_progress`.
- **Root cause:** the overlay (`position: fixed`, intercepts pointer events) is dismissed only when `/api/meta/startup-progress` reports `ready`, i.e. when **no** task is `waiting` or `running`. With `MANTIS_HEAVY_STARTUP_DELAY_S=120` the heavy tasks sit in `waiting` for two minutes and then run for minutes more, so the app shell is unclickable at every launch; only the "Continue anyway" button clears it.
- **Fix:** the loader is no longer a modal. It renders as a panel in the bottom-right corner of the app, and only the card accepts pointer events, so the shell stays clickable from the first paint. After 20 s it folds into a small pill showing `n/m ready`; clicking the pill re-expands it, "Continue anyway" still dismisses, and it closes itself 0.4–1.5 s after `ready`.
- **Test:** `TestNoDeadFrontendRoutes.test_startup_loader_does_not_cover_the_app` (asserts the container is `pointer-events: none` and has no `inset: 0`); live — panel served, app clickable during a simulated long startup (`MANTIS_HEAVY_STARTUP_DELAY_S=86400`).
- **Status:** Fixed / Verified (CSS + markup contract; the visual result was not re-checked in a browser harness).

### BUG-15 — P1 (security) — `MANTIS_MODE=server` did not protect the API at all
- **Root cause:** `get_current_user()` already raises `401 Authentication required in Team Server mode.`, but it was injected into only a handful of routes (~20 of 467). Everything else — including destructive endpoints and the provider-key settings — answered anonymously.
- **Measured:** an anonymous sweep of 459 endpoint/method pairs against a `MANTIS_MODE=server` instance returned **177 × 2xx**, e.g. `DELETE /api/infra-hunts/{id}`, `DELETE /api/credential-stealer/credentials`, `POST /api/ai/settings` (writes provider keys), `POST /api/tg/auth/login`.
- **Fix:** app-wide dependency `_enforce_server_mode_auth` on the `FastAPI(...)` app, so it covers every current and future route instead of a hand-maintained list. It allows only the sign-in surface (`/api/auth/*`), the SSO sign-in flow (`/api/ai/sso/*`), `/api/config/deployment`, `/api/meta/startup-progress`, `/api/meta/startup-status`, and all non-`/api/` paths (static shell). Workstation mode is untouched.
- **Note:** the dependency passes the header/cookie to `get_current_user` explicitly; calling it bare would leave its FastAPI markers (`Header(None)`, `Cookie(None)`) as arguments and raise `AttributeError: 'Header' object has no attribute 'lower'`.
- **Test:** `TestServerModeAuthGate` (5 tests) — anonymous GET and DELETE are 401, the login surface and deployment banner stay open, a bad bearer token is 401, workstation mode still serves. Live: `DELETE /api/infra-hunts/whatever` anon → 401, with a session → 422 (validation), i.e. the route is reached only when authenticated.
- **Status:** Fixed / Verified (unit + live, both modes).

### BUG-16 — P2 — Telegram bot routes return 500 on a fresh database
- **File:** `tg_intel.py` helpers (`_job_token`, `_get_bot`, `start_bot`, `stop_bot`, `delete_bot`, `list_bots`, `prune_old_messages`), `main.py`.
- **Root cause:** the schema is created by `tg_intel.init_db()`, which the public data functions call but these helpers do not, so `POST /api/tg/bots/{id}/validate|pause` raised `sqlite3.OperationalError: no such table: tg_bots` → 500. The hourly `tg_intel.prune_old_messages(90)` in the startup loop failed the same way.
- **Fix:** idempotent `ensure_ready()` (lock + flag) that creates the schema once per process, called from those helpers.
- **Test:** `TestTgSchemaBootstrap` — with a throwaway DB path, `_job_token`/`_get_bot`/`stop_bot`/`prune_old_messages` all work on a fresh file. Live: `/api/tg/artifacts` 200, unknown-bot validate/pause now 404.
- **Status:** Fixed / Verified.

### BUG-17 — P2 — `PUT /api/ransomware-monitor/custom-notes/{id}` turns 404 into 500
- **Root cause:** the handler raises `HTTPException(404, "Custom ransom note not found")` inside its `try`, and the trailing `except Exception` rewrote it as `500 {"detail": "Failed to update note: 404: ..."}`.
- **Fix:** `except HTTPException: raise` before the generic handler. An AST sweep of `main.py` for this pattern found 7 try blocks raising `HTTPException` under a bare `except Exception`; 6 already re-raised, this was the only real one.
- **Test:** live — unknown id now returns 404 in 0.07 s (was 500).
- **Status:** Fixed / Verified.

### BUG-18 — P2 — bot stop/pause answered success for ids that do not exist
- **Root cause:** `stop_bot()` unconditionally returns `{"stopped": true}`; the routes never checked the id, so pausing a nonexistent bot reported success and the UI showed a phantom state change.
- **Fix:** `tg_bot_stop` / `tg_bot_pause` look the bot up first and return 404.
- **Status:** Fixed / Verified (live: 404 for an unknown id, 0.01 s).

### BUG-19 — P2 — Sigma rule pages appear hung for ~30 s on first load
- **File:** `sigma_repos.py::index_rules`, `main.py` startup.
- **Root cause:** `/api/sigma/repos`, `/api/sigma/stats` and `/api/sigma/rules` each call `index_rules()`, which parses **9,542 YAML rule files in ~31 s**. The cache is only populated at the end, so every concurrent request re-parsed the corpus (three parallel page calls = 3 × 30 s and 3 × the memory), and the UI retried.
- **Fix:** single-flight `RLock` around the build (`_build_index` split out; `RLock` because the seeding path re-enters `index_rules(force=True)`), plus `warm_index()` and a startup thread `_sigma_sync_then_warm_index` that syncs repositories and then builds the index off the request path (kill-switch `MANTIS_SIGMA_WARM=0`).
- **Test:** live — first call after the warm-up finishes: **0.04 s** (was a >20 s timeout); concurrent calls share one build instead of stacking.
- **Status:** Fixed / Verified (live). A call arriving **during** the warm-up still waits for the build (measured 31.5 s once); it no longer multiplies across requests.

### BUG-20 — P2 — "Sign in with ChatGPT" blocked the request for 180 s and could never succeed
- **File:** `main.py::ai_sso_signin`, `ai_service.py::sign_in_chatgpt` → `omni_runtime/genesect/chatgpt_oauth.sign_in_interactive`.
- **Root cause:** the sign-in is a browser OAuth flow: it starts a loopback callback server, **opens a browser on the host**, and waits for the redirect for the whole timeout. This server is headless, so no browser can open and no redirect can arrive — the request sat for the full 180 s and then failed. Measured live: `TIMEOUT at 180.1 s`.
- **Fix:** `ai_service.sso_signin_unsupported_reason()` returns a reason when the platform has no desktop session (Linux without `DISPLAY`/`WAYLAND_DISPLAY`); the route answers `400` with that message instead of calling the flow. Desktop/CLI SSO providers are already refused for inference on Linux (PR #16), so this closes the last path that could be triggered.
- **Test:** `TestSsoSigninHeadless`; live — `POST /api/ai/sso/signin` → **400 in 0.1 s** with an actionable message (was 180 s, no answer).
- **Status:** Fixed / Verified (live).

### BUG-21 — P2 — `/api/ransomware-monitor/infrastructure` fetched up to 80 remote profiles serially
- **File:** `ransomware_monitor.py::infrastructure_page`.
- **Root cause:** after listing groups it calls `group_profile()` once per group — up to 80 — **serially**, each doing one or more remote HTTP requests. On a cold cache that is minutes: measured `TIMEOUT at 180.1 s`, and the page could never render. The per-request HTTP calls already had timeouts (25 s / 15 s); the defect is the fan-out count and serial execution, not a missing timeout.
- **Fix:** fetch profiles through a small thread pool (8 workers) with a wall-clock budget (`MANTIS_INFRA_PAGE_BUDGET_S`, default 45 s), returning what finished instead of blocking; and stop early once enough rows exist to fill the requested page when no filter is active (filters still require every group, since they run after collection).
- **Test:** `TestInfrastructurePageFanOut` (early stop, filters unchanged, budget bounds a slow provider); live — first call **30.5 s**, repeat call **3.4 s**, both `200` (was >180 s with no response).
- **Status:** Fixed / Verified (live). Cold start is still ~30 s on a keyless install because of the upstream source latency; the budget caps the worst case.

### BUG-22 — P2 (security) — session cookie was hard-coded `secure=False`
- **File:** `main.py` (login and password-change `set_cookie` calls).
- **Root cause:** every deployment, HTTPS included, issued the session cookie without the `Secure` attribute, so a single plaintext request to the same host would leak it.
- **Fix:** `_cookie_secure(request)` — `MANTIS_COOKIE_SECURE=1/0` forces the value; otherwise it follows the request scheme (`X-Forwarded-Proto` first, then `request.url.scheme`), so HTTPS installs get a `Secure` cookie and plain-HTTP installs keep working.
- **Test:** `TestSessionCookieSecure`; live — login over HTTP sets `HttpOnly` without `Secure`, as intended for that scheme.
- **Status:** Fixed / Verified.

### BUG-23 — P3 (crypto hygiene) — `SECRET_KEY` was both the session HMAC key and the AES-GCM key
- **File:** `auth_service.py` (`_encrypt_key` / `_decrypt_key`).
- **Root cause:** one 32-byte secret signed session tokens and encrypted stored provider API keys, so any key-handling change touched both.
- **Fix:** `MANTIS_ENCRYPTION_KEY` (64 hex chars) supplies dedicated key material when set; `_encryption_keys()` returns the candidates in priority order and decryption tries each, with the legacy `SECRET_KEY` last, so keys written before the split stay readable. Encrypting uses the first candidate.
- **Test:** `TestEncryptionKeySplit` (round trip, legacy decryption after the split, duplicate candidates collapsed).
- **Status:** Fixed / Verified. Opt-in by design: changing the default derivation would have made existing stored keys undecryptable.

### BUG-24 — P3 — Telegram UI called two endpoints that do not exist
- **File:** `frontend/app.js::tgExport`, `tgAddArtifactToInvestigation`, and a dead `.tg-art-add` handler.
- **Root cause:** `/api/tg/export/{id}` and `/api/tg/investigations/seed-artifact` were never implemented (no route, no table, no service function), and no element ever rendered the button that would call them — dead code pointing at nothing.
- **Fix:** removed both functions and the unreachable handler branch (189 lines). Implementing them would be a new feature, not a defect repair.
- **Test:** `TestNoDeadFrontendRoutes`; `node --check frontend/app.js`.
- **Status:** Fixed / Verified.

### BUG-25 — P2 (robustness) — outbound provider calls without `timeout=` could pin a worker thread forever
- **Files:** 23 call sites across 12 modules (`intel_query.py`, `x_providers.py`, `feed_intel.py`, `ai_service.py`, `ktip_features.py`, `misp_query.py`, `phish_feeds.py`, `credential_stealer.py`, `binary_lab_sandbox.py`, `main.py`).
- **Root cause:** `requests` has no default timeout, so a provider that accepts the connection and never answers holds the request thread for as long as the OS allows. This is the same class as the two 180 s hangs (BUG-20, BUG-21) and the reason the HTTP sweep had to run against a real server instead of `TestClient`.
- **Fix:** `http_defaults.py` installs a default on `requests.Session.send` (the one point every helper funnels through) — connect 10 s / read 60 s, overridable per call (`timeout=` always wins), configurable with `MANTIS_HTTP_TIMEOUT=connect,read`, disabled with `MANTIS_HTTP_DEFAULTS=0`.
- **Test:** `TestOutboundTimeoutDefault` (injection, explicit timeout preserved, env parsing, kill switch); live — a request to a black-holed address now fails with `ConnectTimeout` after 3 s when configured to `3,5` instead of hanging until the OS gives up.
- **Status:** Fixed / Verified.

### BUG-26 — P2 — `/api/ransomware-monitor/crypto` made up to 100 remote detail calls serially
- **File:** `ransomware_monitor.py::crypto_page`.
- **Root cause:** identical to BUG-21 in the sibling endpoint — one `_ransomlook("/crypto/<group>")` per group, in sequence, up to 100 groups. Measured **61.8 s** on an 8 GiB host with a warm process; the browser gives up long before that.
- **Fix:** same shape as BUG-21 — 8-worker pool with a wall-clock budget (`MANTIS_CRYPTO_PAGE_BUDGET_S`, default 45 s), returning the groups that finished and logging how many were skipped.
- **Test:** `TestCryptoPageFanOut` (budget bounds a slow upstream, row shape preserved). First attempt failed because the test double matched `/crypto/` with `startswith("/crypto/")`, which is the list endpoint itself — the test was wrong, not the code.
- **Status:** Fixed / unit-verified. Not re-measured live on the XL host after the change.

### BUG-27 — P1 — `GET /api/cti/articles` returned 500 on every pre-existing database
- **Symptom:** `{"detail":"CTI feed failed: no such column: a.image_url"}` — the whole CTI article list, and the country/industry reports built on it, dead on the deployed data set.
- **Root cause:** `init_db()` ran `executescript(SCHEMA)`, whose statements are all `CREATE TABLE IF NOT EXISTS`. For a database created before `image_url` was added to `articles`, SQLite does nothing, so the column was never there. The only place `image_url` was added was the corruption-rebuild path, which never runs on a healthy file. The audit missed it because it verified against an empty, freshly created database.
- **Fix:** `cti_db.ensure_columns(conn)` runs before `executescript(SCHEMA)` on every `init_db()`. It derives the expected columns *from `SCHEMA` itself* (`expected_columns()`), compares them with `PRAGMA table_info`, and issues `ALTER TABLE ... ADD COLUMN` for anything missing. Additive only: no data rewritten, nothing dropped, safe on every startup, idempotent.
- **Verified on the real database (41 MB, 640 articles):** `image_url` added, row count unchanged, the exact failing projection now runs, second run adds nothing. End to end with a real uvicorn: `GET /api/cti/articles` **500 → 200**, log line `CTI schema migrated: added articles.image_url`. No other table had drifted.
- **Tests:** `TestCtiSchemaMigration` (column added + rows kept, idempotent, SCHEMA parsing skips constraint lines, fresh database unaffected). 41 tests pass.
- **Status:** Fixed / verified against production data.

## Endpoint sweep (all OpenAPI paths, anonymous vs authenticated, real HTTP)

Method: every path/method in `app.openapi()` is called twice — no session and with an admin session — through a real uvicorn process (`requests`, 5 s timeout), recording status code and process RSS delta per call. One process cannot cover the whole surface on this host: heavy endpoints allocate several hundred MB each and the sum crosses the 2.9 GB limit, so the sweep runs in four shards, each against a freshly started server (`audit/sweep.py`).

| Result | Count |
| --- | --- |
| endpoint/method pairs probed | 459 |
| answered 2xx | ~330 |
| 4xx (validation / not configured / not found) | ~85 |
| 5xx before fixes | 8 (4 distinct causes) |
| timeouts before fixes | 45 |
| timeouts after fixes | 0 unexplained (only >5 s cold starts, re-measured with a 180 s client timeout) |
| 5xx after fixes | 0 (verified per case; see below) |
| anonymous 2xx before BUG-15 fix | **177** |
| anonymous 2xx after BUG-15 fix | 0 outside the documented public paths |

5xx causes found: TG bot schema (BUG-16), custom-note 404→500 (BUG-17), `502` from `/api/ai/test` (correct: no AI provider reachable — the message leaks the internal URL, minor), `503` from `/api/agent/audit/recent` (by design: `MANTIS_AGENT_TOKEN` unset).

Timeout causes found: Sigma YAML index (BUG-19, three routes), YARA corpus compile (BUG-11), dashboard build (BUG-12), and outbound provider calls that have no client-side timeout (Sigma repo sync, SSO sign-in, X dashboard first-run collection). The no-timeout outbound calls are the same class as the TestClient hang that forced the sweep onto real HTTP; the worst offenders now either run in a background thread or are single-flighted, but the individual `requests.get(...)` calls without `timeout=` remain a **documented gap** (they can still block a worker thread indefinitely on a black-holed host). Two endpoints that timed out even under a 180 s client timeout were tracked down and fixed: browser SSO sign-in (BUG-20) and the ransomware infrastructure fan-out (BUG-21).

Memory: `POST /api/todays-intelligence` +805 MB, `GET /api/yara/status` +829 MB, `GET /api/yara/rules/search` +427 MB, `POST /api/todays-intelligence/ai-report` +833 MB, `ai-brief` +131 MB. Three of the four were unbounded per request; the server was OOM-killed twice during the audit (`Killed process ... anon-rss:2586708kB`) before the guards. With the fixes the same sequence completes, but the host is still the limiting factor: **a 3 GiB VM is marginal for this application; 8 GiB is the realistic minimum for the full feature set under load.**

### Frontend calls with no backend route (open)
- `/api/tg/export/{id}` and `/api/tg/investigations/seed-artifact` are called by `app.js`; neither exists in the backend, so the TG "investigations" feature is frontend-only and throws on `!res.ok`.
- Recommendation: implement or hide. Not changed here — it is a missing feature, not a defect with one obvious fix.

### Auth surface items recorded, not changed
- Session cookie is set with `secure=False` (breaks plain-HTTP deployments if flipped, so it needs a mode flag).
- `SECRET_KEY` is used both for session HMAC and for AES-GCM key material (P3 hygiene).

## Unverified / blocked in this environment
- No IDA, Ghidra, Ghidra-based Genesect GUI, or Qt desktop session → those modules are compile- and static-analysis-only.
- No provider credentials (VirusTotal, FOFA, ZoomEye, Shodan, Censys, SilentPush, Validin, ThreatCluster, Kerberos, Telegram, X) → provider integrations assessed statically and with fixtures.
