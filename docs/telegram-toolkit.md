# Telegram Toolkit

The Telegram Toolkit monitors public Telegram channels, runs bots, and dumps bot messages. It uses your own Telegram API credentials and a session string, which you enter once.

Sidebar: **Telegram** (`tg-channel-mon`), **Bot Info** (`tg-info`), **Dump Messages** (`tg-invest`), **Discord C2 Dump** (`discord-c2-dump`), **Telegram Auth Settings** (`tg-auth-settings`).

Data is stored in `backend/data/telegram_intel.db`.

## Telegram Auth Settings

Set this up first.

1. Get an API ID and API hash from my.telegram.org.
2. Open **Telegram Auth Settings** and enter **API ID**, **API hash** and **Phone number**.
3. Click **Send Login Code**, then enter the code in **Login code** and click **Login**.
4. MANTIS stores the session string. Use the same account only from MANTIS; do not sign in with it elsewhere at the same time.

Environment variables can supply the same values: `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_PHONE`, `TELEGRAM_STRING_SESSION`. Other settings: `TG_API_BASE`, `TG_DB_PATH`, `TG_TIMEOUT`, `TG_UA`.

Store the API hash and session string in the key vault (see [Getting Started](getting-started.md#personal-key-vault)), not in shell history.

## Telegram: channel monitoring

Sidebar: **Telegram** (`tg-channel-mon`).

- **Live Feed** shows new messages from monitored channels. **Refresh Feed** fetches them now.
- **Channels** lists the monitored channels. Add one from the channel's username or link.
- **Targets** holds the keywords and entities to match. **Add Target** creates one; **Discover Related** suggests channels linked to a target.
- **Exposures** shows matches that expose a tracked item.
- **Discovery** runs a search for new channels.
- Views: **Cards** and **List**. **Search** filters the feed.

### Tutorial: monitor a channel for a keyword

1. In **Telegram Auth Settings**, confirm the session is logged in.
2. Open **Telegram**, go to **Channels**, and add the channel.
3. Go to **Targets**, click **Add Target**, and enter the keyword.
4. Open **Live Feed** and click **Refresh Feed**. Matches appear with their channel and time.
5. Use **Discover Related** on the target to find other channels that mention it.

## Bot Info

Sidebar: **Bot Info** (`tg-info`).

Register bots and read their details.

- **Add Bot** registers a bot by its token. The token is stored in the local database; keep it out of shared screenshots.
- **Get Info** fetches the bot's name, username and description.
- The list shows each bot's state. The bot controls (`pause`, `start`, `stop`) and `diagnose` are available on the bot API.

## Dump Messages

Sidebar: **Dump Messages** (`tg-invest`).

Capture a bot's conversation into the database.

- **Operator chat ID** (optional) and **Destination chat ID** (optional) set where messages come from and where they go.
- Filter by **All bots** and by message type: text, photo, document, video, audio, voice, sticker.
- **Search** searches the captured messages.
- Artifacts (files) are listed under their message and can be downloaded.

## Discord C2 Dump

Sidebar: **Discord C2 Dump** (`discord-c2-dump`).

A view for Discord-hosted command-and-control messages. Use the pane's filters to narrow the results.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Login code not received | Check the phone number format, then click **Send Login Code** again after the wait. |
| Feed empty | Confirm the channel is in **Channels** and **Refresh Feed** has run. |
| Bot shows an error | Run diagnose on the bot. |
| Session expired | Log in again from **Telegram Auth Settings**. |

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/tg/auth/send_code`, `/api/tg/auth/login` | POST | Sign-in flow. |
| `/api/tg/monitor/channels` | GET, POST | Monitored channels. |
| `/api/tg/monitor/targets` | GET, POST | Targets. |
| `/api/tg/monitor/exposures` | GET | Exposure matches. |
| `/api/tg/monitor/live-feed` | GET | Live feed. |
| `/api/tg/monitor/stats` | GET | Counts. |
| `/api/tg/discover`, `/api/tg/info` | GET, POST | Channel discovery and info. |
| `/api/tg/bots` | GET, POST | List or add bots. |
| `/api/tg/bots/{id}/pause`, `/start`, `/stop`, `/diagnose` | POST | Bot control. |
| `/api/tg/artifacts` | GET | Captured artifacts. |
