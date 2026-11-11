# Telegram bot: running, deploying and checking it

The bot is one long-running **worker** process that long-polls Telegram:

```
python -m telegram_bot.main
```

It is independent of the Streamlit website. Both import the same
`services/` package (the Trust Engine, analyzers, quota and telemetry),
but they are separate processes: the website can be down while the bot
answers, and the reverse.

## 1. The one rule: exactly one running copy

Telegram allows **one** `getUpdates` long-poll per bot token. If two
copies run with the same token (a forgotten local run, two replicas, a
deploy that starts the new copy before stopping the old one), each
request cuts the other off with `409 Conflict: terminated by other
getUpdates request`. Updates are split between the copies or lost, and
users get duplicate replies or none.

What protects against it:

| Situation | Protection |
|---|---|
| Two copies on the same machine or container | `telegram_bot/runtime.py` takes an OS file lock at startup. The second copy logs "Another Tumar.AI bot worker is already running on this host" and exits with code 2. |
| Copies on different machines | No lock can see across hosts. Run **one** worker instance (replicas = 1) and never run the bot locally with the production token. Use a separate test bot from @BotFather for local work. |
| It happened anyway | aiogram logs `TelegramConflictError` repeatedly. Stop one copy. |

## 2. Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `BOT_TOKEN` | **yes** | Token from @BotFather. Secret: never commit it, never paste it in an issue or a screenshot. |
| `GEMINI_API_KEY` | recommended | AI analysis. Without it (or when Gemini fails) `/audit` and `/scan` return the labelled rules-only offline report and the check is refunded. |
| `TELEGRAM_ADMIN_ID` | for `/broadcast` | Numeric Telegram user id of the one admin allowed to send `/broadcast`. Unset = nobody can. |
| `TUMAR_BROADCAST_DB` | **yes in production** | Path of the SQLite file that remembers which groups added the bot. Must be on a **persistent disk** (see section 4). Default: `telegram_bot/broadcast.db`, fine locally, wiped on redeploy on most hosts. |
| `TUMAR_BROADCAST_LANGUAGE` | no | Language of the daily group tip: `en` (default), `ru` or `kk`. Groups have no single user language. |
| `TUMAR_DAILY_LIMIT_BOT` | no | Paid checks per Telegram user per day (default 30, `0` = unlimited). Resets 00:00 UTC; counters are in memory and reset on restart. |
| `TUMAR_TELEMETRY` | no | `off` silences the JSON telemetry lines (default on). |
| `TUMAR_MODEL_PRICES` | no | JSON prices per million tokens, to log approximate cost. See `services/telemetry.py`. |
| `TUMAR_LOCK_DIR` | no | Where the single-instance lock file lives (default: the OS temp directory). |
| `TESSERACT_CMD`, `TUMAR_OCR_LANGS` | no | Tesseract location and OCR languages for screenshots. |
| `TUMAR_TEXT_PROVIDER`, `TUMAR_VISION_PROVIDER` and the provider keys | no | Optional alternative AI providers. Leave unset to use Gemini. |

`.env` in the project root is read if present, but variables already
set in the environment win. On a host, set them in its secrets or
environment settings, not in a file in the repository.

## 3. Running locally

Use a **separate test bot**, never the production token (see section 1).

```bash
python -m venv venv
venv\Scripts\activate            # Windows; on macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
set BOT_TOKEN=<test bot token>   # PowerShell: $env:BOT_TOKEN="..."; bash: export BOT_TOKEN=...
python -m telegram_bot.main
```

Screenshot text reading needs Tesseract with the `eng`, `rus` and `kaz`
language packs. Without it the bot still scans QR codes and says that
text reading is unavailable.

Stop with Ctrl+C. The log ends with "Bot stopped: polling ended,
scheduler shut down, session closed."

## 4. Deploying as a persistent worker

Any host that runs a long-lived process works (a container platform's
"worker"/"background worker" service, a VPS with systemd, and so on).
What it needs:

1. **Start command** `python -m telegram_bot.main` from the repository
   root. (`telegram_bot/Procfile` declares it as `worker:`. Some hosts
   only read a Procfile at the repository root; then set the start
   command in the host's settings instead.)
2. **One instance**, no autoscaling, no HTTP port, no health-check URL
   (the bot serves no HTTP). If the platform requires a web service,
   use its worker type instead.
3. **Deploy strategy that stops the old copy first** ("recreate", not
   rolling or blue-green), so two copies never poll at once. A few
   seconds of overlap shows up as `TelegramConflictError` lines and
   resolves itself; minutes of it lose updates.
4. **Restart on failure.** The process exits non-zero on a bad token
   (1) or a second copy on the same host (2); a crash loop on code 1
   means the token is wrong, not that a restart will help.
5. **Persistent disk** mounted, with `TUMAR_BROADCAST_DB` pointing into
   it (for example `/data/broadcast.db`). Without it, every deploy
   forgets the registered groups.
6. **System packages** from `packages.txt` (Tesseract and its language
   packs, `libgl1` for OpenCV) for screenshot scanning.
7. Python dependencies from `requirements.txt`.

Signals: on SIGTERM/SIGINT aiogram stops polling, then the scheduler is
shut down and the HTTP session closed. Updates that arrive while the
bot is restarting are **kept** (startup no longer passes
`drop_pending_updates=True`) and answered when it is back.

## 5. Scheduled dispatch vs `/news`

Two different features, deliberately labelled differently:

| | `/news` | Daily group dispatch |
|---|---|---|
| Trigger | A user sends `/news` | Scheduler, every day at **09:00 Asia/Almaty** |
| Content | Live: the news pipeline (`app/news`) fetches current articles and summarises them | A **curated safety tip** from the bot's fixed, translated tip list, rotating by date |
| Labelled as | A news digest | "Daily safety tip", with a footer saying it is not a news alert and pointing to `/news` |
| Audience | The user who asked | Every group or channel that added the bot |

The previous dispatch posted hard-coded "news" items (for example a
"Zero-Day Alert") that were not current events. They were removed: an
automated message to many groups must not present fixed text as news.
Live scheduled digests are not implemented. If added later, they should
reuse the news pipeline, skip articles already sent, and never publish
AI-generated security alerts without human review.

Scheduler settings (`telegram_bot/main.py`): one job with a fixed id
and `replace_existing`, so it cannot be scheduled twice;
`max_instances=1`; `coalesce=True`, so after downtime it sends once,
not once per missed day; a one-hour grace period for a restart around
09:00.

Delivery: each run logs `Broadcast (daily): sent=N failed=N removed=N`
and a `broadcast` telemetry event. Groups that blocked or removed the
bot are deregistered; Telegram flood-control replies are honoured with
one retry.

## 6. Operational checks

After every deploy, and whenever something seems off:

1. **Startup line.** The log shows
   `Bot started as @<username> (id <n>). Daily dispatch next run: <time>+05:00`.
   The `+05:00` offset confirms Almaty time. No such line within a
   minute means it did not start; look for the error above it.
2. **One poller.** No `TelegramConflictError` lines in the first
   minutes. If they appear, another copy is running (section 1).
3. **It answers.** Send `/start` from a phone. You get the menu in your
   Telegram app's language (English, Russian or Kazakh; others fall
   back to English).
4. **The Trust Engine path.** `/audit send me your SMS code` returns a
   "danger" report, and the log shows an `analysis` telemetry line with
   `"channel":"telegram"`. With no AI key it is labelled offline.
5. **Screenshots.** Send a screenshot of a message. Without Tesseract
   the reply says text reading is unavailable.
6. **Groups.** Add the bot to a test group; nothing is posted until
   09:00. To test delivery without waiting, the admin can send
   `/broadcast test` and should see sent/failed/removed counts.
7. **Secrets.** The log never contains the token: `runtime.SecretFilter`
   masks token- and API-key-shaped strings in every log line.

## 7. Troubleshooting

| Log line | Meaning | Action |
|---|---|---|
| `BOT_TOKEN is not set` | Variable missing | Set it in the host's environment. |
| `Telegram rejected BOT_TOKEN` | Token revoked or mistyped | Get the current token from @BotFather, update the secret, redeploy. |
| `Another Tumar.AI bot worker is already running on this host` | Second copy on the same machine | Stop the other process; do not delete the lock file. |
| `TelegramConflictError` repeating | Second copy elsewhere | Find and stop it (local run, second service, old deployment). |
| `Daily dispatch: no registered chats` | Registry empty | Expected before any group adds the bot; after a deploy, check `TUMAR_BROADCAST_DB` is on persistent disk. |
| `Handler failed: ... error=<Type>` | A handler raised | The update is skipped and polling continues; the traceback follows. User content is not logged. |
