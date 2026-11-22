# Incident checklist: switching off an unsafe integration or feature

For the person on duty. Goal: stop harm within minutes, then fix calmly.
Never paste secrets, user messages or screenshots of user data into
chats or tickets while handling an incident.

## 1. Decide quickly (2 minutes)

| Symptom | Likely cause | Switch |
|---|---|---|
| AI answers look manipulated, wrong, or leak instructions | AI provider or prompt problem | `ai` |
| AI bills spike, or the provider reports abuse | Cost abuse | `ai` (and check quotas) |
| Images may be reaching a provider when they should not | Vision configuration | `vision` |
| Breach database misbehaves, leaks, or is down for long | Third-party service | `breach` |
| Screenshot scanning crashes or is abused | Image pipeline | `images` |
| A key may be leaked | Credential exposure | Rotate the key (section 4), then `ai` until done |

## 2. Switch it off (about 1 minute)

1. Streamlit Cloud → the app → **Manage app → Settings → Secrets**.
2. Add or edit one top-level line (above `[auth]`):
   ```toml
   TUMAR_DISABLE_FEATURES = "ai"            # or "ai,vision", "breach", "images"
   ```
3. Save, then **Reboot app**.
4. For the Telegram bot, set the same variable where the worker runs and
   restart it (docs/TELEGRAM_BOT.md).

What users see:

| Switch | Effect |
|---|---|
| `ai` | No AI call is made. Message and link checks still run on the built-in rules and are labelled as an offline check; the check is not counted against the daily limit. Home shows "AI analysis: switched off". `/news` uses the plain feed. |
| `vision` | No image is sent to a vision model; screenshots still get OCR, QR and link checks. |
| `breach` | The email check answers "This check is temporarily switched off". The REST API returns 503. |
| `images` | Screenshot scanning answers the same; the API returns 503. |

## 3. Confirm (2 minutes)

- Home → Platform status shows the service as **switched off**.
- Run one check of the affected type in a private window: a calm message
  or a labelled offline result, never an error page.
- Logs: a `"event":"guard","action":"feature_disabled"` line appears
  when a switched-off AI path is attempted. Logs never contain content.

## 4. If a credential leaked

1. Rotate it at the provider first: Google AI Studio (Gemini key),
   Google Cloud Console (OAuth client secret: add a new secret, update
   Streamlit, then disable and delete the old one), @BotFather `/revoke`
   (Telegram token), or a new random string (cookie secret; this signs
   everyone out).
2. Update the Streamlit secret, then Reboot app.
3. Run `python scripts/check_secrets.py` locally and check the CI
   "Scan for committed secrets" step is green.

## 5. Recover

- Fix the cause on a branch; tests and CI must pass.
- Remove the feature from `TUMAR_DISABLE_FEATURES` (or delete the line),
  then Reboot app, then repeat section 3 with the service **working**.
- Write down: what happened, when it was switched off and back on, who
  was affected, and what changed. No user content in the write-up.
