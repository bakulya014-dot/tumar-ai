# KIMEP AI Conference: demo script, deployment checklist, risks

## 1. Deployment checklist (do in this order, the day before)

**Credentials (owner only, never in chat, code or screenshots).**
These were exposed earlier and must be replaced before the demo:

1. Gemini API key: delete the old one in Google AI Studio, create a new one.
2. Cookie secret: set a new long random string. Everyone is signed out once.
3. Telegram bot token: send `/revoke` to @BotFather and set the new token
   where the bot runs, as `BOT_TOKEN`.
4. Google OAuth client secret: already replaced. In Google Cloud Console,
   disable and then delete any older secret on the same client.

**Streamlit Cloud → Manage app → Settings → Secrets.** Top-level keys
first, then the sections (TOML puts every key after `[auth]` inside it):

```toml
GEMINI_API_KEY = "..."

[auth]
redirect_uri = "https://tumar-ai.streamlit.app/oauth2callback"
cookie_secret = "..."
client_id = "....apps.googleusercontent.com"
client_secret = "..."
server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
```

Save, then **Reboot app**.

**Google Cloud Console → the OAuth client.**
- Authorized redirect URI includes exactly
  `https://tumar-ai.streamlit.app/oauth2callback`.
- Audience: the app is published ("In production"), or every account
  that will sign in on stage is listed as a test user.

**After the reboot, check in a private window:**

| Step | Expected |
|---|---|
| Open https://tumar-ai.streamlit.app | Landing page; no "Google sign-in isn't switched on" banner |
| Continue with Google, choose the demo account | Back in the workspace, a welcome message, your name in the sidebar |
| Refresh the page | Still signed in |
| Home → Platform status | "AI engine connected" (not "AI engine not configured") |
| Scam Analyzer with the demo message below | Dangerous verdict, **no** "Offline check" banner |
| Sign out | Back on the landing page |

Use a normal (not private) window on the demo laptop, already signed in
to the demo Google account, so Google does not ask for 2-Step
Verification on stage.

## 2. Conference demo script (about 4 minutes)

**Before going on stage:** sign in once on the demo laptop, open Home,
and click "Clear this session's history" under Recent analyses, so the Safety Center starts empty.

1. **Sign in.** Landing page → **Continue with Google** → the demo
   account. *"Tumar.AI keeps only your name, email, language and sign-in
   dates, and you can delete them any time."*
2. **My Safety Center.** Menu → My Safety Center. It is empty:
   *"Nothing checked yet. Everything here is this session only; Tumar
   writes no check history to disk."*
3. **Paste a realistic phishing message.** Scam Analyzer, paste:

   > Kaspi Bank: your card is blocked due to suspicious activity. To
   > unlock, confirm your details at http://kaspi-secure-verify.xyz/unlock
   > and tell the operator the code from the SMS. You have 30 minutes.

   Press **Analyze message**.
4. **Indicators.** Point at the verdict (Dangerous), the trust score and
   confidence, then open **Evidence behind this verdict**: urgency
   wording, a request for the SMS code, a look-alike Kaspi domain on a
   cheap TLD with no HTTPS. *"Rules found these; the AI judged the whole
   message. Each item says who found it."*
5. **Plain language.** Read the **In short** line and **What is going on?**
6. **Immediate actions.** **What you should do** and **Don't do this**.
   *"Personal data such as phone and card numbers is masked before the
   message ever reaches the AI."*
7. **The wider trend.** Menu → **Threat Map**. *"Your check looks like
   Phishing, one of the scam types tracked here."* Say clearly: *"These
   figures are simulated for the prototype; the page says so. Real
   counts will come only from people who opt in, as categories, never
   the messages themselves."*
8. Back to **My Safety Center**: status "Action needed", the dangerous
   finding, and the top three actions.
9. **Close:** *"Tumar.AI is your digital amulet against online scams."*

**If the network or the AI fails on stage:** the same message still gets
a labelled "Offline check" verdict from the built-in rules, and the
check is not counted against the daily limit. Say so; do not hide it.

**Russian or Kazakh:** switch the language in the sidebar before step 3;
everything above, including Threat Map and Safety Center, is translated.

## 3. Remaining risks

| Risk | Impact | Mitigation |
|---|---|---|
| Live Google sign-in not yet re-verified after the last changes | Demo cannot start signed in | Run the checklist above the day before; guest mode works as a fallback |
| Streamlit Cloud has no persistent disk | `users.db` resets on each redeploy; "Delete my data" removes the row, a redeploy removes all rows | Acceptable for the pilot; see docs/STORAGE_DECISION.md |
| Safety Center and Threat Map are prototypes | Questions about real data | Both pages say what they are: session-only, and simulated figures |
| Masking before AI may change AI wording slightly | Codes and phone numbers reach the model as placeholders | Rule findings still tell the model what the message does; AI-mode accuracy not re-measured (needs an API key) |
| Daily quotas reset on restart (in memory) | Limits are approximate | Fine for one instance; shared limits need Redis or a database later |
| Russian and Kazakh copy not reviewed by a native speaker | Awkward phrasing in front of a local audience | Have a native speaker read the landing, Safety Center, report and Threat Map pages |
| Family Protection Circle not built | — | Deliberately out of scope: it needs consent flows, access control and lasting storage to be safe |
