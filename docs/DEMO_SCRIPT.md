# Live demo — KIMEP AI Challenge, 27–28 November 2026

Target length: 5 minutes. Every step below has been run on the real
application; the screenshot named in brackets is the backup if the
network or the AI provider fails on stage.

## Before going on stage (T−30 min)

1. Start the app: `streamlit run app.py` (or open the deployed URL).
2. Run one analysis to warm the provider connection — the first call
   after idle is the slowest.
3. Check `python scripts/run_api_local.py` → `http://localhost:8000/v1/health`
   shows `"ai_provider": "configured"` and `"database": "ok"`.
4. Open `docs/demo-screenshots/` in a second window as the fallback.
5. Have the three demo messages below in a text file, ready to paste.

## Script

**1. The problem (30 s)** — landing page `[01-landing-page.png]`.
"Scams in Kazakhstan arrive in Russian, Kazakh and English, through
SMS, WhatsApp and QR codes. Tumar.AI checks them in plain language."

**2. Enter without an account (15 s)** — "Try without an account".
Google sign-in exists, but nothing is gated behind it. `[02-dashboard-home.png]`

**3. A real phishing SMS, in Russian (60 s)** — Scam Analyzer, paste:

> СРОЧНО! Ваша карта Kaspi заблокирована из-за подозрительной операции. Перейдите http://kaspi-secure-verify.xyz/unlock и назовите код из СМС, иначе средства будут заморожены через 30 минут.

Point out: verdict **and** the evidence behind it — the look-alike
domain and the request to *reveal* a code were found by deterministic
rules; the AI explanation is labelled as AI. The analysis takes 5–15
seconds: say so while it runs. `[03-phishing-analysis-result.png]`

**4. A normal message — no false alarm (30 s)** — paste:

> Hi team, the meeting moved to 3pm tomorrow in room 204. Please bring the Q3 slides.

`[04-legitimate-message-result.png]`

**5. Kazakh (45 s)** — switch the language to Қазақша, paste:

> Құттықтаймыз! Сіз 500 000 теңге ұтып алдыңыз. Сыйлықты алу үшін бізге SMS кодты жіберіңіз.

`[05-kazakh-analysis-result.png]`

**6. A QR code (45 s)** — Screenshot Scanner, upload a QR image that
points to a look-alike domain. Point out: the QR code is decoded but
**never opened**; the link is judged by its address. `[06-screenshot-scanner-qr.png]`

**7. How it works and how we measure it (60 s)** — architecture
`[08-system-architecture.png]`, then the real test/evaluation output
`[09-test-and-evaluation-results.png]`: 24 test suites pass; the
rule-based layer flags 90.9% of scam messages in our labelled corpus
and 42.9% of legitimate ones — which is why the AI layer and the
confidence model exist.

## What to say if asked

- **"How accurate is it?"** — Quote only measured numbers, with the
  corpus size: on our 61 labelled messages, every one of the 33 scams
  was caught, and false alarms on the 28 legitimate messages fell from
  25% to 0% after tuning. Then add the caveat yourself: it was tuned on
  that same corpus, so it is not yet validated on unseen messages; the
  image scanner has no labelled evaluation set yet. Do **not** say
  "100% accurate".
- **"Is it production-ready?"** — It is a working beta. See
  `docs/KIMEP_2026_TECHNICAL_REPORT.md` → Limitations.
- **"Does it store my messages?"** — The app keeps results in the
  session only; images are never stored; samples are contributed only
  if the user opts in, and are redacted first.

## Do not

- Do not demo the email breach checker with a real person's address on
  a projector.
- Do not claim the screenshot scanner reads text on the deployed site
  unless Tesseract is confirmed installed there (`/v1/health` → `ocr`).
