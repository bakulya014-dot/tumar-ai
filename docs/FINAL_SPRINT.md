# Tumar.AI — final sprint checklist (KIMEP AI Conference, 27–28 Nov 2026)

Working deadline: **26 November**. Baseline checked on 20 November against
`main` @ `4617bac`.

## Where we stand (verified on 20 Nov)

| Item | Status | Evidence |
|---|---|---|
| Automated tests | ✅ 28 / 28 suites pass | `python run_tests.py` |
| Rule layer, scam messages flagged | 90.9 % (30/33) | `python evals/runner.py` |
| Rule layer, legitimate messages flagged (false positives) | 42.9 % (12/28) | same run |
| URL heuristics (weighted rule): detection / false positives | 100 % / 0 % (20+20 URLs) | same run |
| Demo message 1 — Russian Kaspi phishing | ✅ caught by rules: urgency 85, OTP *disclosure*, look-alike `.xyz` domain | `scan_message` |
| Demo message 2 — English meeting note | ✅ no signals (no false alarm) | `scan_message` |
| Demo message 3 — Kazakh prize scam | ✅ OTP *disclosure* + manipulation signals | `scan_message` |
| QR decoding (OpenCV) | ✅ decodes a generated phishing-URL QR code | `decode_qr` |
| Screenshot OCR / image-scanner accuracy | ⚠️ **not validated**: no labelled images, Tesseract not installed locally | `evals/image_scanner/evaluation.py` |
| Deployed version | ❓ **not yet checked**: no deployed URL is recorded in the repo | — |

## Must fix before 26 Nov

1. ~~**Stale numbers in the docs.**~~ Done 20 Nov: report, demo script and
   regenerated `evaluation-results.*` now say 28 suites. Still to do:
   re-capture `09-test-and-evaluation-results.png`, which shows the old run.
2. **Verify the deployed app end to end** (landing → guest → three demo
   messages → QR upload → Telegram bot `/scan`). Record the URL in the README
   and in `DEMO_SCRIPT.md`.
3. **Screenshot / OCR path:** test it on the deployed app, where
   `packages.txt` installs Tesseract. Either build a small labelled image set
   (10–20 images: RU/KK/EN, scam and legitimate) and run the evaluation, or
   demo **QR only** and say plainly that OCR is not yet benchmarked.
4. **Re-capture demo screenshots** from the current UI (the current set is
   from 9 Nov, before the phase-1 changes) as the offline backup.
5. **Backup demo:** screenshots plus a short screen recording of the full
   scenario, kept locally (USB drive and laptop). Also a local run
   (`streamlit run app.py`) with an API key, in case the deployment fails.

## Should do (if time allows)

- Reduce rule-layer false positives on the 12 listed legitimate messages
  (bank warnings, 2FA setup, password-changed notices). **Re-run the eval
  after each change and report before/after on the same corpus**; label it
  in-sample.
- The 3 missed scams (`adv-ru-qr-parking`, `adv-en-crypto-giveaway`,
  `adv-en-subscription`) are known gaps. Be ready to name them if asked.

## Presentation (7 min, English)

1. Problem: multilingual scams in Kazakhstan (SMS, WhatsApp, QR).
2. Live demo: the Russian Kaspi phishing message, then the legitimate
   message (no false alarm).
3. Trust Engine: deterministic evidence first, AI explanation labelled as AI.
4. Privacy: redaction before the AI call; QR links are decoded, **never
   opened**.
5. Honest evaluation: only the numbers in the table above, with corpus sizes.
6. Vision and next steps.

## Judge questions to rehearse

- "How accurate is it?" → measured numbers only, with corpus size and the
  in-sample caveat.
- "Why 42.9 % false positives?" → that is the rule layer alone. It is
  tuned for recall, and the AI layer plus the confidence model decide the
  final verdict.
- "What happens to my data?" → redaction, no storage of raw messages
  (verify this claim in the code before saying it).
- "What if the AI provider is down?" → the deterministic layer still
  returns evidence (show it).
- "Does the screenshot scanner work?" → only claim what item 3 above has
  verified.

## Rule for every number on a slide

If it is not reproduced by `run_tests.py`, `evals/runner.py` or the image
evaluation on the day we build the slides, it does not go on the slide.
