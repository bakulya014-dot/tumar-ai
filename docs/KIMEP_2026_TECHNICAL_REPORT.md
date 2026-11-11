# Tumar.AI — technical report for the KIMEP AI Challenge (27–28 Nov 2026)

Status as of **2026-11-09**, branch `feat/demo-readiness` (based on
`a030fbc`, changes not yet committed). Every number below was produced
by running the code on that date; nothing is estimated unless it says so.

## 1. Architecture

See `docs/architecture.html` (rendered: `docs/demo-screenshots/08-system-architecture.png`).

- **Streamlit app** (`app.py`, `views/`) — the product UI. Calls the Trust
  Engine **in-process**; it does not use the REST API. Landing page,
  Google sign-in (Streamlit OIDC), guest mode, kk/ru/en.
- **Trust Engine** (`services/trust_engine.py`) — detects the input type
  (email, URL, message, image; password only when declared), routes it,
  returns one `TrustReport` schema for every module.
- **Detection** — deterministic heuristics in three languages
  (`services/heuristics.py`) + an AI layer behind a provider abstraction
  (Gemini default; DeepSeek, OpenAI, Claude optional) + an evidence-based
  confidence model (`services/confidence.py`) that does not trust the
  model's self-reported certainty.
- **Image scanner** (`services/image_scanner/`) — validation, OCR
  (Tesseract kaz+rus+eng, optional), QR decoding, link checks, intent
  categories, documented risk score.
- **REST API** (`api/`, FastAPI 0.2.0) — keys (hashed), rate limit,
  quotas, metering without content, opt-in sample corpus. See `docs/API.md`.
- **Telegram bot** (`telegram_bot/`) — imports services directly.

## 2. Implemented vs planned

| Implemented and run on 2026-11-09 | Planned / not done |
|---|---|
| Message, URL, email-breach, password-health checks | Reputation feeds for URLs (today: local heuristics + AI only) |
| kk / ru / en detection and interface | Labelled image evaluation set |
| Screenshot scanner: QR decoding, link checks, risk levels | OCR on the deployed site (needs Tesseract via packages.txt; unverified there) |
| REST API with keys, quotas, one error envelope | Browser extension, mobile app |
| Landing page, Google sign-in, guest mode | Persistent user registry on the cloud host (disk is ephemeral) |
| Offline test suites in CI, offline evaluation harness | AI-mode evaluation re-run (costs tokens; last run 2026-08-02) |

## 3. Problems found and fixed in this pass

| # | Problem (how it was found) | Fix |
|---|---|---|
| 1 | Telegram bot token hard-coded in `telegram_bot/main.py` (audit; never committed) | read from `BOT_TOKEN`; fails clearly if missing. **Token must still be revoked in @BotFather** |
| 2 | Real Google OAuth client secret in `.streamlit/secrets.toml.example`, a tracked file (audit; never committed) | placeholders restored. **Rotating the secret is recommended** |
| 3 | `telegram_bot/main.py` could not start: wrong middleware import path, wrong router name, wrong middleware arguments (ran it) | all three fixed; starts and refuses cleanly without a token |

Fixes 1 and 3 live in `telegram_bot/main.py`, which is part of the
bot rewrite that is still uncommitted (`handlers/`, `middlewares/`,
`app/news/`). They are in the working copy and must be committed
together with that work — committing `main.py` alone would add a file
whose imports do not exist in the repository.
| 4 | API crashed at import on a clean install — image-scanner dependencies missing from `requirements-api.txt` (fresh virtualenv) | dependencies pinned; verified by a clean install |
| 5 | A message containing `http://[::1` crashed the analysis with HTTP 500 — `urlparse` raised in `url_reasons` and `normalize_url` (new contract test; reproduced on the old code) | malformed URLs are now ignored / rejected as `invalid_url` |
| 6 | `<script>alert(document.cookie)</script>` was accepted as a URL (new test) | hostnames must be letters, digits, `-`, `.`; look-alike Unicode hosts still accepted |
| 7 | 422 errors echoed the submitted content back; 404/405/422 used a different JSON shape (live probe) | one envelope for every status; 422 lists field names only |
| 8 | Anonymous callers could learn whether the AI key was configured (503 before 401) | authentication checked first |
| 9 | Email lookups refused when no AI key was set, though they need none | only AI-backed analyses fail closed |
| 10 | `/v1/analyzers` advertised `image`, which the API cannot accept | removed from the API registry |
| 11 | Language chosen on the landing page was lost on entering the app (screenshot run) | language value detached from the widget (`app.py`) |
| 12 | Image reports without an AI layer showed AI-centric confidence text and "legibility 0" for a decoded QR code (screenshot review) | documented image-specific confidence rule; legibility shown only when text was read |

Incident during testing: while checking fix 3, the bot entry point
loaded a real `BOT_TOKEN` from `.env` and polled the live bot for about
90 seconds before it was stopped. Any updates queued at that moment
were dropped, and if the deployed bot was running, both polled at once.
Production uses polling (`bot.py` at the time), so no webhook was removed.
(Update 2026-11-11: the entry point is now `telegram_bot.main`, and the
legacy `bot.py` has been removed.)

## 4. Tests executed (2026-11-09)

`python run_tests.py` — **24 of 24 suites passed** (≈83 s, offline, no
API keys). Verbatim output: `docs/evaluation-results.txt`.

New this pass:
- `tests/test_api_contract.py` (13 tests) — runs the **real** analyzers
  and replaces only the network calls: one envelope on every status;
  no echo of submitted values; 401 before 503; each provider failure
  (timeout, unreachable, rate limit, bad credentials, unavailable, model
  unavailable, malformed answer) → the documented status with no
  internals and no fabricated verdict; oversized input never reaches
  the provider; evidence provenance; kk/ru/en reach the same detectors;
  hostile input (SQL-like, script tags, prompt injection, control
  characters, malformed URLs) handled as data; CORS closed by default;
  health without secrets.
- `tests/test_image_scanner.py` (20 tests) — validation and security of
  uploads, QR decoding, link judgement, categories, prompt-injection
  detection, risk scoring, report shape. One test (OCR on real text)
  is skipped where Tesseract is not installed, which is the case on the
  development machine.

Also run: a clean virtualenv with only `requirements-api.txt` →
install succeeded, API imported, `/v1/health` returned 200.

## 5. Performance and reliability (measured)

Live API, real Gemini provider, one laptop, single requests — **seven
measurements, not a load test**:

| Input | Result | Latency |
|---|---|---|
| Russian Kaspi phishing | danger, trust 0 | 16.5 s |
| English work message | safe, trust 100 | 5.6 s |
| Kazakh prize scam | danger, trust 5 | 7.1 s |
| URL with private IP | caution, trust 55 | 14.2 s |
| Email address | breach found | 1.8 s |
| Ambiguous ("Please call me back…") | safe, trust 95 | 5.8 s |
| 6000-character input | 413, rejected before AI | 0.5 s |

0 of 7 requests failed; 0 server tracebacks. Not measured: behaviour
under concurrent load, failure rate over time, latency percentiles.

## 6. Evaluation methodology and results

Corpus (unchanged in this pass): `evals/corpus/` — 61 labelled messages
(33 scam / 28 legitimate) and 40 labelled URLs (20 / 20), in kk / ru /
en, including adversarial cases and hard negatives (real one-time-code
messages, genuine bank warnings, urgent work messages).

**Offline (deterministic layer), 2026-11-09:**

| Measure | Value |
|---|---|
| Scam messages with a risk signal (recall of the rule layer) | 90.9% (30/33) |
| Legitimate messages with a risk signal (false-positive rate of the rule layer) | 42.9% (12/28) |
| URL heuristics, weighted rule: detection / false positives | 100% / 0% |
| URL heuristics, any-finding rule: detection / false positives | 100% / 5% |

**Comparison with the previous baseline** (`evals/results/20260802-120822.json`):
identical on every measure. The fixes in this pass changed no detection
behaviour — which is the intended result for reliability work.

The rule layer alone over-flags legitimate messages (42.9%). That is
by design: it is a high-recall first pass; the AI layer and the
confidence model are meant to bring false positives down.

**AI mode (full pipeline with Gemini) — historical runs, not re-run in
this pass** (each run costs provider tokens):

| Run (`evals/results/`) | Cases | Accuracy | Precision | Recall on scams | False-positive rate |
|---|---|---|---|---|---|
| 2026-07-31 15:34 "before" | 61 | 88.5% | 82.5% | 100% | 25.0% |
| 2026-07-31 15:53 "after" | 61 | 100% | 100% | 100% | 0% |
| 2026-08-02 12:08 (Gemini) | 61 | 100% | 100% | 100% | 0% |

**How to read the 100%:** the prompt and heuristics were changed
between the "before" and "after" runs *using this same corpus*, so the
100% is an **in-sample** result on 61 messages, not evidence of
real-world accuracy. There is no held-out test set for messages yet.
The honest headline is: *100% recall on our 33 labelled scams; false
positives fell from 25% to 0% on our 28 legitimate messages after
tuning; not yet validated on unseen data.* Before the event, re-run
`python evals/runner.py --ai` and, ideally, add a small held-out set
written by someone who has not seen the prompt.

Known measurement gap: the 2026-08-02 run recorded 0 tokens for every
call, so token accounting in the harness is not working.

**Image scanner:** evaluation framework in place
(`evals/image_scanner/`); **no labelled image set exists, so no
image-scanner accuracy figure has been validated.**

## 7. Security review (defensive)

| Area | Finding |
|---|---|
| Secrets | Keys read from environment / `secrets.toml` (git-ignored). Two secrets found in working files (fixed, see §3). Provider keys were printed once in a local tool log during the earlier session — rotate if that log was shared. |
| Input validation | Length limit before any AI call; schema validation; password kind refused over HTTP; image uploads validated by signature, size, pixel count, re-encoded, EXIF removed. |
| Injection | No SQL built from input (parameterised SQLite). Prompt injection: input passed to models inside data markers; injection phrases in images reported as evidence. |
| Rate limiting | Per-key, in-process (resets on restart; not shared across instances). Streamlit app itself has no rate limit. |
| CORS | Off by default; enabled only for listed origins. |
| Error disclosure | Generic messages and stable codes; tracebacks logged server-side only. |
| Logs | No content, keys or report previews logged by the API. |
| Authentication | Hashed API keys, constant-time compare, immediate revocation. Streamlit: Google OIDC or guest. |
| Dependencies | **Not scanned.** `pip-audit` is not installed; run `pip install pip-audit && pip-audit -r requirements.txt -r requirements-api.txt`. |

## 8. Deployment checks

| Check | Result |
|---|---|
| `pip install -r requirements-api.txt` in a clean env | passed |
| API startup + `/v1/health` | passed (`database: ok`) |
| Streamlit startup (`streamlit run app.py`) | passed, no server errors in log |
| Telegram bot (`python -m telegram_bot.main`) | starts; refuses without token |
| Streamlit Community Cloud deploy | **not tested in this pass** |
| Tesseract via `packages.txt` on the cloud host | **not verified** |
| Graceful shutdown | **not verified** (Windows force-terminates) |
| External provider connectivity | verified by the live probe (Gemini) |

## 9. Limitations

- AI analyses take 5–17 s; a slow or failing provider means no verdict
  for messages and URLs (by design: no guessed verdicts).
- The rule layer over-flags legitimate messages (42.9%); AI-mode
  accuracy needs a fresh run.
- Confidence on short, harmless messages can be high on little evidence
  (e.g. "Please call me back" → trust 95, confidence 75).
- URL checks judge the address only; no page is fetched and no
  reputation feed is consulted.
- IPv6 literals are not accepted as URLs.
- Rate limits are per process; quotas need the SQLite database to persist.
- User registry and sample corpus need persistent storage on the cloud host.
- Image scanner: OCR requires Tesseract; no labelled evaluation.
- Bot: `/scan` has the same unguarded `urlparse` at
  `telegram_bot/handlers/commands.py:355` (not changed — bot code is
  under separate development); bot calls XposedOrNot directly instead
  of `services/breach_checker.py`.
- UI: icon font overridden by `assets/styles.css` (literal "arrow_right"
  text in expanders); "Launch Film" menu item not translated.

## 10. Remaining tasks before 27 November (prioritised)

1. Revoke the Telegram bot token; rotate the Google client secret.
2. Review and commit this branch; open a pull request; let CI run.
3. Re-run `python evals/runner.py --ai`; add a small held-out message set nobody tuned against; present in-sample and held-out numbers separately. Fix token accounting in the harness.
4. Deploy to Streamlit Cloud; add `[auth]` secrets there; confirm Google sign-in and Tesseract (`/v1/health` → `ocr`).
5. Front-end: fix the icon-font CSS; translate "Launch Film"; re-capture shots 03/03b/06.
6. Run `pip-audit`.
7. Collect and label 30–50 screenshots (consented / synthetic) for a first image-scanner evaluation.
8. Guard `urlparse` in the bot's `/scan`; decide which bot entry point is the real one (`bot.py` vs `main.py`). *Resolved 2026-11-11: `main.py`; `bot.py` removed.*
9. Rehearse `docs/DEMO_SCRIPT.md` twice with the network you will have on stage.
