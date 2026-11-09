# Demo screenshots

Captured from the **real running application** on 2026-11-09 by
`scripts/capture_demo_screenshots.py` (headless Microsoft Edge, 1366×900).
Analyses shown are live calls through the Trust Engine with the Gemini
provider — not mock data. `manifest.json` records the commit, branch,
working-tree state and versions for every image.

| File | Shows | Live analysis |
|---|---|---|
| 01-landing-page.png | Public landing page (English) | — |
| 02-dashboard-home.png | Home dashboard after "Try without an account" | — |
| 03-phishing-analysis-result.png | Russian Kaspi phishing SMS → Dangerous, trust 5 | yes |
| 03b-phishing-analysis-full.png | Same result, full page | yes |
| 04-legitimate-message-result.png | Ordinary work message → Looks safe | yes |
| 05-kazakh-analysis-result.png | Kazakh interface, Kazakh prize scam → Қауіпті | yes |
| 06-screenshot-scanner-qr.png | QR code to a look-alike domain → High (deterministic, no AI) | yes |
| 07-api-docs-swagger.png | API documentation at /docs (v0.2.0) | — |
| 07b-api-health-response.png | Raw /v1/health response | — |
| 08-system-architecture.png | Architecture diagram (docs/architecture.html) | — |
| 09-test-and-evaluation-results.png | Real console output of tests and offline evaluation | — |

**Version:** branch `feat/demo-readiness` on top of commit `a030fbc`,
with uncommitted changes (the work in this branch). App v0.1.0, API 0.2.0.

**Privacy:** no API key, token, email address or personal data appears
in any image. The app was used as a guest; no Google account is shown.

**Known visual defect, visible in 03/03b/06:** the evidence expander
shows the literal text `arrow_right` over its label. Cause:
`assets/styles.css` forces the Inter font on every `.stApp span`,
which overrides Streamlit's Material Symbols icon font. To be fixed by
the front-end developer, then the affected shots re-captured.

## Regenerate

```bash
streamlit run app.py --server.port 8501          # terminal 1
python scripts/run_api_local.py --port 8000      # terminal 2
python scripts/render_evaluation_report.py       # refreshes 09's source page
python scripts/capture_demo_screenshots.py --qr path/to/qr.png --force
```
Without `--force`, existing images are kept and only missing ones are
captured, so a failed run can be resumed without repeating AI calls.

## Manual alternative (no browser automation)

Run both servers, open the app in a browser at 1366×900, follow
`docs/DEMO_SCRIPT.md` steps 1–6, and use the OS screenshot tool
(Win+Shift+S). Use the guest mode, and never an account or email
address that belongs to a real person.
