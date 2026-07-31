# 🛡️ Tumar.AI

# Python 3.11+
# Streamlit
# Google Gemini
# License  

**Your digital amulet against online scams. .**
** 🛡️ Tumar.AI

# AI-powered cybersecurity assistant for scam detection, breach monitoring, and digital safety. **

Tumar.AI is an AI-powered cybersecurity assistant that helps people identify
scams, detect data breaches, improve password security, and make safer
decisions online. Named after the *tumar* (тұмар) — the traditional Kazakh
amulet of protection.

## Vision

The tools that could protect people from online fraud exist, but they are
scattered, technical, and full of jargon. Tumar.AI aims to become a trusted
personal cybersecurity companion: professional-grade checks, explained in
plain language, accessible to everyone.

## Status & Roadmap

✅ Application foundation complete — multipage UI, navigation, theming.

| Feature | Status |
| --- | --- |
| AI Scam Message Analyzer (AI + deterministic scanner) | ✅ Available (beta) |
| URL Scanner (address-only trust verdict, AI + heuristics) | ✅ Available (beta) |
| Email Breach Checker | ✅ Available (beta) |
| Quick Check (auto-routing via the Trust Engine) | ✅ Available (beta) |
| Dashboard (session figures, recent analyses, platform status) | ✅ Available (beta) |
| Password Health Checker (k-anonymity breach lookup + strength) | ✅ Available (beta) |
| Multilingual interface (English / Русский / Қазақша) | ✅ Available |

## Architecture: the Trust Engine

Every capability is an **Analyzer** behind one interface, and every consumer
talks to the platform the same way:

```python
report = TrustEngine().analyze(
    TrustSubject(content="http://suspicious.link"),
    AnalysisContext(api_key=key),
)
```

- `TrustSubject` is an envelope (`content: str | bytes`, `mime_type`,
  `declared_kind`, `language`, `filename`) — so binary inputs such as PDFs,
  screenshots, or audio need no engine change, only a new analyzer.
- `AnalysisContext` carries everything analyzers need beyond the subject.
  New needs become new *optional* fields; analyzer signatures never change.
- Analyzers are registered **most-specific first** in `default_analyzers()`.
  The first `can_handle()` win takes the subject; `declared_kind` skips
  detection when the caller already knows what it holds.
- Every analyzer returns the same `TrustReport`, so any consumer can render
  any module's verdict with no module-specific code.

Adding a capability = write an `Analyzer`, add one line to the registry.
`TrustEngine` itself is never edited (Open/Closed Principle).

## Design system

Every module renders its result through one shared view, so modules cannot
drift into their own visual dialect and a new module page needs no layout
code of its own:

```python
render_trust_report(report)   # report_view.py
```

Fixed layout for every module: verdict and trust score → confidence and
module metrics → what is going on → what you should do → evidence grouped by
who found it (collapsed) → footer with timestamp, detection method, and the
privacy note.

- `components.py` holds the primitives: `verdict_card`, `meter`, `chip_row`,
  `threat_card`, `status_badge`, `stat`, `section_header`, `empty_state`,
  `error_view`. Every dynamic value is `html.escape()`d.
- `report_view.py` composes them. It reads only the `TrustReport` schema and
  never learns which module produced the report — free-text fields (AI
  modules) and translation-key fields (deterministic modules) both just work.
- Module-specific numbers travel as `TrustReport.metrics`, so a module can
  expose its own breakdown without any module-specific rendering code.
  Metrics carry meaning (`higher_is_worse`), never colors — the data layer
  does not know about CSS.
- `report_store.py` keeps the last report per module in session state, so a
  result survives every later re-run. The state container is passed in
  explicitly; a security product must never hold user data in globals where
  one visitor's analysis could surface in another visitor's session.

### Layout and navigation

- Sidebar pages are **grouped into sections** (Overview / Analyze / Monitor /
  Platform) via `st.navigation`'s mapping form. A flat list stops being
  scannable at around eight entries, and the roadmap adds many more modules;
  a new module joins a section without the menu needing a redesign.
- The page is `layout="wide"` so the dashboard can use real columns, with
  `styles.css` capping the container at 1080px and prose lines at `62ch`
  (≈75 characters — the `ch` unit measures the wide `0` glyph, so this is
  calibrated, not guessed). Cards, columns, and meters use the full width.
- Unbuilt modules carry a **Planned** badge on their card. A card identical
  to a working one that leads to a placeholder is a small broken promise.
- Dashboard figures come from `report_store.summarize()`, a pure function
  over a list of reports — testable without Streamlit and reusable by the
  REST API later. The numbers are labeled as session-scoped, because that is
  all they honestly are.

## Privacy and safety guarantees

These are enforced in code and pinned by tests, not just described here:

- **Passwords are never transmitted.** The Password Health check hashes the
  password and sends only the **first five characters** of that hash to Have I
  Been Pwned's range API (k-anonymity). The service replies with every hash
  suffix sharing that prefix and the match happens locally, so it cannot learn
  which password was checked.
- **Passwords are never auto-detected.** `PasswordAnalyzer.can_handle()`
  always returns `False`, so the Trust Engine can only reach it when a caller
  states the kind outright. The fallback analyzer sends text to the AI
  provider; a routing guess that went wrong would send a user's password to a
  third party, so guessing is not allowed at all.
- **Reports carry no secrets.** A password report's `subject_preview` is a
  fixed row of dots — not the password, and not even its length. Email
  previews are masked (`b*******n@gmail.com`). This holds by construction, so
  session history and any future API response inherit it.
- **Nothing is written to disk.** Results live in the browser session and are
  gone when it ends; the dashboard offers a control to clear them sooner.
  The UI says exactly this, rather than the broader "never stored" it used to
  claim before session history existed.

## Tech Stack

- Python 3.11+
- Streamlit — UI framework
- Google Gemini API — AI analysis engine
- Pydantic — validation of all AI responses
- XposedOrNot API — public breach database (no key required)

## Project Structure

```
tumar-ai/
├── app.py                  # Entry point: page config + sidebar navigation
├── components.py           # Design-system primitives (cards, meters, chips, states)
├── report_view.py          # The one shared Trust Report layout
├── report_store.py         # Session-scoped report history (survives re-runs)
├── views/                  # UI layer — one file per page
│   ├── home.py             # Dashboard: Quick Check, session figures, recent analyses
│   ├── scam_analyzer.py    # Scam Analyzer page
│   ├── url_scanner.py      # URL Scanner page
│   ├── breach_checker.py   # Email Breach Checker page
│   ├── password_checker.py # Password Health (UI ready, check pending)
│   └── about.py            # Mission, name story, product principles
├── services/               # Business logic — UI-independent
│   ├── common.py           # Shared error base (code-based errors)
│   ├── trust_engine.py     # Core orchestration: TrustSubject → Analyzer → TrustReport
│   ├── gemini_client.py    # Shared Gemini client: model fallback + error codes
│   ├── scam_analysis.py    # Scam analysis orchestration + response schema
│   ├── url_scanner.py      # URL trust scan (native TrustReport module)
│   ├── password_check.py   # k-anonymity breach lookup + offline strength
│   ├── heuristics.py       # Deterministic scanner (urgency, URLs, OTP…)
│   ├── breach_checker.py   # Breach lookup + risk assessment
│   └── trust_report.py     # Unified TrustReport schema — the platform's shared result language
├── prompts/                # Versioned AI prompts
│   ├── scam_analyzer_v1.md
│   ├── scam_analyzer_v2.md
│   └── url_scanner_v1.md
├── i18n/                   # UI translations (EN / RU / KK)
│   ├── en.json
│   ├── ru.json
│   └── kk.json
├── tests/                  # Offline logic tests (no network needed)
│   ├── test_breach_checker.py
│   ├── test_heuristics.py
│   ├── test_i18n.py
│   ├── test_password_check.py
│   ├── test_report_store.py
│   ├── test_report_view.py
│   ├── test_trust_engine.py
│   ├── test_trust_report.py
│   └── test_url_scanner.py
├── assets/
│   ├── logo.svg            # Brand logo (tumar amulet + wordmark)
│   └── styles.css          # "Aura" design system: theme, motion, components
├── .streamlit/
│   ├── config.toml         # Dark theme configuration
│   └── secrets.toml        # API keys (gitignored — never committed)
├── .gitignore              # Keeps venv, caches, and secrets out of Git
├── requirements.txt        # Python dependencies
└── README.md
```

## Run Locally

Requires Python 3.11 or newer and a free [Gemini API key](https://aistudio.google.com).

```powershell
# from the tumar-ai folder
python -m venv venv          # on Windows, "py -m venv venv" also works
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Then put your Gemini API key into `.streamlit/secrets.toml`:

```toml
GEMINI_API_KEY = "your-key-here"
```

The app opens at http://localhost:8501.
