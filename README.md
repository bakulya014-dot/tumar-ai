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
| Email Breach Checker | ✅ Available (beta) |
| Multilingual interface (English / Русский / Қазақша) | ✅ Available |
| Password Health Checker | 📋 Planned |

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
├── components.py           # Reusable UI building blocks
├── views/                  # UI layer — one file per page
│   ├── home.py             # Landing page with feature cards
│   ├── scam_analyzer.py    # Scam Analyzer page
│   ├── breach_checker.py   # Email Breach Checker page
│   ├── password_checker.py # Password Health (UI ready, check pending)
│   └── about.py            # Mission, name story, product principles
├── services/               # Business logic — UI-independent
│   ├── common.py           # Shared error base (code-based errors)
│   ├── scam_analysis.py    # Gemini call + response validation
│   ├── heuristics.py       # Deterministic scanner (urgency, URLs, OTP…)
│   └── breach_checker.py   # Breach lookup + risk assessment
├── prompts/                # Versioned AI prompts
│   ├── scam_analyzer_v1.md
│   └── scam_analyzer_v2.md
├── i18n/                   # UI translations (EN / RU / KK)
│   ├── en.json
│   ├── ru.json
│   └── kk.json
├── tests/                  # Offline logic tests (no network needed)
│   ├── test_breach_checker.py
│   ├── test_heuristics.py
│   └── test_i18n.py
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
