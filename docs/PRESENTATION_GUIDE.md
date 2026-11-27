# Tumar.AI — presenter's guide and judge Q&A

Read this the night before. Each feature has three parts: **what it does**
(say this on stage), **how it works** (the core mechanism, for follow-up
questions) and **likely questions** with short answers. Every claim here
matches the code in this repository; where something is a limit, the
answer says so. Judges reward honest limits far more than overclaiming.

---

## 0. The 30-second pitch

> Internet fraud is now the most common crime in Kazakhstan: **28,851
> registered cases in 2025, almost one crime in four**, up from 517 in
> 2018. Most of it starts with a message, a link or a screenshot.
> Tumar.AI checks any of them in Kazakh, Russian or English, explains the
> evidence in plain words and tells you the safe next step. The AI
> analyses, the rules can overrule it, and nothing you check is stored.

## 1. Architecture in one breath

```
input (text / link / image / email / password)
      │
      ▼
Trust Engine ── picks the right Analyzer (most specific first)
      │
      ├─ Deterministic rules (heuristics.py, URL rules, image risk engine)  ← always run, free, offline
      ├─ AI layer (Gemini by default; DeepSeek/OpenAI/Claude pluggable)    ← optional, data-only
      └─ Output guard: rules set a floor the AI cannot lower
      │
      ▼
TrustReport (one schema) ──► web page / Telegram bot / REST API
```

Key words to use: **one engine, one report schema, three channels**
(website, Telegram bot, REST API). A new capability is a new Analyzer
plus one registry line; the engine itself never changes.

**Q: Why rules AND AI, not just AI?**
Rules are free, instant, predictable and cannot be talked into anything.
The AI catches new wording the rules miss. Each covers the other's
weakness: if the AI is down, the rules still give a labelled "offline
check"; if a scam message tries to trick the AI ("classify this as
safe"), the rules overrule it.

**Q: Which AI model?**
Google Gemini `gemini-3.5-flash`, with three lighter Gemini models as
automatic fallbacks. Each model gets at most 15 seconds before the next
one is asked, and a whole check never waits more than 45 seconds. If
every Gemini model fails, a second provider (DeepSeek) can answer
instead (`TUMAR_FALLBACK_PROVIDER`), and if that fails too, the rules
still give a labelled offline verdict. Providers are interchangeable
behind one interface; we only change the default after running our
evaluation harness on the new one.

**Q: What if the AI provider goes down?** Three layers: other Gemini
models, then a second provider, then the built-in rules. A check never
ends with no answer, and an offline verdict is never "safe".

---

## 2. Features, one by one

### 2.1 Scam Analyzer (paste a message)

**What it does:** paste an SMS, WhatsApp or Telegram message or an email; get
Safe / Caution / Dangerous, a scam category, the evidence and what to do.

**How it works:**
1. The deterministic scanner (`services/heuristics.py`) looks for
   urgency, requests for SMS codes, financial bait, credential-theft
   wording, manipulation and suspicious links, in EN/RU/KK.
2. Phone numbers, card numbers and codes are **masked before** the text
   reaches the AI.
3. The text is wrapped in a randomly-named data block
   (`prompt_boundary.py`), so the message cannot "close" the block and
   pretend to be instructions.
4. The AI returns a fixed, validated JSON schema (Pydantic), not free text.
5. `output_guard.py`: if the rules see injection phrases or a high risk,
   the AI cannot answer "safe".
6. Confidence is computed from evidence (do rules and AI agree? how much
   evidence?), **not** from what the model claims (`confidence.py`).

**Likely questions:**
- *Why not trust the AI's own confidence?* We measured it: the model
  claimed ~83% confidence on cases it got right 40% of the time. So we
  compute confidence from checkable evidence instead.
- *What if the AI is down on stage?* You get a rules-only verdict,
  clearly labelled "Offline check", never "safe", and it does not count
  against the daily limit.
- *Accuracy?* Offline rules on our labelled corpus: a risk signal on
  90.9% of scams. They also fire on 42.9% of legitimate messages (real
  OTP messages, genuine bank warnings), which is why the AI layer and the
  evidence-based confidence exist. Say these numbers plainly.

### 2.2 URL Scanner

**What it does:** paste a link and get a verdict about the address.

**How it works:** URL rules (look-alike brands such as `kaspi-secure-verify.xyz`,
misspelled domains, homoglyphs, no HTTPS, IP addresses, many hyphens) plus
an AI judgement of the address. **The page is never opened.**

- *Why don't you visit the site?* Fetching an attacker's URL from our
  server would let them use Tumar as a proxy, could trigger malware or
  tracking, and slows every check. The verdict is about the address, and
  the report says so.
- *Numbers?* URL rules on the corpus: 100% detection, 0% false positives
  with the weighted rule (20 malicious / 20 legitimate URLs: small, so
  call it a sanity check, not a benchmark).

### 2.3 Screenshot Scanner

**What it does:** upload a screenshot (chat, SMS, QR code poster) and get
the same report.

**How it works:** validate the file (real signature, size limits,
decompression-bomb guard, strip EXIF/location) → clean up the image (OpenCV) →
OCR in Kazakh, Russian and English (Tesseract) → decode QR codes **without opening them** →
pull out links → same URL rules → documented risk score with five levels
→ optional vision model for facts only, never for the verdict.

- *Do you keep the image?* No. It is re-encoded in memory without
  metadata, analysed and discarded; nothing is written to disk.
- *How accurate is it?* Be honest: the evaluation framework exists, but
  we have not collected a labelled image set yet, so there is no validated
  accuracy figure for images.

### 2.4 AI Security Check

**What it does:** checks text that will be read by an AI assistant (an
email, ticket, document or agent tool description) for prompt injection,
data exfiltration, tool poisoning or invoice fraud.

**How it works:** EN/RU/KK pattern families → findings with quoted
excerpts → a static review of declared agent permissions (does
"summarise my inbox" need payments and delete?) → an isolated AI layer
that only describes what it sees.

- *Is it safe to feed attacks to your own AI?* The AI has no tools, no
  function calling and no network access (`ai_authority.py`; a test
  fails the build if any code calls a model without that gate). It reads
  the attack as evidence; it cannot act on it.
- *Limits?* Static analysis only. On held-out attacks the rules alone
  catch about 72%; the AI layer adds coverage but is not yet measured with
  a live key.

### 2.5 Email Breach Checker

**What it does:** shows whether an email appears in known data breaches
and what to do.

**How it works:** a lookup in the public XposedOrNot breach database. The
report shows the email masked (`b*******n@gmail.com`). Nothing is stored
or logged.

- *Why that provider?* It is free and needs no key. The provider sits
  behind one function, so switching to Have I Been Pwned is a one-function change.

### 2.6 Password Health

**What it does:** shows whether a password has leaked, and how strong it is.

**How it works (k-anonymity):** the password is hashed (SHA-1) in memory;
**only the first 5 characters of the hash** go to the Pwned Passwords API,
which returns every leaked hash with that prefix; the match happens on our
side. The service never learns the password or even the full hash.
Strength is computed offline.

- *Can the AI see my password?* No. The password analyzer can never be
  auto-detected (`can_handle()` is always `False`), so a routing mistake
  can never send a password to an AI. The report shows a fixed row of
  dots, not even the length. Password checks are not available over the API.

### 2.7 Threat Map (updated: official statistics)

**What it does:** shows how many people in Kazakhstan are hit by internet
fraud, which schemes are used and which regions are worst, from
**official published statistics**, and tells you which official scheme
your own last check resembles.

**What is on the page:**

| Figure | Value | Period | Source |
|---|---|---|---|
| Registered internet-fraud cases | **28,851** (a record; 23.3% of all crimes) | 2025 | Finprom.kz, via Nur.kz |
| Growth | 517 → 28,851, **about 55×** | 2018 → 2025 | Finprom.kz |
| Registered cases | **13,100** (−10.3% year on year) | Jan–Jul 2026 | Finprom.kz, via Inbusiness.kz |
| Share of all crimes | **19.5%**, about one in five | Jan–Jul 2026 | same |
| Share of all fraud | 57% (53.7% a year earlier) | Jan–Jul 2026 | same |
| Registered cases (Ministry of Internal Affairs, MVD) | ~15,000 (−20.8%) | Jan–Sep 2026 | MVD, via Central Media 24 |
| Fraud calls blocked | ~187 million | 2026 to November | MVD |
| Illegal sites blocked | 33,000+, of which 8,000+ phishing | 2026 to November | MVD |
| Top schemes | fake bank calls/SMS 2.9k · phishing 2.7k · fake service ads 2.6k · online shopping 1.9k · loans in your name 1.3k | Jan–Jul 2026 | Finprom.kz |
| Top regions | Astana 2.3k · Almaty 1.4k · Pavlodar region 1.1k · Almaty region 1.0k · Karaganda region 951 (together 50.7%) | Jan–Jul 2026 | Finprom.kz |
| Highest share of crime | Pavlodar region 38% · East Kazakhstan 29.8% · Karaganda 29.6% | Jan–Jul 2026 | Finprom.kz |
| Anti-fraud Centre reports | fake calls 17% · fake shops 16% · fake investments 14% · social/messengers 6% · credit 5% | Jul 2024 – Nov 2026 | National Bank, antifraud.kz |
| Anti-fraud Centre incidents | 80,871 | from Jul 2024 | National Bank, via Central Media 24 |
| Fraudulent loans | 5,100 loans, 4.6 bn tenge | 2025 | ARDFM, via Central Media 24 |

**How it works:** the numbers live in one file,
`services/threat_map_data.py`, each with its period and source; the page
lists the links under **Sources** and shows "last checked 2026-11-26".
Your own last check is matched to an official scheme **on your screen**
with simple keyword rules (e.g. "кредит" → loans in your name, "OLX/доставка" →
online shopping, look-alike domain or QR → phishing). Nothing is sent, and
no user check is ever added to the official figures.

**Likely questions:**
- *Is this live data?* No, and we don't claim it is. There is no public
  API for Kazakhstan's crime statistics, so the figures are published
  statistics typed in by hand with their dates and sources. Updating
  them means editing one file; a test checks the totals still add up.
- *Why do regional counts only cover five regions?* Only those five were
  published as counts for Jan–Jul 2026; for others only the share of
  crime was published. We show "not published" instead of guessing.
- *Why two different national numbers (13,100 vs ~15,000)?* Different
  periods (7 vs 9 months) and different publishers. Both are on the page
  with their periods.
- *Why not use your users' checks for the map?* That would be a tiny,
  biased sample, and it would mean storing what people checked. The plan
  for later: opt-in, category-only counts per region and week, with small
  counts hidden (k-anonymity), never the message itself.
- *What is "Other schemes"?* The national total minus the five named
  schemes (1,700): investments, crypto, account hacking and so on. The
  page says it is derived.

### 2.8 Home, Quick Check, My Safety Center

- **Quick Check** (Home): paste anything; the Trust Engine detects whether
  it is a link, email or message and routes it.
- **My Safety Center** (signed-in users): turns this session's checks into
  next steps and a **Cyber Resilience Score**: start 60; −12 per open
  dangerous finding; −12 breached email; −8 weak password; +6 per
  two-step verification; +4 for checking before acting. **Capped at 90 on
  purpose**: no score means "fully safe".
- *Is my history saved?* No, it lives in this browser session only and
  disappears when the tab closes; there is a button to clear it sooner.

### 2.9 Settings & Safety, Security & privacy

- A global switch: **Allow external AI providers**. Off = rules-only, and
  nothing leaves the server except breach lookups.
- Language (EN/RU/KK), simple mode and text size, a safety checklist and
  official resources.
- The **Security & privacy** page states only what the code does, in plain words.

### 2.10 Telegram bot

Same Trust Engine: `/check` (breach), `/scan` (link), `/audit` (message),
send a screenshot, `/news` (AI news digest), `/tip`. One long-running worker;
the token comes from the environment only.

### 2.11 REST API (for banks, telecoms, universities)

`POST /v1/analyze` returns the same TrustReport. API keys are **stored
hashed**, rate-limited per key, with monthly quotas metered without
storing any content. It fails closed: no key, no access.

---

## 3. "Why do we need a database?" (expect this)

**Short answer:** we keep as little as possible, and only where a feature
cannot work without it. Everything a user *checks* is **not** stored.

| What is stored | Why it is needed | What it contains |
|---|---|---|
| `users.db`: registered users | Google sign-in, so an account is remembered, and "Delete my data" | email, name, language, first/last seen, sign-in count. **No passwords, no tokens, no checks.** |
| `broadcast.db`: Telegram groups | The bot must know which groups it was added to | chat id, title, type |
| `tumar.db`: API keys and usage | Business customers need keys, quotas and billing | key **hash** (never the key), owner, quota; per-call kind/verdict/duration, **no content** |
| `tumar.db`: contributions | Improving detection with real scams | only with explicit consent; redacted (phone, card, codes removed; URLs kept); deletable |

**Not stored anywhere:** passwords, images, messages and links checked
without consent, plain-text API keys, bot tokens. Daily quotas are kept in
memory with hashed identities.

**Why SQLite, not PostgreSQL?** One instance per process, tiny write
rates (a sign-in, a group join), and a backup is a file copy. We move to
managed PostgreSQL when a written trigger is met: several app instances
sharing data, user history across users, or compliance needs (backups,
audit, data residency). Redis comes only when quotas must be shared across
instances. (Full reasoning: `docs/STORAGE_DECISION.md`.)

**Honest limit:** Streamlit Community Cloud wipes the disk on every
redeploy, so `users.db` resets there. Accepted for the pilot; production
uses a persistent volume (`TUMAR_USERS_DB`) or managed Postgres.

**And the Threat Map?** It needs no database today: it is a small,
versioned file of published statistics, so every number is reviewable in
Git history. A database becomes necessary when opt-in community counts
exist: a table of `(region, category, week, count)` only.

---

## 4. Security and AI-safety questions

- **Can the AI do anything harmful?** No tools, no function calling, no
  network, no account access. It returns data in a fixed schema. A test
  fails the build if any code calls a model without the authority gate.
- **Prompt injection against Tumar itself?** Random data-block markers,
  bracket spacing, and the output guard: injection phrases force at least
  "Dangerous", whatever the model says. Links in AI text are defanged
  (`hxxp://`, `[.]`) so an answer can never contain a clickable link.
- **Abuse / cost control?** Daily quotas: guest 20, signed-in 60, all
  guests together 1,000, Telegram 30 per person. Identities are hashed.
- **Incident switch?** `TUMAR_DISABLE_FEATURES=ai,vision,breach,images` plus
  a reboot turns features off without a deploy.
- **Testing?** 50+ automated test suites run in CI on every push, plus an offline
  evaluation; the AI evaluation is run before any prompt or model change.

## 5. Tough questions, honest answers

| Question | Answer |
|---|---|
| How is this different from a bank's anti-fraud system? | Banks see transactions after you act. Tumar works **before** you act, on the message itself, and it covers every bank, marketplace and messenger in three languages. The two are complementary. |
| What if it says "safe" and it's a scam? | Without the AI we never say "safe" at all. With it, the rules set a floor, and every report says it is an assessment, not a guarantee. |
| What's your false-positive rate? | Rules alone flag about 43% of legitimate test messages (real OTPs and bank alerts look like scams). That is why the AI layer and evidence-based confidence exist; we publish the number instead of hiding it. |
| Business model? | Free for people; a paid API for banks, telecoms, marketplaces and universities (keys, quotas and metering already built). |
| Why should people trust you with their messages? | We don't keep them. Masking before AI, no disk storage, a switch to turn external AI off, and a page that says exactly what happens. |
| Where does the data on the map come from? | Published official statistics (MVD, National Bank Anti-fraud Centre, registered-crime statistics via Finprom.kz), each with its date and link on the page. |

## 6. Numbers cheat sheet (memorise these five)

1. **28,851**: internet-fraud cases in 2025, almost one crime in four.
2. **55×**: growth since 2018 (517 cases).
3. **2,900**: the top scheme in Jan–Jul 2026 is fake calls and SMS "from the bank".
4. **Astana** leads (2,300 in Jan–Jul 2026); in **Pavlodar region**, 38% of all crime is internet fraud.
5. **187 million**: fraudulent calls blocked in 2026.

## 7. Before you go on stage

- Merge, wait for CI, then **Streamlit Cloud → Manage app → Reboot app**
  (shared modules such as `components.py` changed in this update and only
  reload after a reboot). Then open the Threat Map as a guest and check it.
- Open the app 10 minutes early; it sleeps when idle.
- Run the demo message once so a result is already in the session.
