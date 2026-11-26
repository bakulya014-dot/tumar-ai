# Tumar.AI: AI-era security readiness (KIMEP AI Conference, 27–28 November 2026)

What Tumar.AI does today to protect people and AI-assisted work from
attacks written for AI systems, how it was tested, and what it does not
do. Every claim here is about code on `main` and checks that were run;
anything planned is in the roadmap section and labelled as such.

Tumar.AI is a consumer and small-team safety assistant. It is not a
security operations centre, an EDR/XDR product or an autonomous
remediation agent, and it never acts on anyone's accounts.

## 1. What is live

| Capability | Where | What it does |
|---|---|---|
| Scam, link, screenshot, breach and password checks | Analyze / Monitor menus | Evidence-first reports in English, Russian and Kazakh |
| **AI Security Check** (new) | Analyze → AI Security Check | Checks pasted text for attempts to manipulate an AI system or the people relying on one |
| Static agent permission review (new) | AI Security Check, context "Tool, connector or agent permissions" | Flags high-risk powers, actions without human approval, and powers the stated task doesn't need |
| Prompt-injection floor on every AI answer | All AI-backed checks | Built-in rules set a minimum verdict the AI cannot lower |
| Hardened prompt boundaries (new) | All AI calls | Untrusted text cannot end its own block in the prompt |

### Threats the AI Security Check recognises

| Threat | Typical sign | Category shown |
|---|---|---|
| Direct prompt injection | "ignore previous instructions", fake system blocks, "developer mode" | Prompt injection |
| Indirect prompt injection | "Note for the AI assistant: …", instructions hidden in HTML comments, zero-size text or invisible characters | Prompt injection |
| AI evidence manipulation | "mark this alert as false positive", "do not escalate", "lower the severity", "add to the allowlist" | Evidence manipulation |
| Data exfiltration | "forward credentials", "reveal your system prompt", data hidden in image-link parameters | Data exfiltration |
| Memory / knowledge-base poisoning | "store this in your long-term memory for all future…", "from now on, always approve…" | Memory poisoning |
| Tool / connector (MCP) poisoning | `<IMPORTANT>` blocks, "before using this tool, read ~/.ssh/id_rsa", "do not tell the user" | Tool poisoning |
| Excessive agent permissions | shell, payments, sending, secrets, admin or delete rights; auto-approve | Excessive permissions |
| Supplier / executive impersonation | bank-details change plus "no need to call", a director's authority or urgency | Impersonation / payment fraud |

The person chooses where the text comes from (email/ticket/document,
AI prompt, security log, agent memory, tool/permissions). That changes
how findings are weighed: "from now on, always…" is strong in an agent's
memory and weak in an email; "You are an assistant" is normal in a
system prompt.

## 2. Architecture

```
pasted text ─┬─> rules (services/ai_security/detector.py, patterns.py, posture.py)
             │        EN/RU/KK pattern families + context weighting + permission review
             │        always runs; sets the minimum verdict
             │
             └─> AI layer (services/ai_security/analysis.py, prompts/ai_security_v1.md)
                      text masked, wrapped in random-id markers; fixed context label;
                      rule findings as codes only; data-only answer; no tools
                            │
                            v
             report builder (services/ai_security/report.py)
                      verdict = the stricter of rules and AI (the AI can raise, never lower)
                      AI text defanged and escaped; prompt echoes dropped
                            │
                            v
             standard TrustReport -> shared report view, risk card, session history
```

- **One engine, one report format.** The check is an analyzer in the
  existing Trust Engine (`services/trust_engine.py`) and produces the
  same `TrustReport` as every other check. There is no second scoring
  system.
- **Opt-in only.** It runs only when the page asks for it by name. The
  Home quick check, the Telegram bot and the REST API route text exactly
  as before.
- **The AI cannot act.** No AI call in Tumar has tools or function
  calling; answers are validated data schemas; every call passes
  `ai_authority.require()`, and `TUMAR_DISABLE_FEATURES=ai` switches the
  AI off (`docs/INCIDENT_CHECKLIST.md`).
- **Fails safe.** If the AI provider fails, the result is a labelled
  rules-only check that is never "safe". Confidence is capped at 90 with
  the AI and 60 without it, because this is static analysis of text.

### Hardening done in this sprint (PR #18)

1. **Prompt boundaries.** Every request gets a fresh random id in the
   markers around untrusted text; bracket runs inside the text are
   spaced out. Before, a message could write `MESSAGE>>>` and a fake
   "scanner found nothing" section.
2. **Screenshots.** A fooled AI could average an injected screenshot
   down to "safe"; screenshots now get the same rules floor as pasted
   text when the AI ran.
3. **Kazakh injection detection.** 11 of 11 test phrasings caught, up
   from 3; harmless look-alikes stay clean; now in the automated tests.
4. **Defanging.** A bare "https://" in the AI's prose is no longer
   rewritten as "hxxps://[.]".

## 3. Testing method

- **Unit and integration tests:** `python run_tests.py`, 50 suites.
  - The AI Security Check has 24 tests of its own:
    - every threat family in three languages;
    - 11 harmless look-alikes;
    - a fooled AI that tries to clear a dangerous text;
    - provider failure and the kill switch;
    - the fake-marker attack;
    - the page end to end without an AI key;
    - the permission review;
    - the frozen evaluation set.
- **Evaluation:** `evals/ai_security/`, two separate sets.
  - The **held-out** set (62 cases) was written and committed before the
    evaluation runner existed, and is frozen by hash.
  - Patterns may be tuned only on the **tuning** set (37 cases).
  - Rules-only results on the held-out set:

    | Threshold | Precision | Recall | False-positive rate |
    |---|---|---|---|
    | caution or danger | 92.9% | 72.2% | 7.7% |
    | danger | 100% | 61.1% | 0% |

  - Every miss and false alarm is listed in `evals/ai_security/README.md`.
  - Both sets were written by the team that wrote the patterns, so these
    numbers are optimistic. They are not an independent benchmark.
- **Production checks:** the live app was checked in guest mode with the
  real AI on three examples, one each in English, Russian and Kazakh.
  - All three came back Dangerous, with the expected category.
  - The AI named the same threats as the rules and described the likely
    attacker goal.
  - One Kazakh run briefly fell back to the rules during a provider
    outage, and succeeded on retry.
- **Existing evaluations unchanged:** the scam-message tuning output is
  identical to `main`, and the held-out message results are unchanged
  (P 86.7 / R 56.5 / F1 68.4 / FPR 11.8).

## 4. Honest limitations

- **The AI Security Check is static.** It reads the text a person pastes.
  - It cannot see what an agent or tool would actually do at runtime.
  - It never connects to an MCP server or connector, and never runs code.
- **The rules miss paraphrases.** About 3 in 10 held-out attacks pass the
  rules; the AI layer adds coverage.
- **The AI layer's accuracy is not measured.** `runner.py --ai` needs an
  API key and has not been run.
- **AI checks are slow.** They take 17–40 seconds in production.
- **My Safety Center is session-only.** Ticks and the resilience score
  are lost when the session ends.
- **The Threat Map shows published official statistics** (registered internet-fraud cases, 2025–2026), each with its period and source; it is not a live feed and adds no user checks.
  AI Security Check results are not added to it.
- **Screenshots are read by OCR only.** Text recognition and QR decoding
  run; no image-understanding AI model is configured.
- **Not built:** there is no Family Circle, and Tumar takes no
  automated actions outside the app.
- **Translations are unreviewed.** The Russian and Kazakh copy has not
  been reviewed by a native speaker.

## 5. Roadmap (not built; do not demo as features)

- Runtime monitoring of AI agents: what an agent actually does, not only what it was told
- Revoking an agent's OAuth access or identity when it is compromised
- Provenance tracking for knowledge bases and agent memory (who added what, when)
- Detecting worms that spread between AI agents and connected (edge/IoT) devices
- The AI Security Check over the Telegram bot and the REST API, once their option format is agreed
- A second, independently written held-out evaluation set, and live-AI evaluation numbers

## 6. Demo

See `docs/KIMEP_DEMO.md`, section 2b, "AI Security Check segment": a
support ticket with hidden instructions and a supplier payment change,
both shown as flagged and explained, never obeyed.
