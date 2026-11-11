# Held-out evaluation set

Cases here are **never** used while writing or tuning detection rules.
`evals/heldout_runner.py` reads only this directory and reports
precision, recall, F1 and false-positive rate, overall and by language
(kk / ru / en), input type (message / URL) and attack type.

## Three tiers, never blended

| Tier | Where | What it can support |
|---|---|---|
| Tuning | `evals/corpus/` | Regression checks only. The rules were written against it, so its numbers are in-sample. |
| Team held-out | here, `"source": "team_authored"` | A sanity check on unseen wording. Written by people who know the rules, so not independent. |
| Independent | here, `"source": "independent"` | Real reports or partner-collected examples. The only tier that can back an accuracy claim. |

`team_v1` (40 cases) was written in one pass on 2026-11-11, before the
runner was first run against it, and has not been edited since except
to replace two URLs the overlap check found in the tuning corpus. The
independent tier is empty.

## Rules

1. **Do not tune against these cases.** If a held-out case is missed,
   do not edit a rule and re-run. Write a *new*, different case for
   `evals/corpus/`, fix the rule against that, and leave this file as
   it is. The miss stays in the held-out numbers until a later version
   of the rules catches it on its own.
2. **Add, don't edit.** New cases go in a new file
   (`messages_team_v2.jsonl`, `messages_independent_<partner>_v1.jsonl`).
   Never change a label after seeing a result.
3. **Label provenance honestly.** `independent` only for examples the
   team did not write: user-submitted reports (with consent and
   personal data removed), institutional partners, public datasets.
4. **No overlap.** The runner refuses to run if a held-out text or URL
   also appears in the tuning corpus.
5. **No personal data.** Replace real names, phone numbers, card
   numbers and account ids before adding a real example.

## Format

One JSON object per line:

```json
{"id": "ho-ru-...", "source": "team_authored", "language": "ru",
 "input_type": "message", "attack_type": "otp_harvesting",
 "label": "scam", "text": "..."}
```

- `input_type`: `message` (with `text`, `label` scam/legitimate) or
  `url` (with `url`, `label` malicious/legitimate, `language` `none`).
- `attack_type`: free-form category (`otp_harvesting`,
  `credential_phishing`, `impersonation`, `investment`, `delivery`,
  `prize`, `brand_lookalike`, ...); exactly `none` for legitimate cases.

## What is measured

The rules only, offline: the verdict a user gets when the AI is
unavailable (`danger` counts as flagged), and separately the raw rule
layer. The AI layer is not measured here. Undefined ratios (for
example precision with no positive predictions) print as `n/a`, never
as 0 or 100.
