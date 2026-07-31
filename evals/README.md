# Evaluation harness

Measures whether Tumar.AI's verdicts are actually correct, and whether
the confidence it reports can be believed.

Before this existed, every prompt or heuristic change was a guess and a
regression could ship unnoticed. Three questions get answered here:

| Question | Metric |
| --- | --- |
| How much does it catch? | recall on labelled scams |
| How often does it cry wolf? | false-positive rate on legitimate input |
| Is its confidence honest? | accuracy within each confidence band |

## Running it

```bash
python evals/runner.py              # offline, free — runs in CI
python evals/runner.py --ai         # also calls Gemini, costs tokens
python evals/runner.py --ai --limit 10   # cap the spend
```

Offline mode measures the deterministic layer only: how often the
scanner fires on scams versus on ordinary messages, and how the URL
heuristics classify known-good and known-bad addresses. No API key
needed, so CI enforces it on every push.

AI mode needs `GEMINI_API_KEY` in the environment or in
`.streamlit/secrets.toml`. Run it before shipping a prompt or model
change, and compare against the previous run in `evals/results/`.

## The corpus

`corpus/messages.jsonl` — labelled messages in English, Russian and
Kazakh. `corpus/urls.jsonl` — labelled links.

Half of each file is deliberately **legitimate**, including
`hard-negative` cases: real one-time-code messages, genuine bank
notices, real password-reset emails, and work messages that say
"urgent". These are the cases that expose false positives. A corpus of
scams alone would score a detector that flags everything at 100%.

Adding cases is the highest-value contribution to this project: a
labelled corpus of local fraud patterns is an asset a competitor
cannot copy, and every case makes the next change measurable.

Fields: `id` (unique), `language`, `label` (`scam`/`legitimate` for
messages, `malicious`/`legitimate` for URLs), `text`/`url`, and `tags`.
`tests/test_evals.py` enforces this shape, class balance, and the
presence of hard negatives.

## Reading the calibration table

```
  band      cases  claimed  actual   gap
  90-100        8     94.0    62.5  +31.5
```

The model claimed 94% confidence and was right 62.5% of the time, so
it is overconfident by 31.5 points in that band. A positive gap is the
dangerous direction: it means the interface is showing users more
certainty than the verdict has earned. Confidence shown in the product
should be defensible against this table.

## Measured baselines

Recorded on the 61-message / 40-URL corpus, same cases both runs, paced
so no case was dropped to a rate limit.

| Metric | Before | After |
| --- | --- | --- |
| AI accuracy | 88.5% | 100% |
| Precision | 82.5% | 100% |
| Recall on scams | 100% | 100% |
| False-positive rate | 25.0% | 0% |
| URL detection | 90% | 100% |
| URL false positives | 40% | 0% (weighted rule) |

Paired comparison: 7 cases wrong → right, 0 right → wrong, McNemar
exact two-sided p = 0.0156.

**Read this with suspicion.** The same person wrote the corpus and the
fixes, so this is not independent evaluation. 100% means the corpus has
stopped discriminating — a suite everything passes measures nothing,
and calibration in particular cannot be assessed against a ceiling. The
next contribution to this project should be cases that break it.

## Results

Each run writes a timestamped JSON file to `evals/results/`, so runs
can be compared over time. Results are ignored by Git — they describe
one machine at one moment, and the corpus is what belongs in history.
