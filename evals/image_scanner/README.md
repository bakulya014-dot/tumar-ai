# Image scanner evaluation

Separate from the message baseline in `evals/runner.py`: that measures
the text pipeline on text. This measures the whole image pipeline —
validation, OCR, QR decoding, link checks, categories, risk — on
labelled screenshots.

```bash
python evals/image_scanner/evaluation.py          # offline, free
python evals/image_scanner/evaluation.py --ai     # allow configured providers
```

## Status: framework only

**No labelled image set has been collected yet, so no performance
figure for the image scanner has been validated.** The harness runs
without images, prints `"validated": false`, and exits 0 — CI can
call it, and nothing is reported that was not measured.

Images are deliberately not committed: screenshots of real scams carry
other people's names, numbers and balances. Collect them into
`evals/image_scanner/images/` locally, label them in
`ground_truth.json`, and keep the folder out of version control.

## What it reports once images exist

| Metric | How |
| --- | --- |
| precision / recall / F1 / false-positive rate | flagged = risk level moderate or above |
| per-language performance | the same, split by the label's `language` |
| OCR accuracy | normalised Levenshtein similarity to `expected_text` |
| QR extraction success | decoded payload equals `qr_payload` |
| latency | median and p90 per image |
| provider failure rate | vision and text stages that were tried and failed |

## Hold-out discipline

- `split` is `test` or `dev`. Only `test` rows count toward metrics.
- Near-duplicates (the same scam re-cropped, re-compressed, or
  translated by the same template) share a `family`, and a family is
  never split across `test` and `dev`.
- The collection plan in `ground_truth.json` lists the sixteen case
  types the scanner must be measured on, including corrupted and
  oversized files (expected outcome: refused), images with no text
  (expected: inconclusive), and prompt-injection screenshots
  (expected: flagged, never "safe").
