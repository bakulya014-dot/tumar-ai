"""Evaluation harness for the image scanner.

Kept apart from evals/runner.py on purpose: the message baseline
measures the text pipeline on text, and mixing screenshot results into
it would blur what each number means. This harness measures the whole
image pipeline on labelled images and reports, separately:

    detection      precision / recall / F1 / false-positive rate,
                   where "flagged" = risk level moderate or above
    per language   the same, split by the label's language
    OCR            character accuracy against the expected transcript
                   (normalised Levenshtein similarity), where given
    QR             decode success rate on images labelled with a payload
    latency        median and p90 per image
    provider       failure rate of the vision / text stages

    python evals/image_scanner/evaluation.py              offline, free
    python evals/image_scanner/evaluation.py --ai         allow providers
    python evals/image_scanner/evaluation.py --label run1

Ground truth lives in ground_truth.json (schema at the top of that
file). Images live in evals/image_scanner/images/ and are NOT in the
repository: screenshots of real scams carry other people's data, and
the harness refuses to invent them. With no images present the harness
prints the framework's metrics as "not validated" and exits 0, so CI
runs it without pretending to have measured anything.

Hold-out discipline: `split` in a label is "test" or "dev". Only
"test" rows count toward reported metrics; "dev" rows are for tuning.
Near-duplicate screenshots (same scam, re-cropped) must share a
`family` so a family is never split across the two.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from services.image_scanner import ImageValidationError, scan_image  # noqa: E402
from services.image_scanner import ocr_engine  # noqa: E402

HERE = Path(__file__).resolve().parent
GROUND_TRUTH = HERE / "ground_truth.json"
IMAGES_DIR = HERE / "images"
RESULTS_DIR = HERE / "results"

FLAGGED_LEVELS = frozenset({"moderate", "high", "critical"})


@dataclass
class Outcome:
    id: str
    language: str
    label: str  # "scam" | "legitimate"
    level: str
    flagged: bool
    categories: tuple[str, ...]
    ocr_status: str
    ocr_similarity: float | None
    qr_expected: bool
    qr_decoded: bool
    vision_status: str
    ai_status: str
    latency_ms: int
    error: str = ""


def _similarity(a: str, b: str) -> float:
    """Normalised Levenshtein similarity in [0, 1]."""
    a, b = " ".join(a.lower().split()), " ".join(b.lower().split())
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return 1.0 - previous[-1] / max(len(a), len(b))


def _rates(outcomes: list[Outcome]) -> dict[str, float | int]:
    tp = sum(1 for o in outcomes if o.label == "scam" and o.flagged)
    fn = sum(1 for o in outcomes if o.label == "scam" and not o.flagged)
    fp = sum(1 for o in outcomes if o.label == "legitimate" and o.flagged)
    tn = sum(1 for o in outcomes if o.label == "legitimate" and not o.flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "n": len(outcomes), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "false_positive_rate": round(fpr, 3),
    }


def evaluate(labels: list[dict], allow_external: bool) -> dict:
    outcomes: list[Outcome] = []
    for row in labels:
        if row.get("split", "test") != "test":
            continue
        path = IMAGES_DIR / row["file"]
        if not path.exists():
            continue
        started = time.perf_counter()
        try:
            result = scan_image(path.read_bytes(), language=row.get("language", "en"), allow_external=allow_external)
        except ImageValidationError as error:
            outcomes.append(Outcome(
                id=row["id"], language=row.get("language", "en"), label=row["label"],
                level="refused", flagged=False, categories=(), ocr_status="n/a", ocr_similarity=None,
                qr_expected=bool(row.get("qr_payload")), qr_decoded=False, vision_status="n/a",
                ai_status="n/a", latency_ms=int((time.perf_counter() - started) * 1000), error=error.code,
            ))
            continue
        expected_text = row.get("expected_text")
        payloads = {c.payload for c in result.qr.codes}
        outcomes.append(Outcome(
            id=row["id"], language=row.get("language", "en"), label=row["label"],
            level=result.risk.level, flagged=result.risk.level in FLAGGED_LEVELS,
            categories=result.classification.categories,
            ocr_status=result.ocr.status,
            ocr_similarity=_similarity(result.ocr.text, expected_text) if expected_text and result.ocr.status == "success" else None,
            qr_expected=bool(row.get("qr_payload")),
            qr_decoded=row.get("qr_payload", "") in payloads if row.get("qr_payload") else False,
            vision_status=result.vision_status, ai_status=result.ai_status,
            latency_ms=result.elapsed_ms,
        ))

    by_language: dict[str, list[Outcome]] = defaultdict(list)
    for o in outcomes:
        by_language[o.language].append(o)
    ocr_scores = [o.ocr_similarity for o in outcomes if o.ocr_similarity is not None]
    qr_rows = [o for o in outcomes if o.qr_expected]
    latencies = sorted(o.latency_ms for o in outcomes)
    ran = [o for o in outcomes if not o.error]

    def failure_rate(attr: str) -> float | None:
        tried = [o for o in ran if getattr(o, attr) in {"success", "failed"}]
        return round(sum(1 for o in tried if getattr(o, attr) == "failed") / len(tried), 3) if tried else None

    validated = bool(outcomes)
    return {
        "validated": validated,
        "note": "" if validated else "No labelled images present: performance has NOT been validated.",
        "tesseract_available": ocr_engine.available(),
        "ocr_languages": list(ocr_engine.languages()),
        "detection": _rates(outcomes) if validated else None,
        "per_language": {lang: _rates(rows) for lang, rows in sorted(by_language.items())} if validated else None,
        "ocr_mean_similarity": round(statistics.mean(ocr_scores), 3) if ocr_scores else None,
        "ocr_unavailable_count": sum(1 for o in ran if o.ocr_status == "unavailable"),
        "qr_success_rate": round(sum(1 for o in qr_rows if o.qr_decoded) / len(qr_rows), 3) if qr_rows else None,
        "latency_ms_median": latencies[len(latencies) // 2] if latencies else None,
        "latency_ms_p90": latencies[int(len(latencies) * 0.9)] if latencies else None,
        "vision_failure_rate": failure_rate("vision_status"),
        "text_model_failure_rate": failure_rate("ai_status"),
        "refused_uploads": [o.id for o in outcomes if o.error],
        "cases": [o.__dict__ for o in outcomes],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ai", action="store_true", help="allow configured external providers")
    parser.add_argument("--label", default="", help="name for the results file")
    args = parser.parse_args()

    labels = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))["cases"]
    report = evaluate(labels, allow_external=args.ai)
    report["run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["label"] = args.label
    report["labelled_cases"] = len(labels)
    report["images_present"] = sum(1 for row in labels if (IMAGES_DIR / row["file"]).exists())

    RESULTS_DIR.mkdir(exist_ok=True)
    name = f"{args.label or 'run'}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    (RESULTS_DIR / name).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {k: v for k, v in report.items() if k != "cases"}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not report["validated"]:
        # Relative path: this output is pasted into reports and docs,
        # where an absolute path would leak the machine's user name.
        print(
            "\nImage-scanner performance has not been validated: add labelled images to",
            IMAGES_DIR.relative_to(ROOT).as_posix(),
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
