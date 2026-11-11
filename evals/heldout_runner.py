"""Held-out evaluation: precision, recall, F1 and false-positive rate.

    python evals/heldout_runner.py            # offline, free, runs in CI
    python evals/heldout_runner.py --json     # machine-readable output

Why a separate runner: evals/runner.py measures the corpus in
evals/corpus/, which the rules were tuned against while being written,
so its numbers are in-sample and optimistic. This runner only reads
evals/heldout/, which no rule has been tuned on, and reports every
dataset tier separately so the three are never blended:

    tuning        evals/corpus/*            used while writing the rules
    team_heldout  evals/heldout/ source=team_authored
                  written by the team, kept away from tuning; still
                  written by people who know the rules, so not
                  independent evidence
    independent   evals/heldout/ source=independent
                  collected from outside the team (real reports,
                  institutional partners); the only tier that can
                  support an accuracy claim

What is measured: the product's offline decision, i.e. the Trust
Engine's rules-only report (services/offline_report.py) that users get
when the AI is unavailable. A case is "flagged" when the verdict is
"danger". A second view reports the raw rule layer (any risk signal
from the message scanner, or the weighted URL rule) so a change in one
cannot hide behind the other. The AI layer is not measured here.

Rules for this directory (see evals/heldout/README.md): never edit a
rule to fix a held-out miss and re-run; add a new case to the tuning
corpus instead, and only then change the rule.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.heuristics import is_suspicious_url, scan_message  # noqa: E402
from services.offline_report import offline_message_report, offline_url_report  # noqa: E402

HELDOUT_DIR = Path(__file__).resolve().parent / "heldout"
CORPUS_DIR = Path(__file__).resolve().parent / "corpus"

SOURCES = ("team_authored", "independent")
TIER_OF_SOURCE = {"team_authored": "team_heldout", "independent": "independent"}
LANGUAGES = ("kk", "ru", "en", "none")
INPUT_TYPES = ("message", "url")
POSITIVE_LABELS = {"message": "scam", "url": "malicious"}
NEGATIVE_LABEL = "legitimate"


@dataclass(frozen=True)
class Case:
    id: str
    source: str
    language: str
    input_type: str
    attack_type: str
    label: str
    content: str

    @property
    def positive(self) -> bool:
        return self.label == POSITIVE_LABELS[self.input_type]


class SchemaError(ValueError):
    pass


def validate(row: dict, where: str) -> Case:
    """Reject a malformed case loudly: a silent skip would shrink the test set."""
    required = ("id", "source", "language", "input_type", "attack_type", "label")
    missing = [key for key in required if not row.get(key)]
    if missing:
        raise SchemaError(f"{where}: missing {missing}")
    if row["source"] not in SOURCES:
        raise SchemaError(f"{where}: source must be one of {SOURCES}")
    if row["input_type"] not in INPUT_TYPES:
        raise SchemaError(f"{where}: input_type must be one of {INPUT_TYPES}")
    if row["language"] not in LANGUAGES:
        raise SchemaError(f"{where}: language must be one of {LANGUAGES}")
    content_key = "text" if row["input_type"] == "message" else "url"
    if not row.get(content_key):
        raise SchemaError(f"{where}: missing {content_key}")
    valid_labels = {POSITIVE_LABELS[row["input_type"]], NEGATIVE_LABEL}
    if row["label"] not in valid_labels:
        raise SchemaError(f"{where}: label must be one of {sorted(valid_labels)}")
    if (row["label"] == NEGATIVE_LABEL) != (row["attack_type"] == "none"):
        raise SchemaError(f"{where}: attack_type must be 'none' exactly for legitimate cases")
    return Case(
        id=row["id"], source=row["source"], language=row["language"],
        input_type=row["input_type"], attack_type=row["attack_type"],
        label=row["label"], content=row[content_key],
    )


def load_cases(directory: Path = HELDOUT_DIR) -> list[Case]:
    cases: list[Case] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.jsonl")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            case = validate(json.loads(line), f"{path.name}:{number}")
            if case.id in seen:
                raise SchemaError(f"{path.name}:{number}: duplicate id {case.id}")
            seen.add(case.id)
            cases.append(case)
    return cases


# --- decisions -----------------------------------------------------------


def product_flags(case: Case) -> bool:
    """What a user sees offline: a 'danger' verdict from the rules-only report."""
    build = offline_message_report if case.input_type == "message" else offline_url_report
    return build(case.content, "evaluation").verdict == "danger"


def rule_layer_flags(case: Case) -> bool:
    """The raw rule layer, before the risk model turns it into a verdict."""
    if case.input_type == "url":
        return is_suspicious_url(case.content)
    report = scan_message(case.content)
    return bool(report.strong_signals or report.weak_signals or report.suspicious_urls)


DECISIONS = {"product_offline_verdict": product_flags, "rule_layer_signal": rule_layer_flags}


# --- metrics -------------------------------------------------------------


def metrics(pairs: list[tuple[bool, bool]]) -> dict:
    """pairs = (truth_positive, predicted_positive). None where undefined, never 0."""
    tp = sum(1 for truth, pred in pairs if truth and pred)
    fp = sum(1 for truth, pred in pairs if not truth and pred)
    fn = sum(1 for truth, pred in pairs if truth and not pred)
    tn = sum(1 for truth, pred in pairs if not truth and not pred)

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 3) if denominator else None

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 3)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    return {
        "n": len(pairs), "positives": tp + fn, "negatives": fp + tn,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": ratio(fp, fp + tn),
    }


def evaluate(cases: list[Case]) -> dict:
    results: dict = {"tiers": {}, "cases": len(cases)}
    for source in SOURCES:
        tier_cases = [case for case in cases if case.source == source]
        tier: dict = {"cases": len(tier_cases), "decisions": {}}
        for name, decide in DECISIONS.items():
            predictions = {case.id: decide(case) for case in tier_cases}

            def group(key) -> dict:
                buckets: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
                for case in tier_cases:
                    buckets[key(case)].append((case.positive, predictions[case.id]))
                return {label: metrics(pairs) for label, pairs in sorted(buckets.items())}

            tier["decisions"][name] = {
                "overall": metrics([(case.positive, predictions[case.id]) for case in tier_cases]),
                "by_language": group(lambda case: case.language),
                "by_input_type": group(lambda case: case.input_type),
                # Recall per attack type; legitimate cases form the "none"
                # group, whose only meaningful figure is the false-positive rate.
                "by_attack_type": group(lambda case: case.attack_type),
                "missed": sorted(c.id for c in tier_cases if c.positive and not predictions[c.id]),
                "false_positives": sorted(c.id for c in tier_cases if not c.positive and predictions[c.id]),
            }
        results["tiers"][TIER_OF_SOURCE[source]] = tier
    return results


def overlapping_with_tuning(cases: list[Case]) -> list[str]:
    """Held-out cases whose text or URL also appears in the tuning corpus."""
    tuning: set[str] = set()
    for path in CORPUS_DIR.glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                tuning.add((row.get("text") or row.get("url") or "").strip().lower())
    return [case.id for case in cases if case.content.strip().lower() in tuning]


# --- output --------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "  n/a" if value is None else f"{value * 100:5.1f}"


def _row(label: str, m: dict) -> str:
    return (
        f"  {label:<22} n={m['n']:>3}  P={_pct(m['precision'])}  R={_pct(m['recall'])}"
        f"  F1={_pct(m['f1'])}  FPR={_pct(m['false_positive_rate'])}"
        f"  (tp {m['tp']} fp {m['fp']} fn {m['fn']} tn {m['tn']})"
    )


def print_report(results: dict) -> None:
    print("Held-out evaluation (offline rules; AI layer not measured)")
    print("Tuning-corpus numbers come from evals/runner.py and are in-sample.\n")
    for tier_name, tier in results["tiers"].items():
        print(f"== {tier_name}: {tier['cases']} cases")
        if not tier["cases"]:
            note = "no independently sourced cases yet" if tier_name == "independent" else "no cases"
            print(f"  ({note})\n")
            continue
        if tier_name == "team_heldout":
            print("  Team-authored: kept out of tuning, but not independent evidence.")
        for decision, data in tier["decisions"].items():
            print(f"-- decision: {decision}")
            print(_row("overall", data["overall"]))
            for section in ("by_language", "by_input_type", "by_attack_type"):
                for label, m in data[section].items():
                    print(_row(f"{section[3:]}={label}", m))
            print(f"  missed: {', '.join(data['missed']) or '-'}")
            print(f"  false positives: {', '.join(data['false_positives']) or '-'}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    args = parser.parse_args(argv)

    cases = load_cases()
    overlap = overlapping_with_tuning(cases)
    if overlap:
        print(f"Held-out cases also present in the tuning corpus: {overlap}", file=sys.stderr)
        return 1
    results = evaluate(cases)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_report(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
