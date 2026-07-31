"""Evaluation harness for the Trust Engine.

Until now, every prompt or heuristic change was a guess: nothing
measured whether Tumar.AI's verdicts are actually correct. This
harness answers three questions that a security product must be able
to answer about itself.

    How much does it catch?      recall on labelled scams
    How often does it cry wolf?  false-positive rate on legitimate input
    Is its confidence honest?    accuracy within each confidence band

The third question is the one this product exists to get right. The
AI reports its own confidence, and self-reported confidence tends to
be optimistic; the calibration table shows the gap between what the
model claims and what it delivers, so the number on screen can be
defended rather than merely displayed.

Two modes, deliberately separated by cost:

    python evals/runner.py                 offline, free, runs in CI
    python evals/runner.py --ai            calls Gemini, costs tokens

Offline mode measures the deterministic layer only: how often the
scanner fires on scams versus on legitimate messages, and how the URL
heuristics classify known-good and known-bad addresses. That needs no
API key, so continuous integration can enforce it on every push.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Make the project root importable when running this file directly.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.heuristics import (  # noqa: E402
    is_suspicious_url,
    scan_message,
    url_reasons,
)
from services.scam_analysis import ScamAnalysisError, analyze_message  # noqa: E402
from services.trust_report import from_scam_report  # noqa: E402

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Verdicts that count as "this was flagged to the user". A caution is
# still an interruption, so it counts as flagged when measuring false
# positives — anything else would flatter the numbers.
FLAGGED_VERDICTS = frozenset({"Suspicious", "Dangerous"})

# Confidence bands for the calibration table. Wide enough that a small
# corpus still puts a useful number of cases in each one.
CONFIDENCE_BANDS = ((0, 59), (60, 74), (75, 89), (90, 100))

# Seconds between AI calls, and how many times to retry a case the
# provider refused. Tuned for a free-tier per-minute quota; raise the
# delay rather than accepting dropped cases.
DEFAULT_DELAY_S = 4.5
RATE_LIMIT_RETRIES = 3


@dataclass(frozen=True)
class MessageCase:
    """One labelled message. `label` is ground truth, not a prediction."""

    id: str
    language: str
    label: str  # "scam" | "legitimate"
    text: str
    tags: list[str] = field(default_factory=list)

    @property
    def is_scam(self) -> bool:
        return self.label == "scam"


@dataclass(frozen=True)
class UrlCase:
    """One labelled URL."""

    id: str
    label: str  # "malicious" | "legitimate"
    url: str
    tags: list[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.label == "malicious"


@dataclass(frozen=True)
class AiResult:
    """What the AI said about one case, next to the truth."""

    case_id: str
    language: str
    expected_scam: bool
    verdict: str
    confidence: int  # what the model claimed about itself
    risk_score: int
    # What the product actually shows, after the evidence-based
    # confidence model has adjusted the model's self-report. This is
    # the number a user sees, so this is the number worth calibrating.
    shown_confidence: int = 0

    @property
    def flagged(self) -> bool:
        return self.verdict in FLAGGED_VERDICTS

    @property
    def correct(self) -> bool:
        return self.flagged == self.expected_scam


def load_messages() -> list[MessageCase]:
    """Read every labelled message file in the corpus."""
    return [
        MessageCase(
            id=row["id"],
            language=row["language"],
            label=row["label"],
            text=row["text"],
            tags=row.get("tags", []),
        )
        for row in _read_corpus("messages")
    ]


def load_urls() -> list[UrlCase]:
    """Read every labelled URL file in the corpus."""
    return [
        UrlCase(
            id=row["id"],
            label=row["label"],
            url=row["url"],
            tags=row.get("tags", []),
        )
        for row in _read_corpus("urls")
    ]


def _read_corpus(prefix: str) -> list[dict]:
    """Read every corpus file with this prefix, in filename order.

    Globbed rather than named, so a new batch of cases is a new file
    rather than an edit to an existing one — which keeps additions
    reviewable and makes the corpus easy to grow.
    """
    rows: list[dict] = []
    for path in sorted(CORPUS_DIR.glob(f"{prefix}*.jsonl")):
        with open(path, encoding="utf-8") as handle:
            rows.extend(json.loads(line) for line in handle if line.strip())
    return rows


# --- Offline: the deterministic layer ---


def scanner_fired(text: str) -> bool:
    """True when the deterministic scanner found anything at all.

    The scanner does not produce a verdict — it produces evidence that
    is fed to the AI. So what matters is its signal-to-noise: firing on
    scams is the point, firing on ordinary messages poisons the prompt
    and pushes the AI toward false positives.
    """
    report = scan_message(text)
    return bool(
        report.urgency_matches
        or report.otp_matches
        or report.credential_indicators
        or report.financial_indicators
        or report.manipulation_indicators
        or report.suspicious_urls
    )


def rate(count: int, total: int) -> float:
    """Percentage, guarding against an empty denominator."""
    return round(100 * count / total, 1) if total else 0.0


def scanner_risk_signal(text: str) -> bool:
    """True when the scanner reported something it treats as risk.

    Narrower than scanner_fired: a one-time code being delivered is
    matched by the scanner but is explicitly labelled as ordinary, so
    counting it as noise would misdescribe what the AI is handed. Both
    figures are reported, because changing a metric's definition and
    then claiming an improvement would prove nothing.
    """
    report = scan_message(text)
    return bool(
        report.strong_signals or report.weak_signals or report.suspicious_urls
    )


def evaluate_scanner(cases: list[MessageCase]) -> dict:
    """How well the deterministic scanner separates scams from noise."""
    scams = [case for case in cases if case.is_scam]
    legit = [case for case in cases if not case.is_scam]
    return {
        "scam_cases": len(scams),
        "legitimate_cases": len(legit),
        # Any pattern matched at all — the original definition.
        "signal_rate_on_scams": rate(
            sum(1 for case in scams if scanner_fired(case.text)), len(scams)
        ),
        "signal_rate_on_legitimate": rate(
            sum(1 for case in legit if scanner_fired(case.text)), len(legit)
        ),
        # Only matches the engine treats as evidence of risk.
        "risk_rate_on_scams": rate(
            sum(1 for case in scams if scanner_risk_signal(case.text)), len(scams)
        ),
        "risk_rate_on_legitimate": rate(
            sum(1 for case in legit if scanner_risk_signal(case.text)), len(legit)
        ),
        "noisy_cases": [
            case.id for case in legit if scanner_risk_signal(case.text)
        ],
        "missed_cases": [
            case.id for case in scams if not scanner_risk_signal(case.text)
        ],
    }


def evaluate_urls(cases: list[UrlCase]) -> dict:
    """How the URL heuristics classify known-good and known-bad links.

    Reported under both decision rules: "any finding at all", which is
    how the scanner used to decide, and the weighted rule the engine
    now uses. Showing both keeps the comparison honest — an
    improvement that only exists because the rule changed is not one.
    """
    malicious = [case for case in cases if case.is_malicious]
    legit = [case for case in cases if not case.is_malicious]

    def measure(decide) -> dict:
        caught = [case for case in malicious if decide(case.url)]
        flagged = [case for case in legit if decide(case.url)]
        return {
            "detection_rate": rate(len(caught), len(malicious)),
            "false_positive_rate": rate(len(flagged), len(legit)),
            "missed_cases": [
                case.id for case in malicious if not decide(case.url)
            ],
            "false_positives": [
                {"id": case.id, "reasons": url_reasons(case.url)}
                for case in flagged
            ],
        }

    return {
        "malicious_cases": len(malicious),
        "legitimate_cases": len(legit),
        "any_finding_rule": measure(lambda url: bool(url_reasons(url))),
        "weighted_rule": measure(is_suspicious_url),
    }


# --- AI layer ---


def run_ai(
    cases: list[MessageCase],
    api_key: str,
    limit: int | None = None,
    delay: float = DEFAULT_DELAY_S,
    retries: int = RATE_LIMIT_RETRIES,
) -> tuple[list[AiResult], list[str]]:
    """Run the real analysis over the corpus. Costs tokens.

    Paced and retried on purpose. Free-tier quotas drop requests once
    the per-minute limit is hit, and a dropped case silently shrinks
    the corpus — leaving two runs measured over different subsets and
    no longer comparable. Losing a few minutes to pacing is cheaper
    than a benchmark that cannot be trusted.

    Returns the results plus the ids of cases that still failed, so an
    incomplete run is visible rather than quietly flattering itself.
    """
    selected = cases[:limit] if limit else cases
    results: list[AiResult] = []
    failures: list[str] = []
    for index, case in enumerate(selected, start=1):
        print(f"  [{index}/{len(selected)}] {case.id}", flush=True)
        for attempt in range(retries):
            try:
                report = analyze_message(case.text, api_key=api_key)
            except ScamAnalysisError as error:
                retriable = error.code in ("rate_limited", "service_down")
                if retriable and attempt < retries - 1:
                    backoff = delay * (2**attempt) + 5
                    print(f"      {error.code}, retrying in {backoff:.0f}s", flush=True)
                    time.sleep(backoff)
                    continue
                failures.append(f"{case.id}: {error.code}")
                break
            shown = from_scam_report(report, case.text)
            results.append(
                AiResult(
                    case_id=case.id,
                    language=case.language,
                    expected_scam=case.is_scam,
                    verdict=report.ai.verdict,
                    confidence=report.ai.confidence,
                    risk_score=report.ai.risk_score,
                    shown_confidence=shown.confidence,
                )
            )
            break
        if index < len(selected):
            time.sleep(delay)
    return results, failures


def score(results: list[AiResult]) -> dict:
    """Accuracy, recall, and the two error types that matter.

    The two are not equally bad, so they are reported separately: a
    missed scam can cost someone their savings, while a false alarm
    costs trust in the product. Both are counted; neither is hidden
    inside a single accuracy figure.
    """
    scams = [item for item in results if item.expected_scam]
    legit = [item for item in results if not item.expected_scam]
    missed = [item for item in scams if not item.flagged]
    false_alarms = [item for item in legit if item.flagged]
    hard_false_alarms = [item for item in legit if item.verdict == "Dangerous"]
    caught = len(scams) - len(missed)
    return {
        "cases": len(results),
        "accuracy": rate(sum(1 for item in results if item.correct), len(results)),
        # Of everything we flagged, how much deserved it. Precision is
        # what a user experiences as "this tool cries wolf".
        "precision": rate(caught, caught + len(false_alarms)),
        "recall_on_scams": rate(caught, len(scams)),
        "false_positive_rate": rate(len(false_alarms), len(legit)),
        "missed_scams": [item.case_id for item in missed],
        "false_alarms": [item.case_id for item in false_alarms],
        "hard_false_alarms": [item.case_id for item in hard_false_alarms],
    }


def by_category(results: list[AiResult], cases: list[MessageCase]) -> dict:
    """Accuracy per tag, so weak scam families are visible.

    An overall average hides the shape of the failures: being strong on
    prize scams and blind to business-email compromise is a very
    different product from being evenly mediocre.
    """
    tags = {tag for case in cases for tag in case.tags}
    by_id = {case.id: case for case in cases}
    table: dict[str, dict] = {}
    for tag in sorted(tags):
        bucket = [
            item
            for item in results
            if item.case_id in by_id and tag in by_id[item.case_id].tags
        ]
        if len(bucket) < 2:  # too few to say anything
            continue
        table[tag] = {
            "cases": len(bucket),
            "accuracy": rate(sum(1 for item in bucket if item.correct), len(bucket)),
        }
    return table


def calibration(results: list[AiResult]) -> list[dict]:
    """Is a stated confidence of 90 actually right 90% of the time?

    For each band: how many cases landed there, the mean confidence
    claimed, and the accuracy delivered. `gap` is claimed minus
    delivered — positive means overconfident, which is the direction
    that misleads users into trusting a wrong verdict.
    """
    table: list[dict] = []
    for low, high in CONFIDENCE_BANDS:
        bucket = [item for item in results if low <= item.confidence <= high]
        if not bucket:
            continue
        mean_confidence = round(
            sum(item.confidence for item in bucket) / len(bucket), 1
        )
        accuracy = rate(sum(1 for item in bucket if item.correct), len(bucket))
        table.append(
            {
                "band": f"{low}-{high}",
                "cases": len(bucket),
                "mean_confidence": mean_confidence,
                "accuracy": accuracy,
                "gap": round(mean_confidence - accuracy, 1),
            }
        )
    return table


def by_language(results: list[AiResult]) -> dict:
    """Accuracy per language.

    Tumar.AI's advantage is Kazakh and Russian. If quality is worse
    there than in English, that is the most important thing to know
    and the easiest thing to miss in an overall average.
    """
    languages: dict[str, dict] = {}
    for code in sorted({item.language for item in results}):
        bucket = [item for item in results if item.language == code]
        languages[code] = {
            "cases": len(bucket),
            "accuracy": rate(sum(1 for item in bucket if item.correct), len(bucket)),
        }
    return languages


# --- Reporting ---


def print_offline(scanner: dict, urls: dict) -> None:
    print("\nDETERMINISTIC SCANNER (messages)")
    print(f"  corpus:                    {scanner['scam_cases']} scam / {scanner['legitimate_cases']} legitimate")
    print(f"  any match, scams:          {scanner['signal_rate_on_scams']}%")
    print(f"  any match, legitimate:     {scanner['signal_rate_on_legitimate']}%")
    print(f"  RISK signal, scams:        {scanner['risk_rate_on_scams']}%   (higher is better)")
    print(f"  RISK signal, legitimate:   {scanner['risk_rate_on_legitimate']}%   (lower is better)")
    if scanner["missed_cases"]:
        print(f"  no risk signal on scams:   {', '.join(scanner['missed_cases'])}")
    if scanner["noisy_cases"]:
        print(f"  noise on legitimate:       {', '.join(scanner['noisy_cases'])}")

    print("\nURL HEURISTICS")
    print(f"  corpus:                    {urls['malicious_cases']} malicious / {urls['legitimate_cases']} legitimate")
    for rule in ("any_finding_rule", "weighted_rule"):
        block = urls[rule]
        print(f"  [{rule}]")
        print(f"    detection rate:          {block['detection_rate']}%")
        print(f"    false positive rate:     {block['false_positive_rate']}%")
        if block["missed_cases"]:
            print(f"    missed:                  {', '.join(block['missed_cases'])}")
        for item in block["false_positives"]:
            print(f"    false positive:          {item['id']} -> {', '.join(item['reasons'])}")


def print_ai(
    summary: dict,
    bands: list[dict],
    languages: dict,
    categories: dict,
    failures: list[str],
) -> None:
    print("\nAI LAYER")
    print(f"  cases:                     {summary['cases']}")
    print(f"  accuracy:                  {summary['accuracy']}%")
    print(f"  precision:                 {summary['precision']}%")
    print(f"  recall on scams:           {summary['recall_on_scams']}%")
    print(f"  false positive rate:       {summary['false_positive_rate']}%")
    if summary["missed_scams"]:
        print(f"  MISSED SCAMS:              {', '.join(summary['missed_scams'])}")
    if summary["false_alarms"]:
        print(f"  false alarms:              {', '.join(summary['false_alarms'])}")
    if summary["hard_false_alarms"]:
        print(f"  called legitimate DANGEROUS: {', '.join(summary['hard_false_alarms'])}")

    print("\nCONFIDENCE CALIBRATION")
    print("  band      cases  claimed  actual   gap")
    for row in bands:
        print(
            f"  {row['band']:<9} {row['cases']:>5}  {row['mean_confidence']:>7}  "
            f"{row['accuracy']:>6}  {row['gap']:>+5}"
        )
    print("  gap = claimed confidence minus measured accuracy; positive = overconfident")

    print("\nBY LANGUAGE")
    for code, stats in languages.items():
        print(f"  {code}: {stats['accuracy']}% over {stats['cases']} cases")

    print("\nWEAKEST CATEGORIES")
    ranked = sorted(categories.items(), key=lambda row: row[1]["accuracy"])
    for tag, stats in ranked[:8]:
        print(f"  {tag:<16} {stats['accuracy']:>5}% over {stats['cases']} cases")

    if failures:
        print(f"\n  {len(failures)} case(s) failed to run: {', '.join(failures)}")


def save(payload: dict) -> Path:
    """Write one run to evals/results/ so runs can be compared later."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = RESULTS_DIR / f"{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _api_key() -> str:
    """Read the key from the environment or Streamlit's secrets file.

    The harness runs outside Streamlit, so it cannot use st.secrets.
    """
    import os

    key = os.environ.get("GEMINI_API_KEY", "")
    if key:
        return key
    secrets = ROOT / ".streamlit" / "secrets.toml"
    if secrets.exists():
        for line in secrets.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "GEMINI_API_KEY":
                return value.strip().strip('"').strip("'")
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ai",
        action="store_true",
        help="also run the AI layer (calls Gemini, costs tokens)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="only run the first N cases through the AI, to cap spend",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_S,
        help="seconds between AI calls, to stay inside the provider quota",
    )
    parser.add_argument(
        "--label",
        default="",
        help="tag this run in the saved results (e.g. 'before', 'after')",
    )
    args = parser.parse_args()

    messages = load_messages()
    urls = load_urls()
    print(f"Corpus: {len(messages)} messages, {len(urls)} URLs")

    scanner = evaluate_scanner(messages)
    url_metrics = evaluate_urls(urls)
    print_offline(scanner, url_metrics)

    payload = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "corpus": {"messages": len(messages), "urls": len(urls)},
        "scanner": scanner,
        "urls": url_metrics,
    }

    if args.ai:
        key = _api_key()
        if not key:
            print("\nNo GEMINI_API_KEY found — set it in the environment or .streamlit/secrets.toml")
            return 1
        print(f"\nRunning the AI layer over {args.limit or len(messages)} case(s)…")
        results, failures = run_ai(messages, key, args.limit, args.delay)
        if not results:
            print("Every AI call failed — nothing to score.")
            return 1
        summary = score(results)
        bands = calibration(results)
        languages = by_language(results)
        categories = by_category(results, messages)
        print_ai(summary, bands, languages, categories, failures)
        payload["ai"] = {
            "summary": summary,
            "calibration": bands,
            "by_language": languages,
            "by_category": categories,
            "failures": failures,
            "results": [vars(item) for item in results],
        }

    print(f"\nSaved: {save(payload).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
