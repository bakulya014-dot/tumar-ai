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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Make the project root importable when running this file directly.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.heuristics import scan_message, url_reasons  # noqa: E402
from services.scam_analysis import ScamAnalysisError, analyze_message  # noqa: E402

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Verdicts that count as "this was flagged to the user". A caution is
# still an interruption, so it counts as flagged when measuring false
# positives — anything else would flatter the numbers.
FLAGGED_VERDICTS = frozenset({"Suspicious", "Dangerous"})

# Confidence bands for the calibration table. Wide enough that a small
# corpus still puts a useful number of cases in each one.
CONFIDENCE_BANDS = ((0, 59), (60, 74), (75, 89), (90, 100))


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
    confidence: int
    risk_score: int

    @property
    def flagged(self) -> bool:
        return self.verdict in FLAGGED_VERDICTS

    @property
    def correct(self) -> bool:
        return self.flagged == self.expected_scam


def load_messages() -> list[MessageCase]:
    """Read the labelled message corpus."""
    return [
        MessageCase(
            id=row["id"],
            language=row["language"],
            label=row["label"],
            text=row["text"],
            tags=row.get("tags", []),
        )
        for row in _read_jsonl(CORPUS_DIR / "messages.jsonl")
    ]


def load_urls() -> list[UrlCase]:
    """Read the labelled URL corpus."""
    return [
        UrlCase(
            id=row["id"],
            label=row["label"],
            url=row["url"],
            tags=row.get("tags", []),
        )
        for row in _read_jsonl(CORPUS_DIR / "urls.jsonl")
    ]


def _read_jsonl(path: Path) -> list[dict]:
    """Parse one JSON object per line, ignoring blank lines."""
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


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


def evaluate_scanner(cases: list[MessageCase]) -> dict:
    """How well the deterministic scanner separates scams from noise."""
    scams = [case for case in cases if case.is_scam]
    legit = [case for case in cases if not case.is_scam]
    fired_scam = sum(1 for case in scams if scanner_fired(case.text))
    fired_legit = sum(1 for case in legit if scanner_fired(case.text))
    return {
        "scam_cases": len(scams),
        "legitimate_cases": len(legit),
        "signal_rate_on_scams": rate(fired_scam, len(scams)),
        "signal_rate_on_legitimate": rate(fired_legit, len(legit)),
        "noisy_cases": [
            case.id for case in legit if scanner_fired(case.text)
        ],
        "missed_cases": [
            case.id for case in scams if not scanner_fired(case.text)
        ],
    }


def evaluate_urls(cases: list[UrlCase]) -> dict:
    """How the URL heuristics classify known-good and known-bad links."""
    malicious = [case for case in cases if case.is_malicious]
    legit = [case for case in cases if not case.is_malicious]
    caught = [case for case in malicious if url_reasons(case.url)]
    flagged_legit = [case for case in legit if url_reasons(case.url)]
    return {
        "malicious_cases": len(malicious),
        "legitimate_cases": len(legit),
        "detection_rate": rate(len(caught), len(malicious)),
        "false_positive_rate": rate(len(flagged_legit), len(legit)),
        "missed_cases": [case.id for case in malicious if not url_reasons(case.url)],
        "false_positives": [
            {"id": case.id, "reasons": url_reasons(case.url)}
            for case in flagged_legit
        ],
    }


# --- AI layer ---


def run_ai(
    cases: list[MessageCase], api_key: str, limit: int | None = None
) -> tuple[list[AiResult], list[str]]:
    """Run the real analysis over the corpus. Costs tokens.

    Returns the results plus the ids of cases that errored, so a
    provider outage is visible instead of quietly shrinking the corpus
    and inflating the scores.
    """
    selected = cases[:limit] if limit else cases
    results: list[AiResult] = []
    failures: list[str] = []
    for index, case in enumerate(selected, start=1):
        print(f"  [{index}/{len(selected)}] {case.id}", flush=True)
        try:
            report = analyze_message(case.text, api_key=api_key)
        except ScamAnalysisError as error:
            failures.append(f"{case.id}: {error.code}")
            continue
        results.append(
            AiResult(
                case_id=case.id,
                language=case.language,
                expected_scam=case.is_scam,
                verdict=report.ai.verdict,
                confidence=report.ai.confidence,
                risk_score=report.ai.risk_score,
            )
        )
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
    return {
        "cases": len(results),
        "accuracy": rate(sum(1 for item in results if item.correct), len(results)),
        "recall_on_scams": rate(len(scams) - len(missed), len(scams)),
        "false_positive_rate": rate(len(false_alarms), len(legit)),
        "missed_scams": [item.case_id for item in missed],
        "false_alarms": [item.case_id for item in false_alarms],
        "hard_false_alarms": [item.case_id for item in hard_false_alarms],
    }


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
    print(f"  signal rate on scams:      {scanner['signal_rate_on_scams']}%   (higher is better)")
    print(f"  signal rate on legitimate: {scanner['signal_rate_on_legitimate']}%   (lower is better)")
    if scanner["missed_cases"]:
        print(f"  no signal on scams:        {', '.join(scanner['missed_cases'])}")
    if scanner["noisy_cases"]:
        print(f"  noise on legitimate:       {', '.join(scanner['noisy_cases'])}")

    print("\nURL HEURISTICS")
    print(f"  corpus:                    {urls['malicious_cases']} malicious / {urls['legitimate_cases']} legitimate")
    print(f"  detection rate:            {urls['detection_rate']}%")
    print(f"  false positive rate:       {urls['false_positive_rate']}%")
    if urls["missed_cases"]:
        print(f"  missed:                    {', '.join(urls['missed_cases'])}")
    for item in urls["false_positives"]:
        print(f"  false positive:            {item['id']} -> {', '.join(item['reasons'])}")


def print_ai(summary: dict, bands: list[dict], languages: dict, failures: list[str]) -> None:
    print("\nAI LAYER")
    print(f"  cases:                     {summary['cases']}")
    print(f"  accuracy:                  {summary['accuracy']}%")
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
    args = parser.parse_args()

    messages = load_messages()
    urls = load_urls()
    print(f"Corpus: {len(messages)} messages, {len(urls)} URLs")

    scanner = evaluate_scanner(messages)
    url_metrics = evaluate_urls(urls)
    print_offline(scanner, url_metrics)

    payload = {
        "run_at": datetime.now(timezone.utc).isoformat(),
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
        results, failures = run_ai(messages, key, args.limit)
        if not results:
            print("Every AI call failed — nothing to score.")
            return 1
        summary = score(results)
        bands = calibration(results)
        languages = by_language(results)
        print_ai(summary, bands, languages, failures)
        payload["ai"] = {
            "summary": summary,
            "calibration": bands,
            "by_language": languages,
            "failures": failures,
            "results": [vars(item) for item in results],
        }

    print(f"\nSaved: {save(payload).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
