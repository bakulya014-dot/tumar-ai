"""Compare two evaluation runs and say whether the difference is real.

    python evals/compare.py gemini deepseek

Choosing a provider is a measured decision, not a preference. This
prints the numbers that decision rests on — accuracy, precision,
recall, both kinds of error, confidence calibration, latency and token
cost — and, for the paired cases, whether the difference is larger
than chance.

The significance test is McNemar's, which is the right one here: the
two runs saw the same cases, so what matters is not how many each got
right but how many one got right that the other did not. Comparing
headline accuracies on paired data overstates confidence.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS_DIR = Path(__file__).resolve().parent / "results"

FLAGGED = {"Suspicious", "Dangerous"}


def load(label: str) -> dict:
    """The most recent AI run carrying this label."""
    runs = []
    for path in sorted(RESULTS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if data.get("ai") and (data.get("label") == label or data.get("provider") == label):
            runs.append((path.name, data))
    if not runs:
        raise SystemExit(
            f"No run found labelled '{label}'. Produce one with:\n"
            f"  python evals/runner.py --ai --provider {label} --label {label}"
        )
    return runs[-1][1]


def correct(result: dict) -> bool:
    return (result["verdict"] in FLAGGED) == result["expected_scam"]


def mcnemar(fixed: int, broke: int) -> float:
    """Exact two-sided p for the discordant pairs."""
    total = fixed + broke
    if total == 0:
        return 1.0
    return min(1.0, 2 * 0.5**total)


def _row(name: str, left, right, unit: str = "", lower_is_better: bool = False) -> str:
    try:
        delta = right - left
    except TypeError:
        return f"  {name:<24} {left!s:>12} {right!s:>12}"
    arrow = ""
    if delta:
        better = delta < 0 if lower_is_better else delta > 0
        arrow = "  better" if better else "  worse"
    return (
        f"  {name:<24} {left:>10}{unit} {right:>10}{unit} "
        f"{delta:>+8.1f}{unit}{arrow}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="label of the run to compare against")
    parser.add_argument("candidate", help="label of the new run")
    args = parser.parse_args()

    left, right = load(args.baseline), load(args.candidate)
    left_ai, right_ai = left["ai"], right["ai"]
    left_sum, right_sum = left_ai["summary"], right_ai["summary"]

    print(f"\n{args.baseline}  vs  {args.candidate}")
    print(f"  corpus: {left['corpus']['messages']} messages")
    print(f"\n  {'metric':<24} {args.baseline:>12} {args.candidate:>12}   change")
    print(_row("accuracy", left_sum["accuracy"], right_sum["accuracy"], "%"))
    print(_row("precision", left_sum["precision"], right_sum["precision"], "%"))
    print(_row("recall on scams", left_sum["recall_on_scams"], right_sum["recall_on_scams"], "%"))
    print(
        _row(
            "false positive rate",
            left_sum["false_positive_rate"],
            right_sum["false_positive_rate"],
            "%",
            lower_is_better=True,
        )
    )
    print(
        _row(
            "median latency",
            left_sum.get("median_latency_ms", 0),
            right_sum.get("median_latency_ms", 0),
            " ms",
            lower_is_better=True,
        )
    )
    print(
        _row(
            "total tokens",
            left_sum.get("total_tokens", 0),
            right_sum.get("total_tokens", 0),
            "",
            lower_is_better=True,
        )
    )

    print("\n  errors")
    print(f"    missed scams   {args.baseline}: {left_sum['missed_scams'] or 'none'}")
    print(f"    missed scams   {args.candidate}: {right_sum['missed_scams'] or 'none'}")
    print(f"    false alarms   {args.baseline}: {left_sum['false_alarms'] or 'none'}")
    print(f"    false alarms   {args.candidate}: {right_sum['false_alarms'] or 'none'}")

    print("\n  confidence calibration (claimed minus delivered)")
    for label, run in ((args.baseline, left_ai), (args.candidate, right_ai)):
        bands = ", ".join(
            f"{band['band']}: {band['gap']:+.1f}" for band in run["calibration"]
        )
        print(f"    {label}: {bands or 'no bands'}")

    print("\n  per language")
    for label, run in ((args.baseline, left_ai), (args.candidate, right_ai)):
        langs = ", ".join(
            f"{code} {stats['accuracy']}%" for code, stats in run["by_language"].items()
        )
        print(f"    {label}: {langs}")

    by_left = {item["case_id"]: item for item in left_ai["results"]}
    by_right = {item["case_id"]: item for item in right_ai["results"]}
    shared = sorted(set(by_left) & set(by_right))
    fixed = [c for c in shared if not correct(by_left[c]) and correct(by_right[c])]
    broke = [c for c in shared if correct(by_left[c]) and not correct(by_right[c])]

    print(f"\n  paired on {len(shared)} case(s)")
    print(f"    {args.candidate} got right that {args.baseline} did not: {len(fixed)}")
    for case in fixed:
        print(f"      + {case}")
    print(f"    {args.candidate} got wrong that {args.baseline} did not: {len(broke)}")
    for case in broke:
        print(f"      - {case}")

    p_value = mcnemar(len(fixed), len(broke))
    print(f"    McNemar exact two-sided p = {p_value:.4f}")
    if len(fixed) + len(broke) == 0:
        print("    The two runs agreed on every case.")
    elif p_value >= 0.05:
        print(
            "    Not significant: this difference is within what chance "
            "would produce on a corpus this size."
        )
    else:
        direction = args.candidate if len(fixed) > len(broke) else args.baseline
        print(f"    Significant, favouring {direction}.")

    print(
        "\n  Read this alongside the corpus caveat in evals/README.md: the "
        "cases were written in-house, so a provider scoring perfectly has "
        "shown it is not worse, not that it is flawless."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
