"""Evaluate the AI Security Check on labelled cases.

    venv\\Scripts\\python.exe evals\\ai_security\\runner.py              # rules only, both sets
    venv\\Scripts\\python.exe evals\\ai_security\\runner.py --set heldout
    venv\\Scripts\\python.exe evals\\ai_security\\runner.py --ai         # rules + live AI (needs GEMINI_API_KEY)

Two sets, kept apart on purpose:

- cases_tuning.jsonl   patterns MAY be adjusted to fix misses here.
- cases_heldout.jsonl  written and committed BEFORE this runner existed,
                       and frozen by SHA-256 (HELDOUT_SHA256, checked by
                       tests/test_ai_security_eval.py). Never tuned on.

Both sets are team-written by the same people who wrote the patterns,
so even the held-out numbers are optimistic compared with real-world
text. They measure regressions and blind spots; they are not an
independent benchmark, and the README says so.

Metrics, at two thresholds:
    flagged   verdict is caution or danger ("have a person look")
    danger    verdict is danger
    precision, recall, F1, false-positive rate on benign look-alikes,
    recall per language and per threat, and whether the expected
    threat family was the one named (family match).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("TUMAR_TELEMETRY", "off")

from services.ai_security.detector import detect  # noqa: E402

HERE = Path(__file__).resolve().parent
SETS = {"tuning": HERE / "cases_tuning.jsonl", "heldout": HERE / "cases_heldout.jsonl"}
# SHA-256 of cases_heldout.jsonl with LF line endings. Changing the file
# means the held-out numbers are no longer held out: start a new set.
HELDOUT_SHA256 = "5a2b7b86857a0e8129511bebe85843aac324cce972e9d469e1c15e3bd1a7d241"

# The codes that count as naming the expected threat.
FAMILY = {
    "direct_injection": {"ais_direct_injection"},
    "indirect_injection": {"ais_indirect_injection", "ais_hidden_text", "ais_direct_injection"},
    "evidence_manipulation": {"ais_evidence_manipulation"},
    "exfiltration": {"ais_exfiltration"},
    "memory_poisoning": {"ais_memory_poisoning"},
    "tool_poisoning": {"ais_tool_poisoning"},
    "excessive_permissions": {
        "ais_perm_no_approval", "ais_perm_beyond_task", "ais_perm_excessive", "ais_perm_shell", "ais_perm_filesystem",
        "ais_perm_payments", "ais_perm_messaging", "ais_perm_secrets", "ais_perm_admin", "ais_perm_delete",
    },
    "payment_redirect": {"ais_payment_redirect", "ais_payment_change", "ais_impersonation_supplier", "ais_impersonation_exec"},
}


@dataclass(frozen=True)
class Case:
    id: str
    lang: str
    context: str
    label: str
    threat: str
    text: str
    task: str = ""


@dataclass(frozen=True)
class Outcome:
    case: Case
    verdict: str
    codes: frozenset[str]

    @property
    def flagged(self) -> bool:
        return self.verdict in {"caution", "danger"}

    @property
    def family_match(self) -> bool:
        return bool(self.codes & FAMILY.get(self.case.threat, set()))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load(name: str) -> list[Case]:
    path = SETS[name]
    return [Case(**json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_rules(case: Case) -> Outcome:
    detection = detect(case.text, case.context, case.task)
    return Outcome(case, detection.verdict, frozenset(detection.codes))


def run_ai(case: Case) -> Outcome:
    """Rules + the live AI, through the real engine (no offline fallback)."""
    from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject

    report = TrustEngine().analyze(
        TrustSubject(content=case.text, declared_kind="ai_content", language=case.lang,
                     hints={"context": case.context, "task": case.task}),
        AnalysisContext(api_key=os.environ.get("GEMINI_API_KEY", ""), offline_fallback=False, channel="eval"),
    )
    return Outcome(case, report.verdict, frozenset(e.code for e in report.evidence))


def _rate(hits: int, total: int) -> float:
    return round(100 * hits / total, 1) if total else 0.0


def score(outcomes: list[Outcome], strict: bool = False) -> dict:
    def positive(o: Outcome) -> bool:
        return o.verdict == "danger" if strict else o.flagged

    tp = sum(positive(o) and o.case.label == "attack" for o in outcomes)
    fp = sum(positive(o) and o.case.label == "benign" for o in outcomes)
    fn = sum(not positive(o) and o.case.label == "attack" for o in outcomes)
    tn = sum(not positive(o) and o.case.label == "benign" for o in outcomes)
    precision, recall = _rate(tp, tp + fp), _rate(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 1) if precision + recall else 0.0
    return {"n": len(outcomes), "precision": precision, "recall": recall, "f1": f1,
            "fpr": _rate(fp, fp + tn), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def report(outcomes: list[Outcome]) -> dict:
    attacks = [o for o in outcomes if o.case.label == "attack"]
    by = lambda key: sorted({getattr(o.case, key) for o in outcomes})  # noqa: E731
    return {
        "flagged": score(outcomes),
        "danger": score(outcomes, strict=True),
        "recall_by_language": {
            lang: _rate(sum(o.flagged for o in attacks if o.case.lang == lang), sum(o.case.lang == lang for o in attacks))
            for lang in by("lang")
        },
        "fpr_by_language": {
            lang: _rate(sum(o.flagged for o in outcomes if o.case.label == "benign" and o.case.lang == lang),
                        sum(o.case.label == "benign" and o.case.lang == lang for o in outcomes))
            for lang in by("lang")
        },
        "recall_by_threat": {
            threat: f"{sum(o.flagged for o in attacks if o.case.threat == threat)}/{sum(o.case.threat == threat for o in attacks)}"
            for threat in sorted({o.case.threat for o in attacks})
        },
        "family_match": _rate(sum(o.family_match for o in attacks if o.flagged), sum(o.flagged for o in attacks)),
        "missed": [o.case.id for o in attacks if not o.flagged],
        "false_alarms": [o.case.id for o in outcomes if o.case.label == "benign" and o.flagged],
    }


def _print(name: str, mode: str, result: dict) -> None:
    print(f"\n== {name} ({mode}) ==")
    for threshold in ("flagged", "danger"):
        s = result[threshold]
        print(f"  {threshold:8} n={s['n']:3}  P={s['precision']:5}  R={s['recall']:5}  F1={s['f1']:5}  FPR={s['fpr']:5}"
              f"  (tp {s['tp']} fp {s['fp']} fn {s['fn']} tn {s['tn']})")
    print(f"  recall by language   {result['recall_by_language']}")
    print(f"  false alarms by lang {result['fpr_by_language']}")
    print(f"  recall by threat     {result['recall_by_threat']}")
    print(f"  expected threat named in {result['family_match']}% of flagged attacks")
    print(f"  missed attacks: {result['missed'] or 'none'}")
    print(f"  false alarms:   {result['false_alarms'] or 'none'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--set", choices=["tuning", "heldout", "both"], default="both")
    parser.add_argument("--ai", action="store_true", help="include the live AI layer (needs GEMINI_API_KEY)")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args()

    if file_sha256(SETS["heldout"]) != HELDOUT_SHA256:
        print("cases_heldout.jsonl changed since it was frozen: its numbers are no longer held out.", file=sys.stderr)
        return 2
    if args.ai and not os.environ.get("GEMINI_API_KEY"):
        print("--ai needs GEMINI_API_KEY in the environment.", file=sys.stderr)
        return 2

    mode, runner = ("rules+ai", run_ai) if args.ai else ("rules only", run_rules)
    names = ["tuning", "heldout"] if args.set == "both" else [args.set]
    results = {name: report([runner(case) for case in load(name)]) for name in names}
    if args.json:
        print(json.dumps({"mode": mode, **results}, ensure_ascii=False, indent=2))
    else:
        for name in names:
            _print(name, mode, results[name])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
