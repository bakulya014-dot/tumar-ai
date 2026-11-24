"""The AI Security Check evaluation: frozen held-out set, tuning baseline.

    venv\\Scripts\\python.exe tests\\test_ai_security_eval.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

from evals.ai_security import runner  # noqa: E402


def test_heldout_set_is_frozen() -> None:
    # Editing the held-out file after seeing results would make its numbers
    # meaningless. Start a new held-out file instead, and say so.
    assert runner.file_sha256(runner.SETS["heldout"]) == runner.HELDOUT_SHA256
    print("test_heldout_set_is_frozen PASSED")


def test_sets_are_balanced_and_separate() -> None:
    tuning, heldout = runner.load("tuning"), runner.load("heldout")
    assert not {c.text for c in tuning} & {c.text for c in heldout}  # no case appears in both
    for cases in (tuning, heldout):
        assert {c.lang for c in cases} == {"en", "ru", "kk"}
        assert {c.label for c in cases} == {"attack", "benign"}
        assert {c.threat for c in cases if c.label == "attack"} == set(runner.FAMILY)
        assert all(c.context in {"document", "prompt", "log", "memory", "tool"} for c in cases)
    print(f"test_sets_are_balanced_and_separate PASSED ({len(tuning)} tuning, {len(heldout)} held-out)")


def test_tuning_baseline_does_not_regress() -> None:
    # Floors on the TUNING set only: the held-out set is measured, never targeted.
    result = runner.report([runner.run_rules(case) for case in runner.load("tuning")])
    assert result["flagged"]["recall"] == 100.0, result["missed"]
    assert result["danger"]["fpr"] == 0.0, result["false_alarms"]
    assert result["family_match"] == 100.0
    print("test_tuning_baseline_does_not_regress PASSED")


def test_heldout_evaluation_runs() -> None:
    result = runner.report([runner.run_rules(case) for case in runner.load("heldout")])
    assert result["flagged"]["n"] == 62
    print(
        "test_heldout_evaluation_runs PASSED "
        f"(flagged P {result['flagged']['precision']} R {result['flagged']['recall']} FPR {result['flagged']['fpr']})"
    )


if __name__ == "__main__":
    test_heldout_set_is_frozen()
    test_sets_are_balanced_and_separate()
    test_tuning_baseline_does_not_regress()
    test_heldout_evaluation_runs()
    print("All AI security evaluation tests passed.")
