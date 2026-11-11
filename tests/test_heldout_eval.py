"""The held-out evaluation framework (evals/heldout_runner.py).

Tests the arithmetic, the data rules and the separation from tuning.
It deliberately asserts no accuracy figure: pinning one would turn the
held-out set into a tuning target.

    venv\\Scripts\\python.exe tests\\test_heldout_eval.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evals import heldout_runner as runner  # noqa: E402


def test_metric_arithmetic() -> None:
    # 3 TP, 1 FP, 1 FN, 5 TN
    pairs = [(True, True)] * 3 + [(False, True)] + [(True, False)] + [(False, False)] * 5
    m = runner.metrics(pairs)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (3, 1, 1, 5)
    assert m["precision"] == 0.75 and m["recall"] == 0.75 and m["f1"] == 0.75
    assert m["false_positive_rate"] == round(1 / 6, 3)
    print("test_metric_arithmetic PASSED")


def test_undefined_ratios_are_none_not_zero() -> None:
    only_legit = runner.metrics([(False, False), (False, False)])
    assert only_legit["precision"] is None and only_legit["recall"] is None and only_legit["f1"] is None
    assert only_legit["false_positive_rate"] == 0.0
    missed_all = runner.metrics([(True, False)])
    assert missed_all["recall"] == 0.0 and missed_all["precision"] is None
    assert runner.metrics([])["n"] == 0
    print("test_undefined_ratios_are_none_not_zero PASSED")


def test_schema_rejects_bad_cases() -> None:
    good = {"id": "x", "source": "team_authored", "language": "ru", "input_type": "message",
            "attack_type": "otp_harvesting", "label": "scam", "text": "t"}
    runner.validate(good, "ok")
    bad_variants = [
        {**good, "source": "found_online"},  # unknown provenance
        {**good, "label": "malicious"},  # URL label on a message
        {**good, "attack_type": "none"},  # a scam with no attack type
        {**good, "label": "legitimate"},  # legitimate but with an attack type
        {key: value for key, value in good.items() if key != "text"},
        {**good, "language": "de"},
    ]
    for variant in bad_variants:
        try:
            runner.validate(variant, "bad")
        except runner.SchemaError:
            continue
        raise AssertionError(f"accepted {variant}")
    print("test_schema_rejects_bad_cases PASSED")


def test_shipped_cases_are_valid_and_separate_from_tuning() -> None:
    cases = runner.load_cases()
    assert len(cases) >= 40
    assert {case.input_type for case in cases} == {"message", "url"}
    assert {case.language for case in cases if case.input_type == "message"} == {"kk", "ru", "en"}
    assert runner.overlapping_with_tuning(cases) == []
    # The team set must not pretend to be independent.
    for path in runner.HELDOUT_DIR.glob("*team*.jsonl"):
        sources = {json.loads(line)["source"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
        assert sources == {"team_authored"}, (path.name, sources)
    print("test_shipped_cases_are_valid_and_separate_from_tuning PASSED")


def test_tiers_are_reported_separately() -> None:
    results = runner.evaluate(runner.load_cases())
    assert set(results["tiers"]) == {"team_heldout", "independent"}
    team = results["tiers"]["team_heldout"]
    assert set(team["decisions"]) == {"product_offline_verdict", "rule_layer_signal"}
    overall = team["decisions"]["product_offline_verdict"]["overall"]
    assert overall["n"] == team["cases"]
    for section in ("by_language", "by_input_type", "by_attack_type"):
        groups = team["decisions"]["product_offline_verdict"][section]
        assert sum(m["n"] for m in groups.values()) == team["cases"], section
    print("test_tiers_are_reported_separately PASSED")


def test_tuning_runner_does_not_read_heldout() -> None:
    source = (ROOT / "evals" / "runner.py").read_text(encoding="utf-8")
    assert "heldout" not in source
    print("test_tuning_runner_does_not_read_heldout PASSED")


def test_runner_exits_cleanly() -> None:
    assert runner.main(["--json"]) == 0
    print("test_runner_exits_cleanly PASSED")


if __name__ == "__main__":
    test_metric_arithmetic()
    test_undefined_ratios_are_none_not_zero()
    test_schema_rejects_bad_cases()
    test_shipped_cases_are_valid_and_separate_from_tuning()
    test_tiers_are_reported_separately()
    test_tuning_runner_does_not_read_heldout()
    test_runner_exits_cleanly()
    print("All held-out evaluation tests passed.")
