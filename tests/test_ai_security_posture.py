"""Static permission review for agents, tools and connectors.

Only the declared text is read: nothing is connected to or executed.

    venv\\Scripts\\python.exe tests\\test_ai_security_posture.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

from services.ai_security import posture  # noqa: E402
from services.ai_security.detector import detect  # noqa: E402


def _codes(text: str, task: str = "") -> dict[str, bool]:
    return {f.code: f.strong for f in posture.review(text, task)}


def test_high_risk_powers_are_named() -> None:
    manifest = '{"scopes": ["shell", "filesystem:*", "payments", "send_email", "secrets:read", "admin", "delete"]}'
    found = _codes(manifest)
    for scope in ("shell", "payments", "messaging", "secrets", "admin", "delete"):
        assert f"ais_perm_{scope}" in found, (scope, found)
    assert not any(found.values())  # declaring powers alone is weak: the task may need them
    print("test_high_risk_powers_are_named PASSED")


def test_no_approval_is_strong_only_with_a_high_risk_power() -> None:
    assert _codes('{"scopes": ["payments"], "auto_approve": true}')["ais_perm_no_approval"] is True
    assert _codes('{"scopes": ["send_email"], "require_approval": false}')["ais_perm_no_approval"] is True
    assert _codes('{"scopes": ["weather.read"], "auto_approve": true}')["ais_perm_no_approval"] is False
    assert detect('{"scopes": ["payments"], "auto_approve": true}', "tool").verdict == "danger"
    print("test_no_approval_is_strong_only_with_a_high_risk_power PASSED")


def test_powers_beyond_the_stated_task() -> None:
    manifest = '{"scopes": ["gmail.read", "send_email", "payments", "delete"]}'
    summarise = _codes(manifest, "Summarise my inbox every morning")
    assert "ais_perm_beyond_task" in summarise  # summarising needs none of send, pay or delete
    beyond = next(f for f in posture.review(manifest, "Summarise my inbox") if f.code == "ais_perm_beyond_task")
    assert set(beyond.excerpts) == {"payments", "send_email", "delete"}, beyond.excerpts
    replies = next(f for f in posture.review(manifest, "Reply to customer emails") if f.code == "ais_perm_beyond_task")
    assert set(replies.excerpts) == {"payments", "delete"}, replies.excerpts  # replying does need to send
    assert "ais_perm_beyond_task" not in _codes('{"scopes": ["payments"]}', "Pay supplier invoices on time")
    assert "ais_perm_beyond_task" not in _codes(manifest)  # no task given, no comparison
    # Russian and Kazakh tasks are understood too.
    assert "ais_perm_beyond_task" not in _codes('{"scopes": ["payments"]}', "Оплачивать счета поставщиков")
    assert "ais_perm_beyond_task" not in _codes('{"scopes": ["payments"]}', "Жеткізушілердің шоттарын төлеу")
    print("test_powers_beyond_the_stated_task PASSED")


def test_descriptions_in_russian_and_kazakh() -> None:
    assert _codes("Агент может выполнять платежи без подтверждения.")["ais_perm_no_approval"] is True
    assert "ais_perm_payments" in _codes("Агент төлем жасай алады және файлдарды жою құқығы бар.")
    print("test_descriptions_in_russian_and_kazakh PASSED")


def test_a_read_only_tool_is_clean() -> None:
    tool = '{"name": "weather", "description": "Returns the forecast for a city.", "scopes": ["weather.read"]}'
    assert posture.review(tool, "Tell me the weather") == []
    assert detect(tool, "tool", "Tell me the weather").verdict == "safe"
    print("test_a_read_only_tool_is_clean PASSED")


def test_permission_review_runs_only_for_tools() -> None:
    email = "Our finance team handles payments and will delete old records next week."
    assert detect(email, "document").verdict == "safe"
    print("test_permission_review_runs_only_for_tools PASSED")


if __name__ == "__main__":
    test_high_risk_powers_are_named()
    test_no_approval_is_strong_only_with_a_high_risk_power()
    test_powers_beyond_the_stated_task()
    test_descriptions_in_russian_and_kazakh()
    test_a_read_only_tool_is_clean()
    test_permission_review_runs_only_for_tools()
    print("All permission review tests passed.")
