"""Tests for the daily quota (services/quota.py). Offline, no Streamlit.

    venv\\Scripts\\python.exe tests\\test_quota.py
"""

import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.quota import (  # noqa: E402
    DEFAULT_LIMITS,
    DailyQuota,
    MemoryQuotaStore,
    identity_key,
    limit_for,
    next_reset,
)

DAY1 = datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc)
DAY2 = datetime(2026, 11, 17, 0, 0, 1, tzinfo=timezone.utc)


def _with_env(name, value, fn):
    old = os.environ.get(name)
    os.environ[name] = value
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old


def test_defaults_and_env_overrides() -> None:
    assert limit_for("guest") == DEFAULT_LIMITS["guest"]
    assert _with_env("TUMAR_DAILY_LIMIT_GUEST", "5", lambda: limit_for("guest")) == 5
    assert _with_env("TUMAR_DAILY_LIMIT_GUEST", "zero", lambda: limit_for("guest")) == DEFAULT_LIMITS["guest"]
    assert _with_env("TUMAR_DAILY_LIMIT_GUEST", "-3", lambda: limit_for("guest")) == DEFAULT_LIMITS["guest"]
    print("test_defaults_and_env_overrides PASSED")


def test_limit_is_enforced_per_identity_and_resets_daily() -> None:
    def run():
        quota = DailyQuota()
        results = [quota.consume("ip:1.2.3.4", "guest", "message", now=DAY1).allowed for _ in range(4)]
        assert results == [True, True, True, False], results
        assert quota.consume("ip:5.6.7.8", "guest", "url", now=DAY1).allowed  # someone else
        blocked = quota.consume("ip:1.2.3.4", "guest", "url", now=DAY1)
        assert not blocked.allowed and blocked.remaining == 0 and blocked.limit == 3
        assert quota.consume("ip:1.2.3.4", "guest", "message", now=DAY2).allowed  # new UTC day
    _with_env("TUMAR_DAILY_LIMIT_GUEST", "3", run)
    print("test_limit_is_enforced_per_identity_and_resets_daily PASSED")


def test_tiers_are_counted_separately() -> None:
    def run():
        quota = DailyQuota()
        assert quota.consume("same", "guest", now=DAY1).allowed
        assert not quota.consume("same", "guest", now=DAY1).allowed
        assert quota.consume("same", "user", now=DAY1).allowed
    _with_env("TUMAR_DAILY_LIMIT_GUEST", "1", run)
    print("test_tiers_are_counted_separately PASSED")


def test_password_checks_and_zero_limit_are_never_blocked() -> None:
    def run():
        quota = DailyQuota()
        for _ in range(5):
            assert quota.consume("x", "guest", "password", now=DAY1).allowed
        assert quota.consume("x", "guest", "message", now=DAY1).allowed
        assert not quota.consume("x", "guest", "message", now=DAY1).allowed
    _with_env("TUMAR_DAILY_LIMIT_GUEST", "1", run)

    def unlimited():
        quota = DailyQuota()
        assert all(quota.consume("y", "bot", "image", now=DAY1).allowed for _ in range(500))
    _with_env("TUMAR_DAILY_LIMIT_BOT", "0", unlimited)
    print("test_password_checks_and_zero_limit_are_never_blocked PASSED")


def test_identities_are_hashed_not_stored_raw() -> None:
    store = MemoryQuotaStore()
    quota = DailyQuota(store)
    quota.consume("user:alice@example.com", "user", now=DAY1)
    keys = list(store._counts)
    assert keys and all("alice" not in k and "@" not in k for k in keys), keys
    assert identity_key("A@B.c ") == identity_key("a@b.c")
    print("test_identities_are_hashed_not_stored_raw PASSED")


def test_concurrent_use_never_exceeds_the_limit() -> None:
    def run():
        quota = DailyQuota()
        allowed = []
        lock = threading.Lock()

        def worker():
            for _ in range(50):
                ok = quota.consume("shared", "bot", "message", now=DAY1).allowed
                with lock:
                    allowed.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert sum(allowed) == 25, sum(allowed)
    _with_env("TUMAR_DAILY_LIMIT_BOT", "25", run)
    print("test_concurrent_use_never_exceeds_the_limit PASSED")


def test_next_reset_is_utc_midnight() -> None:
    assert next_reset(DAY1) == datetime(2026, 11, 17, tzinfo=timezone.utc)
    print("test_next_reset_is_utc_midnight PASSED")


if __name__ == "__main__":
    test_defaults_and_env_overrides()
    test_limit_is_enforced_per_identity_and_resets_daily()
    test_tiers_are_counted_separately()
    test_password_checks_and_zero_limit_are_never_blocked()
    test_identities_are_hashed_not_stored_raw()
    test_concurrent_use_never_exceeds_the_limit()
    test_next_reset_is_utc_midnight()
    print("All quota tests passed.")
