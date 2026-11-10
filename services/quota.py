"""Daily per-person quotas for checks that cost money.

Every check that can reach a paid service (an AI provider, a breach
database) counts against a daily allowance, so one visitor cannot run
up the AI bill for everyone. Password checks are local plus a free
k-anonymity lookup and are never counted.

Identities are hashed before they are stored: the counter needs to tell
callers apart, not to know who they are.

Storage is in-process today (one counter per running app or bot). That
is honest for one instance and resets on restart; the QuotaStore
interface is where a shared store (Redis) plugs in when the app runs on
several instances. Limits come from the environment:

    TUMAR_DAILY_LIMIT_GUEST   web visitors without an account (default 20)
    TUMAR_DAILY_LIMIT_USER    signed-in web users              (default 60)
    TUMAR_DAILY_LIMIT_BOT     Telegram users                   (default 30)

A limit of 0 switches that tier's quota off.
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

DEFAULT_LIMITS = {"guest": 20, "user": 60, "bot": 30}
_ENV = {
    "guest": "TUMAR_DAILY_LIMIT_GUEST",
    "user": "TUMAR_DAILY_LIMIT_USER",
    "bot": "TUMAR_DAILY_LIMIT_BOT",
}

# Check kinds that may call a paid or rate-limited service.
COUNTED_KINDS = frozenset({"message", "url", "image", "email"})


def limit_for(tier: str) -> int:
    """The daily allowance for a tier (0 = unlimited)."""
    default = DEFAULT_LIMITS.get(tier, DEFAULT_LIMITS["guest"])
    raw = os.environ.get(_ENV.get(tier, ""), "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def identity_key(raw: str) -> str:
    """A stable, non-reversible key for one caller."""
    return hashlib.sha256(raw.strip().lower().encode("utf-8")).hexdigest()[:32]


def _today(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%d")


def next_reset(now: datetime | None = None) -> datetime:
    """When today's allowance renews: the next 00:00 UTC."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    used: int  # checks counted today, including this one when allowed
    limit: int  # 0 = unlimited

    @property
    def remaining(self) -> int | None:
        return None if self.limit == 0 else max(self.limit - self.used, 0)


class QuotaStore(Protocol):
    def increment_if_below(self, key: str, day: str, limit: int) -> tuple[bool, int]:
        """Atomically add one use if below `limit`. Returns (added, count)."""


class MemoryQuotaStore:
    """Thread-safe in-process counters, pruned when the day changes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._day = ""
        self._counts: dict[str, int] = {}

    def increment_if_below(self, key: str, day: str, limit: int) -> tuple[bool, int]:
        with self._lock:
            if day != self._day:  # a new UTC day: yesterday's counts go
                self._day, self._counts = day, {}
            count = self._counts.get(key, 0)
            if limit and count >= limit:
                return False, count
            self._counts[key] = count + 1
            return True, count + 1


class DailyQuota:
    def __init__(self, store: QuotaStore | None = None) -> None:
        self.store = store or MemoryQuotaStore()

    def consume(
        self, identity: str, tier: str, kind: str = "message", now: datetime | None = None
    ) -> QuotaDecision:
        """Count one check for `identity` and say whether it may run.

        Kinds outside COUNTED_KINDS (passwords) always pass uncounted.
        """
        limit = limit_for(tier)
        if kind not in COUNTED_KINDS or limit == 0:
            return QuotaDecision(True, 0, limit)
        day = _today(now or datetime.now(timezone.utc))
        added, count = self.store.increment_if_below(identity_key(f"{tier}:{identity}"), day, limit)
        return QuotaDecision(added, count, limit)


_default: DailyQuota | None = None
_default_lock = threading.Lock()


def default_quota() -> DailyQuota:
    """The process-wide quota (shared by every session of the web app)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = DailyQuota()
        return _default
