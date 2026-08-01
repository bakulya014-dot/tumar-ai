"""Authentication and rate limiting for the REST API.

Both are pure logic with time and configuration passed in, so they can
be tested exhaustively without a server, a clock, or a network.
"""

import hashlib
import secrets
from collections import defaultdict


def verify_key(provided: str, configured: tuple[str, ...]) -> bool:
    """Check an API key in constant time.

    `secrets.compare_digest` rather than `==`: string comparison exits
    at the first differing byte, and the time it takes leaks how much
    of a guess was correct. That is a practical attack against a
    long-lived key, and avoiding it costs nothing.

    An empty configured set never matches, so an unconfigured
    deployment rejects everyone rather than accepting anyone.
    """
    if not provided or not configured:
        return False
    # Compare against every candidate — no early exit, so the answer
    # takes the same time regardless of which key matched.
    matched = False
    for candidate in configured:
        if secrets.compare_digest(provided, candidate):
            matched = True
    return matched


def key_fingerprint(key: str) -> str:
    """A short, stable, non-reversible label for logs.

    Logs need to attribute traffic to a caller. They must never
    contain the key itself, so they carry the first bytes of a hash
    instead — enough to group requests, useless to an attacker who
    reads the log.
    """
    if not key:
        return "anonymous"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


class RateLimiter:
    """Fixed-window request counter, per caller.

    Deliberately simple and in-process. That is honest for a single
    instance and is documented as such: running several replicas
    multiplies the effective limit, and a shared store (Redis) is the
    fix when that day comes. A simple limiter that works is worth more
    than a distributed one that is not needed yet.
    """

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self._windows: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))

    def check(self, caller: str, now: float) -> tuple[bool, int]:
        """Record a request. Returns (allowed, seconds until reset)."""
        window = int(now // self.window_seconds)
        current_window, count = self._windows[caller]

        if window != current_window:
            count = 0

        reset_in = int((window + 1) * self.window_seconds - now)
        if count >= self.limit:
            self._windows[caller] = (window, count)
            return False, max(reset_in, 1)

        self._windows[caller] = (window, count + 1)
        return True, max(reset_in, 1)

    def remaining(self, caller: str, now: float) -> int:
        """How many requests this caller has left in the window."""
        window = int(now // self.window_seconds)
        current_window, count = self._windows[caller]
        used = count if window == current_window else 0
        return max(0, self.limit - used)
