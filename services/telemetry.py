"""Structured, content-free telemetry for every channel.

One JSON line per event on stderr, which Streamlit Cloud and any bot
host already collect. Three events cover the questions operations
needs answered:

    analysis       one Trust Engine check: kind, channel, outcome
                   (ok / offline / error), error code, duration
    provider_call  one attempt at an AI model: provider, model, HTTP
                   status, error code, duration, tokens, approx. cost
    quota          one allowance decision: allowed / denied / refund

Every event in one check shares a `request_id`, so a slow or failed
check can be followed from the quota gate to the model call.

Privacy is enforced here, not left to callers' discipline:
- only field names in _FIELDS are written; anything else is dropped;
- string values must look like identifiers (letters, digits, `._:-`,
  at most 64 characters). Messages, URLs, e-mail addresses and
  passwords contain spaces, slashes or `@`, so they cannot pass even
  if someone passes one by mistake. They are replaced by "redacted".
- identities (user ids, IPs, sessions) have no field at all.

Cost is approximate and only reported when prices are configured in
TUMAR_MODEL_PRICES, as JSON of USD per million tokens:

    {"gemini-3.5-flash": {"input": 0.3, "output": 2.5}}

No prices are built in: a wrong default would be a made-up number.
Token counts are always logged, so cost can be computed afterwards.

Set TUMAR_TELEMETRY=off to silence it (tests do).
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

LOGGER_NAME = "tumar.telemetry"

# The only fields an event may carry.
_FIELDS = frozenset(
    {
        "request_id",
        "channel",
        "kind",
        "outcome",
        "error_code",
        "mode",
        "verdict",
        "risk_level",
        "duration_ms",
        "provider",
        "model",
        "attempt",
        "http_status",
        "input_tokens",
        "output_tokens",
        "cost_usd",
        "tier",
        "action",
        "limit",
    }
)
_SAFE_STRING = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
REDACTED = "redacted"

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "tumar_request_id", default=None
)

_logger = logging.getLogger(LOGGER_NAME)


def _configure_logger() -> None:
    """Attach our own JSON handler once; never touch the root logger."""
    if getattr(_logger, "_tumar_configured", False):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False  # the bot's basicConfig would print it twice
    _logger._tumar_configured = True  # type: ignore[attr-defined]


def enabled() -> bool:
    return os.environ.get("TUMAR_TELEMETRY", "on").strip().lower() not in {"off", "0", "false"}


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def current_request_id() -> str | None:
    return _request_id.get()


def begin_request(request_id: str | None = None) -> str:
    """Start a new request id for everything that follows in this context.

    For entry points that cannot wrap the whole check in a `with`
    block: the web quota gate (each Streamlit check starts there), the
    bot's quota gate, the REST API middleware (which already has an
    id). asyncio tasks and Streamlit script threads keep their own
    context, so ids do not leak between users.
    """
    request_id = request_id or new_request_id()
    _request_id.set(request_id)
    return request_id


@contextmanager
def request_scope() -> Iterator[str]:
    """Give every event inside the block one request id.

    Nested scopes reuse the outer id, so the web page's quota gate and
    the engine call it wraps end up in the same request.
    """
    existing = _request_id.get()
    if existing:
        yield existing
        return
    token = _request_id.set(new_request_id())
    try:
        yield _request_id.get() or ""
    finally:
        _request_id.reset(token)


def _clean(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, str) and _SAFE_STRING.match(value):
        return value
    return REDACTED


def sanitize(fields: dict[str, object]) -> dict[str, object]:
    """Keep allow-listed fields with identifier-like or numeric values."""
    return {name: _clean(value) for name, value in fields.items() if name in _FIELDS}


def emit(event: str, **fields: object) -> dict[str, object]:
    """Write one event and feed the in-memory metrics. Returns the record."""
    record: dict[str, object] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event if _SAFE_STRING.match(event) else REDACTED,
    }
    fields.setdefault("request_id", _request_id.get())
    record.update(sanitize(fields))
    metrics.observe(record)
    if enabled():
        _configure_logger()
        _logger.info(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
    return record


class Timer:
    """Milliseconds since construction, for duration_ms fields."""

    def __init__(self) -> None:
        self._start = time.perf_counter()

    @property
    def ms(self) -> int:
        return int((time.perf_counter() - self._start) * 1000)


# --------------------------------------------------------------- cost


def _prices() -> dict[str, dict[str, float]]:
    raw = os.environ.get("TUMAR_MODEL_PRICES", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def approximate_cost(model: str, input_tokens: int | None, output_tokens: int | None) -> float | None:
    """USD for one call, or None when the model's price is not configured."""
    price = _prices().get(model)
    if not isinstance(price, dict) or input_tokens is None:
        return None
    try:
        per_in = float(price.get("input", 0))
        per_out = float(price.get("output", 0))
    except (TypeError, ValueError):
        return None
    return (input_tokens * per_in + (output_tokens or 0) * per_out) / 1_000_000


# ------------------------------------------------------------ metrics


class Metrics:
    """Per-process counters and recent latencies, for a health summary.

    Bounded: the last `window` durations per (event, kind), so memory
    stays flat however long the process runs. Resets on restart, like
    the quota counters; durable history is a persistence decision.
    """

    def __init__(self, window: int = 1000) -> None:
        self._lock = threading.Lock()
        self._window = window
        self._counts: dict[str, int] = defaultdict(int)
        self._durations: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=self._window))
        self._tokens: dict[str, int] = defaultdict(int)
        self._cost = 0.0

    def observe(self, record: dict[str, object]) -> None:
        event = str(record.get("event"))
        label = event
        if record.get("kind") or record.get("provider"):
            label = f"{event}:{record.get('kind') or record.get('provider')}"
        outcome = record.get("outcome") or record.get("action") or "seen"
        with self._lock:
            self._counts[f"{label}:{outcome}"] += 1
            duration = record.get("duration_ms")
            if isinstance(duration, int):
                self._durations[label].append(duration)
            for name in ("input_tokens", "output_tokens"):
                value = record.get(name)
                if isinstance(value, int):
                    self._tokens[name] += value
            cost = record.get("cost_usd")
            if isinstance(cost, float):
                self._cost += cost

    def summary(self) -> dict[str, object]:
        with self._lock:
            latency = {
                label: {
                    "count": len(values),
                    "p50_ms": _percentile(values, 50),
                    "p95_ms": _percentile(values, 95),
                }
                for label, values in self._durations.items()
            }
            return {
                "counts": dict(self._counts),
                "latency": latency,
                "tokens": dict(self._tokens),
                "approx_cost_usd": round(self._cost, 6),
            }

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
            self._durations.clear()
            self._tokens.clear()
            self._cost = 0.0


def _percentile(values: deque[int] | list[int], pct: int) -> int | None:
    """Nearest-rank percentile; None for no data (never a made-up 0)."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-pct * len(ordered) // 100))  # ceil(pct/100 * n)
    return ordered[rank - 1]


metrics = Metrics()
