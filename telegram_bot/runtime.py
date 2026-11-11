"""Process-level safety for the bot worker: one poller per host, no secrets in logs.

Telegram allows exactly one getUpdates long-poll per bot token. A second
copy (a forgotten local run, a double deploy) makes the two fight:
each request ends the other's with "409 Conflict", updates are split
between them or dropped, and replies arrive twice or not at all.

- SingleInstanceLock stops a second copy on the same host before it
  polls. Copies on different hosts cannot see each other's lock; the
  deployment guide (docs/TELEGRAM_BOT.md) covers that, and aiogram logs
  the 409 Conflict loudly if it ever happens.
- SecretFilter masks anything shaped like a bot token or an API key in
  every log record, whichever library wrote it.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from pathlib import Path

# 123456789:AA... (Telegram) and AIza... (Google API keys). No leading
# \b: in API URLs the token directly follows "bot" (/bot123456:AA...).
_SECRET_PATTERNS = (
    re.compile(r"(?<!\d)\d{6,12}:[A-Za-z0-9_-]{30,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
)


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


class SecretFilter(logging.Filter):
    """Rewrites a record's message with secrets masked. Never drops a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        cleaned = redact(message)
        if cleaned != message:
            record.msg, record.args = cleaned, None
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """Plain, timestamped logs on stdout with secrets masked everywhere."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    secret_filter = SecretFilter()
    for handler in logging.getLogger().handlers:
        handler.addFilter(secret_filter)
    # HTTP client chatter adds nothing operationally and logs request URLs.
    for noisy in ("httpx", "httpcore", "aiohttp.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class AlreadyRunning(RuntimeError):
    """Another bot worker holds the lock on this host."""


class SingleInstanceLock:
    """An OS-level exclusive lock on a file; released when the process exits.

    The OS drops the lock if the process dies, so a crash never leaves a
    stale lock behind (unlike a PID file).
    """

    def __init__(self, name: str = "tumar-telegram-bot.lock", directory: str | None = None):
        base = directory or os.getenv("TUMAR_LOCK_DIR") or tempfile.gettempdir()
        self.path = Path(base) / name
        self._handle = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+")
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise AlreadyRunning(str(self.path)) from exc
        self._handle = handle

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "SingleInstanceLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
