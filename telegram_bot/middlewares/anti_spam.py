"""In-memory anti-spam and rate-limiting middleware for aiogram.

Prevents bot abuse, flood attacks, and LLM quota exhaustion by enforcing
per-user cooldowns across incoming messages.
"""

from collections.abc import Awaitable, Callable
import logging
import time
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

logger = logging.getLogger(__name__)


class AntiSpamMiddleware(BaseMiddleware):
    """In-memory TTL rate-limiter middleware for aiogram.

    Enforces a cooldown window (default: 2.5 seconds) between commands per user.
    """

    def __init__(self, rate_limit_seconds: float = 2.5, cleanup_interval_seconds: float = 120.0):
        super().__init__()
        self.rate_limit_seconds = rate_limit_seconds
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self._user_timestamps: dict[int, float] = {}
        self._last_alert_timestamps: dict[int, float] = {}
        self._last_cleanup = time.monotonic()

    def _cleanup_expired(self, current_time: float) -> None:
        """Prune entries older than cleanup interval to prevent memory growth."""
        if current_time - self._last_cleanup < self.cleanup_interval_seconds:
            return

        cutoff = current_time - self.cleanup_interval_seconds
        expired_users = [
            user_id for user_id, ts in self._user_timestamps.items() if ts < cutoff
        ]
        for uid in expired_users:
            self._user_timestamps.pop(uid, None)
            self._last_alert_timestamps.pop(uid, None)

        self._last_cleanup = current_time

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        # Only rate-limit Message events with an identified sender
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)

        user_id = event.from_user.id
        now = time.monotonic()

        self._cleanup_expired(now)

        last_time = self._user_timestamps.get(user_id)
        if last_time is not None:
            elapsed = now - last_time
            if elapsed < self.rate_limit_seconds:
                remaining = max(0.1, round(self.rate_limit_seconds - elapsed, 1))
                logger.info(
                    "Rate limit hit for user %d (elapsed: %.2fs, limit: %.2fs)",
                    user_id,
                    elapsed,
                    self.rate_limit_seconds,
                )

                # Send at most one throttling reminder every 2 seconds to avoid message flood
                last_alert = self._last_alert_timestamps.get(user_id, 0.0)
                if now - last_alert > 2.0:
                    self._last_alert_timestamps[user_id] = now
                    try:
                        await event.answer(
                            f"⏳ <b>Slow down:</b> Please wait <b>{remaining}s</b> before sending "
                            "another request.",
                            parse_mode="HTML",
                        )
                    except Exception as err:
                        logger.warning("Failed to send rate-limit notice: %s", err)

                # Throttle: halt further execution of the handler chain
                return None

        # Update last request time and allow execution
        self._user_timestamps[user_id] = now
        return await handler(event, data)
