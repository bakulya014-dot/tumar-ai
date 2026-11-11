"""Tumar.AI Telegram bot (router-based entry point).

Run from the project root:
    python -m telegram_bot.main

Run it as ONE long-running worker, separate from the Streamlit website:
Telegram allows a single long-poll per bot token, so two copies split or
drop updates. See docs/TELEGRAM_BOT.md for environment variables,
deployment and the operational checks.

BOT_TOKEN is read from the environment (or a .env file). It must never
be written into source or logs: anyone holding it controls the bot.
"""

import asyncio
import logging
import os
import sys

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramUnauthorizedError
from aiogram.types import ErrorEvent
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv

from telegram_bot.handlers import (
    commands_router,
    community_router,
    screenshot_router,
    send_daily_broadcast,
)
from telegram_bot.handlers.community import TIMEZONE
from telegram_bot.middlewares.anti_spam import AntiSpamMiddleware
from telegram_bot.runtime import AlreadyRunning, SingleInstanceLock, configure_logging

load_dotenv(override=False)  # a variable already set in the shell wins

logger = logging.getLogger("tumar.bot")

DAILY_JOB_ID = "daily_dispatch"
DAILY_HOUR = 9  # 09:00 Asia/Almaty


def build_dispatcher() -> Dispatcher:
    dp = Dispatcher()
    # Outer scope, so a flood is stopped before any handler runs.
    dp.message.outer_middleware(AntiSpamMiddleware(rate_limit_seconds=1.25))
    # Community goes last: its private-chat text hint must only see
    # messages no command or screenshot handler took.
    dp.include_router(commands_router)
    dp.include_router(screenshot_router)
    dp.include_router(community_router)
    dp.errors.register(on_handler_error)
    return dp


async def on_handler_error(event: ErrorEvent) -> bool:
    """Log a handler failure without the user's content, and keep polling."""
    update = event.update
    kind = next(
        (name for name in ("message", "callback_query", "my_chat_member") if getattr(update, name, None)),
        "other",
    )
    logger.error(
        "Handler failed: update_id=%s type=%s error=%s",
        update.update_id, kind, type(event.exception).__name__,
        exc_info=event.exception,
    )
    return True  # handled: aiogram must not re-raise and stop the update


def build_scheduler(bot: Bot) -> AsyncIOScheduler:
    """The daily dispatch, scheduled once, in Kazakhstan time.

    An explicit time zone: the host's clock is usually UTC, which would
    send the "09:00" tip at 14:00 Almaty time.
    """
    scheduler = AsyncIOScheduler(timezone=TIMEZONE)
    scheduler.add_job(
        send_daily_broadcast,
        "cron",
        hour=DAILY_HOUR,
        minute=0,
        args=[bot],
        id=DAILY_JOB_ID,
        replace_existing=True,  # never two copies of the job
        max_instances=1,  # a slow run is not overlapped by the next
        coalesce=True,  # after downtime, send once, not once per missed day
        misfire_grace_time=3600,  # a restart at 09:20 still sends today's tip
    )
    return scheduler


async def run() -> None:
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        logger.error("BOT_TOKEN is not set. Export it or add it to .env, then restart.")
        raise SystemExit(1)

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = build_dispatcher()
    scheduler = build_scheduler(bot)
    try:
        me = await bot.get_me()  # fails fast on a revoked or mistyped token
        # Polling needs no webhook. Pending updates are kept: messages sent
        # while the bot was restarting are answered, not silently dropped.
        await bot.delete_webhook(drop_pending_updates=False)
        scheduler.start()
        job = scheduler.get_job(DAILY_JOB_ID)
        logger.info(
            "Bot started as @%s (id %s). Daily dispatch next run: %s",
            me.username, me.id, job.next_run_time.isoformat() if job else "not scheduled",
        )
        await dp.start_polling(bot, handle_signals=True)
    except TelegramUnauthorizedError:
        logger.error("Telegram rejected BOT_TOKEN (revoked or mistyped). Not starting.")
        raise SystemExit(1)
    finally:
        if scheduler.running:
            scheduler.shutdown(wait=False)
        await bot.session.close()
        logger.info("Bot stopped: polling ended, scheduler shut down, session closed.")


def main() -> None:
    configure_logging()
    try:
        with SingleInstanceLock():
            asyncio.run(run())
    except AlreadyRunning as exc:
        logger.error(
            "Another Tumar.AI bot worker is already running on this host (lock %s). "
            "Telegram allows one poller per token; not starting a second.", exc,
        )
        sys.exit(2)
    except KeyboardInterrupt:
        logger.info("Interrupted.")


if __name__ == "__main__":
    main()
