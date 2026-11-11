"""Bot worker reliability: scheduler, startup, errors, one instance, logs, delivery.

No network: the Telegram API is never called.

    venv\\Scripts\\python.exe tests\\test_bot_runtime.py
"""

import asyncio
import logging
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

from aiogram.exceptions import TelegramForbiddenError, TelegramRetryAfter  # noqa: E402

from i18n import translate  # noqa: E402
from telegram_bot import main as bot_main  # noqa: E402
from telegram_bot.handlers import community  # noqa: E402
from telegram_bot.runtime import AlreadyRunning, SecretFilter, SingleInstanceLock, redact  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def test_scheduler_is_almaty_time_with_one_job() -> None:
    async def scenario():
        scheduler = bot_main.build_scheduler(MagicMock())
        # Scheduling again under the same id replaces, never duplicates.
        scheduler.add_job(community.send_daily_broadcast, "cron", hour=9, id=bot_main.DAILY_JOB_ID,
                          replace_existing=True, args=[MagicMock()])
        scheduler.start(paused=True)
        try:
            jobs = scheduler.get_jobs()
            assert str(scheduler.timezone) == "Asia/Almaty", scheduler.timezone
            assert [job.id for job in jobs] == [bot_main.DAILY_JOB_ID], jobs
            first = bot_main.build_scheduler(MagicMock()).get_job(bot_main.DAILY_JOB_ID)
            assert first.max_instances == 1 and first.coalesce is True
            assert str(first.trigger.timezone) == "Asia/Almaty"
            assert "hour='9'" in str(first.trigger) and "minute='0'" in str(first.trigger)
        finally:
            scheduler.shutdown(wait=False)

    _run(scenario())
    print("test_scheduler_is_almaty_time_with_one_job PASSED")


def test_startup_keeps_pending_updates() -> None:
    source = (ROOT / "telegram_bot" / "main.py").read_text(encoding="utf-8")
    assert "drop_pending_updates=True" not in source
    assert "drop_pending_updates=False" in source
    print("test_startup_keeps_pending_updates PASSED")


def test_missing_token_stops_cleanly() -> None:
    saved = os.environ.pop("BOT_TOKEN", None)
    try:
        try:
            _run(bot_main.run())
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("expected SystemExit")
    finally:
        if saved is not None:
            os.environ["BOT_TOKEN"] = saved
    print("test_missing_token_stops_cleanly PASSED")


def test_dispatcher_has_routers_and_error_handler() -> None:
    dp = bot_main.build_dispatcher()
    names = [router.name for router in dp.sub_routers]
    assert names == ["commands_router", "screenshot_router", "community_router"], names
    assert dp.errors.handlers, "no error handler registered"
    print("test_dispatcher_has_routers_and_error_handler PASSED")


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []
        self.addFilter(SecretFilter())

    def emit(self, record):
        self.lines.append(self.format(record))


def test_handler_errors_are_logged_without_content() -> None:
    capture = _Capture()
    logging.getLogger("tumar.bot").addHandler(capture)
    try:
        update = SimpleNamespace(update_id=42, message=SimpleNamespace(text="my card 4400 1234"), callback_query=None)
        event = SimpleNamespace(update=update, exception=ValueError("boom"))
        assert _run(bot_main.on_handler_error(event)) is True
    finally:
        logging.getLogger("tumar.bot").removeHandler(capture)
    log = "\n".join(capture.lines)
    assert "update_id=42" in log and "type=message" in log and "ValueError" in log, log
    assert "4400" not in log and "my card" not in log
    print("test_handler_errors_are_logged_without_content PASSED")


def test_secrets_are_masked_in_logs() -> None:
    token = "1234567890:" + "A" * 35
    assert token not in redact(f"GET https://api.telegram.org/bot{token}/getMe")
    assert "AIza" not in redact("key=AIza" + "b" * 35)
    capture = _Capture()
    logger = logging.getLogger("tumar.test.secrets")
    logger.addHandler(capture)
    logger.propagate = False
    logger.warning("token is %s", token)
    logger.removeHandler(capture)
    assert token not in capture.lines[0] and "[redacted]" in capture.lines[0], capture.lines
    print("test_secrets_are_masked_in_logs PASSED")


def test_second_instance_is_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        first = SingleInstanceLock(directory=tmp)
        first.acquire()
        try:
            try:
                SingleInstanceLock(directory=tmp).acquire()
            except AlreadyRunning:
                pass
            else:
                raise AssertionError("a second worker got the lock")
        finally:
            first.release()
        again = SingleInstanceLock(directory=tmp)  # released: a restart works
        again.acquire()
        again.release()
    print("test_second_instance_is_refused PASSED")


def test_daily_tip_is_labelled_and_rotates() -> None:
    monday = community.daily_tip_text("en", datetime(2026, 11, 9, tzinfo=community.TIMEZONE))
    tuesday = community.daily_tip_text("en", datetime(2026, 11, 10, tzinfo=community.TIMEZONE))
    assert monday != tuesday  # no tip on two consecutive days
    assert "not a news alert" in monday and translate("bot.daily.header", "en") in monday
    assert "Zero-Day" not in monday  # the legacy fake "news" is gone
    kk = community.daily_tip_text("kk", datetime(2026, 11, 9, tzinfo=community.TIMEZONE))
    assert translate("bot.daily.footer", "kk") in kk
    print("test_daily_tip_is_labelled_and_rotates PASSED")


def test_delivery_outcomes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        saved = community._registry
        community._registry = community.TargetRegistry(Path(tmp) / "b.db")
        try:
            for chat in (-1, -2, -3, -4):
                community._registry.add(chat, "g", "group")
            method = MagicMock()
            outcomes = {
                -1: [None],  # delivered
                -2: [TelegramForbiddenError(method=method, message="bot was kicked")],
                -3: [TelegramRetryAfter(method=method, message="flood", retry_after=0), None],  # retried once
                -4: [RuntimeError("network")],
            }

            async def send_message(chat_id, text, parse_mode):
                outcome = outcomes[chat_id].pop(0)
                if isinstance(outcome, Exception):
                    raise outcome

            bot = SimpleNamespace(send_message=AsyncMock(side_effect=send_message))
            result = _run(community._send_to_all(bot, "hi", {-1, -2, -3, -4}, kind="daily"))
            assert (result.sent, result.failed, result.removed) == (2, 1, 1), result
            assert community._registry.get_all() == {-1, -3, -4}  # the kicked chat is gone
        finally:
            community._registry.conn.close()
            community._registry = saved
    print("test_delivery_outcomes PASSED")


def test_registry_path_is_configurable() -> None:
    source = (ROOT / "telegram_bot" / "handlers" / "community.py").read_text(encoding="utf-8")
    assert 'os.getenv("TUMAR_BROADCAST_DB"' in source
    print("test_registry_path_is_configurable PASSED")


if __name__ == "__main__":
    test_scheduler_is_almaty_time_with_one_job()
    test_startup_keeps_pending_updates()
    test_missing_token_stops_cleanly()
    test_dispatcher_has_routers_and_error_handler()
    test_handler_errors_are_logged_without_content()
    test_secrets_are_masked_in_logs()
    test_second_instance_is_refused()
    test_daily_tip_is_labelled_and_rotates()
    test_delivery_outcomes()
    test_registry_path_is_configurable()
    print("All bot runtime tests passed.")
