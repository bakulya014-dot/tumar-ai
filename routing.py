"""Page routing helpers for app.py: crash guard and route logging.

Kept out of app.py so they can be tested without running the whole app.
"""

from __future__ import annotations

import logging
import traceback

import streamlit as st

from components import error_view
from i18n import t
from services import telemetry

_logger = logging.getLogger("tumar.app")


def run_page(page) -> None:
    """Run one page; turn an unexpected crash into a calm message.

    Streamlit's own stop/rerun signals derive from BaseException, so
    `except Exception` never swallows them. The log gets the error type
    and the code frames only (no exception message, which could quote
    what the user typed), and the visitor sees a translated notice
    instead of a Python traceback.
    """
    try:
        page.run()
    except Exception as exc:
        name = type(exc).__name__
        telemetry.emit("error", kind=str(getattr(page, "url_path", "") or "home"), error_code=name)
        _logger.error("Page crashed: %s\n%s", name, "".join(traceback.format_tb(exc.__traceback__)))
        error_view(t("errors.unexpected"))


def log_route(route: str, signed_in: bool, guest: bool) -> None:
    """One content-free 'route' event per change of page or access state."""
    key = (route, signed_in, guest)
    if st.session_state.get("_tumar_last_route") != key:
        st.session_state["_tumar_last_route"] = key
        telemetry.emit("route", route=route, signed_in=signed_in, guest=guest)
