"""Session-scoped store for Trust Reports (UI layer).

Streamlit re-runs a page script on every widget interaction. Anything
rendered inside `if button_clicked:` therefore disappears as soon as
the user touches anything else — including the language selector. This
store keeps the last report per module so results survive re-runs, and
keeps a bounded history that the upcoming Trust Timeline reads.

The state container is passed IN rather than reached for globally:
services and helpers in a security product must never hold user data
in module-level globals, where one visitor's analysis could surface in
another visitor's session. Pages pass `st.session_state`; tests pass a
plain dict.
"""

from collections.abc import MutableMapping
from typing import Any

from pydantic import BaseModel

from services.trust_report import TrustReport

# Where the history list lives inside the session state mapping.
HISTORY_KEY = "trust_history"

# Newest-first cap. Bounded on purpose: an unbounded list would grow
# with every check for the lifetime of the session.
MAX_HISTORY = 20


def remember(state: MutableMapping[str, Any], report: TrustReport) -> None:
    """Record a report as the newest entry in the session history."""
    history: list[TrustReport] = state.setdefault(HISTORY_KEY, [])
    history.insert(0, report)
    del history[MAX_HISTORY:]


def latest(
    state: MutableMapping[str, Any], source: str = ""
) -> TrustReport | None:
    """Most recent report, optionally restricted to one module.

    Pages call this on every re-run to re-render the last result the
    user asked for, instead of losing it.
    """
    for report in state.get(HISTORY_KEY, []):
        if not source or report.source == source:
            return report
    return None


def history(state: MutableMapping[str, Any]) -> list[TrustReport]:
    """All remembered reports, newest first."""
    return list(state.get(HISTORY_KEY, []))


def clear(state: MutableMapping[str, Any]) -> None:
    """Forget everything — the user's escape hatch for privacy."""
    state.pop(HISTORY_KEY, None)


class Summary(BaseModel):
    """Counts behind the dashboard tiles.

    Session-scoped by definition: nothing is stored between visits, so
    these numbers describe this session only. The dashboard says so
    rather than implying an all-time total it cannot honestly claim.
    """

    checks: int = 0
    threats: int = 0  # verdict "danger" — the ones that mattered
    average_trust: int = 0


def summarize(reports: list[TrustReport]) -> Summary:
    """Aggregate reports into dashboard figures.

    A pure function over a list, so the dashboard's numbers can be
    tested without Streamlit and reused later by the REST API.
    """
    if not reports:
        return Summary()
    scores = [report.trust_score for report in reports]
    return Summary(
        checks=len(reports),
        threats=sum(1 for report in reports if report.verdict == "danger"),
        average_trust=round(sum(scores) / len(scores)),
    )
