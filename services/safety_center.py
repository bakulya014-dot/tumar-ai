"""My Safety Center: what this session's checks add up to.

Pure functions over the session's TrustReports, so the page stays thin
and the numbers are testable. Tumar.AI keeps no check history between
visits (nothing is written to disk), so everything here describes the
current session only, and the page says so.

Definitions, stated so they can be explained on stage:
- safety score: the average trust score Tumar.AI gave the things you
  checked this session (100 = fully trustworthy). It is the same figure
  as "average trust" on the Home page.
- status: "act" if anything you checked was dangerous, "watch" if
  something needed caution, "calm" otherwise.
- top actions: the most relevant recommended actions from your
  dangerous checks first, then cautionary ones, without repeats.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from services.trust_report import TrustReport

DEFAULT_ACTION_KEYS = (
    "center.default_action_1",
    "center.default_action_2",
    "center.default_action_3",
)


@dataclass(frozen=True)
class Snapshot:
    checks: int = 0
    dangerous: int = 0
    cautious: int = 0
    safety_score: int | None = None  # None with no checks: never a made-up 100
    status: str = "empty"  # empty | calm | watch | act
    trend: list[int] = field(default_factory=list)  # trust scores, oldest first


def snapshot(reports: list[TrustReport]) -> Snapshot:
    """reports: newest first, as report_store.history() returns them."""
    if not reports:
        return Snapshot()
    dangerous = sum(1 for r in reports if r.verdict == "danger")
    cautious = sum(1 for r in reports if r.verdict == "caution")
    scores = [r.trust_score for r in reports]
    status = "act" if dangerous else "watch" if cautious else "calm"
    return Snapshot(
        checks=len(reports),
        dangerous=dangerous,
        cautious=cautious,
        safety_score=round(sum(scores) / len(scores)),
        status=status,
        trend=list(reversed(scores)),
    )


def dangerous_findings(reports: list[TrustReport]) -> list[TrustReport]:
    return [r for r in reports if r.verdict == "danger"]


def top_actions(
    reports: list[TrustReport], translate: Callable[[str], str], limit: int = 3
) -> list[str]:
    """Up to `limit` distinct actions: dangerous checks first, then cautious.

    Falls back to general advice when no check produced actions (for
    example, everything looked safe), so the list is never empty.
    """
    ordered = [r for r in reports if r.verdict == "danger"] + [
        r for r in reports if r.verdict == "caution"
    ]
    actions: list[str] = []
    for report in ordered:
        texts = report.recommended_actions or [translate(k) for k in report.recommended_action_keys]
        for text in texts:
            text = text.strip()
            if text and text not in actions:
                actions.append(text)
            if len(actions) == limit:
                return actions
    for key in DEFAULT_ACTION_KEYS:
        if len(actions) == limit:
            break
        text = translate(key)
        if text not in actions:
            actions.append(text)
    return actions
