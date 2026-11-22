"""Personal Cyber Resilience Score: transparent, session-only, never a guarantee.

Every point comes from a factor the person can see and change:

    starting point                                  60
    each dangerous finding not yet dealt with      -12  (up to -24)
    email found in a known breach                  -12
    a weak or breached password checked            -8
    two-step verification on email / bank / Telegram +6 each
    checked something before acting                 +4
    a clean email-breach check                      +4
    a strong password check                         +4

The maximum is 90, on purpose: no score means "fully safe", and the page
says so. Nothing is stored beyond this browser session; the checklist
and "dealt with" marks live in session state and vanish with it.
"""

from __future__ import annotations

from dataclasses import dataclass

from services.trust_report import TrustReport

BASE = 60
TWO_FACTOR_ITEMS = ("email", "bank", "telegram")


@dataclass(frozen=True)
class Factor:
    key: str  # i18n: resilience.factor.<key>
    points: int  # signed contribution to the score
    active: bool  # counted now?


@dataclass(frozen=True)
class Step:
    key: str  # i18n: resilience.step.<key>
    gain: int  # points it would add
    detail: str = ""  # e.g. which 2FA item


def report_id(report: TrustReport) -> str:
    """A stable id for one check in this session (no content in it)."""
    return f"{report.source}:{report.created_at.isoformat()}"


def factors(
    reports: list[TrustReport], two_factor: dict[str, bool], handled: set[str]
) -> list[Factor]:
    dangerous_open = [
        r for r in reports
        if r.verdict == "danger" and r.subject_type not in {"email", "password"} and report_id(r) not in handled
    ]
    breached = any(r.subject_type == "email" and r.verdict != "safe" for r in reports)
    clean_email = any(r.subject_type == "email" and r.verdict == "safe" for r in reports)
    weak_password = any(r.subject_type == "password" and r.verdict != "safe" for r in reports)
    strong_password = any(r.subject_type == "password" and r.verdict == "safe" for r in reports)
    result = [
        Factor("base", BASE, True),
        Factor("dangerous_open", -12 * min(len(dangerous_open), 2), bool(dangerous_open)),
        Factor("breach_exposure", -12, breached),
        Factor("weak_password", -8, weak_password),
    ]
    result += [Factor(f"two_factor_{item}", 6, bool(two_factor.get(item))) for item in TWO_FACTOR_ITEMS]
    result += [
        Factor("checked_first", 4, bool(reports)),
        Factor("clean_email", 4, clean_email and not breached),
        Factor("strong_password", 4, strong_password and not weak_password),
    ]
    return result


def score(items: list[Factor]) -> int:
    return max(0, min(100, sum(f.points for f in items if f.active)))


def _contribution(factor: Factor) -> int:
    return factor.points if factor.active else 0


def changes(before: list[Factor] | None, after: list[Factor]) -> list[tuple[str, int]]:
    """(factor key, point change) since the last view: the 'why it changed'."""
    if before is None:
        return []
    previous = {f.key: _contribution(f) for f in before}
    return [
        (f.key, _contribution(f) - previous.get(f.key, 0))
        for f in after
        if _contribution(f) != previous.get(f.key, 0)
    ]


def top_steps(
    reports: list[TrustReport], two_factor: dict[str, bool], handled: set[str], limit: int = 3
) -> list[Step]:
    """The highest-impact things the person can still do, biggest gain first."""
    items = {f.key: f for f in factors(reports, two_factor, handled)}
    steps: list[Step] = []
    if items["dangerous_open"].active:
        steps.append(Step("deal_dangerous", -items["dangerous_open"].points))
    if items["breach_exposure"].active:
        steps.append(Step("change_breached", 12))
    if items["weak_password"].active:
        steps.append(Step("replace_weak", 8))
    steps += [Step("two_factor", 6, item) for item in TWO_FACTOR_ITEMS if not two_factor.get(item)]
    if not reports:
        steps.append(Step("check_first", 4))
    if not any(r.subject_type == "email" for r in reports):
        steps.append(Step("check_email", 4))
    steps.sort(key=lambda s: -s.gain)
    return steps[:limit]
