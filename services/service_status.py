"""Health of each outside service, from what this server has already seen.

No probing: a status page that calls Gemini or the breach database on
every view would cost money, leak timing, and could itself be abused.
Instead each service's state comes from configuration, the incident
kill switches, and the outcome of the most recent real call (kept in
memory by services/telemetry.py, content-free).

States:
    ready           working, or not used yet with nothing wrong known
    degraded        the last call failed recently; Tumar falls back
    off             switched off by the operator (kill switch)
    not_configured  no key on this installation
    limited         partly available (e.g. no text reading for images)
"""

from __future__ import annotations

from dataclasses import dataclass

from services import ai_authority, telemetry
from services.image_scanner import ocr_engine

RECENT_SECONDS = 15 * 60
_OUTAGE_CODES = {
    "unreachable", "timeout", "rate_limited", "service_down", "model_unavailable",
    "credentials", "unexpected_answer", "ai_error", "unavailable", "malformed",
}


@dataclass(frozen=True)
class ServiceState:
    key: str  # i18n: status.service.<key>
    state: str  # i18n: status.state.<state>
    variant: str  # chip colour: ok | warn | danger | neutral


_VARIANTS = {"ready": "ok", "degraded": "warn", "off": "neutral", "not_configured": "warn", "limited": "warn"}


def _recent_failure(label: str) -> bool:
    last = telemetry.metrics.last(label)
    if last is None:
        return False
    outcome, code, age = last
    return outcome in {"error", "offline"} and code in _OUTAGE_CODES and age <= RECENT_SECONDS


def _state(key: str, state: str) -> ServiceState:
    return ServiceState(key, state, _VARIANTS[state])


def statuses(ai_key_present: bool) -> list[ServiceState]:
    result = []

    if not ai_authority.feature_enabled("ai"):
        result.append(_state("ai", "off"))
    elif not ai_key_present:
        result.append(_state("ai", "not_configured"))
    elif _recent_failure("provider_call:gemini") or _recent_failure("analysis:message"):
        result.append(_state("ai", "degraded"))
    else:
        result.append(_state("ai", "ready"))

    if not ai_authority.feature_enabled("breach"):
        result.append(_state("breach", "off"))
    else:
        result.append(_state("breach", "degraded" if _recent_failure("analysis:email") else "ready"))

    result.append(_state("password", "degraded" if _recent_failure("analysis:password") else "ready"))

    if not ai_authority.feature_enabled("images"):
        result.append(_state("images", "off"))
    else:
        result.append(_state("images", "ready" if ocr_engine.available() else "limited"))
    return result
