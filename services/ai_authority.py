"""What the AI in Tumar.AI is allowed to do — and the switch to stop it.

The AI is an analyst. It reads what the person pasted or uploaded and
returns a structured assessment (a fixed, validated schema). It has no
tools, no function calling, no network access of its own, and no
access to accounts or other people's data. Every AI entry point calls
require() first; nothing else in the codebase may call a model.

ALLOWED is the complete list of AI capabilities. FORBIDDEN documents
what the AI must never do on its own; tests/test_ai_authority.py checks
the code cannot do it (no tool parameters, schemas with data fields
only). Actions that change something — today only "Delete my data" —
are taken by the person, with an explicit second confirmation, and are
logged by type and outcome only.

Incident kill switch: set TUMAR_DISABLE_FEATURES (comma-separated) in
the app's secrets or environment and reboot:
    ai      — no AI calls at all; checks fall back to the labelled
              rules-only result (web and Telegram)
    vision  — no image is sent to a vision model
    breach  — the email breach lookup is switched off
    images  — screenshot scanning is switched off
See docs/INCIDENT_CHECKLIST.md.
"""

from __future__ import annotations

import os

from services import telemetry
from services.common import ServiceError

ALLOWED = {
    "analyze_text": "Read a message or link and return a structured assessment.",
    "read_image": "Read the text, links and brands in an image the person chose to share with an AI provider.",
    "summarize_public_news": "Summarise public cybersecurity news articles (no user data) for /news.",
}

FORBIDDEN = (
    "send_message", "make_payment", "delete_data", "change_account_settings",
    "invite_family_member", "submit_report", "access_other_users_data",
    "call_tools_or_urls", "reveal_prompts_or_credentials",
)

# Actions a person can trigger, and how many confirmations each needs.
USER_ACTIONS = {"delete_my_data": 2}  # open "Delete my data", then "Yes, delete everything"

FEATURES = ("ai", "vision", "breach", "images")
_CAPABILITY_FEATURE = {"analyze_text": "ai", "read_image": "vision", "summarize_public_news": "ai"}


class FeatureDisabled(ServiceError):
    """A feature was switched off by the operator (incident kill switch)."""


def disabled_features() -> frozenset[str]:
    raw = os.environ.get("TUMAR_DISABLE_FEATURES", "")
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip()) & set(FEATURES)


def feature_enabled(feature: str) -> bool:
    return feature not in disabled_features()


def require(capability: str) -> None:
    """Gate every AI call. Raises for an unknown capability or a switched-off feature."""
    if capability not in ALLOWED:
        raise PermissionError(f"AI capability not allowed: {capability}")
    feature = _CAPABILITY_FEATURE[capability]
    if feature == "vision" and not feature_enabled("ai"):
        feature = "ai"  # switching off AI switches off every model
    if not feature_enabled(feature):
        telemetry.emit("guard", kind=capability, action="feature_disabled")
        raise FeatureDisabled("ai_disabled")
