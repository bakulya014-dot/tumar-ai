"""Unified Trust Report — the shared result language of the platform.

Every module (scam analyzer, breach checker, and each future scanner)
keeps its own detailed result type, but the platform speaks one
language: the TrustReport. One schema means the UI can render any
module's verdict with the same components, history can store results
from different modules side by side, and a future API can return them
to external callers unchanged.

Design decisions:
- Pydantic, not a dataclass: reports will cross process boundaries —
  kept in history, returned over an API — so they need validation and
  loss-free JSON serialization built in.
- trust_score points UP: 100 = fully trustworthy, 0 = do not trust.
  Individual modules think in risk (higher = worse); the platform
  speaks in trust so every screen reads the same way.
- Two kinds of text: AI modules produce free text already in the
  user's language (explanation / recommended_actions); deterministic
  modules produce translation keys (explanation_key /
  recommended_action_keys) that the UI resolves. A report fills one
  of each pair and leaves the other empty. Keys are FULL dotted i18n
  keys ("breach.rec_enable_mfa"), so any consumer can render any
  report with t(key) alone — no per-module knowledge required.
- Previews are safe by construction: emails are masked and messages
  truncated before they enter a report, so a report can always be
  displayed or stored without re-checking for sensitive content.
"""

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from services.breach_checker import EmailBreachResult
from services.confidence import estimate as estimate_confidence
from services.heuristics import is_strong_url_signal
from services.scam_analysis import ScamReport
from services.vision_analysis import VisionFinding, to_analysis_text

SubjectType = Literal["message", "email", "url", "password", "image"]
Verdict = Literal["safe", "caution", "danger"]

# Longest subject preview we keep; enough to recognize the item in a
# history list without storing the full (possibly sensitive) content.
PREVIEW_LIMIT = 80


class Evidence(BaseModel):
    """One reason behind a verdict, with its origin.

    `kind` tells the user WHO found it (deterministic scanner, AI, or
    an external database) — a core trust-UX principle: never blur the
    line between a pattern match and an AI judgement.

    Code vocabulary is shared platform-wide so one renderer can
    present any module's evidence: "url_*" for per-link findings,
    "red_flag" for AI-named techniques, "breach" for database hits,
    and a signal family ("urgency", "otp", "credential", "financial",
    "manipulation") for matched wording.
    """

    kind: Literal["heuristic", "ai", "external"]
    code: str  # short machine code, e.g. "urgency", "red_flag", "breach"
    detail: str = ""  # verbatim data: the phrase, URL, or breach name
    # Whether this finding justifies suspicion alone, or only in
    # company. Users deserve to know which signals actually carried the
    # verdict rather than seeing a flat list where a hyphen in a domain
    # looks as damning as a request for a one-time code.
    weight: Literal["strong", "weak"] = "weak"


class Metric(BaseModel):
    """One named 0–100 measurement behind a verdict.

    Modules expose their own breakdowns (credential-theft risk,
    urgency pressure, and later deepfake likelihood or payment risk)
    without the UI needing module-specific code: the renderer draws
    whatever metrics a report carries.

    `label_key` is a full dotted i18n key, so any consumer localizes
    it with t(key). `higher_is_worse` carries the SEMANTICS, never a
    color — the data layer must not know about CSS.
    """

    label_key: str
    value: int = Field(ge=0, le=100)
    higher_is_worse: bool = True


class TrustReport(BaseModel):
    """One standardized verdict about one subject."""

    report_id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source: str  # module id, e.g. "scam_analyzer"
    subject_type: SubjectType
    subject_preview: str  # masked/truncated — always safe to show
    verdict: Verdict
    trust_score: int = Field(ge=0, le=100)  # 100 = fully trustworthy
    confidence: int = Field(ge=0, le=100)
    metrics: list[Metric] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str = ""  # free text (AI modules)
    explanation_key: str = ""  # translation key (deterministic modules)
    recommended_actions: list[str] = Field(default_factory=list)
    recommended_action_keys: list[str] = Field(default_factory=list)
    # Why the confidence is what it is — agreement between layers, a
    # contradiction, too little text to judge. Translation keys, so any
    # consumer can render them.
    confidence_reason_keys: list[str] = Field(default_factory=list)


# --- Adapters: module results -> TrustReport ---

_SCAM_VERDICTS: dict[str, Verdict] = {
    "Safe": "safe",
    "Suspicious": "caution",
    "Dangerous": "danger",
}

_BREACH_VERDICTS: dict[str, Verdict] = {
    "none": "safe",
    "medium": "caution",
    "high": "danger",
}

# Absence from known breaches is good news, not proof of safety — the
# platform never claims more certainty than it has, so a clean email
# scores 85, not 100.
_BREACH_SCORES = {"none": 85, "medium": 40, "high": 15}

# A breach lookup is a deterministic database match, so confidence is
# high — but not 100: breach databases always lag behind reality.
_BREACH_CONFIDENCE = 95


def from_scam_report(report: ScamReport, message: str) -> TrustReport:
    """Convert a scam analysis (heuristics + AI) into a TrustReport."""
    evidence: list[Evidence] = []
    heuristics = report.heuristics

    # A code being delivered to you is not evidence of anything; only
    # being asked to hand it over, or to type it somewhere, is.
    otp_code = {
        "disclosure": "otp_disclosure",
        "entry": "otp_entry",
    }.get(heuristics.otp_signal, "")

    for code, matches, weight in (
        ("urgency", heuristics.urgency_matches, "weak"),
        (otp_code, heuristics.otp_matches if otp_code else [], "strong"),
        ("credential", heuristics.credential_indicators, "strong"),
        ("financial", heuristics.financial_indicators, "weak"),
        ("manipulation", heuristics.manipulation_indicators, "weak"),
    ):
        for phrase in matches:
            evidence.append(
                Evidence(
                    kind="heuristic",
                    code=code,
                    detail=phrase,
                    weight="weak" if code == "otp_entry" else weight,
                )
            )
    for finding in heuristics.suspicious_urls:
        for reason in finding.reasons:
            evidence.append(
                Evidence(
                    kind="heuristic",
                    code=f"url_{reason}",
                    detail=finding.url,
                    weight="strong" if is_strong_url_signal(reason) else "weak",
                )
            )
    for flag in report.ai.red_flags:
        evidence.append(
            Evidence(kind="ai", code="red_flag", detail=flag, weight="weak")
        )

    verdict = _SCAM_VERDICTS[report.ai.verdict]
    confidence = estimate_confidence(
        ai_confidence=report.ai.confidence,
        verdict=verdict,
        heuristics=heuristics,
        text_length=len(message.strip()),
    )

    return TrustReport(
        source="scam_analyzer",
        subject_type="message",
        subject_preview=preview_text(message),
        verdict=verdict,
        trust_score=100 - report.ai.risk_score,
        confidence=confidence.value,
        confidence_reason_keys=confidence.reason_keys,
        metrics=[
            Metric(
                label_key="scam.credential_risk_label",
                value=report.ai.credential_theft_risk,
            ),
            Metric(
                label_key="scam.financial_risk_label",
                value=report.ai.financial_scam_risk,
            ),
            Metric(
                label_key="scam.metric_urgency",
                value=heuristics.urgency_score,
            ),
        ],
        evidence=evidence,
        explanation=report.ai.explanation,
        recommended_actions=list(report.ai.recommended_actions),
    )


def from_image_analysis(
    report: ScamReport,
    vision: "VisionFinding",
    filename: str = "",
) -> TrustReport:
    """Build a report for a screenshot, from both layers.

    The verdict still comes from the engine reading the text that was
    extracted — the vision provider contributed facts, not a judgement.
    Its observations are attached as evidence of their own so a user
    can see what the image reader noticed and weigh it separately.

    Nothing derived from the image bytes reaches the report: the
    preview is the file name, never a thumbnail or a data URI, so a
    report about a screenshot is as safe to store and return as any
    other.
    """
    base = from_scam_report(report, to_analysis_text(vision))

    evidence = list(base.evidence)
    for indicator in vision.risk_indicators:
        evidence.append(
            Evidence(kind="ai", code="vision_indicator", detail=indicator, weight="weak")
        )
    for brand in vision.brands:
        evidence.append(
            Evidence(kind="ai", code="vision_brand", detail=brand, weight="weak")
        )

    # The vision layer read the image; the engine judged the text. When
    # they disagree the confidence model has already said so, and this
    # keeps the two contributions visible rather than blended.
    confidence = estimate_confidence(
        ai_confidence=report.ai.confidence,
        verdict=base.verdict,
        heuristics=report.heuristics,
        text_length=len(vision.detected_text),
        vision_flagged=bool(vision.risk_indicators or vision.otp_requests),
        vision_legibility=vision.confidence,
    )

    return base.model_copy(
        update={
            "source": "image_scanner",
            "subject_type": "image",
            "subject_preview": preview_text(filename or "screenshot"),
            "evidence": evidence,
            "confidence": confidence.value,
            "confidence_reason_keys": confidence.reason_keys,
            "metrics": base.metrics
            + [
                Metric(
                    label_key="image.metric_legibility",
                    value=vision.confidence,
                    higher_is_worse=False,
                )
            ],
        }
    )


def from_breach_result(result: EmailBreachResult) -> TrustReport:
    """Convert an email breach lookup into a TrustReport."""
    return TrustReport(
        source="breach_checker",
        subject_type="email",
        subject_preview=mask_email(result.email),
        verdict=_BREACH_VERDICTS[result.risk_level],
        trust_score=_BREACH_SCORES[result.risk_level],
        confidence=_BREACH_CONFIDENCE,
        evidence=[
            Evidence(kind="external", code="breach", detail=name)
            for name in result.breaches
        ],
        explanation_key=f"breach.explanation_{result.risk_level}",
        recommended_action_keys=[
            f"breach.{code}" for code in result.recommendations
        ],
    )


# --- Preview helpers ---


def preview_text(text: str) -> str:
    """Collapse whitespace and truncate to one recognizable line."""
    flattened = " ".join(text.split())
    if len(flattened) <= PREVIEW_LIMIT:
        return flattened
    return flattened[: PREVIEW_LIMIT - 1] + "…"


def mask_email(email: str) -> str:
    """Mask the local part: 'bakytzhan@gmail.com' -> 'b*******n@gmail.com'.

    The domain stays visible (it is what makes the entry recognizable);
    the identifying part is hidden so the report itself never carries
    the full address.
    """
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = local[:1] + "*"
    else:
        masked = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked}@{domain}"
