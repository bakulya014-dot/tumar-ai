"""Evidence-first risk card: the four questions every Tumar result answers.

1. What happened?           category + the evidence, sorted by how sure we are
2. How serious is it?       severity (low/medium/high/critical) + confidence band
3. What should I do now?    the report's actions, plus "Contain now" when dangerous
4. What did Tumar protect?  what Tumar did, and did not do, with the user's data

Pure functions over a TrustReport, so every channel can reuse them and
they are testable without Streamlit. Nothing here changes a verdict: the
card re-presents what the engine already found.

Honesty rules built in:
- Evidence is split into what was CONFIRMED (verifiable facts: a breach
  database hit, a raw IP address, a link without encryption), what is a
  SUSPICIOUS SIGNAL (wording and look-alike patterns), and what is an AI
  ASSESSMENT (never presented as fact).
- "malware" and "misinformation" exist as categories for the schema, but
  no Tumar check detects them today, so nothing is ever labelled with them.
- Tumar takes no action on anyone's accounts; the card says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.trust_report import Evidence, TrustReport

CATEGORIES = (
    "phishing", "impersonation", "malware", "account_takeover",
    "breach_exposure", "payment_fraud", "misinformation", "unknown",
)
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCE_BANDS = ("low", "medium", "high")

# Link facts anyone can verify from the address itself.
_CONFIRMED_URL_REASONS = {"ip_address", "no_https", "punycode", "shortener", "internal"}
_CONFIRMED_CODES = {"breach", "pw_breached", "qr_link", "prompt_injection"}

# Image-scanner categories -> risk card categories.
_IMAGE_CATEGORIES = {
    "phishing": "phishing",
    "social_engineering": "phishing",
    "identity_impersonation": "impersonation",
    "credential_theft": "account_takeover",
    "otp_harvesting": "account_takeover",
    "suspicious_authentication": "account_takeover",
    "financial_fraud": "payment_fraud",
    "fake_payment_request": "payment_fraud",
    "investment_scam": "payment_fraud",
    "delivery_scam": "payment_fraud",
}

CONTAIN_KEYS = {
    "phishing": ("no_click", "official_app", "block_report", "keep_evidence", "tell_family"),
    "impersonation": ("no_click", "official_app", "block_report", "keep_evidence"),
    "account_takeover": ("no_codes", "reset_password", "two_factor", "official_app"),
    "payment_fraud": ("no_pay", "call_bank", "block_report", "keep_evidence"),
    "breach_exposure": ("reset_password", "two_factor", "watch_signins"),
    "unknown": ("no_click", "official_app", "keep_evidence"),
}


@dataclass(frozen=True)
class RiskCard:
    category: str
    severity: str
    confidence_band: str
    confirmed: list[Evidence] = field(default_factory=list)
    suspicious: list[Evidence] = field(default_factory=list)
    ai_assessment: list[Evidence] = field(default_factory=list)
    contain_keys: list[str] = field(default_factory=list)  # i18n: protect.contain.<key>
    protected_keys: list[str] = field(default_factory=list)  # i18n: protect.done.<key>

    @property
    def exposure_key(self) -> str:
        return f"protect.exposure.{self.category}"

    @property
    def why_key(self) -> str:
        return f"protect.why.{self.category}"


def _codes(report: TrustReport) -> set[str]:
    return {e.code for e in report.evidence}


def category(report: TrustReport) -> str:
    if report.verdict == "safe":
        return "unknown"
    codes = _codes(report)
    if report.subject_type == "email" or "breach" in codes:
        return "breach_exposure"
    if report.subject_type == "password":
        return "account_takeover"
    if report.subject_type == "image":
        for raw in report.analysis_metadata.get("categories", "").split(","):
            mapped = _IMAGE_CATEGORIES.get(raw.strip())
            if mapped:
                return mapped
    if {"url_brand_lookalike", "url_misspelled_domain", "url_homoglyph"} & codes:
        return "impersonation" if not ({"credential", "otp_disclosure"} & codes) else "phishing"
    if any(c.startswith("url_") for c in codes) or "credential" in codes or "qr_link" in codes:
        return "phishing"
    if "otp_disclosure" in codes:
        return "account_takeover"
    if "financial" in codes:
        return "payment_fraud"
    if codes & {"urgency", "manipulation", "red_flag"}:
        return "phishing"
    return "unknown"


def severity(report: TrustReport) -> str:
    level = report.risk_level
    if level in {"high", "critical"}:
        return level
    if level == "moderate":
        return "medium"
    if report.verdict == "danger":
        return "critical" if report.trust_score <= 15 else "high"
    if report.verdict == "caution":
        return "medium"
    return "low"


def confidence_band(confidence: int) -> str:
    return "high" if confidence >= 75 else "medium" if confidence >= 50 else "low"


def _split(evidence: list[Evidence]) -> tuple[list[Evidence], list[Evidence], list[Evidence]]:
    confirmed, suspicious, ai = [], [], []
    for item in evidence:
        reason = item.code.removeprefix("url_")
        if item.kind == "ai":
            ai.append(item)
        elif item.kind == "external" or item.code in _CONFIRMED_CODES or (
            item.code.startswith("url_") and reason in _CONFIRMED_URL_REASONS
        ):
            confirmed.append(item)
        else:
            suspicious.append(item)
    return confirmed, suspicious, ai


def protected_keys(report: TrustReport) -> list[str]:
    """What Tumar did with the data, true for every path, per subject type."""
    per_type = {
        "message": ["masked"],
        "url": ["link_not_opened"],
        "image": ["image_not_stored"],
        "email": ["email_not_stored"],
        "password": ["password_prefix"],
    }
    keys = list(per_type.get(report.subject_type, []))
    if report.subject_type in {"message", "image"} and any(
        e.code.startswith("url_") or e.code == "qr_link" for e in report.evidence
    ):
        keys.append("link_not_opened")  # links inside a message or picture are never fetched
    return keys + ["no_action"]


def build(report: TrustReport) -> RiskCard:
    cat = category(report)
    confirmed, suspicious, ai = _split(report.evidence)
    contain = list(CONTAIN_KEYS.get(cat, CONTAIN_KEYS["unknown"])) if report.verdict == "danger" else []
    return RiskCard(
        category=cat,
        severity=severity(report),
        confidence_band=confidence_band(report.confidence),
        confirmed=confirmed,
        suspicious=suspicious,
        ai_assessment=ai,
        contain_keys=contain,
        protected_keys=protected_keys(report),
    )
