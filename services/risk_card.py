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
    # AI Security Check (subject type "ai_content")
    "prompt_injection", "evidence_manipulation", "data_exfiltration",
    "memory_poisoning", "tool_poisoning", "excessive_permissions",
)

# AI Security Check evidence -> category, most serious first. Rule
# findings are consulted before the AI's, so the category rests on
# what was matched whenever something was.
_AI_CONTENT_CATEGORIES = (
    ({"ais_exfiltration"}, "data_exfiltration"),
    ({"ais_tool_poisoning"}, "tool_poisoning"),
    ({"ais_evidence_manipulation"}, "evidence_manipulation"),
    ({"ais_memory_poisoning"}, "memory_poisoning"),
    ({"ais_payment_redirect", "ais_payment_change", "ais_impersonation_supplier", "ais_impersonation_exec"}, "payment_fraud"),
    ({"ais_direct_injection", "ais_indirect_injection", "ais_hidden_text", "prompt_injection"}, "prompt_injection"),
    ({"ais_perm_no_approval", "ais_perm_beyond_task", "ais_perm_excessive", "ais_perm_shell", "ais_perm_filesystem",
      "ais_perm_payments", "ais_perm_messaging", "ais_perm_secrets", "ais_perm_admin", "ais_perm_delete"}, "excessive_permissions"),
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
    "prompt_injection": ("ai_hold", "ai_quarantine", "ai_report"),
    "evidence_manipulation": ("ai_human_review", "ai_original_logs", "ai_report"),
    "data_exfiltration": ("ai_hold", "ai_rotate", "ai_report"),
    "memory_poisoning": ("ai_quarantine", "ai_check_decisions", "ai_report"),
    "tool_poisoning": ("ai_disconnect", "ai_rotate", "ai_report"),
    "excessive_permissions": ("ai_least_privilege", "ai_require_approval", "ai_hold"),
}
# A payment redirect found by the AI Security Check gets the payment steps
# plus an out-of-band check, not the consumer "block the sender" advice.
_AI_CONTENT_CONTAIN = {"payment_fraud": ("no_pay", "ai_verify_known_contact", "ai_report")}


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
    if report.subject_type == "ai_content":
        return _ai_content_category(report)
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


def _ai_content_category(report: TrustReport) -> str:
    for kinds in ({"heuristic", "external"}, {"ai"}):
        codes = {e.code for e in report.evidence if e.kind in kinds}
        for members, name in _AI_CONTENT_CATEGORIES:
            if codes & members:
                if name == "payment_fraud" and codes & {"ais_authority_claim", "ais_impersonation_exec"}:
                    return "impersonation"
                return name
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
        "ai_content": ["ai_static_only", "masked_ai"],
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
    steps = CONTAIN_KEYS.get(cat, CONTAIN_KEYS["unknown"])
    if report.subject_type == "ai_content":
        steps = _AI_CONTENT_CONTAIN.get(cat, steps)
        if cat in {"impersonation", "unknown"}:
            steps = _AI_CONTENT_CONTAIN["payment_fraud"] if cat == "impersonation" else CONTAIN_KEYS["prompt_injection"]
    contain = list(steps) if report.verdict == "danger" else []
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
