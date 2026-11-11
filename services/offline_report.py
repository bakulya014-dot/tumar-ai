"""Rules-only TrustReports, for when the AI layer cannot run.

When the AI provider is unreachable, times out, is rate-limited or has
no valid key, a message or link check would otherwise end in an error
and no verdict. This module produces the honest alternative: a report
built ONLY from the deterministic layer, labelled as such everywhere it
is shown, and never stronger than that layer can support.

Nothing here is new scoring. The score and level come from the
documented risk model the screenshot scanner already uses without AI
(services/image_scanner/risk_engine.py: fixed signal weights, grouped
so correlated signals count once, five levels). Evidence comes from the
same heuristics the online path feeds to the AI.

Three deliberate limits:

- No "safe" verdict. Without the AI layer, "no rule matched" is not a
  clean bill of health, so the mildest offline verdict is "caution",
  with an explanation that says exactly that.
- Confidence AND trust score are capped at OFFLINE_CAP (the cap the
  image scanner applies when nothing suspicious was found): the rules
  alone have no second layer to corroborate them, and a "100/100"
  beside "be careful" would contradict itself.
- analysis_metadata["mode"] = "offline", so every consumer (web, bot,
  API, logs, quota refunds) can tell this report apart from an AI one.
"""

from __future__ import annotations

from services.heuristics import scan_message
from services.image_scanner import risk_engine
from services.image_scanner.classifier import injection_phrases
from services.image_scanner.report import ABSENCE_CAP
from services.image_scanner.url_extractor import UrlFinding, analyze_urls
from services.trust_report import (
    Evidence,
    Metric,
    TrustReport,
    evidence_from_heuristics,
    preview_text,
)

# Error codes that mean "the AI provider could not answer" — as opposed
# to "the input is invalid", which must still be reported as an error.
PROVIDER_FAILURES = frozenset({
    "unreachable", "timeout", "rate_limited", "service_down",
    "model_unavailable", "missing_key", "credentials",
    "unexpected_answer", "ai_error",
})

OFFLINE_CAP = ABSENCE_CAP  # 60, for confidence and trust score alike

_VERDICTS = {
    "inconclusive": "caution",
    "low": "caution",  # see module docstring: offline never says "safe"
    "moderate": "caution",
    "high": "danger",
    "critical": "danger",
}


def is_provider_failure(code: str) -> bool:
    return code in PROVIDER_FAILURES


def offline_message_report(message: str, reason: str) -> TrustReport:
    """A rules-only report for a pasted message."""
    text = message.strip()
    heuristics = scan_message(text)
    findings = analyze_urls(text, []).findings
    injections = injection_phrases(text)
    evidence = [e for e in evidence_from_heuristics(heuristics) if not e.code.startswith("url_")]
    evidence += _url_evidence(findings)
    evidence += [
        Evidence(kind="heuristic", code="prompt_injection", detail=phrase, weight="strong")
        for phrase in injections
    ]
    risk = risk_engine.assess(heuristics, findings, len(text), injection_count=len(injections))
    return _report("scam_analyzer", "message", text, risk, evidence, reason)


def offline_url_report(url: str, reason: str) -> TrustReport:
    """A rules-only report for a single link."""
    text = url.strip()
    findings = analyze_urls(text, []).findings
    risk = risk_engine.assess(None, findings, len(text))
    return _report("url_scanner", "url", text, risk, _url_evidence(findings), reason)


def _url_evidence(findings: tuple[UrlFinding, ...]) -> list[Evidence]:
    """Same codes as the online URL scanner, so the report renders alike."""
    evidence: list[Evidence] = []
    for finding in findings:
        weight = "strong" if finding.strong else "weak"
        for code in finding.reasons:
            evidence.append(Evidence(kind="heuristic", code=f"url_{code}", detail=finding.url, weight=weight))
    return evidence


def _report(source, subject_type, text, risk, evidence, reason) -> TrustReport:
    level = risk.level
    verdict = _VERDICTS[level]
    actions = ["trust.offline.rec_do_not_act"] if verdict == "danger" else ["trust.offline.rec_verify"]
    actions.append("trust.offline.rec_retry")
    return TrustReport(
        source=source,
        subject_type=subject_type,
        subject_preview=preview_text(text),
        verdict=verdict,
        trust_score=min(100 - risk.score, OFFLINE_CAP),
        confidence=OFFLINE_CAP,
        metrics=[Metric(label_key="image.metric_deterministic", value=risk.deterministic_score)],
        evidence=evidence,
        explanation_key=f"trust.offline.explain.{level}",
        recommended_action_keys=actions,
        confidence_reason_keys=["trust.offline.confidence"],
        risk_level=level,
        analysis_metadata={
            "mode": "offline",
            "offline_reason": reason,
            "risk_contributions": ", ".join(f"{name}:{points}" for name, points in risk.contributions) or "none",
        },
    )
