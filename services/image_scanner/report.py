"""ImageScanResult -> TrustReport, the platform's shared result.

The report is built so that any consumer — the Streamlit page, the
REST API, the bot — can render it with no image-specific code: every
finding is an Evidence item with a conventional code, the explanation
and recommendations are translation keys when no AI wrote free text,
and the extras an image needs (risk level, layer statuses, the
transcript) travel in `analysis_metadata` as plain strings.

Nothing derived from the image bytes reaches the report. The preview
is the file name; the transcript is text.
"""

from __future__ import annotations

import dataclasses

from services.confidence import CEILING as CONFIDENCE_CEILING
from services.confidence import FLOOR as CONFIDENCE_FLOOR
from services.confidence import estimate as estimate_confidence
from services.heuristics import HeuristicReport, SuspiciousURL, is_strong_url_signal
from services.image_scanner.pipeline import ImageScanResult
from services.trust_report import (
    Evidence,
    Metric,
    TrustReport,
    Verdict,
    evidence_from_heuristics,
    preview_text,
)

_VERDICTS: dict[str, Verdict] = {
    "low": "safe",
    "moderate": "caution",
    "high": "danger",
    "critical": "danger",
    "inconclusive": "caution",
}

# How much of the transcript is carried in the report for display.
TRANSCRIPT_LIMIT = 2000

# Recommendations are keyed by category; the first three categories
# found each contribute one, and every report ends with the general
# advice.
_MAX_CATEGORY_RECOMMENDATIONS = 3


def _url_evidence(result: ImageScanResult) -> list[Evidence]:
    evidence: list[Evidence] = []
    for finding in result.urls.findings:
        if finding.invalid:
            continue
        if finding.origin == "qr":
            evidence.append(Evidence(kind="heuristic", code="qr_link", detail=finding.url, weight="weak"))
        for reason in finding.reasons:
            evidence.append(
                Evidence(
                    kind="heuristic",
                    code=f"url_{reason}",
                    detail=finding.url,
                    weight="strong" if is_strong_url_signal(reason) else "weak",
                )
            )
        if finding.internal:
            evidence.append(Evidence(kind="heuristic", code="url_internal", detail=finding.url, weight="strong"))
    for code in result.qr.codes:
        if not code.is_link:
            evidence.append(Evidence(kind="heuristic", code=f"qr_{code.kind}", detail=code.preview, weight="weak"))
    return evidence


# Confidence for images analysed WITHOUT the AI text layer.
#
# Confidence here answers "how sure are we that we read the image
# correctly and that the evidence supports the level?" — never "how
# dangerous is it" (that is the risk score). The rules:
#
#   start   what was read: a decoded QR code is exact (QR_EXACT); OCR
#           and vision readings bring their own reading confidence
#   +bonus  two or more independent signal groups agree (INDEPENDENT)
#   cap     a "low" level is absence of evidence, which is weaker than
#           evidence found (ABSENCE_CAP)
#   floor   nothing read at all -> FLOOR, level is "inconclusive"
#
# Bounded by the platform's CEILING / FLOOR, like every other report.
QR_EXACT = 90
INDEPENDENT_BONUS = 5
ABSENCE_CAP = 60


def image_confidence(result: ImageScanResult) -> tuple[int, list[str]]:
    """Evidence-based confidence for an image report with no AI layer."""
    reasons: list[str] = []
    readings: list[int] = []
    if result.qr.codes:
        readings.append(QR_EXACT)
        reasons.append("image.conf.qr_exact")
    if result.ocr.status == "success":
        readings.append(result.ocr.confidence)
        reasons.append("image.conf.ocr_read")
    if result.vision_status == "success" and result.vision:
        readings.append(result.vision.confidence)
        reasons.append("image.conf.vision_read")
    if not readings:
        return CONFIDENCE_FLOOR, ["image.conf.nothing_read"]

    value = max(readings)
    groups = {name for name, _ in result.risk.contributions}
    if len(groups) >= 2:
        value += INDEPENDENT_BONUS
        reasons.append("image.conf.independent_signals")
    if result.risk.level == "low":
        value = min(value, ABSENCE_CAP)
        reasons.append("image.conf.absence")
    return max(CONFIDENCE_FLOOR, min(CONFIDENCE_CEILING, value)), reasons


def _with_ai_layer(
    result: ImageScanResult,
    heuristics: HeuristicReport,
    verdict: Verdict,
    legibility: int,
    vision_flagged: bool,
) -> tuple[int, list[str]]:
    extra = [
        SuspiciousURL(url=f.url, reasons=list(f.reasons) + (["ip_address"] if f.internal and "ip_address" not in f.reasons else []))
        for f in result.urls.findings
        if f.suspicious and not f.invalid
    ]
    known = {s.url for s in heuristics.suspicious_urls}
    merged = dataclasses.replace(
        heuristics, suspicious_urls=list(heuristics.suspicious_urls) + [s for s in extra if s.url not in known]
    )
    estimate = estimate_confidence(
        ai_confidence=result.ai.confidence if result.ai else 0,
        verdict=verdict,
        heuristics=merged,
        text_length=len(result.text),
        vision_flagged=vision_flagged if result.vision else None,
        vision_legibility=legibility,
    )
    return estimate.value, estimate.reason_keys


def to_trust_report(result: ImageScanResult, filename: str = "") -> TrustReport:
    heuristics = result.heuristics or HeuristicReport(0, [], "none", [], False, [], [], [], [])
    level = result.risk.level
    verdict = _VERDICTS[level]

    evidence = evidence_from_heuristics(heuristics)
    # The message scanner already judged URLs it saw in the text; the
    # image layer re-judges them together with QR and vision links.
    # Drop the scanner's copies so each address is listed once.
    evidence = [e for e in evidence if not e.code.startswith("url_")]
    evidence += _url_evidence(result)
    for phrase in result.classification.injection_phrases:
        evidence.append(Evidence(kind="heuristic", code="prompt_injection", detail=phrase, weight="strong"))
    if result.vision:
        for indicator in result.vision.risk_indicators:
            evidence.append(Evidence(kind="ai", code="vision_indicator", detail=indicator, weight="weak"))
        for brand in result.vision.brands:
            evidence.append(Evidence(kind="ai", code="vision_brand", detail=brand, weight="weak"))
    if result.ai:
        for flag in result.ai.red_flags:
            evidence.append(Evidence(kind="ai", code="red_flag", detail=flag, weight="weak"))

    legibility = max(result.ocr.confidence, result.vision.confidence if result.vision else 0)
    if result.ai:
        # The platform's confidence model, given every scanner finding —
        # including links that came from QR codes or the vision reader,
        # which the message scanner alone would not have seen.
        vision_flagged = bool(result.vision and (result.vision.risk_indicators or result.vision.otp_requests))
        confidence_value, confidence_reasons = _with_ai_layer(
            result, heuristics, verdict, legibility, vision_flagged
        )
    else:
        confidence_value, confidence_reasons = image_confidence(result)

    categories = [c for c in result.classification.categories if c != "inconclusive"]
    if result.ai:
        explanation, explanation_key = result.ai.explanation, ""
        actions, action_keys = list(result.ai.recommended_actions), []
    else:
        explanation, explanation_key = "", f"image.explain.{level}"
        actions = []
        action_keys = [f"image.rec.{c}" for c in categories[:_MAX_CATEGORY_RECOMMENDATIONS]]
        action_keys.append("image.rec.general" if level != "inconclusive" else "image.rec.inconclusive")

    metrics = []
    # Legibility only means something when text was actually read; a
    # QR-only image would otherwise show a misleading 0.
    if result.ocr.status == "success" or result.vision_status == "success":
        metrics.append(Metric(label_key="image.metric_legibility", value=legibility, higher_is_worse=False))
    metrics.append(Metric(label_key="image.metric_deterministic", value=result.risk.deterministic_score))
    if result.ai:
        metrics += [
            Metric(label_key="scam.credential_risk_label", value=result.ai.credential_theft_risk),
            Metric(label_key="scam.financial_risk_label", value=result.ai.financial_scam_risk),
        ]

    metadata = {
        "ocr_status": result.ocr.status,
        "ocr_detail": result.ocr.detail,
        "ocr_languages": "+".join(result.ocr.languages_loaded),
        "qr_status": result.qr.status,
        "url_analysis_status": result.urls.status,
        "visual_analysis_status": result.vision_status,
        "ai_status": result.ai_status,
        "url_reputation": "heuristic",
        "detected_language": result.language,
        "risk_level": level,
        "risk_score": str(result.risk.score),
        "deterministic_score": str(result.risk.deterministic_score),
        "ai_score": "" if result.risk.ai_score is None else str(result.risk.ai_score),
        "contributions": ", ".join(f"{name}+{points}" for name, points in result.risk.contributions),
        "categories": ", ".join(categories) or "inconclusive",
        "themes": ", ".join(result.classification.themes),
        "extracted_text": result.text[:TRANSCRIPT_LIMIT],
        "text_chars": str(len(result.text)),
        "urls": "\n".join(f.url for f in result.urls.findings if not f.invalid),
        "qr_codes": "\n".join(f"{c.kind}: {c.preview}" for c in result.qr.codes),
        "image_size": f"{result.image.width}x{result.image.height}",
        "elapsed_ms": str(result.elapsed_ms),
    }

    return TrustReport(
        source="image_scanner",
        subject_type="image",
        subject_preview=preview_text(filename or "screenshot"),
        verdict=verdict,
        trust_score=100 - result.risk.score,
        confidence=confidence_value,
        confidence_reason_keys=confidence_reasons,
        metrics=metrics,
        evidence=evidence,
        explanation=explanation,
        explanation_key=explanation_key,
        recommended_actions=actions,
        recommended_action_keys=action_keys,
        risk_level=level,
        analysis_metadata=metadata,
    )
