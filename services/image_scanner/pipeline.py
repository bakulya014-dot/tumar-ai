"""The image-scanner pipeline: one call, every layer, honest statuses.

    validate -> decode -> OCR -> QR -> URLs -> (vision) -> text analysis
             -> intent categories -> risk

Each optional layer reports a status instead of failing the scan:

    ocr      success | empty | unavailable | failed
    qr       success | none  | failed
    urls     success | none
    vision   success | skipped | disabled | failed
    ai       success | skipped | disabled | failed

"skipped" means nothing was configured for it; "disabled" means the
user switched external providers off; "failed" means it was tried.
The deterministic layers (OCR, QR, URL heuristics, the message
scanner, intent categories, risk) run on every image, so a verdict is
always evidence-based and never depends on a paid service.

Privacy: the original upload is discarded after validation; only the
re-encoded, metadata-free copy exists in memory, and nothing is ever
written to disk. The image bytes reach an external provider only when
the caller allows it and a vision provider is configured.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from services.heuristics import HeuristicReport, scan_message
from services.image_scanner import ocr_engine
from services.image_scanner.classifier import Classification, classify
from services.image_scanner.preprocessing import to_array
from services.image_scanner.qr_decoder import QrResult, decode_qr
from services.image_scanner.risk_engine import RiskAssessment, assess
from services.image_scanner.url_extractor import UrlResult, analyze_urls
from services.image_scanner.validator import ValidatedImage, validate_image
from services.language import detect as detect_language
from services.providers import text_provider, vision_provider
from services.scam_analysis import ScamAnalysis, ScamAnalysisError, analyze_message
from services.vision_analysis import VisionAnalysisError, VisionFinding, analyze_image

# The scam prompt was measured on messages up to a few thousand
# characters; a whole OCR'd web page is cut to that before it is sent.
MAX_TEXT_FOR_AI = 6000


@dataclass(frozen=True)
class ImageScanResult:
    """Everything the scanner found, with the status of every layer."""

    image: ValidatedImage
    ocr: ocr_engine.OcrResult
    qr: QrResult
    urls: UrlResult
    vision: VisionFinding | None
    vision_status: str
    heuristics: HeuristicReport | None
    ai: ScamAnalysis | None
    ai_status: str
    classification: Classification
    risk: RiskAssessment
    text: str
    language: str
    elapsed_ms: int

    @property
    def anything_read(self) -> bool:
        return bool(self.text) or bool(self.qr.codes)


def _combine_text(ocr_text: str, vision: VisionFinding | None) -> str:
    """OCR is the primary transcript; the vision model fills gaps.

    When both read the image, the longer transcript wins and the other
    is appended only if it adds words — the two are the same text read
    twice, and feeding both verbatim would double every signal.
    """
    parts = [ocr_text.strip()]
    if vision and vision.detected_text:
        extra = vision.detected_text.strip()
        primary = parts[0]
        if not primary:
            parts = [extra]
        elif len(extra) > len(primary) * 1.5:
            parts = [extra]
        elif extra.lower() not in primary.lower():
            ocr_words = set(primary.lower().split())
            new_words = [w for w in extra.split() if w.lower() not in ocr_words]
            if len(new_words) >= 5:
                parts.append(" ".join(new_words))
    if vision:
        if vision.otp_requests:
            parts.append("Code requests seen: " + "; ".join(vision.otp_requests))
        if vision.phone_numbers:
            parts.append("Phone numbers shown: " + ", ".join(vision.phone_numbers))
    return "\n".join(p for p in parts if p).strip()


def scan_image(
    data: bytes,
    *,
    api_key: str = "",
    language: str = "en",
    allow_external: bool = True,
    preferred_vision: str = "",
) -> ImageScanResult:
    """Analyse one uploaded image end to end.

    Raises:
        ImageValidationError: the upload was refused (see validator).
    Everything after validation degrades to a status, never an error.
    """
    started = time.perf_counter()
    image = validate_image(data)
    del data  # the original bytes are not needed again
    array = to_array(image.png_bytes)

    ocr = ocr_engine.read_text(array)
    qr = decode_qr(array)

    vision: VisionFinding | None = None
    if not allow_external:
        vision_status = "disabled"
    else:
        provider = vision_provider(preferred_vision)
        if provider is None:
            vision_status = "skipped"
        else:
            try:
                vision = analyze_image(image.png_bytes, "image/png", provider, language)
                vision_status = "success"
            except VisionAnalysisError:
                vision_status = "failed"

    text = _combine_text(ocr.text, vision)
    urls = analyze_urls(
        ocr.text,
        [code.payload for code in qr.codes if code.is_link],
        vision.urls if vision else None,
    )

    heuristics: HeuristicReport | None = scan_message(text) if text else None

    ai: ScamAnalysis | None = None
    if not text:
        ai_status = "skipped"
    elif not allow_external:
        ai_status = "disabled"
    elif text_provider() is None and not api_key:
        ai_status = "skipped"
    else:
        try:
            report = analyze_message(text[:MAX_TEXT_FOR_AI], api_key=api_key)
            ai = report.ai
            heuristics = report.heuristics
            ai_status = "success"
        except ScamAnalysisError:
            ai_status = "failed"

    empty = HeuristicReport(0, [], "none", [], False, [], [], [], [])
    classification = classify(
        text,
        heuristics or empty,
        url_strong=any(u.strong for u in urls.findings),
        url_suspicious=any(u.suspicious for u in urls.findings),
        vision_indicators=tuple(vision.risk_indicators) if vision else (),
        vision_otp=bool(vision and vision.otp_requests),
    )
    risk = assess(
        heuristics,
        urls.findings,
        text_length=len(text),
        injection_count=len(classification.injection_phrases),
        vision_indicators=len(vision.risk_indicators) if vision else 0,
        vision_otp=bool(vision and vision.otp_requests),
        ai_risk_score=ai.risk_score if ai else None,
        anything_read=bool(text) or bool(qr.codes),
    )

    detected = ocr.language or (vision.language if vision else "") or (detect_language(text) if text else "")

    return ImageScanResult(
        image=image,
        ocr=ocr,
        qr=qr,
        urls=urls,
        vision=vision,
        vision_status=vision_status,
        heuristics=heuristics,
        ai=ai,
        ai_status=ai_status,
        classification=classification,
        risk=risk,
        text=text,
        language=detected[:2] if detected else "",
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )
