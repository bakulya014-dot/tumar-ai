"""Tumar.AI Visual Threat Intelligence — the image scanner.

    from services.image_scanner import scan_image, to_trust_report

    result = scan_image(upload_bytes, api_key=key, language="ru")
    report = to_trust_report(result, filename)

Layers, each in its own module and each testable alone:

    validator       signatures, size and pixel limits, re-encode, strip EXIF
    preprocessing   grayscale / upscale / denoise / threshold / deskew
    ocr_engine      Tesseract, kaz+rus+eng, status-not-exception
    qr_decoder      OpenCV QR detection; payloads classified, never opened
    url_extractor   links from OCR, QR and vision; platform URL heuristics
    classifier      scam-intent categories; prompt-injection phrases
    risk_engine     documented, grouped scoring -> five risk levels
    pipeline        runs the layers, records a status for each
    report          ImageScanResult -> TrustReport
"""

from services.image_scanner.pipeline import ImageScanResult, scan_image
from services.image_scanner.report import to_trust_report
from services.image_scanner.validator import (
    SUPPORTED_MIME_TYPES,
    ImageValidationError,
    ValidatedImage,
    validate_image,
)

__all__ = [
    "SUPPORTED_MIME_TYPES",
    "ImageScanResult",
    "ImageValidationError",
    "ValidatedImage",
    "scan_image",
    "to_trust_report",
    "validate_image",
]
