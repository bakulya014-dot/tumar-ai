"""QR code detection and decoding with OpenCV.

OpenCV's detector needs no system dependency, which is why it was
chosen over pyzbar (libzbar is not installable from packages.txt on
every host). It reads one or many codes per image.

A decoded payload is DATA. It is classified here — URL, text, Wi-Fi
credentials, payment request — and handed on for analysis; it is
never opened, fetched or executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import cv2
import numpy as np

# Payload kinds, by prefix, lower-cased. Order matters: more specific
# first.
_KINDS: tuple[tuple[str, str], ...] = (
    ("http://", "url"),
    ("https://", "url"),
    ("wifi:", "wifi"),
    ("mailto:", "email"),
    ("tel:", "phone"),
    ("sms:", "sms"),
    ("smsto:", "sms"),
    ("bitcoin:", "crypto"),
    ("ethereum:", "crypto"),
    ("upi:", "payment"),
    ("begin:vcard", "contact"),
)

# A bare domain without scheme is still a link to most phone cameras.
_BARE_DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}(?:[/?#].*)?$", re.IGNORECASE)

# Payloads longer than this are not what a QR code on a screen should
# carry; they are kept but truncated in the report.
MAX_PAYLOAD_PREVIEW = 300


@dataclass(frozen=True)
class QrCode:
    payload: str
    kind: str  # url | wifi | email | phone | sms | crypto | payment | contact | text
    bbox: tuple[int, int, int, int]  # x, y, w, h in source pixels

    @property
    def is_link(self) -> bool:
        return self.kind == "url"

    @property
    def preview(self) -> str:
        text = self.payload
        return text if len(text) <= MAX_PAYLOAD_PREVIEW else text[:MAX_PAYLOAD_PREVIEW] + "…"


@dataclass(frozen=True)
class QrResult:
    status: str  # "success" | "none" | "failed"
    codes: tuple[QrCode, ...] = ()
    detail: str = ""


def classify_payload(payload: str) -> str:
    lowered = payload.strip().lower()
    for prefix, kind in _KINDS:
        if lowered.startswith(prefix):
            return kind
    if _BARE_DOMAIN.match(lowered) and " " not in lowered:
        return "url"
    return "text"


def _bbox(points: np.ndarray) -> tuple[int, int, int, int]:
    xs = points[:, 0]
    ys = points[:, 1]
    return (int(xs.min()), int(ys.min()), int(xs.max() - xs.min()), int(ys.max() - ys.min()))


def decode_qr(image: np.ndarray) -> QrResult:
    """Find and decode every QR code in a BGR array. Never raises."""
    detector = cv2.QRCodeDetector()
    try:
        found, payloads, points, _ = detector.detectAndDecodeMulti(image)
    except cv2.error as exc:
        return QrResult(status="failed", detail=str(exc).splitlines()[0][:120])

    if not found or points is None:
        return QrResult(status="none")

    codes: list[QrCode] = []
    for payload, quad in zip(payloads, points):
        text = (payload or "").strip()
        if not text:
            # Detected but undecodable: damaged, too small, or not a
            # QR code at all. Reported as such rather than invented.
            continue
        codes.append(QrCode(payload=text, kind=classify_payload(text), bbox=_bbox(quad)))

    if not codes:
        return QrResult(status="failed", detail="detected_but_unreadable")
    return QrResult(status="success", codes=tuple(codes))
