"""Multilingual OCR (Kazakh, Russian, English) through Tesseract.

Tesseract is a system binary, not a pip package, so it may be missing:
on Streamlit Community Cloud it is installed from packages.txt, on a
developer's Windows machine it has to be installed by hand. Absence is
reported as a status, never raised — the rest of the scanner (QR codes,
the vision model) keeps working, and the report says honestly that
text could not be read locally.

Configuration:
    TESSERACT_CMD   full path to the tesseract executable (optional)
    TUMAR_OCR_LANGS languages to load, "+"-joined (default kaz+rus+eng)
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from functools import lru_cache

import numpy as np

from services.image_scanner import preprocessing
from services.language import detect as detect_language

_DEFAULT_LANGS = ("kaz", "rus", "eng")

# Where the official Windows installer puts the binary.
_WINDOWS_DEFAULT = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Page segmentation 6 = "assume a single uniform block of text", which
# is the right prior for chat bubbles, notifications and web pages.
_TESSERACT_CONFIG = "--psm 6"

# Tesseract reports -1 for layout boxes that hold no recognized word.
_NO_CONFIDENCE = -1

_WHITESPACE = re.compile(r"[ \t]+")
_BLANK_LINES = re.compile(r"\n{3,}")


@dataclass(frozen=True)
class OcrResult:
    """What the text engine read, and how far to trust it."""

    status: str  # "success" | "empty" | "unavailable" | "failed"
    text: str = ""
    confidence: int = 0  # 0-100 mean word confidence
    language: str = ""  # en / ru / kk, from the text itself
    languages_loaded: tuple[str, ...] = ()
    word_count: int = 0
    skew_corrected: float = 0.0
    detail: str = ""
    regions: tuple[tuple[int, int, int, int], ...] = field(default=())


def _tesseract_path() -> str:
    for candidate in (os.environ.get("TESSERACT_CMD", ""), shutil.which("tesseract"), _WINDOWS_DEFAULT):
        if candidate and os.path.exists(candidate):
            return candidate
    return ""


@lru_cache(maxsize=1)
def available() -> bool:
    """Whether Tesseract can be called at all. Cached per process."""
    path = _tesseract_path()
    if not path:
        return False
    try:
        import pytesseract

        pytesseract.pytesseract.tesseract_cmd = path
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


@lru_cache(maxsize=1)
def languages() -> tuple[str, ...]:
    """The requested languages that this installation actually has."""
    if not available():
        return ()
    import pytesseract

    wanted = tuple(
        lang for lang in os.environ.get("TUMAR_OCR_LANGS", "+".join(_DEFAULT_LANGS)).split("+") if lang
    )
    try:
        installed = set(pytesseract.get_languages(config=""))
    except Exception:
        installed = set()
    present = tuple(lang for lang in wanted if lang in installed)
    return present or (("eng",) if "eng" in installed else ())


def _clean(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = _WHITESPACE.sub(" ", raw).strip()
        # Lines with no letters or digits are box-drawing noise.
        if sum(ch.isalnum() for ch in line) >= 2:
            lines.append(line)
    return _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()


def read_text(image: np.ndarray) -> OcrResult:
    """Run OCR over a BGR array. Never raises."""
    if not available():
        return OcrResult(status="unavailable", detail="tesseract_missing")
    langs = languages()
    if not langs:
        return OcrResult(status="unavailable", detail="no_language_data")

    import pytesseract

    try:
        prepared = preprocessing.for_ocr(image)
        prepared, angle = preprocessing.deskew(prepared)
        data = pytesseract.image_to_data(
            prepared,
            lang="+".join(langs),
            config=_TESSERACT_CONFIG,
            output_type=pytesseract.Output.DICT,
        )
    except Exception as exc:  # pytesseract wraps many failure modes
        return OcrResult(status="failed", detail=type(exc).__name__, languages_loaded=langs)

    words: list[str] = []
    confidences: list[float] = []
    regions: list[tuple[int, int, int, int]] = []
    current_line: tuple[int, int, int] | None = None
    line_words: list[str] = []
    lines: list[str] = []

    for i, word in enumerate(data.get("text", [])):
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError, IndexError):
            conf = _NO_CONFIDENCE
        token = (word or "").strip()
        line_key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        if current_line is not None and line_key != current_line and line_words:
            lines.append(" ".join(line_words))
            line_words = []
        current_line = line_key
        if not token or conf == _NO_CONFIDENCE:
            continue
        line_words.append(token)
        words.append(token)
        confidences.append(conf)
        regions.append((data["left"][i], data["top"][i], data["width"][i], data["height"][i]))
    if line_words:
        lines.append(" ".join(line_words))

    text = _clean("\n".join(lines))
    if not text:
        return OcrResult(status="empty", languages_loaded=langs, skew_corrected=angle)

    confidence = int(round(sum(confidences) / len(confidences))) if confidences else 0
    return OcrResult(
        status="success",
        text=text,
        confidence=max(0, min(100, confidence)),
        language=detect_language(text),
        languages_loaded=langs,
        word_count=len(words),
        skew_corrected=angle,
        regions=tuple(regions[:200]),
    )
