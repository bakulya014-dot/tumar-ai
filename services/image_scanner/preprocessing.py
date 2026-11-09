"""Image preparation for OCR and QR detection.

Screenshots arrive at phone resolution, often compressed, sometimes
photographed off another screen at an angle. These steps make them
more readable by a text engine and are all pure array operations:

    to_array     PNG bytes -> BGR numpy array
    for_ocr      grayscale, upscale small images, denoise, threshold
    deskew       straighten text that is slightly rotated

OpenCV is a required dependency of this package (opencv-python-headless
needs no display libraries), so these never fail for want of it.
"""

from __future__ import annotations

import cv2
import numpy as np

# Tesseract reads best at roughly 30 px of x-height. Phone screenshots
# are usually sharper than that, but cropped chat bubbles are not;
# anything narrower than this is scaled up before OCR.
_MIN_OCR_WIDTH = 1200

# Rotations below this are noise from the estimator, not real skew.
_MIN_SKEW_DEGREES = 0.5
# Rotations above this are a sideways image, not a skewed one, and a
# naive rotation would make things worse.
_MAX_SKEW_DEGREES = 15.0


def to_array(png_bytes: bytes) -> np.ndarray:
    """Decode validated PNG bytes into a BGR array."""
    buffer = np.frombuffer(png_bytes, dtype=np.uint8)
    image = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("png bytes did not decode")
    return image


def for_ocr(image: np.ndarray) -> np.ndarray:
    """Return a cleaned grayscale image tuned for text recognition."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image.copy()

    height, width = gray.shape[:2]
    if width < _MIN_OCR_WIDTH:
        scale = _MIN_OCR_WIDTH / width
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # Dark-mode screenshots (light text on dark) are inverted so the
    # engine always sees dark text on a light background.
    if gray.mean() < 110:
        gray = cv2.bitwise_not(gray)

    gray = cv2.fastNlMeansDenoising(gray, None, h=7)
    gray = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 11
    )
    return gray


def estimate_skew(binary: np.ndarray) -> float:
    """Estimate the text rotation in degrees (positive = anticlockwise)."""
    inverted = cv2.bitwise_not(binary)
    coords = cv2.findNonZero(inverted)
    if coords is None or len(coords) < 50:
        return 0.0
    angle = cv2.minAreaRect(coords)[-1]
    # minAreaRect reports in (-90, 0]; fold into a small signed skew.
    if angle < -45:
        angle += 90
    elif angle > 45:
        angle -= 90
    return float(angle)


def deskew(image: np.ndarray, angle: float | None = None) -> tuple[np.ndarray, float]:
    """Rotate `image` to straighten slightly skewed text.

    Returns the (possibly unchanged) image and the angle applied.
    """
    if angle is None:
        angle = estimate_skew(image)
    if abs(angle) < _MIN_SKEW_DEGREES or abs(angle) > _MAX_SKEW_DEGREES:
        return image, 0.0
    height, width = image.shape[:2]
    matrix = cv2.getRotationMatrix2D((width / 2, height / 2), angle, 1.0)
    border = 255 if image.ndim == 2 else (255, 255, 255)
    rotated = cv2.warpAffine(
        image, matrix, (width, height),
        flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_CONSTANT, borderValue=border,
    )
    return rotated, angle
