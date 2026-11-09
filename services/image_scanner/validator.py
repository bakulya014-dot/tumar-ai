"""Secure image ingestion: accept only what we can prove is an image.

Everything that arrives here is untrusted bytes with a user-supplied
name. Nothing about the name is believed: the format is read from the
file's own signature, the image is decoded under hard size limits, and
what leaves is a freshly re-encoded PNG with no metadata — the original
bytes are never passed further down the pipeline.

The limits are configurable from the environment so a deployment with
more memory can raise them without a code change:

    TUMAR_IMAGE_MAX_BYTES    (default 6 MiB)
    TUMAR_IMAGE_MAX_SIDE     (default 6000 px)
    TUMAR_IMAGE_MAX_PIXELS   (default 24 MP)

Nothing is written to disk and nothing from the upload is executed.
"""

from __future__ import annotations

import io
import os
from dataclasses import dataclass

from PIL import Image, ImageOps, UnidentifiedImageError

from services.common import ServiceError

# Pillow's own decompression-bomb guard. It is set to the same pixel
# limit we enforce ourselves so an oversized image fails inside the
# decoder, before a single row is allocated.
_DEFAULT_MAX_BYTES = 6 * 1024 * 1024
_DEFAULT_MAX_SIDE = 6000
_DEFAULT_MAX_PIXELS = 24_000_000

# Smaller than this and there is nothing to read. Icons and tracking
# pixels are refused rather than analysed into an empty verdict.
MIN_SIDE = 16

# Signature -> (Pillow format, mime type). Formats are matched on the
# bytes, never on the extension the browser or user supplied.
_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"),
    (b"\xff\xd8\xff", "JPEG", "image/jpeg"),
)
_WEBP_RIFF = b"RIFF"
_WEBP_TAG = b"WEBP"

SUPPORTED_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp"})


class ImageValidationError(ServiceError):
    """The upload was refused. `code` selects a localized message."""


@dataclass(frozen=True)
class ValidatedImage:
    """A decoded, re-encoded, metadata-free image ready for analysis."""

    png_bytes: bytes
    width: int
    height: int
    source_mime: str
    source_bytes: int

    @property
    def pixels(self) -> int:
        return self.width * self.height


def _limit(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def max_bytes() -> int:
    return _limit("TUMAR_IMAGE_MAX_BYTES", _DEFAULT_MAX_BYTES)


def max_side() -> int:
    return _limit("TUMAR_IMAGE_MAX_SIDE", _DEFAULT_MAX_SIDE)


def max_pixels() -> int:
    return _limit("TUMAR_IMAGE_MAX_PIXELS", _DEFAULT_MAX_PIXELS)


def sniff_mime(data: bytes) -> str:
    """The image format according to the bytes themselves, or ""."""
    for magic, _fmt, mime in _SIGNATURES:
        if data.startswith(magic):
            return mime
    if data[:4] == _WEBP_RIFF and data[8:12] == _WEBP_TAG:
        return "image/webp"
    return ""


def validate_image(data: bytes) -> ValidatedImage:
    """Prove `data` is a supported image and return a clean copy of it.

    Raises:
        ImageValidationError with one of:
            empty_image, image_too_large, unsupported_image,
            image_corrupted, image_dimensions, image_too_small
    """
    if not data:
        raise ImageValidationError("empty_image")
    if len(data) > max_bytes():
        raise ImageValidationError("image_too_large")

    mime = sniff_mime(data)
    if mime not in SUPPORTED_MIME_TYPES:
        raise ImageValidationError("unsupported_image")

    # Pillow raises DecompressionBombError past this many pixels, so a
    # crafted 1-KB file claiming to be 50 000 × 50 000 never allocates.
    Image.MAX_IMAGE_PIXELS = max_pixels()

    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()  # structural check, no pixel decode yet
    except Image.DecompressionBombError as exc:
        raise ImageValidationError("image_dimensions") from exc
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError) as exc:
        raise ImageValidationError("image_corrupted") from exc

    try:
        with Image.open(io.BytesIO(data)) as image:
            width, height = image.size
            if width > max_side() or height > max_side() or width * height > max_pixels():
                raise ImageValidationError("image_dimensions")
            if width < MIN_SIDE or height < MIN_SIDE:
                raise ImageValidationError("image_too_small")
            # Honour the EXIF orientation tag, then drop EXIF entirely by
            # converting to a fresh RGB image that carries no metadata.
            image = ImageOps.exif_transpose(image)
            image.load()
            clean = Image.new("RGB", image.size, (255, 255, 255))
            if image.mode in ("RGBA", "LA", "P"):
                image = image.convert("RGBA")
                clean.paste(image, mask=image.getchannel("A"))
            else:
                clean.paste(image.convert("RGB"))
    except Image.DecompressionBombError as exc:
        raise ImageValidationError("image_dimensions") from exc
    except ImageValidationError:
        raise
    except (OSError, ValueError) as exc:
        raise ImageValidationError("image_corrupted") from exc

    out = io.BytesIO()
    clean.save(out, format="PNG", optimize=False)
    return ValidatedImage(
        png_bytes=out.getvalue(),
        width=clean.width,
        height=clean.height,
        source_mime=mime,
        source_bytes=len(data),
    )
