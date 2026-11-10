"""Screenshot Scanner page — Visual Threat Intelligence.

UI only. The image goes to the Trust Engine, which runs the image
scanner (services/image_scanner): validation, OCR, QR decoding, link
checks, scam patterns, optional vision and text models, risk scoring.
This page never decides anything; it renders the TrustReport and then
the image-specific extras the report carries in analysis_metadata.

Two privacy rules are enforced here rather than described:

- The external-AI toggle sits above the uploader, so the choice is
  made before a file is chosen. With it off, the scan runs entirely on
  this server: nothing — not the image, not the text — leaves it.
- The image itself is never stored or contributed. What can be
  contributed is the redacted text read out of it.
"""

import streamlit as st

import components
import quota_ui
import report_store
from components import page_header
from contribution_ui import contribution_box
from i18n import current_language, t
from report_view import render_trust_report
from services.common import ServiceError
from services.image_scanner import ocr_engine
from services.image_scanner.validator import max_bytes
from services.providers import text_provider, vision_provider
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject

SOURCE = "image_scanner"
ACCEPTED = ["png", "jpg", "jpeg", "webp"]

# Risk level -> chip colour. "inconclusive" is deliberately neutral:
# it is not a warning, it is an admission.
_LEVEL_VARIANTS = {
    "low": "ok",
    "moderate": "warn",
    "high": "danger",
    "critical": "danger",
    "inconclusive": "neutral",
}
_STAGE_VARIANTS = {
    "success": "ok",
    "empty": "neutral",
    "none": "neutral",
    "skipped": "neutral",
    "disabled": "neutral",
    "unavailable": "warn",
    "failed": "warn",
}
_STAGES = (
    ("ocr", "ocr_status"),
    ("qr", "qr_status"),
    ("urls", "url_analysis_status"),
    ("vision", "visual_analysis_status"),
    ("ai", "ai_status"),
)

page_header(t("image.title"), t("image.subtitle"), "image")

# The privacy decision comes first, above the uploader.
allow_external = st.toggle(
    t("image.allow_external"),
    value=st.session_state.get("allow_external_ai", True),
    key="allow_external_ai",
    help=t("image.allow_external_help"),
)
st.caption(components.labeled("privacy", t("image.privacy_note")))

has_vision = vision_provider() is not None
has_text_ai = text_provider() is not None or bool(components.get_gemini_api_key())

if not allow_external:
    st.info(t("image.disabled_by_user"))
elif not has_vision and not has_text_ai:
    st.info(t("image.local_only"))
elif not has_vision:
    st.info(t("image.no_provider"))

if not ocr_engine.available():
    st.caption(t("image.ocr_hint_missing"))

upload = st.file_uploader(
    t("image.upload_label"),
    type=ACCEPTED,
    accept_multiple_files=False,
    help=t("image.upload_help", mb=max_bytes() // (1024 * 1024)),
)

if upload is not None:
    st.image(upload, caption=upload.name, width=320)

analyze_clicked = st.button(
    t("image.analyze_button"),
    type="primary",
    use_container_width=True,
    icon=components.icon("image"),
    disabled=upload is None,
)

if analyze_clicked and upload is not None and quota_ui.allow_check("image"):
    payload = upload.getvalue()
    # The declared type is only a routing hint; the scanner verifies
    # the real format from the bytes and refuses anything else.
    extension = upload.name.rsplit(".", 1)[-1].lower()
    mime_hint = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}.get(
        extension, "image/png"
    )
    with st.spinner(t("image.spinner")):
        try:
            report = TrustEngine().analyze(
                TrustSubject(
                    content=payload,
                    mime_type=mime_hint,
                    filename=upload.name,
                    language=current_language(),
                ),
                AnalysisContext(
                    api_key=components.get_gemini_api_key(),
                    allow_external_ai=allow_external,
                ),
            )
        except ServiceError as error:
            components.error_view(t(f'errors.{error.code}'))
        else:
            report_store.remember(st.session_state, report)

remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    meta = remembered.analysis_metadata
    level = remembered.risk_level or meta.get("risk_level", "")

    if level:
        st.caption(t("image.level_label"))
        components.status_badge(t(f"image.level.{level}"), _LEVEL_VARIANTS.get(level, "neutral"))

    render_trust_report(remembered)

    st.subheader(t("image.details_title"))

    categories = [c for c in meta.get("categories", "").split(", ") if c]
    if categories:
        st.caption(t("image.categories_title"))
        components.chip_row(
            [t(f"image.category.{c}") for c in categories],
            "neutral" if categories == ["inconclusive"] else "warn",
        )

    st.caption(t("image.status_title"))
    components.chip_row(
        [
            f"{t(f'image.stage.{stage}')}: {t(f'image.status.{meta.get(key, 'skipped')}')}"
            for stage, key in _STAGES
        ]
    )

    urls = [u for u in meta.get("urls", "").split("\n") if u]
    qr_codes = [q for q in meta.get("qr_codes", "").split("\n") if q]
    if urls:
        st.caption(t("image.urls_title"))
        for url in urls:
            st.code(url, language=None)
        st.caption(t("image.reputation_note"))
    if qr_codes:
        st.caption(t("image.qr_title"))
        for code in qr_codes:
            st.code(code, language=None)

    extracted = meta.get("extracted_text", "")
    if extracted:
        with st.expander(t("image.text_title")):
            st.text(extracted)

    with st.expander(t("image.limitations_title")):
        st.write(t("image.limitations_text"))
        if meta.get("ocr_status") == "unavailable":
            st.write(t("image.ocr_hint_missing"))
        st.caption(
            t(
                "image.method_note",
                size=meta.get("image_size", ""),
                ms=meta.get("elapsed_ms", ""),
                lang=meta.get("detected_language", "") or "—",
            )
        )

    if extracted:
        contribution_box(extracted, remembered)
else:
    components.empty_state("image", t("image.empty_title"), t("image.empty_text"))
