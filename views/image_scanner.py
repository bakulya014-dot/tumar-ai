"""Screenshot Scanner page — upload an image, get a trust report.

UI only. The image is read by an optional vision provider and the
verdict is reached by the Trust Engine, exactly as for a pasted
message: this page never decides anything.

Two privacy rules are enforced here rather than described:

- Nothing is uploaded while external AI providers are switched off.
  The control sits above the uploader, so the choice is made before a
  file is chosen, not after it has already been sent.
- The image itself is never stored or contributed. What can be
  contributed is the redacted text read out of it, which is what the
  corpus can actually learn from.
"""

import streamlit as st

import components
import report_store
from components import page_header
from contribution_ui import contribution_box
from i18n import current_language, t
from report_view import render_trust_report
from services.common import ServiceError
from services.providers import vision_provider
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject
from services.vision_analysis import MAX_IMAGE_BYTES

SOURCE = "image_scanner"
ACCEPTED = ["png", "jpg", "jpeg", "webp"]

# Streamlit reports jpg as image/jpeg already, but a browser can send
# an empty type for an unusual file; map from the extension instead of
# trusting whatever arrives.
_MIME_BY_EXTENSION = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
}

page_header(t("image.title"), t("image.subtitle"))

# The privacy decision comes first, above the uploader.
allow_external = st.toggle(
    t("image.allow_external"),
    value=st.session_state.get("allow_external_ai", True),
    key="allow_external_ai",
    help=t("image.allow_external_help"),
)
st.caption(t("image.privacy_note"))

provider = vision_provider() if allow_external else None

if not allow_external:
    st.info(t("image.disabled_by_user"))
elif provider is None:
    st.info(t("image.no_provider"))

upload = st.file_uploader(
    t("image.upload_label"),
    type=ACCEPTED,
    accept_multiple_files=False,
    help=t("image.upload_help"),
    disabled=provider is None,
)

if upload is not None and provider is not None:
    st.image(upload, caption=upload.name, width=320)

analyze_clicked = st.button(
    t("image.analyze_button"),
    type="primary",
    use_container_width=True,
    disabled=provider is None or upload is None,
)

if analyze_clicked and upload is not None:
    payload = upload.getvalue()
    extension = upload.name.rsplit(".", 1)[-1].lower()
    mime_type = _MIME_BY_EXTENSION.get(extension, "")

    if len(payload) > MAX_IMAGE_BYTES:
        st.warning(t("image.too_large"))
    elif not mime_type:
        st.warning(t("image.unsupported"))
    else:
        with st.spinner(t("image.spinner")):
            try:
                report = TrustEngine().analyze(
                    TrustSubject(
                        content=payload,
                        mime_type=mime_type,
                        filename=upload.name,
                        language=current_language(),
                    ),
                    AnalysisContext(api_key=components.get_gemini_api_key()),
                )
            except ServiceError as error:
                components.error_view(f"😕 {t(f'errors.{error.code}')}")
            else:
                report_store.remember(st.session_state, report)

remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    render_trust_report(remembered)
    st.caption(t("image.method_note"))
    # Only the text read out of the image can be contributed — never
    # the image, which is why the preview shows words and not a
    # thumbnail.
    extracted = "\n".join(
        item.detail for item in remembered.evidence if item.kind == "heuristic"
    )
    if extracted:
        contribution_box(extracted, remembered)
else:
    components.empty_state("🖼️", t("image.empty_title"), t("image.empty_text"))
