"""Settings & Safety — privacy, language and accessibility, a safety checklist, official resources.

Open to guests and signed-in users alike. Every choice here lasts for
this browser session only: the free deployment keeps no settings or
check history on disk, and the page says so.
"""

import streamlit as st

import checklist_ui
import components
import report_store
from i18n import LANGUAGES, current_language, t
from services import safety_resources

components.page_header(t("settings.title"), t("settings.subtitle"), "tune")
st.caption(t("settings.session_only"))

# --- Privacy ---
components.section_header(t("settings.privacy_title"), icon_name="privacy")
ai_on = components.pref_toggle(t("settings.allow_ai"), components.PREF_ALLOW_AI, default=True)
st.caption(t("settings.allow_ai_on" if ai_on else "settings.allow_ai_off"))

# Session state kept on purpose: language and these settings themselves.
_SESSION_DATA = (checklist_ui.TICKS, "_res_prev", "_feedback")
if st.button(t("settings.clear_button"), icon=components.icon("delete")):
    report_store.clear(st.session_state)
    for key in _SESSION_DATA:
        st.session_state.pop(key, None)
    for key in [k for k in st.session_state if str(k).startswith("_w_habit_") or str(k).startswith("_w_2fa_")]:
        del st.session_state[key]
    st.success(t("settings.cleared"))
st.caption(t("settings.clear_help"))

# --- Language and accessibility ---
components.section_header(t("settings.access_title"), icon_name="translate")
codes = list(LANGUAGES)


def _set_language() -> None:
    st.session_state["language"] = st.session_state["_w_settings_language"]


st.selectbox(
    t("settings.language"), codes, index=codes.index(current_language()),
    format_func=LANGUAGES.get, key="_w_settings_language", on_change=_set_language,
)
components.pref_toggle(t("settings.large_text"), components.PREF_LARGE_TEXT, help_text=t("settings.large_text_help"))
components.pref_toggle(t("settings.simple"), components.PREF_SIMPLE, help_text=t("settings.simple_help"))

# --- Personal safety checklist ---
components.section_header(t("checklist.title"), t("checklist.caption"), icon_name="actions")
checklist_ui.render()

# --- Official resources ---
components.section_header(t("settings.resources_title"), icon_name="link")
resources = safety_resources.verified()
if resources:
    st.caption(t("settings.resources_note"))
    for resource in resources:
        st.markdown(
            f"- [{resource.name}]({resource.url}) · `{resource.host}` · {t('settings.external_link')}  \n"
            f"  {t(resource.description_key)}"
        )
else:
    st.caption(t("settings.resources_pending"))

# --- What Tumar can and cannot do ---
st.info(t("settings.limits"), icon=components.icon("info"))
