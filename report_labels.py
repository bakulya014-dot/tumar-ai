"""Label keys for TrustReport evidence, shared by every channel.

The web report (report_view.py) and the Telegram bot both turn an
evidence code into words through these keys, so a finding is named the
same way wherever it is shown. No Streamlit here: the bot imports it.
"""

# Heuristic signal families -> existing i18n label keys. These four
# predate the shared vocabulary and keep their original keys; every
# other code resolves by convention (see signal_label_key), so a new
# module's evidence appears without touching this file.
SIGNAL_LABELS = {
    "urgency": "scam.signal_urgency",
    "credential": "scam.signal_credential",
    "financial": "scam.signal_financial",
    "manipulation": "scam.signal_manipulation",
}

# Evidence origin -> the label that names the method. A pattern match
# and an AI judgement are not the same kind of claim, and users deserve
# to know which they are reading.
METHOD_LABELS = {
    "heuristic": "trust.evidence_scanner",
    "ai": "trust.evidence_ai",
    "external": "trust.evidence_external",
}


def signal_label_key(code: str) -> str:
    """The i18n key that labels one evidence code.

    Unknown codes resolve to "trust.signal.<code>" rather than being
    dropped. Silently discarding evidence would be the worst possible
    failure mode for this product: the verdict would still appear, but
    the reasons behind it would quietly go missing.
    """
    return SIGNAL_LABELS.get(code, f"trust.signal.{code}")
