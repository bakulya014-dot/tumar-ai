"""The one way Tumar.AI presents a Trust Report.

Every module — today's three, and Browser Protection, Payment Scam
Detector, Deepfake Checker, and the AI Agent Recorder later — renders
its result through render_trust_report(). A new module page therefore
inherits the platform's layout, trust signals, and accessibility
behavior for free, and cannot drift into its own visual dialect.

Layout, fixed for every module:

    verdict + trust score
    confidence and module metrics
    what is going on (explanation)
    what you should do (recommendations)
    evidence, grouped by who found it     [collapsed by default]
    footer: timestamp · method · privacy

Nothing here knows which module produced the report; it reads only the
TrustReport schema. Free-text fields (AI modules) and translation-key
fields (deterministic modules) are both handled, so callers never
branch on the module either.
"""

import html
from collections import OrderedDict

import streamlit as st

import components
from i18n import t
from services.trust_report import Evidence, TrustReport

# Heuristic signal families -> existing i18n label keys. These five
# predate the shared vocabulary and keep their original keys; every
# other code resolves by convention (see signal_label_key), so a new
# module's evidence appears without touching this file.
_SIGNAL_LABELS = {
    "urgency": "scam.signal_urgency",
    "credential": "scam.signal_credential",
    "financial": "scam.signal_financial",
    "manipulation": "scam.signal_manipulation",
    "otp": "scam.otp_label",
}


def signal_label_key(code: str) -> str:
    """The i18n key that labels one heuristic evidence code.

    Unknown codes resolve to "trust.signal.<code>" rather than being
    dropped. Silently discarding evidence would be the worst possible
    failure mode for this product: the verdict would still appear, but
    the reasons behind it would quietly go missing.
    """
    return _SIGNAL_LABELS.get(code, f"trust.signal.{code}")

# Evidence origin -> the label shown to the user. Naming the method is
# a trust signal: a pattern match and an AI judgement are not the same
# kind of claim, and users deserve to know which they are reading.
_METHOD_LABELS = {
    "heuristic": "trust.evidence_scanner",
    "ai": "trust.evidence_ai",
    "external": "trust.evidence_external",
}


def render_trust_report(report: TrustReport, expand_evidence: bool = False) -> None:
    """Render one Trust Report in the platform's standard layout."""
    components.verdict_card(
        components.TRUST_CSS_VARIANTS[report.verdict],
        t(f"trust.verdict.{report.verdict}"),
        report.trust_score,
        t("trust.score_label"),
    )

    _render_metrics(report)

    st.subheader(t("trust.explanation_title"))
    st.write(_text(report.explanation, report.explanation_key))

    actions = report.recommended_actions or [
        t(key) for key in report.recommended_action_keys
    ]
    if actions:
        st.subheader(t("trust.actions_title"))
        for number, action in enumerate(actions, start=1):
            st.markdown(f"{number}. {action}")

    _render_evidence(report, expand_evidence)
    _render_footer(report)


def _text(free_text: str, key: str) -> str:
    """AI modules send free text; deterministic modules send a key."""
    if free_text:
        return free_text
    return t(key) if key else ""


def _render_metrics(report: TrustReport) -> None:
    """Confidence plus whatever breakdown the module reported.

    Confidence comes first and is never colored as a risk: a low
    confidence is a caveat, not a threat.
    """
    cells = st.columns(2)
    with cells[0]:
        components.meter(
            t("trust.confidence"),
            report.confidence,
            "brand",
            t("scam.metric_confidence_help"),
        )
    for index, metric in enumerate(report.metrics, start=1):
        with cells[index % 2]:
            components.meter(
                t(metric.label_key),
                metric.value,
                components.metric_variant(metric.value, metric.higher_is_worse),
            )


def _render_evidence(report: TrustReport, expanded: bool) -> None:
    """Group evidence by origin, collapsed unless asked otherwise.

    Progressive disclosure: the verdict, the story, and the next steps
    are what most users need. The full evidence trail stays one click
    away for the users — and auditors — who want to check the work.
    """
    if not report.evidence:
        st.caption(t("trust.no_evidence"))
        return

    with st.expander(t("trust.evidence_title"), expanded=expanded):
        links = [item for item in report.evidence if item.code.startswith("url_")]
        if links:
            st.markdown(f"**{t('trust.evidence_urls')}**")
            for url, codes in _group_url_reasons(links).items():
                reasons = "; ".join(
                    t(f"scam.url_reason.{code.removeprefix('url_')}")
                    for code in codes
                )
                components.threat_card(url, reasons)

        flags = [item.detail for item in report.evidence if item.kind == "ai"]
        if flags:
            st.markdown(f"**{t('trust.evidence_ai')}**")
            components.chip_row(flags, "danger")

        _render_group(
            "trust.evidence_scanner", _group_by_code(report.evidence, "heuristic"), "warn"
        )
        _render_group(
            "trust.evidence_external", _group_by_code(report.evidence, "external"), "danger"
        )


def _group_url_reasons(links: list[Evidence]) -> "OrderedDict[str, list[str]]":
    """One card per link, listing every reason found for it."""
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    for item in links:
        grouped.setdefault(item.detail, []).append(item.code)
    return grouped


def _group_by_code(
    evidence: list[Evidence], kind: str
) -> "OrderedDict[str, list[str]]":
    """Findings of one origin, grouped by code and labeled.

    Every finding is kept — an unrecognized code gets a conventional
    label key instead of disappearing. Link findings are excluded
    because they are drawn as their own cards above.
    """
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    for item in evidence:
        if item.kind != kind or item.code.startswith("url_"):
            continue
        grouped.setdefault(signal_label_key(item.code), []).append(item.detail)
    return grouped


def _render_group(
    header_key: str, grouped: "OrderedDict[str, list[str]]", variant: str
) -> None:
    """Draw one origin's findings under a heading.

    Some findings quote what was matched (a scam phrase, a breach
    name) and read as "label: these values". Others are the finding
    itself (a password is too short) and read as a single statement.
    The first kind gets a label plus chips, the second becomes a chip.
    """
    if not grouped:
        return
    st.markdown(f"**{t(header_key)}**")
    bare: list[str] = []
    for label_key, details in grouped.items():
        quoted = [detail for detail in details if detail]
        if quoted:
            st.caption(t(label_key))
            components.chip_row(quoted, variant)
        else:
            bare.append(t(label_key))
    if bare:
        components.chip_row(bare, variant)


def _render_footer(report: TrustReport) -> None:
    """Timestamp, detection method, and the privacy promise.

    These are the product's trust signals. They are deliberately
    factual — the footer states how the verdict was reached, never
    how certain it is; certainty is the confidence meter's job.
    """
    stamp = report.created_at.strftime("%Y-%m-%d %H:%M UTC")
    methods = ", ".join(t(key) for key in _method_keys(report))
    parts = [
        t("trust.analyzed_at", time=stamp),
        t("trust.method_label", methods=methods),
        t("trust.privacy_note"),
    ]
    cells = "".join(f"<span>{html.escape(part)}</span>" for part in parts)
    st.markdown(f'<div class="t-foot">{cells}</div>', unsafe_allow_html=True)


def _method_keys(report: TrustReport) -> list[str]:
    """Which detection methods actually contributed to this report."""
    kinds = {item.kind for item in report.evidence}
    if not kinds:
        # No evidence to cite: an AI module still reasoned about it,
        # a deterministic module still consulted its source.
        kinds = {"ai"} if report.explanation else {"external"}
    return [_METHOD_LABELS[kind] for kind in ("heuristic", "ai", "external") if kind in kinds]
