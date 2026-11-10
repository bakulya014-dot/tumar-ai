"""Render a TrustReport as a Telegram message.

The bot shows the same report the web app and the API produce, so a
message gets the same verdict, score and evidence on every channel.
Words come from the shared i18n files in the user's language; anything
quoted from the analysed content is HTML-escaped.
"""

import html

from i18n import translate
from report_labels import METHOD_LABELS, signal_label_key
from services.trust_report import TrustReport

TELEGRAM_LIMIT = 4096
_BADGES = {"safe": "🟢", "caution": "🟡", "danger": "🔴"}
_MAX_FINDINGS = 8


def _shorten(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def format_report(report: TrustReport, title: str, language: str = "en") -> str:
    """The Telegram HTML for one report, always within one message."""
    tr = lambda key, **kw: translate(key, language, **kw)  # noqa: E731
    badge = _BADGES.get(report.verdict, "🟡")
    verdict = tr(f"trust.verdict.{report.verdict}")

    lines = [f"🛡️ <b>{html.escape(title)}</b>", ""]
    if report.subject_preview:
        lines.append(f"🎯 <code>{html.escape(_shorten(report.subject_preview, 100))}</code>")
    lines.append(f"⚖️ {badge} <b>{html.escape(verdict.upper())}</b>")
    lines.append(
        f"📈 {html.escape(tr('trust.score_label'))}: <code>{report.trust_score}/100</code>"
        f" · {html.escape(tr('trust.confidence'))}: {report.confidence}%"
    )

    findings = [e for e in report.evidence][:_MAX_FINDINGS]
    if findings:
        lines += ["", f"🚩 <b>{html.escape(tr('trust.evidence_title'))}</b>"]
        for item in findings:
            label = tr(signal_label_key(item.code))
            method = tr(METHOD_LABELS.get(item.kind, "trust.evidence_scanner"))
            detail = f": <i>{html.escape(_shorten(item.detail, 120))}</i>" if item.detail else ""
            lines.append(f"• {html.escape(label)}{detail} <i>({html.escape(method)})</i>")

    explanation = report.explanation or (tr(report.explanation_key) if report.explanation_key else "")
    if explanation:
        lines += ["", f"💡 <b>{html.escape(tr('trust.explanation_title'))}</b>", html.escape(_shorten(explanation, 900))]

    actions = list(report.recommended_actions) or [tr(k) for k in report.recommended_action_keys]
    if actions:
        lines += ["", f"✅ <b>{html.escape(tr('trust.actions_title'))}</b>"]
        lines += [f"• {html.escape(_shorten(a, 300))}" for a in actions[:4]]

    lines += ["", f"<i>{html.escape(tr('trust.privacy_note'))}</i>"]
    text = "\n".join(lines)
    if len(text) > TELEGRAM_LIMIT:  # long AI text: keep the verdict, drop the tail
        text = text[: TELEGRAM_LIMIT - 2].rsplit("\n", 1)[0] + "\n…"
    return text
