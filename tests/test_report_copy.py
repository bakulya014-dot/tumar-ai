"""Report wording: every evidence code has a real label, and the "In short"
sentence fits what was checked.

Both bugs were found in production: the AI evidence chip read "red flag"
(a raw code), and an email breach result said "strong signs of a scam".
The codes are collected from the source, so a new code without a
translation fails here instead of reaching users.

    venv\\Scripts\\python.exe tests\\test_report_copy.py
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import report_view  # noqa: E402
from i18n import LANGUAGES, translate  # noqa: E402
from report_labels import SIGNAL_LABELS  # noqa: E402
from services.trust_report import TrustReport  # noqa: E402


def _emitted_codes() -> set[str]:
    """Every evidence code the services can produce, read from their source."""
    services = ROOT / "services"
    text = "\n".join(p.read_text(encoding="utf-8") for p in services.rglob("*.py"))
    codes = set(re.findall(r'code="([a-z_]+)"', text))
    codes |= set(re.findall(r'"(otp_(?:disclosure|entry))"', text))
    codes |= set(re.findall(r'codes\.append\("(pw_[a-z_]+)"\)', text))
    codes |= set(SIGNAL_LABELS)
    qr = (services / "image_scanner" / "qr_decoder.py").read_text(encoding="utf-8")
    kinds = set(re.findall(r'\(\s*"[^"]+",\s*"([a-z_]+)"\s*\)', qr)) | set(re.findall(r'return "([a-z_]+)"', qr))
    codes |= {f"qr_{k}" for k in kinds if k != "url"}  # link QR codes are reported as qr_link
    heuristics = (services / "heuristics.py").read_text(encoding="utf-8")
    reasons = set(re.findall(r'reasons\.append\("([a-z_]+)"\)', heuristics)) | {"shortener", "punycode", "internal"}
    codes |= {f"url_{r}" for r in reasons}
    return codes


def test_every_emitted_code_has_a_real_label() -> None:
    codes = _emitted_codes()
    assert {"red_flag", "breach", "otp_disclosure", "pw_short", "url_brand_lookalike"} <= codes, codes
    raw = []
    for language in LANGUAGES:
        with _language(language):
            for code in sorted(codes):
                label = report_view.evidence_label(code)
                if label == code.replace("_", " ") or label.startswith(("trust.", "scam.")):
                    raw.append(f"{language}:{code}")
    assert not raw, f"evidence codes shown as raw text: {raw}"
    print(f"test_every_emitted_code_has_a_real_label PASSED ({len(codes)} codes x {len(LANGUAGES)} languages)")


class _language:
    """Render labels in one language (report_view.t reads the session language)."""

    def __init__(self, language: str):
        self.language = language

    def __enter__(self):
        self.saved = report_view.t
        report_view.t = lambda key, **kw: translate(key, self.language, **kw)

    def __exit__(self, *exc):
        report_view.t = self.saved


def _report(kind: str, verdict: str) -> TrustReport:
    return TrustReport(source="test", subject_type=kind, subject_preview="x", verdict=verdict,
                       trust_score=10, confidence=70)


def test_in_short_fits_what_was_checked() -> None:
    assert report_view.summary_key(_report("email", "danger")) == "trust.summary_email.danger"
    assert report_view.summary_key(_report("password", "caution")) == "trust.summary_password.caution"
    for kind in ("message", "url", "image"):
        assert report_view.summary_key(_report(kind, "danger")) == "trust.summary.danger"
    scam_words = {"en": "scam", "ru": "мошен", "kk": "алаяқ"}
    for language, word in scam_words.items():
        for kind in ("email", "password"):
            for verdict in ("safe", "caution", "danger"):
                text = translate(report_view.summary_key(_report(kind, verdict)), language)
                assert not text.startswith("trust."), (language, kind, verdict)
                assert word not in text.lower(), (language, kind, verdict, text)  # a leak is not a "scam"
    print("test_in_short_fits_what_was_checked PASSED")


if __name__ == "__main__":
    test_every_emitted_code_has_a_real_label()
    test_in_short_fits_what_was_checked()
    print("All report copy tests passed.")
