"""Contract tests for the shared report view.

The renderer resolves i18n keys derived from report data (evidence
codes, metric label keys). A missing key does not crash — t() falls
back to the key itself — so users would silently see raw text like
"trust.evidence_ai" on screen. These tests fail instead, in all three
languages, and they guard every future module too: any new evidence
code or metric must arrive with its translations.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_report_view.py
"""

import json
import sys
from pathlib import Path

# Make the project root and this folder importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from report_view import _METHOD_LABELS, _SIGNAL_LABELS
from services.heuristics import _SUSPICIOUS_TLDS, url_reasons
from services.trust_report import Metric, from_scam_report
from test_trust_report import _sample_scam_report

I18N_DIR = Path(__file__).resolve().parent.parent / "i18n"
LANGUAGES = ("en", "ru", "kk")

# Every reason code services/heuristics.py can emit for a URL.
_URL_REASON_CODES = (
    "shortener",
    "ip_address",
    "punycode",
    "suspicious_tld",
    "no_https",
    "many_hyphens",
    "misleading_subdomain",
    "brand_lookalike",
    "misspelled_domain",
    "trust_bait",
)

# Keys the renderer always resolves, independent of report content.
_STATIC_KEYS = (
    "trust.verdict.safe",
    "trust.verdict.caution",
    "trust.verdict.danger",
    "trust.score_label",
    "trust.confidence",
    "trust.explanation_title",
    "trust.actions_title",
    "trust.evidence_title",
    "trust.evidence_ai",
    "trust.evidence_scanner",
    "trust.evidence_external",
    "trust.evidence_urls",
    "trust.no_evidence",
    "trust.analyzed_at",
    "trust.method_label",
    "trust.privacy_note",
    "scam.metric_confidence_help",
)


def _flatten(node: dict, prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def _keys(language: str) -> set[str]:
    with open(I18N_DIR / f"{language}.json", encoding="utf-8") as fh:
        return set(_flatten(json.load(fh)))


def _assert_resolvable(keys: list[str], label: str) -> None:
    for language in LANGUAGES:
        available = _keys(language)
        missing = [key for key in keys if key not in available]
        assert not missing, f"{language}.json missing {label}: {missing}"


def test_static_renderer_keys_exist() -> None:
    _assert_resolvable(list(_STATIC_KEYS), "renderer keys")
    print("test_static_renderer_keys_exist PASSED")


def test_evidence_label_keys_exist() -> None:
    _assert_resolvable(list(_SIGNAL_LABELS.values()), "signal labels")
    _assert_resolvable(list(_METHOD_LABELS.values()), "method labels")
    print("test_evidence_label_keys_exist PASSED")


def test_every_url_reason_code_has_a_translation() -> None:
    keys = [f"scam.url_reason.{code}" for code in _URL_REASON_CODES]
    _assert_resolvable(keys, "url reason labels")
    print("test_every_url_reason_code_has_a_translation PASSED")


def test_url_reason_codes_list_is_complete() -> None:
    # If heuristics.py gains a reason code, this catches the missing
    # entry above rather than letting it reach users untranslated.
    samples = (
        "http://bit.ly/x",
        "http://192.168.0.1/login",
        "https://xn--80ak6aa92e.com",
        f"https://pay.{next(iter(_SUSPICIOUS_TLDS))}",
        "http://plain-domain.com",
        "https://a-b-c-d.com",
        "https://kaspi.kz.evil.com",
        "https://kaspi-secure.com",
        "https://kapsi.kz",
        "https://secure-login.com",
    )
    seen: set[str] = set()
    for url in samples:
        seen.update(url_reasons(url))
    unknown = seen - set(_URL_REASON_CODES)
    assert not unknown, f"heuristics emits untranslated codes: {sorted(unknown)}"
    print("test_url_reason_codes_list_is_complete PASSED")


def test_adapter_metric_label_keys_exist() -> None:
    report = from_scam_report(_sample_scam_report(), "urgent, send the code")
    assert report.metrics, "scam reports should expose a risk breakdown"
    _assert_resolvable(
        [metric.label_key for metric in report.metrics], "metric labels"
    )
    print("test_adapter_metric_label_keys_exist PASSED")


def test_metric_semantics_are_data_not_color() -> None:
    # The data layer must not carry CSS: it states meaning, and the
    # renderer decides how to paint it.
    metric = Metric(label_key="scam.metric_urgency", value=80)
    assert metric.higher_is_worse is True
    assert not hasattr(metric, "variant")

    from components import metric_variant

    assert metric_variant(80, higher_is_worse=True) == "danger"
    assert metric_variant(80, higher_is_worse=False) == "ok"
    assert metric_variant(40, higher_is_worse=True) == "warn"
    print("test_metric_semantics_are_data_not_color PASSED")


if __name__ == "__main__":
    test_static_renderer_keys_exist()
    test_evidence_label_keys_exist()
    test_every_url_reason_code_has_a_translation()
    test_url_reason_codes_list_is_complete()
    test_adapter_metric_label_keys_exist()
    test_metric_semantics_are_data_not_color()
    print("ALL REPORT VIEW TESTS PASSED")
