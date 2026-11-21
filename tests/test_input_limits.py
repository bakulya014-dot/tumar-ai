"""Oversized and malformed input is refused calmly, never crashes, never costs.

Also checks the CI secret scanner catches a planted credential.
Fake values only, built at runtime.

    venv\\Scripts\\python.exe tests\\test_input_limits.py
"""

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
os.environ["TUMAR_TELEMETRY"] = "off"

import check_secrets  # noqa: E402
from i18n import LANGUAGES, _load  # noqa: E402
from services.image_scanner import ImageValidationError, validate_image  # noqa: E402
from services.trust_engine import MAX_TEXT_CHARS, AnalysisContext, EngineError, TrustEngine, TrustSubject  # noqa: E402


def _code(fn) -> str:
    try:
        fn()
    except (EngineError, ImageValidationError) as exc:
        return exc.code
    raise AssertionError("expected a refusal")


def test_engine_refuses_oversized_text_before_any_analysis() -> None:
    huge = "Send me your SMS code " * (MAX_TEXT_CHARS // 10)
    code = _code(lambda: TrustEngine().analyze(
        TrustSubject(content=huge, declared_kind="message"),
        AnalysisContext(offline_fallback=True),
    ))
    assert code == "too_long"
    # At the limit is still accepted (offline here: no key).
    ok = TrustEngine().analyze(
        TrustSubject(content="x" * MAX_TEXT_CHARS, declared_kind="message"),
        AnalysisContext(offline_fallback=True),
    )
    assert ok.verdict in {"safe", "caution", "danger"}
    print("test_engine_refuses_oversized_text_before_any_analysis PASSED")


def test_every_channel_caps_below_the_engine_limit() -> None:
    pages = {
        "views/scam_analyzer.py": r"MAX_MESSAGE_LENGTH = (\d+)",
        "views/home.py": r"MAX_QUICK_LENGTH = (\d+)",
        "views/url_scanner.py": r"MAX_URL_LENGTH = (\d+)",
    }
    for page, pattern in pages.items():
        source = (ROOT / page).read_text(encoding="utf-8")
        limit = int(re.search(pattern, source).group(1))
        assert limit <= MAX_TEXT_CHARS and "max_chars=" in source, page
    settings = (ROOT / "api" / "settings.py").read_text(encoding="utf-8")
    assert int(re.search(r"max_content_length: int = (\d+)", settings).group(1)) <= MAX_TEXT_CHARS
    api = (ROOT / "api" / "main.py").read_text(encoding="utf-8")
    assert '"too_long": 413' in api
    for language in LANGUAGES:
        assert "errors.too_long" in _load(language), language
    print("test_every_channel_caps_below_the_engine_limit PASSED")


def test_malformed_uploads_are_refused_with_a_code() -> None:
    assert _code(lambda: validate_image(b"")) == "empty_image"
    assert _code(lambda: validate_image(b"%PDF-1.7 not an image at all")) in {"unsupported_image", "image_corrupted"}
    assert _code(lambda: validate_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)) in {"image_corrupted", "unsupported_image"}
    print("test_malformed_uploads_are_refused_with_a_code PASSED")


def test_secret_scanner_flags_a_planted_credential_without_printing_it() -> None:
    fake = "GOCSPX-" + "z" * 28  # built at runtime: never a literal in the repo
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "config.py"
        planted.write_text(f'client_secret = "{fake}"\n', encoding="utf-8")
        original_root = check_secrets.ROOT
        check_secrets.ROOT = Path(tmp)
        try:
            findings = check_secrets.scan([planted])
        finally:
            check_secrets.ROOT = original_root
    assert findings == ["config.py:1: Google OAuth client secret"], findings
    assert fake not in "\n".join(findings)
    print("test_secret_scanner_flags_a_planted_credential_without_printing_it PASSED")


def test_repository_is_clean() -> None:
    assert check_secrets.scan(check_secrets.tracked_files()) == []
    print("test_repository_is_clean PASSED")


if __name__ == "__main__":
    test_engine_refuses_oversized_text_before_any_analysis()
    test_every_channel_caps_below_the_engine_limit()
    test_malformed_uploads_are_refused_with_a_code()
    test_secret_scanner_flags_a_planted_credential_without_printing_it()
    test_repository_is_clean()
    print("All input limit tests passed.")
