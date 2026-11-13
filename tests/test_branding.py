"""The Tumar.AI logo set: generated, in sync, well-formed and used everywhere.

    venv\\Scripts\\python.exe tests\\test_branding.py
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import branding  # noqa: E402

BRAND_DIR = ROOT / "assets" / "brand"


def test_files_match_the_generator() -> None:
    for name, svg in branding.brand_files().items():
        on_disk = (BRAND_DIR / name).read_text(encoding="utf-8").strip()
        assert on_disk == svg.strip(), f"{name} is stale: run python scripts/build_brand_assets.py"
    assert (BRAND_DIR / "tumar-favicon.png").stat().st_size > 1000
    print("test_files_match_the_generator PASSED")


def test_svgs_are_well_formed_and_font_free() -> None:
    for name in branding.brand_files():
        text = (BRAND_DIR / name).read_text(encoding="utf-8")
        root = ET.fromstring(text)
        assert root.tag.endswith("svg") and root.get("viewBox"), name
        # Shapes only: a <text> element would depend on a font the image may not have.
        assert "<text" not in text, name
    print("test_svgs_are_well_formed_and_font_free PASSED")


def test_variants_use_the_brand_palette() -> None:
    dark = branding.logo_svg("dark")
    light = branding.logo_svg("light")
    assert branding.INK_DARK_BG in dark and branding.PURPLE in dark
    assert branding.INK_LIGHT_BG in light and branding.AI_ON_LIGHT in light
    assert branding.INK_DARK_BG not in light.split("</g>")[-1]  # wordmark ink differs on light
    print("test_variants_use_the_brand_palette PASSED")


def test_gradient_ids_do_not_collide_on_one_page() -> None:
    a, b = branding.symbol_markup("one"), branding.symbol_markup("two")
    assert 'id="one-l"' in a and 'id="two-l"' in b and 'id="one-l"' not in b
    print("test_gradient_ids_do_not_collide_on_one_page PASSED")


def test_old_branding_is_gone() -> None:
    assert not (ROOT / "assets" / "logo.svg").exists()
    sources = [ROOT / "app.py", ROOT / "components.py", *sorted((ROOT / "views").glob("*.py"))]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert '"logo.svg"' not in text and '/ "logo.svg"' not in text, path.name
        assert "#22D3EE" not in text and "#00F0FF" not in text and "#F5C97B" not in text, path.name
    for css in ("styles.css", "landing.css"):
        text = (ROOT / "assets" / css).read_text(encoding="utf-8").upper()
        for old in ("#22D3EE", "#00F0FF", "#F5C97B", "34, 211, 238", "0, 240, 255"):
            assert old not in text, (css, old)
    print("test_old_branding_is_gone PASSED")


def test_app_uses_the_new_assets() -> None:
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '"tumar-favicon.png"' in app and '"tumar-logo.svg"' in app and '"tumar-symbol.svg"' in app
    print("test_app_uses_the_new_assets PASSED")


if __name__ == "__main__":
    test_files_match_the_generator()
    test_svgs_are_well_formed_and_font_free()
    test_variants_use_the_brand_palette()
    test_gradient_ids_do_not_collide_on_one_page()
    test_old_branding_is_gone()
    test_app_uses_the_new_assets()
    print("All branding tests passed.")
