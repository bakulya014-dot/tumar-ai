"""Write assets/brand/ from branding.py.

    python scripts/build_brand_assets.py

SVG files come straight from branding.py. The favicon PNG (for the
browser tab, via st.set_page_config) is drawn with Pillow from the same
geometry, with each facet in a flat colour: gradients are invisible at
32 pixels anyway.
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import branding  # noqa: E402

OUT = ROOT / "assets" / "brand"


def favicon(size: int = 128) -> Image.Image:
    scale = 8  # draw large, then downsample for smooth edges
    canvas = 64 * scale
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def p(*points):
        return [(x * scale, y * scale) for x, y in points]

    top, right, left = (32, 4), (60.6, 55), (3.4, 55)
    in_top, in_right, in_left = branding._IN_TOP, branding._IN_RIGHT, branding._IN_LEFT
    draw.polygon(p(top, in_top, in_left, left), fill="#1C9BFF")
    draw.polygon(p(top, right, in_right, in_top), fill="#9A74FF")
    draw.polygon(p(left, in_left, in_right, right), fill="#5D63FF")
    draw.polygon(p(in_top, in_right, in_left), fill="#0D1220")
    draw.line(p((25, 37.5), (30, 42.2), (38.6, 31.6)), fill="#F8FAFC", width=int(3.6 * scale), joint="curve")
    for x, y in p((25, 37.5), (38.6, 31.6)):  # round line caps
        r = 1.8 * scale
        draw.ellipse((x - r, y - r, x + r, y + r), fill="#F8FAFC")
    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, svg in branding.brand_files().items():
        (OUT / name).write_text(svg + "\n", encoding="utf-8")
        print("wrote", OUT / name)
    favicon(128).save(OUT / "tumar-favicon.png")
    print("wrote", OUT / "tumar-favicon.png")


if __name__ == "__main__":
    main()
