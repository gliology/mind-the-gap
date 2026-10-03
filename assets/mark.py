"""The Mind the Gap mark: a red shield with a blue bar across it reading MIND THE GAP,
in the spirit of the popular London souvenir signs.

This is the drawing library; `export.py` next to it writes the actual files. The
word outlines are shaped with HarfBuzz and traced from a classic London signage face,
which is not in the repository (see FONT below), so regeneration
needs the assets dev shell plus the font:

    MTG_FONT=/path/to/the-font.ttf \
      nix develop .#assets -c python3 assets/export.py
"""

import os
import pathlib

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

# The words are set in a classic London signage face. The font is NOT part of this
# repository, regeneration takes the font file by path.
FONT = pathlib.Path(os.environ["MTG_FONT"]) if "MTG_FONT" in os.environ else None


def text_width(text, font_path, size, **axes):
    """Total advance width of `text` at `size`, in canvas units."""
    blob = hb.Blob.from_file_path(str(font_path))
    face = hb.Face(blob)
    font = hb.Font(face)
    if axes:
        font.set_variations(axes)
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": False})
    return sum(p.x_advance for p in buf.glyph_positions) * size / face.upem


def text_paths(text, font_path, size, cx, baseline, **axes):
    """Centre `text` at cx on `baseline`, return SVG path data (glyphs as outlines)."""
    tt = TTFont(font_path)
    if "fvar" in tt:
        tt = instancer.instantiateVariableFont(tt, axes, inplace=True)
    blob = hb.Blob.from_file_path(str(font_path))
    face = hb.Face(blob)
    font = hb.Font(face)
    if axes:
        font.set_variations(axes)
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": False})
    names = tt.getGlyphOrder()
    gs = tt.getGlyphSet()
    s = size / face.upem
    total = sum(p.x_advance for p in buf.glyph_positions) * s
    x = cx - total / 2
    out = []
    for i, p in zip(buf.glyph_infos, buf.glyph_positions):
        pen = SVGPathPen(gs, ntos=lambda v: f"{v:.1f}".rstrip("0").rstrip("."))
        gs[names[i.codepoint]].draw(
            TransformPen(pen, (s, 0, 0, -s, x + p.x_offset * s, baseline))
        )
        out.append(pen.getCommands())
        x += p.x_advance * s
    return " ".join(out)


# The shield's outer box is 78x96; the other relationships are the reference sign's:
# bar aspect 1024:167 with its overhang past the shield, word cap height 0.527 of the
# bar, bar centre on the golden section of the shield's height. The ring weight sits
# above the sign's 0.182 because a shield's taper reads lighter than a closed ring.
VIEWBOX = "0 0 100 98"
SHIELD = "M50 10C67.6 10 80 13 80 19V48.5C80 70.3 65.9 81.3 50 88C34.1 81.3 20 70.3 20 48.5V19C20 13 32.4 10 50 10Z"
# The circular sign, drawn with the same command skeleton (M C V C C V C Z) so a
# browser can interpolate it into the shield
CIRCLE = "M50 19C66.6 19 80 32.4 80 49V49C80 65.6 66.6 79 50 79C33.4 79 20 65.6 20 49V49C20 32.4 33.4 19 50 19Z"
STROKE = 18

# The sign palette: red #dc241f, blue #0019a8, white words. Fixed on purpose: a sign
# does not follow the viewer's colour scheme.
RED, BLUE, WHITE = "#dc241f", "#0019a8", "#fff"


def cap_ratio(font_path):
    """Cap height as a share of the em, from the font's own metrics."""
    tt = TTFont(font_path)
    try:
        return tt["OS/2"].sCapHeight / tt["head"].unitsPerEm
    except (KeyError, AttributeError, ZeroDivisionError):
        return 0.7


# The bar at the sign's aspect, its centre on the golden section of the outer box
BAR_H = 98 * 167 / 1024
BAR_Y = 1 + (97 - 1) * 0.382 - BAR_H / 2


def mtg_mark():
    """The mark's inner SVG: red shield, blue bar across it, white words."""
    if FONT is None:
        raise SystemExit("MTG_FONT must point at the font file for the words")
    cr = cap_ratio(FONT)
    # Size follows the sign's cap-height share of the bar; every rendition carries
    # the full words
    size = 0.527 * BAR_H / cr
    cap = size * cr / 2
    path = text_paths("MIND THE GAP", FONT, size, 50, BAR_Y + BAR_H / 2 + cap)
    return (
        f'<path d="{SHIELD}" fill="none" stroke="{RED}" stroke-width="{STROKE}" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
        + f'<rect x="1" y="{BAR_Y:.2f}" width="98" height="{BAR_H:.2f}" fill="{BLUE}"/>'
        + f'<path d="{path}" fill="{WHITE}"/>'
    )
