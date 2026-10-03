#!/usr/bin/env python3
"""Export the Mind the Gap mark: colour and monochrome SVGs, PNG icons, a favicon.ico,
and two text shields for the live image's banner.

Writes into this directory unless another output directory is given. Run inside the
assets dev shell (raster tools and python), with the word font supplied by path:

    MTG_FONT=/path/to/the-font.ttf \
      nix develop .#assets -c python3 assets/export.py
"""

import pathlib
import subprocess
import sys

import mark

OUT = pathlib.Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent
OUT.mkdir(parents=True, exist_ok=True)


def svg(body, fg="currentColor"):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{mark.VIEWBOX}" fill="{fg}" '
        f'color="{fg}" role="img" aria-label="Mind the Gap">{body}</svg>\n'
    )


def mono(body):
    # One colour for inline use: shield and bar in the text colour, words stay knocked out
    return body.replace(mark.RED, "currentColor").replace(mark.BLUE, "currentColor")


# Every size carries the full words; there is no separate small form
full = mark.mtg_mark()


def animated(body):
    """The mark morphing from the circular sign it descends from: same bar and words, the
    shield interpolating from the circle twin, the bar riding from the circle's centre
    up to its golden-section home. Pure SMIL, so it plays anywhere an SVG renders."""
    import re
    bar = re.search(r'<rect x="1" y="([0-9.]+)" width="98" height="([0-9.]+)"', body)
    bar_y, bar_h = float(bar.group(1)), float(bar.group(2))
    words = re.search(r'<path d="(M[^"]+)" fill="#fff"/>', body).group(1)
    circle_bar_y = 49 - bar_h / 2
    dy = circle_bar_y - bar_y
    timing = ('dur="6s" repeatCount="indefinite" calcMode="spline" '
              'keyTimes="0;.25;.5;.75;1" keySplines=".4 0 .2 1;0 0 1 1;.4 0 .2 1;0 0 1 1"')
    return (
        f'<path fill="none" stroke="{mark.RED}" stroke-width="{mark.STROKE}" '
        f'stroke-linejoin="round" stroke-linecap="round" d="{mark.CIRCLE}">'
        f'<animate attributeName="d" {timing} '
        f'values="{mark.CIRCLE};{mark.SHIELD};{mark.SHIELD};{mark.CIRCLE};{mark.CIRCLE}"/></path>'
        f'<rect x="1" y="{circle_bar_y:.2f}" width="98" height="{bar_h:.2f}" fill="{mark.BLUE}">'
        f'<animate attributeName="y" {timing} '
        f'values="{circle_bar_y:.2f};{bar_y:.2f};{bar_y:.2f};{circle_bar_y:.2f};{circle_bar_y:.2f}"/></rect>'
        f'<g transform="translate(0 {dy:.2f})" fill="#fff">'
        f'<animateTransform attributeName="transform" type="translate" {timing} '
        f'values="0 {dy:.2f};0 0;0 0;0 {dy:.2f};0 {dy:.2f}"/>'
        f'<path d="{words}"/></g>'
    )


files = {
    "logo.svg": svg(full),  # the sign's own palette, fixed on any background
    "logo-mono.svg": svg(mono(full)),
    "logo-animated.svg": svg(animated(svg(full))),
}
for name, content in files.items():
    (OUT / name).write_text(content)


# The palette is literal now, so the rasters render straight from the shipped SVGs.
# The canvas is taller than wide; rasters fit the height and pad to a square with
# transparency, since icons and favicons want square pixels.
def png(src, size, name):
    subprocess.run(["resvg", "-h", str(size), str(OUT / src), str(OUT / name)], check=True)
    subprocess.run(
        ["magick", str(OUT / name), "-background", "none", "-gravity", "center",
         "-extent", f"{size}x{size}", str(OUT / name)],
        check=True,
    )
    subprocess.run(["oxipng", "-o", "4", "--strip", "safe", "-q", str(OUT / name)], check=True)


png("logo.svg", 512, "logo-512.png")
png("logo.svg", 192, "logo-192.png")
for size in (64, 48, 32, 16):
    png("logo.svg", size, f"icon-{size}.png")
subprocess.run(
    ["magick", str(OUT / "icon-16.png"), str(OUT / "icon-32.png"), str(OUT / "icon-48.png"), str(OUT / "favicon.ico")],
    check=True,
)

# The coloured banner is rasterised from the shield itself: supersampled, mirror-
# symmetrised, the tail forced onto a monotone staircase, a three-row box composed
# over it with the words bold on the bar. Stroke 15.75 keeps air between crown and
# box while the tail stays solid.
BANNER_COLS, BANNER_ROWS, BAR_ROWS = 16, 9, (2, 3, 4)
BANNER_STROKE, BANNER_SS, BANNER_THRESH = 15.75, 8, 0.45
RGB = {name: tuple(int(value[i:i+2], 16) for i in (1, 3, 5))
       for name, value in (("red", mark.RED), ("blue", mark.BLUE), ("white", "#f1f1f1"))}


def banner_coverage():
    """Per half-cell ink coverage of the bar-less shield, supersampled."""
    cols, rows, ss = BANNER_COLS, BANNER_ROWS, BANNER_SS
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{mark.VIEWBOX}" '
           f'width="{cols*ss}" height="{rows*2*ss}" preserveAspectRatio="none">'
           f'<path d="{mark.SHIELD}" fill="none" stroke="{mark.RED}" '
           f'stroke-width="{BANNER_STROKE}" stroke-linejoin="round" stroke-linecap="round"/></svg>')
    tmp = OUT / ".banner"
    tmp.mkdir(exist_ok=True)
    (tmp / "shield.svg").write_text(svg)
    subprocess.run(["resvg", str(tmp / "shield.svg"), str(tmp / "shield.png")], check=True)
    subprocess.run(["magick", str(tmp / "shield.png"), "-depth", "8", "-colorspace", "sRGB",
                    "-type", "TrueColorAlpha", str(tmp / "shield.pam")], check=True)
    data = (tmp / "shield.pam").read_bytes()
    head = data.index(b"ENDHDR\n") + 7
    hdr = data[:head].decode()
    width = int(hdr.split("WIDTH")[1].split()[0])
    depth = int(hdr.split("DEPTH")[1].split()[0])
    px = data[head:]
    halves = []
    for hy in range(rows * 2):
        row = []
        for cx in range(cols):
            acc = 0
            for sy in range(ss):
                base = depth * ((hy * ss + sy) * width + cx * ss)
                for sx in range(ss):
                    acc += px[base + sx * depth + 3]
            row.append(acc / (ss * ss * 255))
        halves.append(row)
    for f in tmp.iterdir():
        f.unlink()
    tmp.rmdir()
    return halves


def banner_ink():
    """Half-cell ink: thresholded, mirror-symmetrised, tail forced inward-monotone."""
    cols, rows = BANNER_COLS, BANNER_ROWS
    halves = banner_coverage()
    ink = [[halves[y][c] > BANNER_THRESH for c in range(cols)] for y in range(rows * 2)]
    for y in range(rows * 2):
        ink[y] = [ink[y][c] and ink[y][cols - 1 - c] for c in range(cols)]
    prev_l, prev_r = 0, cols - 1
    for y in range((max(BAR_ROWS) + 1) * 2, rows * 2):
        xs = [c for c in range(cols) if ink[y][c]]
        if not xs:
            continue
        l, r = max(min(xs), prev_l), min(max(xs), prev_r)
        for c in range(cols):
            if c < l or c > r:
                ink[y][c] = False
        xs = [c for c in range(cols) if ink[y][c]]
        if xs:
            prev_l, prev_r = min(xs), max(xs)
    return ink


def banner(label=" MIND THE GAP "):
    """The login banner: the rasterised shield behind a three-row box, in ANSI colour."""
    cols, rows = BANNER_COLS, BANNER_ROWS
    ink = banner_ink()
    fg = lambda c: f"\x1b[38;2;{c[0]};{c[1]};{c[2]}m"
    bg = lambda c: f"\x1b[48;2;{c[0]};{c[1]};{c[2]}m"
    reset = "\x1b[0m"
    mid = BAR_ROWS[len(BAR_ROWS) // 2]
    lines = []
    for r in range(rows):
        if r in BAR_ROWS:
            if r == mid:
                pad = cols - len(label)
                lines.append(bg(RGB["blue"]) + fg(RGB["white"]) + "\x1b[1m"
                             + " " * (pad // 2) + label + " " * (pad - pad // 2) + reset)
            else:
                lines.append(fg(RGB["blue"]) + ("▄" if r < mid else "▀") * cols + reset)
            continue
        cells = []
        for c in range(cols):
            t, b = ink[2 * r][c], ink[2 * r + 1][c]
            cells.append("█" if t and b else "▀" if t else "▄" if b else " ")
        lines.append(fg(RGB["red"]) + "".join(cells).rstrip() + reset)
    return "\n".join(lines) + "\n"



def check_shield(art):
    """Hand-drawn or rasterised, verify what the eye would miss: every row's ink is
    centred on one column (symmetry), and the words sit on the golden section of the
    height, like the mark's bar. ANSI colour is stripped before measuring."""
    import re as _re
    lines = [_re.sub("\x1b\\[[0-9;]*m", "", line) for line in art.splitlines()]
    mids = set()
    bar_row = None
    for row, line in enumerate(lines):
        ink = [i for i, ch in enumerate(line) if ch != " "]
        if ink:
            mids.add((min(ink) + max(ink)) / 2)
        if "MIND THE GAP" in line or "Mind the Gap" in line:
            bar_row = row
    assert len(mids) == 1, f"shield rows are not centred on one column: {sorted(mids)}"
    assert bar_row is not None, "the bar row lost its words"
    golden = bar_row / (len(lines) - 1)
    assert abs(golden - 0.382) < 0.06, f"bar sits at {golden:.3f} of the height, not the golden section"


MOTD_ANSI = banner()
check_shield(MOTD_ANSI)
(OUT / "motd.ansi").write_text(MOTD_ANSI)
print("\n".join(sorted(p.name for p in OUT.iterdir())))
