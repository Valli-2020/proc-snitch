#!/usr/bin/env python3
"""Generate proc-snitch logo as .ico (Windows) and .png (README)."""

from PIL import Image, ImageDraw
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ICO = os.path.join(HERE, "proc-snitch.ico")
OUT_PNG = os.path.join(HERE, "proc-snitch.png")

# ── palette ─────────────────────────────────────────────────────────
BG = "#1a1b26"
FG = "#7aa2f7"     # blue shield
ACCENT = "#ff9e64" # orange cut bar
RED = "#f7768e"

def make_logo(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = max(2, size // 16)

    # shield shape
    cx, cy = size // 2, size // 2
    r = size // 2 - pad
    shield = [
        (cx, cy - r),                 # top
        (cx + r, cy - r // 2),        # right upper
        (cx + r, cy + r // 3),        # right lower
        (cx, cy + r),                 # bottom point
        (cx - r, cy + r // 3),         # left lower
        (cx - r, cy - r // 2),         # left upper
    ]
    d.polygon(shield, fill=FG)

    # inner darker shield
    inner_r = int(r * 0.78)
    inner = [
        (cx, cy - inner_r),
        (cx + inner_r, cy - inner_r // 2),
        (cx + inner_r, cy + inner_r // 3),
        (cx, cy + inner_r),
        (cx - inner_r, cy + inner_r // 3),
        (cx - inner_r, cy - inner_r // 2),
    ]
    d.polygon(inner, fill=BG)

    # horizontal cut bar (the "snitch" slash)
    bar_h = max(3, size // 10)
    bar_y = cy - bar_h // 2
    d.rectangle([cx - inner_r + 4, bar_y, cx + inner_r - 4, bar_y + bar_h], fill=RED)

    return img

# ── PNG (for README) ────────────────────────────────────────────────
logo = make_logo(256)
logo.save(OUT_PNG)
print(f"  saved {OUT_PNG}")

# ── ICO (for .exe icon) ─────────────────────────────────────────────
sizes = [16, 32, 48, 64, 128, 256]
frames = [make_logo(s).convert("RGBA") for s in sizes]
frames[0].save(
    OUT_ICO,
    format="ICO",
    sizes=[(s, s) for s in sizes],
    append_images=frames[1:],
)
print(f"  saved {OUT_ICO}")
