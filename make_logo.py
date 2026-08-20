#!/usr/bin/env python3
"""Generate the proc-snitch logo: a shield with a cut bar through it.

Writes `proc-snitch.ico` (multi-size, PNG-encoded frames — Windows Vista+)
for the executable icon and `proc-snitch.png` (256x256) for the README.

Deps: pip install pillow
Run:  python make_logo.py
"""

import io
import os
import struct
from typing import List, Sequence, Tuple

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ICO = os.path.join(HERE, "proc-snitch.ico")
OUT_PNG = os.path.join(HERE, "proc-snitch.png")

# Tokyo Night palette, matching the overlay in proc-snitch.py.
BG = "#1a1b26"
FG = "#7aa2f7"
RED = "#f7768e"

ICO_SIZES = (16, 32, 48, 64, 128, 256)
PNG_SIZE = 256


def _shield(cx: int, cy: int, r: int) -> List[Tuple[int, int]]:
    """Shield outline centred on (cx, cy) with radius r."""
    return [
        (cx, cy - r),
        (cx + r, cy - r // 2),
        (cx + r, cy + r // 3),
        (cx, cy + r),
        (cx - r, cy + r // 3),
        (cx - r, cy - r // 2),
    ]


def make_logo(size: int) -> Image.Image:
    """Render the logo at `size` x `size` pixels on a transparent background."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = max(2, size // 12)
    cx = cy = size // 2
    r = size // 2 - pad

    d.polygon(_shield(cx, cy, r), fill=FG)          # outer shield
    inner_r = int(r * 0.75)
    d.polygon(_shield(cx, cy, inner_r), fill=BG)    # hollow it out

    bar_h = max(2, size // 8)
    bar_y = cy - bar_h // 2
    margin = inner_r - size // 10
    d.rectangle([cx - margin, bar_y, cx + margin, bar_y + bar_h], fill=RED)
    return img


def write_ico(path: str, sizes: Sequence[int]) -> None:
    """Write a multi-size ICO whose frames are PNG-encoded (Windows Vista+).

    Layout: a 6-byte ICONDIR header, then one 16-byte ICONDIRENTRY per
    frame, then the frame data.

      bWidth         1 byte   (0 means 256)
      bHeight        1 byte   (0 means 256)
      bColorCount    1 byte
      bReserved      1 byte
      wPlanes        2 bytes
      wBitCount      2 bytes
      dwBytesInRes   4 bytes
      dwImageOffset  4 bytes
    """
    frames = []
    for s in sizes:
        buf = io.BytesIO()
        make_logo(s).save(buf, format="PNG")
        frames.append((s, buf.getvalue()))

    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = len(header) + len(frames) * 16       # start of the image data
    directory = b""
    data = b""
    for s, png in frames:
        dim = s if s < 256 else 0                 # 0 encodes 256
        directory += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        data += png
        offset += len(png)

    with open(path, "wb") as f:
        f.write(header + directory + data)


def describe_ico(path: str) -> None:
    """Print the frame table of an ICO, as a sanity check after writing."""
    with open(path, "rb") as f:
        raw = f.read()
    _reserved, kind, count = struct.unpack_from("<HHH", raw, 0)
    print(f"  {len(raw)} bytes, type={kind}, frames={count}")
    for i in range(count):
        e = struct.unpack_from("<BBBBHHII", raw, 6 + i * 16)
        w = e[0] or 256
        h = e[1] or 256
        print(f"    frame {i}: {w}x{h}, offset={e[7]}, bytes={e[6]}")


def main() -> None:
    make_logo(PNG_SIZE).save(OUT_PNG)
    print(f"  saved {OUT_PNG}")
    write_ico(OUT_ICO, ICO_SIZES)
    print(f"  saved {OUT_ICO}")
    describe_ico(OUT_ICO)


if __name__ == "__main__":
    main()
