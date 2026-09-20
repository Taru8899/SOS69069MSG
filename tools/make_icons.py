"""Generate Android launcher icons from the embedded logo (run by the GitHub workflow).

Writes src/sos69069_msg/resources/sos69069_msg-{round,square,adaptive}-<px>.png,
which pyproject.toml's `icon = ".../sos69069_msg"` setting picks up.
"""
import io
import os
import sys

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from sos69069_msg.logo import icon_bytes  # noqa: E402

OUT = os.path.join(ROOT, "src", "sos69069_msg", "resources")
os.makedirs(OUT, exist_ok=True)
src = Image.open(io.BytesIO(icon_bytes())).convert("RGBA")


def save(im, variant, px):
    im.save(os.path.join(OUT, f"sos69069_msg-{variant}-{px}.png"))


for px in (48, 72, 96, 144, 192):
    save(src.resize((px, px), Image.LANCZOS), "square", px)
    big = src.resize((px * 4, px * 4), Image.LANCZOS)
    mask = Image.new("L", big.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, px * 4 - 1, px * 4 - 1), fill=255)
    big.putalpha(mask)
    save(big.resize((px, px), Image.LANCZOS), "round", px)

for px in (108, 162, 216, 324, 432):     # adaptive foreground: logo inside the 66/108 safe zone
    canvas = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    inner = int(px * 0.62)
    logo = src.resize((inner, inner), Image.LANCZOS)
    canvas.paste(logo, ((px - inner) // 2, (px - inner) // 2))
    save(canvas, "adaptive", px)

print("icons written to", OUT, sorted(os.listdir(OUT))[:3], "...")
