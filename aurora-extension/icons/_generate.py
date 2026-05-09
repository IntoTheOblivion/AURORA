"""
Genera le icone PNG dell'estensione (16/32/48/128) a partire da un semplice
disegno a scudo. Lanciare una sola volta dopo modifiche al design:

    python icons/_generate.py
"""
from PIL import Image, ImageDraw

SIZES = [16, 32, 48, 128]
BG = (192, 57, 43, 255)        # rosso BitM (allineato al banner block)
FG = (255, 255, 255, 255)
OUTLINE = (120, 30, 20, 255)


def shield(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = max(1, size // 16)
    w = size - 2 * pad
    h = size - 2 * pad
    top = pad
    left = pad
    right = left + w
    bottom = top + h
    cx = left + w // 2
    # Forma scudo: pentagono arrotondato
    points = [
        (left, top + h * 0.20),
        (cx, top),
        (right, top + h * 0.20),
        (right, top + h * 0.55),
        (cx, bottom),
        (left, top + h * 0.55),
    ]
    d.polygon(points, fill=BG, outline=OUTLINE)
    # Lettera B centrata (semplice barra verticale + due archi)
    if size >= 32:
        bar_w = max(2, size // 16)
        bar_h = int(h * 0.5)
        bar_x = cx - int(w * 0.18)
        bar_y = top + int(h * 0.22)
        d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + bar_h], fill=FG)
        # due "pancie" della B
        belly_w = int(w * 0.30)
        belly_h = bar_h // 2 - 1
        d.rectangle(
            [bar_x, bar_y, bar_x + belly_w, bar_y + belly_h],
            outline=FG,
            width=max(1, size // 24),
        )
        d.rectangle(
            [bar_x, bar_y + belly_h, bar_x + belly_w, bar_y + bar_h],
            outline=FG,
            width=max(1, size // 24),
        )
    else:
        # 16px troppo piccolo per la B leggibile: pallino centrale
        r = max(2, size // 4)
        d.ellipse([cx - r, top + h // 3 - r // 2, cx + r, top + h // 3 + r * 3 // 2], fill=FG)
    return img


if __name__ == "__main__":
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for s in SIZES:
        out = os.path.join(here, f"icon-{s}.png")
        shield(s).save(out, "PNG")
        print(f"  wrote {out}")
