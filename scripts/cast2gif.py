#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pillow>=10"]
# ///
"""Render a honeypot session recording (.cast, asciinema v2) as a GIF.

    uv run scripts/cast2gif.py data/sessions/<day>/<conn>.cast docs/demo.gif

The text on every frame is exactly what the honeypot sent. Only the clock is
evened out: keystroke echoes land 5/100 s apart, long pauses are capped, and
the last frame dissolves into the first so the loop does not jump. GIF frame
delays are whole hundredths of a second, so every delay is chosen in those
units rather than rounded from real timings.

The honeypot's terminal output is plain text (CR/LF, no escape sequences),
so a tiny screen model is enough; anything else is ignored.
"""

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BG = (13, 17, 23)  # terminal background
BAR = (22, 27, 34)  # window title bar
FG = (230, 237, 243)  # text
MUTED = (125, 133, 144)  # title text
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]

FONT_CANDIDATES = [
    "/usr/share/fonts/adobe-source-code-pro-fonts/SourceCodePro-Regular.otf",
    "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]

TYPING_CS = 5  # one keystroke
OUTPUT_CS = 4  # a burst of output after Enter
IDLE_CAP_CS = 140  # longest pause kept
HOLD_END_CS = 350  # last frame
DISSOLVE_STEPS = 10


def load_cast(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    events = [json.loads(line) for line in lines[1:] if line.strip()]
    return header, [(t, d) for t, kind, d in events if kind == "o"]


class Screen:
    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.lines = [[] for _ in range(rows)]
        self.row = self.col = 0

    def feed(self, text):
        for ch in text:
            if ch == "\r":
                self.col = 0
            elif ch == "\n":
                self.newline()
            elif ch == "\b":
                self.col = max(0, self.col - 1)
            elif ch == "\t":
                self.col = min(self.cols - 1, (self.col // 8 + 1) * 8)
            elif ch >= " ":
                if self.col >= self.cols:
                    self.col = 0
                    self.newline()
                line = self.lines[self.row]
                while len(line) < self.col:
                    line.append(" ")
                if self.col < len(line):
                    line[self.col] = ch
                else:
                    line.append(ch)
                self.col += 1

    def newline(self):
        if self.row == self.rows - 1:
            self.lines.pop(0)
            self.lines.append([])
        else:
            self.row += 1

    def text(self):
        return ["".join(line) for line in self.lines]


def frames_from(header, events):
    """Group output into frames on a virtual clock; returns [(lines, cs)]."""
    screen = Screen(header["width"], header["height"])
    frames = []
    prev_t = None
    pending = ""
    for t, data in events:
        if prev_t is not None and t - prev_t > 0.012:
            screen.feed(pending)
            pending = ""
            gap = t - prev_t
            typed = len(frames) > 0 and gap < 0.2
            if typed:
                cs = TYPING_CS
            elif gap < 0.5:
                cs = max(OUTPUT_CS, round(gap * 100))
            else:
                cs = min(IDLE_CAP_CS, round(gap * 100))
            frames.append((screen.text(), cs))
        pending += data
        prev_t = t
    screen.feed(pending)
    frames.append((screen.text(), HOLD_END_CS))
    return frames


def render(lines, font, size, cell_w, cell_h, pad, bar_h, title):
    img = Image.new("RGB", size, BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, size[0], bar_h], fill=BAR)
    for i, colour in enumerate(DOTS):
        cx = pad + 8 + i * 22
        d.ellipse([cx - 6, bar_h // 2 - 6, cx + 6, bar_h // 2 + 6], fill=colour)
    tw = d.textlength(title, font=font)
    d.text(((size[0] - tw) / 2, (bar_h - cell_h) / 2 + 2), title, font=font, fill=MUTED)
    for r, line in enumerate(lines):
        if line:
            d.text((pad, bar_h + pad + r * cell_h), line, font=font, fill=FG)
    return img


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: cast2gif.py SESSION.cast OUT.gif")
    header, events = load_cast(sys.argv[1])
    font_path = next(p for p in FONT_CANDIDATES if Path(p).exists())
    font = ImageFont.truetype(font_path, 17)
    cell_w = round(font.getlength("M"))
    cell_h = 23
    pad, bar_h = 18, 34
    cols, rows = header["width"], header["height"]
    size = (cols * cell_w + 2 * pad, rows * cell_h + 2 * pad + bar_h)
    title = "attacker@internet: ssh root@srv-web01"

    frames = frames_from(header, events)
    images = [render(lines, font, size, cell_w, cell_h, pad, bar_h, title) for lines, _ in frames]
    delays = [cs * 10 for _, cs in frames]

    # Dissolve the last frame into the first so the loop is seamless.
    first, last = images[0], images[-1]
    for k in range(1, DISSOLVE_STEPS + 1):
        images.append(Image.blend(last, first, k / DISSOLVE_STEPS))
        delays.append(40)
    delays[-1] = 120

    # One shared palette keeps the file small and the text crisp.
    palette_img = images[-1].quantize(colors=48, method=Image.Quantize.MEDIANCUT)
    paletted = [im.quantize(palette=palette_img, dither=Image.Dither.NONE) for im in images]
    paletted[0].save(
        sys.argv[2],
        save_all=True,
        append_images=paletted[1:],
        duration=delays,
        loop=0,
        optimize=False,
        disposal=1,
    )
    total = sum(delays) / 1000
    print(f"{len(paletted)} frames, {total:.1f}s, {size[0]}x{size[1]} -> {sys.argv[2]}")


if __name__ == "__main__":
    main()
