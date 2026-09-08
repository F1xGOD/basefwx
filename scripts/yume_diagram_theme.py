#!/usr/bin/env python3
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Derive standalone SVG colors and fonts from the website's token source."""

from __future__ import annotations

import math
import re
from pathlib import Path

TOKEN_RE = re.compile(r"(--[\w-]+)\s*:\s*([^;{}]+);")


def srgb(value: str) -> str:
    """Convert this workspace's opaque OKLCH tokens to SVG presentation colors."""
    match = re.fullmatch(r"oklch\(([\d.]+)% ([\d.]+) ([\d.]+)\)", value)
    if not match:
        raise ValueError(f"diagram theme needs an opaque OKLCH token, got {value!r}")
    light, chroma, hue = map(float, match.groups())
    light /= 100
    a, b = chroma * math.cos(math.radians(hue)), chroma * math.sin(math.radians(hue))
    l = (light + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m = (light - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s = (light - 0.0894841775 * a - 1.2914855480 * b) ** 3
    channels = (4.0767416621*l - 3.3077115913*m + 0.2309699292*s,
                -1.2684380046*l + 2.6097574011*m - 0.3413193965*s,
                -0.0041960863*l - 0.7034186147*m + 1.7076147010*s)
    def encode(channel: float) -> int:
        channel = 12.92 * channel if channel <= 0.0031308 else 1.055 * channel ** (1/2.4) - 0.055
        return round(max(0, min(1, channel)) * 255)
    return "#" + "".join(f"{encode(channel):02x}" for channel in channels)


def load(path: Path) -> tuple[tuple, str, str]:
    css = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
    root = re.search(r":root\s*\{([^{}]*)\}", css)
    if root is None:
        raise ValueError(f"{path}: missing root tokens")
    baseline = dict(TOKEN_RE.findall(root.group(1)))

    def theme(name: str) -> dict[str, str]:
        selector = re.search(r':root\[data-theme="' + name + r'"\]\s*\{([^{}]*)\}', css)
        values = dict(baseline)
        if selector:
            values.update(TOKEN_RE.findall(selector.group(1)))
        return values

    light, dark = theme("light"), theme("dark")
    # The two maintained websites have different token names. The mapping
    # names their consumers; all color values remain owned by tokens.css.
    tokens = (
        {"plate": "--color-paper", "card": "--color-cloud", "ink": "--color-ink",
         "muted": "--color-muted", "rule": "--color-rule", "accent": "--color-accent",
         "strong": "--color-accent-strong", "soft": "--color-accent-soft"}
        if "--color-paper" in baseline else
        {"plate": "--paper", "card": "--surface", "ink": "--text", "muted": "--text-3",
         "rule": "--rule", "accent": "--accent", "strong": "--accent-hover", "soft": "--accent-wash"}
    )

    def color(values: dict[str, str], token: str) -> str:
        seen = set()
        while True:
            if token in seen or token not in values:
                raise ValueError(f"{path}: unresolved or cyclic diagram token {token}")
            seen.add(token)
            value = values[token].strip()
            alias = re.fullmatch(r"var\((--[\w-]+)\)", value)
            if not alias:
                return srgb(value)
            token = alias.group(1)

    palette = tuple((local, token, color(light, token), color(dark, token)) for local, token in tokens.items())
    return palette, baseline["--font-display"].replace('"', "'"), baseline["--font-mono"].replace('"', "'")
