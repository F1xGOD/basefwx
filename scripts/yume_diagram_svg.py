#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render a diagram specification as a self-contained animated SVG.

The file paints and animates itself. Its stylesheet reads a website token
first and falls back to the value that token resolves to today:

    fill: var(--color-cloud, #fffcfe)

Inlined by the website, `--color-cloud` is defined on :root, so the theme
toggle still recolours the figure and there is no second palette to keep in
step. Loaded as an image the token is absent and the fallback applies, with a
`prefers-color-scheme` block swapping only the fallbacks. That block is inert
wherever the tokens exist, so an explicit light theme on a dark desktop still
wins, and an image takes the colour scheme of the page embedding it, which is
how a GitHub document gets a figure matching its theme.

Under the stylesheet every painted element also carries its light-theme value
as a presentation attribute. Presentation attributes lose to any stylesheet
rule, so they change nothing in a browser, and they are what a renderer with
no CSS support draws instead of SVG's default black fill.

A packet is always in one of two places: on a wire, or inside a node. The
figure draws both. The orb travels the hops, and while it is inside a card
that card is lit, so nothing is ever happening off-screen. Timing both from
one clock is what makes the handover read as the same packet arriving.

Two more things keep a route from reading as a row of identical boxes, and
both come from the specification rather than from decoration:

  * A node that is YUME software carries the accent. Everything the route
    only reaches is drawn in the quiet neutral. The eye follows the part of
    the path this project is responsible for.
  * A run of adjacent nodes sharing a `group` is enclosed and named. In the
    across-the-page layout the enclosure is a raised plateau, so the hops
    into and out of it rise and fall and the figure has a shape of its own.

Geometry is computed, never transformed: a hop and its arrow head are drawn
from their own coordinates at whatever angle they run. The site resets
transforms inside a revealed section, so a `transform` attribute here would
be silently dropped.

Output is integer or two-decimal and the element order is fixed, so two runs
over the same specification produce identical bytes.
"""

from __future__ import annotations

import html
import math
import textwrap
from dataclasses import dataclass
from pathlib import Path

import yume_diagram_theme

from yume_diagram_spec import NARROW_WIDTH, Node, Spec, groups, is_yume_owned

# The stacked layout, read top to bottom. Cards are rows: a glyph, a title,
# and a subtitle beside it.
CARD_HEIGHT = 76
CARD_GAP = 60
MARGIN = 20
CARD_WIDTH_NARROW = 360
CARD_WIDTH_WIDE = 560
GLYPH_COLUMN = 64
LABEL_OFFSET = 20

# The across-the-page layout, used where a route is the spatial anchor of a
# page. Cards are portrait and centre their own content.
H_CARD_WIDTH = 168
H_CARD_HEIGHT = 104
H_CARD_GAP = 84
H_MARGIN = 20

# A group is drawn as an enclosure. Across the page it also lifts its members
# onto a plateau, which is what gives a grouped route its silhouette.
GROUP_PAD = 14
GROUP_TITLE_HEIGHT = 22
PLATEAU_RISE = 30

# Text is measured, never laid out, so a card and the gap above a hop can be
# sized without font metrics. Both faces are set at their drawn size: IBM Plex
# Mono advances 0.6em, and the rounded display face averages near 0.55em at
# the weight used for a title.
TITLE_SIZE = 14
LABEL_SIZE = 11
GROUP_SIZE = 11
TITLE_ADVANCE = TITLE_SIZE * 0.55
LABEL_ADVANCE = LABEL_SIZE * 0.6
GROUP_ADVANCE = GROUP_SIZE * 0.62
CARD_PADDING = 24
GAP_PADDING = 28
EDGE_LABEL_COLUMNS = 18

# The protected hop is given more room than an ordinary one. A conduit needs
# length before it reads as a channel rather than as a badge, and the extra
# space is itself informative: it is the hop the rest of the figure is about.
TUNNEL_GAP_H = 168
TUNNEL_GAP_V = 104

# How long a node takes to light up and go dark again. Long enough to read as
# a change of state rather than a flash, short enough that a packet crossing a
# card still looks like it arrived and left.
PRESENCE_RAMP_SECONDS = 0.18

# The soft shape behind a card does two jobs. At rest it is the card's
# shadow, which is what separates a card from the ground in the light theme,
# where paper and cloud are within a percent of each other in lightness. The
# dark theme separates them by lightness instead and barely shows this. It
# stands proud of the card and sits a little below it, because under an opaque
# card of its own size it would show nothing but its blur tail.
LIFT_SPREAD = 3
LIFT_DROP = 3
LIFT_BLUR = 5

CONDUIT_BORE = 20
ARROW_LENGTH = 11
ARROW_HALF = 6
CARD_CLEARANCE = 5

# One packet moves at one rate in every figure. Timing the loop by hop count
# instead made the same route cross its stacked drawing at half the speed of
# its across-the-page drawing, which said something about the layout rather
# than about the route. A long route now takes longer because it is longer,
# which is the only thing a moving dot can honestly mean here. The rate is a
# legibility calibration, taken from what the across-the-page figures already
# ran at; what a packet's speed, size, or shape should say about the hop it is
# crossing is a separate question and is not answered by this number.
PIXELS_PER_SECOND = 140

# There is one packet, because that is what a packet is. It leaves the first
# node, crosses each gap along the hop that is actually drawn, and is hidden by
# every card it passes through, so it reads as one thing entering a node and
# coming out the other side. The loop restarts while it is inside the last
# card, which is why the return is never seen.

# The carrier inside a conduit: a short capsule and a long gap, so what moves
# reads as discrete traffic rather than as a dashed rule.
FLOW_DASH = 12
FLOW_PERIOD = 38
FLOW_SECONDS = "2.4s"

# Glyphs are placed with a nested <svg x y>, never a transform attribute.
GLYPHS = {
    "process": '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/>',
    "file": '<path d="M5 2h9l5 5v15H5zM14 2v6h5M8 12h8M8 16h8"/>',
    "app": (
        '<rect x="2.5" y="4.5" width="19" height="15" rx="2.5"/>'
        '<path d="M2.5 9.5h19"/>'
        '<circle cx="5.6" cy="7" r="0.9" class="dgm-glyph-fill"/>'
        '<circle cx="8.4" cy="7" r="0.9" class="dgm-glyph-fill"/>'
    ),
    "client": (
        '<rect x="3.5" y="5.5" width="17" height="11" rx="1.8"/>'
        '<path d="M1.5 19.5h21"/>'
    ),
    "server": (
        '<rect x="3.5" y="3.5" width="17" height="7" rx="1.8"/>'
        '<rect x="3.5" y="13.5" width="17" height="7" rx="1.8"/>'
        '<circle cx="7" cy="7" r="1" class="dgm-glyph-fill"/>'
        '<circle cx="7" cy="17" r="1" class="dgm-glyph-fill"/>'
    ),
    "target": (
        '<circle cx="12" cy="12" r="8.5"/>'
        '<path d="M3.5 12h17"/>'
        '<path d="M12 3.5c4 4.5 4 12.5 0 17c-4-4.5-4-12.5 0-17z"/>'
    ),
    "relay": (
        '<path d="M12 3.2 20 7.6v8.8L12 20.8 4 16.4V7.6z"/>'
        '<circle cx="12" cy="12" r="1.5" class="dgm-glyph-fill"/>'
    ),
    "tor": (
        '<path d="M12 2.8c5.4 4.6 7.2 9.2 5.4 13.2A6.1 6.1 0 0 1 12 21.2'
        'a6.1 6.1 0 0 1-5.4-5.2C4.8 12 6.6 7.4 12 2.8z"/>'
        '<path d="M12 8.2c2.4 2.3 3.2 4.6 2.4 6.6A2.7 2.7 0 0 1 12 16.6'
        'a2.7 2.7 0 0 1-2.4-1.8c-0.8-2 0-4.3 2.4-6.6z"/>'
    ),
    "tun": (
        '<rect x="2.5" y="7" width="19" height="10" rx="5"/>'
        '<path d="M8.6 7.4v9.2M15.4 7.4v9.2" stroke-dasharray="2 2"/>'
    ),
    "cloud": (
        '<path d="M7.4 18.4a4.3 4.3 0 0 1 .3-8.5 5.7 5.7 0 0 1 10.7-1'
        'a3.9 3.9 0 0 1 .4 7.7z"/>'
    ),
}

# Each entry is one website token and the value that token resolves to in the
# light and the dark theme. scripts/test_yume_diagrams.py checks every name
# here against website/assets/tokens.css, so a renamed token fails a test
# rather than silently falling back on every page.
PALETTE, DISPLAY_FACES, MONO_FACES = yume_diagram_theme.load(
    Path(__file__).resolve().parents[1] / "website/assets/tokens.css"
)

LIGHT = {local: value for local, _token, value, _dark in PALETTE}

# Single quotes so the same string is both a CSS value and an XML attribute
# value. Neither face can be fetched by an image-embedded SVG, so the stacks
# end in a rounded and a monospace fallback the reader already has.
DISPLAY_STACK = f"var(--font-display, {DISPLAY_FACES})"
MONO_STACK = f"var(--font-mono, {MONO_FACES})"

# The light-theme value of every class below, as presentation attributes.
BASELINE: dict[str, dict[str, str]] = {
    "dgm-plate": {"fill": LIGHT["plate"], "stroke": LIGHT["rule"], "stroke-width": "1"},
    "dgm-lift": {"fill": LIGHT["rule"], "opacity": "0.85"},
    "dgm-card": {"fill": LIGHT["card"], "stroke": LIGHT["rule"], "stroke-width": "1.5"},
    "dgm-owned-card": {"stroke": LIGHT["accent"], "stroke-width": "2"},
    "dgm-chip": {"fill": LIGHT["rule"]},
    "dgm-owned-chip": {"fill": LIGHT["soft"]},
    "dgm-glyph": {
        "fill": "none",
        "stroke": LIGHT["muted"],
        "stroke-width": "1.5",
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
    },
    "dgm-owned-glyph": {"stroke": LIGHT["strong"]},
    "dgm-glyph-fill": {"fill": LIGHT["muted"], "stroke": "none"},
    "dgm-owned-glyph-fill": {"fill": LIGHT["strong"]},
    "dgm-title": {
        "fill": LIGHT["ink"],
        "font-family": DISPLAY_FACES,
        "font-size": f"{TITLE_SIZE}px",
        "font-weight": "600",
        "letter-spacing": "0.02em",
    },
    "dgm-sub": {
        "fill": LIGHT["muted"],
        "font-family": MONO_FACES,
        "font-size": f"{LABEL_SIZE}px",
    },
    "dgm-edge-label": {
        "fill": LIGHT["muted"],
        "font-family": MONO_FACES,
        "font-size": f"{LABEL_SIZE}px",
    },
    "dgm-centred": {"text-anchor": "middle"},
    "dgm-group": {
        "fill": LIGHT["soft"],
        "fill-opacity": "0.55",
        "stroke": LIGHT["accent"],
        "stroke-width": "1.5",
        "stroke-dasharray": "1 5",
        "stroke-linecap": "round",
    },
    "dgm-group-title": {
        "fill": LIGHT["strong"],
        "font-family": MONO_FACES,
        "font-size": f"{GROUP_SIZE}px",
        "letter-spacing": "0.08em",
    },
    "dgm-link": {
        "fill": "none",
        "stroke": LIGHT["accent"],
        "stroke-width": "2.5",
        "stroke-linecap": "round",
    },
    "dgm-link-onion": {"stroke-dasharray": "2 5"},
    "dgm-conduit": {
        "fill": "none",
        "stroke": LIGHT["soft"],
        "stroke-width": str(CONDUIT_BORE),
        "stroke-linecap": "round",
    },
    "dgm-conduit-wall": {
        "fill": "none",
        "stroke": LIGHT["accent"],
        "stroke-width": "2",
        "stroke-linecap": "round",
    },
    "dgm-conduit-flow": {
        "fill": "none",
        "stroke": LIGHT["strong"],
        "stroke-width": "4",
        "stroke-linecap": "round",
        "stroke-dasharray": f"{FLOW_DASH} {FLOW_PERIOD - FLOW_DASH}",
    },
    "dgm-arrow": {
        "fill": LIGHT["strong"],
        "stroke": LIGHT["strong"],
        "stroke-width": "2",
        "stroke-linejoin": "round",
    },
    # A renderer that cannot follow offset-path would otherwise stack every
    # packet in the top-left corner, so they stay hidden until the stylesheet
    # confirms the property is available.
    "dgm-packet": {"display": "none"},
    "dgm-packet-core": {"fill": LIGHT["strong"]},
    "dgm-packet-glow": {"fill": LIGHT["accent"], "opacity": "0.38"},
}

# Baseline keys that stand for a CSS rule rather than for a class in the
# markup. They select presentation attributes and are not written out.
PAINT_ONLY = frozenset(
    {"dgm-owned-card", "dgm-owned-chip", "dgm-owned-glyph", "dgm-owned-glyph-fill"}
)


Point = tuple[float, float]


@dataclass
class Placed:
    """One node's card, already positioned."""

    node: Node
    x: float
    y: float
    width: float
    height: float

    @property
    def centre_x(self) -> float:
        return self.x + self.width / 2

    @property
    def centre_y(self) -> float:
        return self.y + self.height / 2

    @property
    def right(self) -> float:
        return self.x + self.width

    @property
    def bottom(self) -> float:
        return self.y + self.height


@dataclass
class Enclosure:
    """The box drawn around one group, and the title above it."""

    title: str
    x: float
    y: float
    width: float
    height: float
    first: int
    last: int


def _paint(*classes: str) -> str:
    """`class="..."` plus the merged light-theme presentation attributes."""
    attributes: dict[str, str] = {}
    for name in classes:
        attributes.update(BASELINE.get(name, {}))
    drawn = " ".join(
        f'{key}="{html.escape(value, quote=True)}"' for key, value in attributes.items()
    )
    names = " ".join(name for name in classes if name not in PAINT_ONLY)
    return f'class="{names}" {drawn}' if drawn else f'class="{names}"'


def _palette_block(index: int, indent: str) -> str:
    return "\n".join(
        f"{indent}--dgm-{local}: var({token}, {values[index]});"
        for local, token, *values in PALETTE
    )


def _stylesheet(presence: str) -> str:
    """The figure's whole stylesheet, including its per-card presence rules."""
    presence = textwrap.indent(presence, "  ") if presence else ""
    return f"""<style>
.dgm {{
{_palette_block(0, "  ")}
}}

/* Only the fallbacks change. Where the tokens exist this block resolves to
   the same values as the one above, so an explicit theme still decides. */
@media (prefers-color-scheme: dark) {{
  .dgm {{
{_palette_block(1, "    ")}
  }}
}}

.dgm-plate {{
  fill: var(--dgm-plate);
  stroke: var(--dgm-rule);
  stroke-width: 1;
  opacity: var(--dgm-plate-opacity, 1);
}}

/* The shadow is its own shape behind the card, never a filter on the card
   itself. A renderer that cannot resolve the filter drops only the shadow;
   SVG says a reference to a missing filter hides the element that names it,
   which would take the card with it. */
/* The halo under a card and the chip behind its glyph are the presence
   channel: they say the packet is in this node right now. The card's border
   is left alone, because that already says whether the node is YUME software
   and one mark cannot carry two meanings. */
/* The glow and the chip light up with different tokens because they are
   doing different things. A glow is read as colour, not as brightness: on a
   near-white page nothing can be brighter than the page, so it uses accent,
   which stays a mid pink in both themes. Accent-strong there would be a dark
   bloom, which reads as weight rather than attention. */
.dgm-lift {{
  fill: var(--dgm-rest);
  opacity: 0.85;
  --dgm-rest: var(--dgm-rule);
  --dgm-live: var(--dgm-accent);
}}

.dgm-card {{
  fill: var(--dgm-card);
  stroke: var(--dgm-rule);
  stroke-width: 1.5;
}}

/* A card YUME itself runs carries the accent, and everything the route only
   reaches stays neutral, so the eye follows the part of the path this
   project is responsible for. It is a software boundary, not a trust claim:
   yumed still terminates the tunnel and sees the traffic it forwards. */
.dgm-node-owned .dgm-card {{
  stroke: var(--dgm-accent);
  stroke-width: 2;
}}

/* The chip is a filled shape with the glyph knocked out of it, so it needs
   contrast against the card in both themes, which is what accent-strong is
   for: dark on light paper, bright on dark paper. */
.dgm-chip {{
  fill: var(--dgm-rest);
  --dgm-rest: var(--dgm-rule);
  --dgm-live: var(--dgm-strong);
}}

.dgm-node-owned .dgm-chip {{
  --dgm-rest: var(--dgm-soft);
}}

/* The glyph goes with its chip. Leaving it on the accent while the chip fills
   with the accent puts light on light, and the icon smears instead of
   reading, so it is knocked out to the card it sits on. */
.dgm-glyph {{
  --dgm-rest: none;
  --dgm-live: none;
  --dgm-rest-line: var(--dgm-muted);
  --dgm-live-line: var(--dgm-card);
}}

.dgm-node-owned .dgm-glyph {{
  --dgm-rest-line: var(--dgm-strong);
}}

.dgm-glyph-fill {{
  --dgm-rest: var(--dgm-muted);
  --dgm-live: var(--dgm-card);
  --dgm-rest-line: none;
  --dgm-live-line: none;
}}

.dgm-node-owned .dgm-glyph-fill {{
  --dgm-rest: var(--dgm-strong);
}}

.dgm-lift,
.dgm-chip,
.dgm-glyph,
.dgm-glyph-fill {{
  animation-duration: var(--dgm-dur, 6s);
  animation-timing-function: linear;
  animation-iteration-count: infinite;
}}

.dgm-lift,
.dgm-chip {{
  --dgm-rest-line: none;
  --dgm-live-line: none;
}}

.dgm-glyph {{
  fill: none;
  stroke: var(--dgm-muted);
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}}

.dgm-glyph-fill {{
  fill: var(--dgm-muted);
  stroke: none;
}}

.dgm-node-owned .dgm-glyph {{
  stroke: var(--dgm-strong);
}}

.dgm-node-owned .dgm-glyph-fill {{
  fill: var(--dgm-strong);
}}

.dgm-title {{
  fill: var(--dgm-ink);
  font-family: {DISPLAY_STACK};
  font-size: {TITLE_SIZE}px;
  font-weight: 600;
  letter-spacing: 0.02em;
}}

.dgm-sub,
.dgm-edge-label {{
  fill: var(--dgm-muted);
  font-family: {MONO_STACK};
  font-size: {LABEL_SIZE}px;
}}

.dgm-centred {{
  text-anchor: middle;
}}

/* An enclosure holds a run of nodes the specification says belong together,
   and carries the name it gives them. */
.dgm-group {{
  fill: var(--dgm-soft);
  fill-opacity: 0.55;
  stroke: var(--dgm-accent);
  stroke-width: 1.5;
  stroke-dasharray: 1 5;
  stroke-linecap: round;
}}

.dgm-group-title {{
  fill: var(--dgm-strong);
  font-family: {MONO_STACK};
  font-size: {GROUP_SIZE}px;
  letter-spacing: 0.08em;
}}

.dgm-link {{
  fill: none;
  stroke: var(--dgm-accent);
  stroke-width: 2.5;
  stroke-linecap: round;
}}

.dgm-link-onion {{
  stroke-dasharray: 2 5;
}}

/* The protected hop is drawn as a conduit: a soft bore, two walls, and the
   carrier moving between them. Each is one stroked line, so the treatment
   holds at whatever angle the hop runs. This is the ==YUME==> of the ASCII. */
.dgm-conduit {{
  fill: none;
  stroke: var(--dgm-soft);
  stroke-width: {CONDUIT_BORE};
  stroke-linecap: round;
}}

.dgm-conduit-wall {{
  fill: none;
  stroke: var(--dgm-accent);
  stroke-width: 2;
  stroke-linecap: round;
}}

.dgm-conduit-flow {{
  fill: none;
  stroke: var(--dgm-strong);
  stroke-width: 4;
  stroke-linecap: round;
  stroke-dasharray: {FLOW_DASH} {FLOW_PERIOD - FLOW_DASH};
  animation: dgm-flow {FLOW_SECONDS} linear infinite;
}}

/* The stroke rounds the triangle's corners, which is the same softening the
   cards and the chips carry. */
.dgm-arrow {{
  fill: var(--dgm-strong);
  stroke: var(--dgm-strong);
  stroke-width: 2;
  stroke-linejoin: round;
}}

.dgm-packet-core {{
  fill: var(--dgm-strong);
}}

.dgm-packet-glow {{
  fill: var(--dgm-accent);
  opacity: 0.38;
}}

@keyframes dgm-travel {{
  from {{ offset-distance: 0%; }}
  to {{ offset-distance: 100%; }}
}}

@keyframes dgm-flow {{
  to {{ stroke-dashoffset: -{FLOW_PERIOD}; }}
}}

/* The packets are hidden by the markup and revealed only where the property
   that positions them exists. */
@supports (offset-path: path("M0 0")) {{
  .dgm-packet {{
    display: block;
    offset-path: var(--dgm-path);
    offset-rotate: 0deg;
    offset-distance: 0%;
    animation: dgm-travel var(--dgm-dur, 6s) linear infinite;
  }}

{presence}
}}

@media (prefers-reduced-motion: reduce) {{
  .dgm-packet {{
    display: none;
  }}

  .dgm-conduit-flow,
  .dgm-lift,
  .dgm-chip,
  .dgm-glyph,
  .dgm-glyph-fill {{
    animation: none;
  }}
}}
</style>"""


def dimensions(spec: Spec, layout: str) -> tuple[str, str]:
    """The drawn size of one figure, for a Markdown image that wants both."""
    markup = render(spec, layout)
    header = markup.split(">", 1)[0]
    width = header.split(' width="', 1)[1].split('"', 1)[0]
    height = header.split(' height="', 1)[1].split('"', 1)[0]
    return width, height


def render(spec: Spec, layout: str = "vertical") -> str:
    """The self-contained SVG for one diagram, ending in a newline."""
    if spec.type != "route":
        raise ValueError(f"no SVG renderer for diagram type {spec.type!r}")
    if layout == "horizontal":
        return _render_horizontal(spec)
    if layout != "vertical":
        raise ValueError(f"unknown layout {layout!r}")
    return _render_vertical(spec)


def _render_vertical(spec: Spec) -> str:
    """A stack read top to bottom. A group becomes a section of the stack."""
    card_width = CARD_WIDTH_NARROW if spec.box_width() == NARROW_WIDTH else CARD_WIDTH_WIDE
    sub_columns = int((card_width - CARD_PADDING - GLYPH_COLUMN) // LABEL_ADVANCE)
    runs = groups(spec)
    inset = GROUP_PAD if runs else 0
    width = MARGIN * 2 + inset * 2 + card_width
    left = MARGIN + inset
    axis = left + card_width / 2
    # A label sits to the right of the centre line and has to stop inside the
    # plate, so it wraps to whatever room is left there.
    label_room = card_width / 2 + inset - LABEL_OFFSET - MARGIN
    label_columns = max(8, int(label_room // LABEL_ADVANCE))

    # The hop is spent before the enclosure opens, so a group's title sits
    # just above its first card rather than a gap away from it.
    placed: list[Placed] = []
    boxes: list[Enclosure] = []
    y = float(MARGIN)
    for index, node in enumerate(spec.nodes):
        run = _run_at(runs, index)
        if index:
            edge = spec.edges[index - 1]
            y += TUNNEL_GAP_V if edge.channel == "tunnel" else CARD_GAP
            if (_run_at(runs, index - 1) is None) != (run is None):
                y += GROUP_PAD
        if run and run[0] == index:
            boxes.append(
                Enclosure(run[2], left - GROUP_PAD, y, card_width + GROUP_PAD * 2, 0, *run[:2])
            )
            y += GROUP_TITLE_HEIGHT + GROUP_PAD
        placed.append(Placed(node, left, y, card_width, CARD_HEIGHT))
        y += CARD_HEIGHT
        if run and run[1] == index:
            y += GROUP_PAD
            boxes[-1].height = y - boxes[-1].y
    height = y + MARGIN

    hops: list[tuple[Point, Point]] = []
    body: list[str] = [_enclosures(boxes, left + 4)]
    body.append('<g class="dgm-links">')
    for index in range(1, len(spec.nodes)):
        edge = spec.edges[index - 1]
        start, stop = _span(
            placed[index - 1], index - 1, placed[index], index, boxes, across=False
        )
        start += CARD_CLEARANCE
        stop -= CARD_CLEARANCE
        hops.append(((axis, start), (axis, stop)))
        body.extend(_hop(edge, *hops[-1]))
        lines = _wrap(edge.label, label_columns)
        for offset, line in enumerate(lines):
            centred = offset - (len(lines) - 1) / 2
            baseline = (start + stop) / 2 + 4 + centred * 13
            body.append(
                f'<text {_paint("dgm-edge-label")} x="{_n(axis + LABEL_OFFSET)}" '
                f'y="{_n(baseline)}">{html.escape(line)}</text>'
            )
    body.append("</g>")
    motion = _packets(placed, hops)
    body.append(motion.markup)

    body.append('<g class="dgm-nodes">')
    for index, card in enumerate(placed):
        lines = _wrap(card.node.sub, sub_columns)
        text_x = card.x + GLYPH_COLUMN
        body.append(
            f'<g class="{_node_class(card.node.kind)}">'
            f"{_card(spec, 'vertical', index, card)}"
            f'<rect {_paint("dgm-chip", "dgm-owned-chip", f"dgm-here-{index}")} x="{_n(card.x + 14)}" '
            f'y="{_n(card.y + 20)}" width="36" height="36" rx="12"/>'
            f'<svg {_paint("dgm-glyph", "dgm-owned-glyph", f"dgm-here-{index}")} '
            f'x="{_n(card.x + 20)}" y="{_n(card.y + 26)}" '
            f'width="24" height="24" viewBox="0 0 24 24">'
            f"{_glyph(card.node.kind, index)}</svg>"
            f'<text {_paint("dgm-title")} x="{_n(text_x)}" '
            f'y="{_n(card.y + (34 if lines else 43))}">'
            f"{html.escape(card.node.title)}</text>"
        )
        for offset, line in enumerate(lines):
            body.append(
                f'<text {_paint("dgm-sub")} x="{_n(text_x)}" '
                f'y="{_n(card.y + 52 + offset * 13)}">{html.escape(line)}</text>'
            )
        body.append("</g>")
    body.append("</g>")
    return _document(spec, "vertical", width, height, body, motion)


def _render_horizontal(spec: Spec) -> str:
    """A band read across the page. A group rises onto a plateau."""
    card_width = _card_width(spec)
    sub_columns = int((card_width - CARD_PADDING) // LABEL_ADVANCE)
    labels = [_wrap(edge.label, EDGE_LABEL_COLUMNS) for edge in spec.edges]
    runs = groups(spec)

    plateau_y = float(H_MARGIN + (GROUP_TITLE_HEIGHT + GROUP_PAD if runs else 0))
    base_y = plateau_y + (PLATEAU_RISE if runs else 0)
    height = base_y + H_CARD_HEIGHT + H_MARGIN

    placed: list[Placed] = []
    x = float(H_MARGIN)
    for index, node in enumerate(spec.nodes):
        run = _run_at(runs, index)
        if index:
            x += _hop_gap(spec.edges[index - 1], labels[index - 1], runs, index)
        if run and run[0] == index:
            x += GROUP_PAD
        placed.append(
            Placed(node, x, plateau_y if run else base_y, card_width, H_CARD_HEIGHT)
        )
        x += card_width
        if run and run[1] == index:
            x += GROUP_PAD
    width = x + H_MARGIN

    boxes = [
        Enclosure(
            title,
            placed[first].x - GROUP_PAD,
            plateau_y - GROUP_TITLE_HEIGHT - GROUP_PAD,
            placed[last].right - placed[first].x + GROUP_PAD * 2,
            GROUP_TITLE_HEIGHT + GROUP_PAD * 2 + H_CARD_HEIGHT,
            first,
            last,
        )
        for first, last, title in runs
    ]

    hops: list[tuple[Point, Point]] = []
    body: list[str] = [_enclosures(boxes, None)]
    body.append('<g class="dgm-links">')
    for index in range(1, len(spec.nodes)):
        edge = spec.edges[index - 1]
        previous, following = placed[index - 1], placed[index]
        start_x, stop_x = _span(previous, index - 1, following, index, boxes, across=True)
        start_x += CARD_CLEARANCE
        stop_x -= CARD_CLEARANCE
        start = (start_x, previous.centre_y)
        stop = (stop_x, following.centre_y)
        hops.append((start, stop))
        body.extend(_hop(edge, start, stop))
        lines = labels[index - 1]
        middle_x = (start_x + stop_x) / 2
        middle_y = min(previous.centre_y, following.centre_y)
        for offset, line in enumerate(lines):
            baseline = middle_y - 19 - (len(lines) - 1 - offset) * 13
            body.append(
                f'<text {_paint("dgm-edge-label", "dgm-centred")} '
                f'x="{_n(middle_x)}" y="{_n(baseline)}">{html.escape(line)}</text>'
            )
    body.append("</g>")
    motion = _packets(placed, hops)
    body.append(motion.markup)

    body.append('<g class="dgm-nodes">')
    for index, card in enumerate(placed):
        lines = _wrap(card.node.sub, sub_columns)
        body.append(
            f'<g class="{_node_class(card.node.kind)}">'
            f"{_card(spec, 'horizontal', index, card)}"
            f'<rect {_paint("dgm-chip", "dgm-owned-chip", f"dgm-here-{index}")} '
            f'x="{_n(card.centre_x - 16)}" y="{_n(card.y + 14)}" '
            f'width="32" height="32" rx="11"/>'
            f'<svg {_paint("dgm-glyph", "dgm-owned-glyph", f"dgm-here-{index}")} '
            f'x="{_n(card.centre_x - 12)}" y="{_n(card.y + 18)}" '
            f'width="24" height="24" viewBox="0 0 24 24">'
            f"{_glyph(card.node.kind, index)}</svg>"
            f'<text {_paint("dgm-title", "dgm-centred")} x="{_n(card.centre_x)}" '
            f'y="{_n(card.y + (66 if lines else 74))}">'
            f"{html.escape(card.node.title)}</text>"
        )
        for offset, line in enumerate(lines):
            body.append(
                f'<text {_paint("dgm-sub", "dgm-centred")} x="{_n(card.centre_x)}" '
                f'y="{_n(card.y + 82 + offset * 13)}">{html.escape(line)}</text>'
            )
        body.append("</g>")
    body.append("</g>")
    return _document(spec, "horizontal", width, height, body, motion)


def _run_at(runs: list[tuple[int, int, str]], index: int) -> tuple[int, int, str] | None:
    for run in runs:
        if run[0] <= index <= run[1]:
            return run
    return None


def _card_width(spec: Spec) -> int:
    """Wide enough for the longest title the specification actually carries."""
    longest = max(len(node.title) for node in spec.nodes)
    return max(H_CARD_WIDTH, math.ceil(longest * TITLE_ADVANCE) + CARD_PADDING + 4)


def _hop_gap(edge, lines: list[str], runs, index: int) -> int:
    """Wide enough for the channel it draws and for any label above it."""
    base = TUNNEL_GAP_H if edge.channel == "tunnel" else H_CARD_GAP
    longest = max((len(line) for line in lines), default=0)
    gap = max(base, math.ceil(longest * LABEL_ADVANCE) + GAP_PADDING)
    # A hop that steps on or off a plateau has further to travel, and its
    # ends are eaten by the two enclosure walls it passes.
    if (_run_at(runs, index - 1) is None) != (_run_at(runs, index) is None):
        gap += GROUP_PAD * 2
    return gap


def _box_of(boxes: list[Enclosure], index: int) -> Enclosure | None:
    for box in boxes:
        if box.first <= index <= box.last:
            return box
    return None


def _span(
    first: Placed,
    first_index: int,
    second: Placed,
    second_index: int,
    boxes: list[Enclosure],
    across: bool,
) -> tuple[float, float]:
    """Where a hop starts and stops.

    A hop between two nodes of the same enclosure runs card to card. One that
    enters or leaves an enclosure stops at its wall instead, so the line does
    not run underneath the box.
    """
    box_first = _box_of(boxes, first_index)
    box_second = _box_of(boxes, second_index)
    inside = box_first is not None and box_first is box_second
    if across:
        start = first.right if inside or box_first is None else box_first.x + box_first.width
        stop = second.x if inside or box_second is None else box_second.x
    else:
        start = first.bottom if inside or box_first is None else box_first.y + box_first.height
        stop = second.y if inside or box_second is None else box_second.y
    return start, stop


def _enclosures(boxes: list[Enclosure], title_x: float | None) -> str:
    """Every group box, drawn behind the cards it holds."""
    if not boxes:
        return '<g class="dgm-groups"></g>'
    drawn = ['<g class="dgm-groups">']
    for box in boxes:
        drawn.append(
            f'<rect {_paint("dgm-group")} '
            f"{_rect(box.x, box.y, box.width, box.height, 20)}/>"
        )
        if title_x is None:
            drawn.append(
                f'<text {_paint("dgm-group-title", "dgm-centred")} '
                f'x="{_n(box.x + box.width / 2)}" y="{_n(box.y + 22)}">'
                f"{html.escape(box.title)}</text>"
            )
        else:
            drawn.append(
                f'<text {_paint("dgm-group-title")} x="{_n(title_x)}" '
                f'y="{_n(box.y + 22)}">{html.escape(box.title)}</text>'
            )
    drawn.append("</g>")
    return "".join(drawn)


def _hop(edge, start: Point, stop: Point) -> list[str]:
    """One hop between two points, at whatever angle they lie.

    Every channel is a stroked line, so a diagonal hop is drawn exactly like a
    level one and neither layout needs a rotation the site could reset.
    """
    length = math.dist(start, stop)
    if length <= ARROW_LENGTH:
        return []
    ux = (stop[0] - start[0]) / length
    uy = (stop[1] - start[1]) / length
    back = (stop[0] - ux * ARROW_LENGTH, stop[1] - uy * ARROW_LENGTH)
    drawn: list[str] = []

    if edge.channel == "tunnel":
        head = (start[0] + ux * CONDUIT_BORE / 2, start[1] + uy * CONDUIT_BORE / 2)
        tail = (back[0] - ux * CONDUIT_BORE / 2, back[1] - uy * CONDUIT_BORE / 2)
        drawn.append(f'<path {_paint("dgm-conduit")} d="{_line(head, tail)}"/>')
        for side in (-CONDUIT_BORE / 2, CONDUIT_BORE / 2):
            drawn.append(
                f'<path {_paint("dgm-conduit-wall")} '
                f'd="{_line(_offset(head, -uy, ux, side), _offset(tail, -uy, ux, side))}"/>'
            )
        drawn.append(f'<path {_paint("dgm-conduit-flow")} d="{_line(head, tail)}"/>')
    else:
        drawn.append(
            f'<path {_paint("dgm-link", f"dgm-link-{edge.channel}")} '
            f'd="{_line(start, back)}"/>'
        )

    left = _offset(back, -uy, ux, ARROW_HALF)
    right = _offset(back, -uy, ux, -ARROW_HALF)
    drawn.append(
        f'<path {_paint("dgm-arrow")} d="M{_n(left[0])} {_n(left[1])}'
        f"L{_n(right[0])} {_n(right[1])}L{_n(stop[0])} {_n(stop[1])}Z\"/>"
    )
    return drawn


def _offset(point: Point, nx: float, ny: float, by: float) -> Point:
    return (point[0] + nx * by, point[1] + ny * by)


def _line(start: Point, stop: Point) -> str:
    return f"M{_n(start[0])} {_n(start[1])}L{_n(stop[0])} {_n(stop[1])}"


def _node_class(kind: str) -> str:
    classes = f"dgm-node dgm-node-{kind}"
    return f"{classes} dgm-node-owned" if is_yume_owned(kind) else classes


def _card(spec: Spec, layout: str, index: int, card: Placed) -> str:
    """A card, the soft shape behind it, and which presence window it uses."""
    halo = _rect(
        card.x - LIFT_SPREAD,
        card.y - LIFT_SPREAD + LIFT_DROP,
        card.width + LIFT_SPREAD * 2,
        card.height + LIFT_SPREAD * 2,
        16 + LIFT_SPREAD,
    )
    return (
        f'<rect {_paint("dgm-lift", f"dgm-here-{index}")} {halo} '
        f'filter="url(#{_lift_id(spec, layout)})"/>'
        f'<rect {_paint("dgm-card", "dgm-owned-card")} '
        f"{_rect(card.x, card.y, card.width, card.height)}/>"
    )


def _glyph(kind: str, index: int) -> str:
    """The glyph strokes, each carrying its baseline paint and its window."""
    return GLYPHS[kind].replace(
        'class="dgm-glyph-fill"',
        _paint("dgm-glyph-fill", "dgm-owned-glyph-fill", f"dgm-here-{index}"),
    )


@dataclass
class Motion:
    """One loop: the packet's markup, its period, and where it is held."""

    markup: str
    duration: float
    spans: list[tuple[Point, Point]]


def _packets(placed: list[Placed], hops: list[tuple[Point, Point]]) -> Motion:
    """The travelling packet, on the line the route is actually drawn along.

    The path alternates: across a card to where its hop leaves, then the hop
    itself, exactly as `_hop` drew it. Building it from card centres instead
    would give a diagonal a different slope from its own arrow, and the packet
    would visibly miss the line it is supposed to be on.

    It is drawn under the cards, so it disappears into one node and emerges
    from the next, and the loop turns over while it is inside the last card,
    which is why the return is never seen. The card it is inside is lit from
    the same clock, so the two halves of the journey cannot drift apart.
    """
    points: list[Point] = [(placed[0].centre_x, placed[0].centre_y)]
    for index, (start, stop) in enumerate(hops):
        points.extend((start, stop))
        points.append((placed[index + 1].centre_x, placed[index + 1].centre_y))

    drawn_points: list[str] = []
    kept: list[Point] = []
    for index, point in enumerate(points):
        if index and points[index - 1] == point:
            continue
        kept.append(point)
        drawn_points.append(f"{'M' if len(kept) == 1 else 'L'} {_n(point[0])} {_n(point[1])}")

    travelled = sum(math.dist(a, b) for a, b in zip(kept, kept[1:]))
    duration = max(1.0, round(travelled / PIXELS_PER_SECOND, 2))
    markup = (
        '<g class="dgm-packets" aria-hidden="true">'
        f'<circle {_paint("dgm-packet", "dgm-packet-glow")} cx="0" cy="0" r="9" '
        f"style=\"--dgm-path:path('{' '.join(drawn_points)}')\"/>"
        f'<circle {_paint("dgm-packet", "dgm-packet-core")} cx="0" cy="0" r="4" '
        f"style=\"--dgm-path:path('{' '.join(drawn_points)}')\"/>"
        "</g>"
    )
    return Motion(markup, duration, _presence(kept, placed))


def _clip(start: Point, stop: Point, card: Placed) -> tuple[float, float] | None:
    """Where a segment lies inside a card, as a fraction of its own length.

    The Liang-Barsky slabs, which stay exact for the axis-parallel segments a
    card is actually crossed by and stay correct if a future layout runs one
    at an angle.
    """
    dx = stop[0] - start[0]
    dy = stop[1] - start[1]
    low, high = 0.0, 1.0
    for direction, room in (
        (-dx, start[0] - card.x),
        (dx, card.right - start[0]),
        (-dy, start[1] - card.y),
        (dy, card.bottom - start[1]),
    ):
        if direction == 0:
            if room < 0:
                return None
            continue
        edge = room / direction
        if direction < 0:
            if edge > high:
                return None
            low = max(low, edge)
        else:
            if edge < low:
                return None
            high = min(high, edge)
    return (low, high) if low < high else None


def _presence(points: list[Point], placed: list[Placed]) -> list[tuple[float, float]]:
    """When the packet is inside each card, as a fraction of one loop.

    This is the other half of the packet's journey. Without it a route with
    wide cards spends most of its loop with nothing drawn anywhere, which
    reads as the figure having stopped rather than as the packet being held.
    """
    lengths = [math.dist(a, b) for a, b in zip(points, points[1:])]
    total = sum(lengths)
    spans: list[tuple[float, float]] = []
    for card in placed:
        first: float | None = None
        last = 0.0
        run = 0.0
        for (start, stop), length in zip(zip(points, points[1:]), lengths):
            if length:
                window = _clip(start, stop, card)
                if window is not None:
                    if first is None:
                        first = run + window[0] * length
                    last = run + window[1] * length
            run += length
        spans.append((0.0, 0.0) if first is None else (first / total, last / total))
    return spans


def _presence_rules(scope: str, spans: list[tuple[float, float]], duration: float) -> str:
    """One keyframe per card, on the same clock the packet runs on.

    Keyframe names are global to the document that inlines the SVG, so both
    the names and the rules that reach for them carry the figure's own scope.
    """
    ramp = PRESENCE_RAMP_SECONDS / duration if duration else 0.0
    rules: list[str] = []
    for index, (enter, leave) in enumerate(spans):
        if enter == leave:
            continue
        lead = max(0.0, enter - min(ramp, (leave - enter) / 3))
        trail = min(1.0, leave + min(ramp, (leave - enter) / 3))
        name = f"dgm-{scope}-here-{index}"
        rest = "fill: var(--dgm-rest); stroke: var(--dgm-rest-line);"
        live = "fill: var(--dgm-live); stroke: var(--dgm-live-line);"
        stops = [f"  {_pct(enter)}, {_pct(leave)} {{ {live} }}"]
        if lead > 0:
            stops.insert(0, f"  0%, {_pct(lead)} {{ {rest} }}")
        if trail < 1:
            stops.append(f"  {_pct(trail)}, 100% {{ {rest} }}")
        body = "\n".join(stops)
        rules.append(f"@keyframes {name} {{\n{body}\n}}")
        rules.append(
            f'[data-dgm="{scope}"] .dgm-here-{index} {{ animation-name: {name}; }}'
        )
    return "\n\n".join(rules)


def _pct(fraction: float) -> str:
    return f"{_n(round(fraction * 100, 2))}%"


def _rect(x: float, y: float, width: float, height: float, radius: int = 16) -> str:
    """The geometry attributes a card and the shape under it both use."""
    return (
        f'x="{_n(x)}" y="{_n(y)}" width="{_n(width)}" '
        f'height="{_n(height)}" rx="{radius}"'
    )


def _lift_id(spec: Spec, layout: str) -> str:
    return f"dgm-{spec.name}-{layout}-lift"


def _document(
    spec: Spec,
    layout: str,
    width: float,
    height: float,
    body: list[str],
    motion: Motion,
) -> str:
    """One figure.

    Ids, keyframe names, and the scope attribute all carry the diagram name,
    because a page may inline several and both are global to that document.
    """
    scope = f"{spec.name}-{layout}"
    title_id = f"dgm-{scope}-title"
    desc_id = f"dgm-{scope}-desc"
    lines = [
        f'<svg class="dgm dgm-{layout}" data-dgm="{scope}" '
        f'width="{_n(width)}" height="{_n(height)}" '
        f'viewBox="0 0 {_n(width)} {_n(height)}" '
        f'role="img" aria-labelledby="{title_id} {desc_id}" '
        f'style="--dgm-dur:{_n(motion.duration)}s" '
        'xmlns="http://www.w3.org/2000/svg">',
        f'<title id="{title_id}">{html.escape(spec.title)}</title>',
        f'<desc id="{desc_id}">{html.escape(spec.summary)}</desc>',
        _stylesheet(_presence_rules(scope, motion.spans, motion.duration)),
        f'<defs><filter id="{_lift_id(spec, layout)}" x="-20%" y="-20%" '
        f'width="140%" height="140%"><feGaussianBlur stdDeviation="{LIFT_BLUR}"/>'
        "</filter></defs>",
        f'<rect {_paint("dgm-plate")} x="0.5" y="0.5" width="{_n(width - 1)}" '
        f'height="{_n(height - 1)}" rx="18"/>',
        *body,
        "</svg>",
        "",
    ]
    return "\n".join(lines)


def _wrap(text: str, columns: int) -> list[str]:
    """Greedy word wrap. Deterministic and stable for identical input."""
    if not text:
        return []
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if current and len(candidate) > columns:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _n(value: float) -> str:
    """Format a coordinate without trailing zeros so output stays stable."""
    rounded = round(float(value) + 0.0, 2)
    if rounded == int(rounded):
        return str(int(rounded))
    return f"{rounded:.2f}".rstrip("0").rstrip(".")
