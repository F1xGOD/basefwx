#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Draw a diagram specification as the ASCII form manuals and fences carry.

The figure is drawn on a character canvas. A route runs straight down one
column of equal boxes, and each hop is a short shaft with its label beside
the arrow head:

    +-------------------------+
    |  HUMAN APP              |
    |  browser / curl         |
    +------------+------------+
                 |
                 v ==YUME==> TLS 1.3 + HTTP/2
    +------------+------------+
    |  YUME CLIENT            |
    |  TLS / H2 / YUME frames |
    +-------------------------+

Every box shares one left edge and one port column, so the eye reads the
route as a single line and a label is never pushed off to the right by the
hops before it. A branch turns off on its parent's title row, and inputs
join one bus above the first box.

Two rules keep the drawing honest. A box is sized to the longest label in its
own figure, so a diagram that says less is narrower. The whole block stays
inside `BUDGET` columns, because a manual indents a literal region and a
terminal at eighty columns must not fold it.

Output is deterministic, so regeneration is a byte comparison.
"""

from __future__ import annotations

from yume_diagram_spec import Spec

# The widest block this renderer will emit. A manual indents a literal region
# by seven columns, so this leaves a terminal at eighty columns some room.
BUDGET = 68

# One box is a border, a title, a subtitle, and a border.
BOX_ROWS = 4

# Rows between two boxes: one for the shaft, one for the arrow head and the
# label beside it.
GAP_ROWS = 2

# Space between the arrow head and the text describing that hop.
LABEL_GUTTER = 1

GLYPH_DOWN = "|"
GLYPH_ARROW = "v"

# Where a hop meets a box. Marking the border is what separates a connected
# drawing from a line that merely passes near one, and it is the join every
# good manual figure draws.
GLYPH_PORT = "+"

# Columns between an input box and the bus its inputs share.
INPUT_REACH = 3


class Canvas:
    """A sparse character grid that trims itself when rendered."""

    def __init__(self) -> None:
        self.cells: dict[tuple[int, int], str] = {}

    def put(self, x: int, y: int, character: str) -> None:
        if x < 0 or y < 0:
            raise ValueError(f"character placed outside the canvas at {x},{y}")
        self.cells[(y, x)] = character

    def text(self, x: int, y: int, value: str) -> None:
        for offset, character in enumerate(value):
            self.put(x + offset, y, character)

    def width(self) -> int:
        return max((x for _, x in self.cells), default=-1) + 1

    def render(self, indent: int = 0) -> str:
        """Every row, left padded, with no trailing space on any line."""
        if not self.cells:
            return ""
        height = max(y for y, _ in self.cells) + 1
        pad = " " * indent
        rows: list[str] = []
        for y in range(height):
            row = [self.cells.get((y, x), " ") for x in range(self.width())]
            line = "".join(row).rstrip()
            rows.append(pad + line if line else "")
        return "\n".join(rows) + "\n"


def render(spec: Spec) -> str:
    """The complete ASCII block for one diagram, ending in a newline."""
    if spec.type == "layers":
        return _render_layers(spec)
    if spec.type == "sequence":
        return _render_sequence(spec)
    if spec.type not in ("route", "flow"):
        raise ValueError(f"no ASCII renderer for diagram type {spec.type!r}")
    if not _fits(spec, _chain_width(spec)):
        raise ValueError(f"{spec.name}: ASCII labels exceed the {BUDGET}-column budget; shorten the labels")
    return _render_route(spec)


def _box_width(nodes) -> int:
    """Two borders, a two-space left pad, the longest label, one trailing space."""
    return max(max(len(node.title), len(node.sub)) for node in nodes) + 5


def _chain_width(spec: Spec) -> int:
    return _box_width(spec.chain())


def _branch_gap(label: str) -> int:
    """Columns between a node and its side box: the arrow, with its label under it."""
    return max(6, len(label) + 4)


def _origin(spec: Spec, width: int) -> tuple[int, int, int]:
    """Where the chain starts, and where the inputs and their bus sit.

    Returns (chain left, input left, bus column). The bus drops onto the first
    chain box's port, so whichever of the two would sit left of the other is
    moved right until they meet.
    """
    inputs = spec.inputs()
    if not inputs:
        return 0, 0, 0
    bus = _box_width([node for _edge, node in inputs]) + INPUT_REACH
    left = max(0, bus - width // 2)
    shift = left + width // 2 - bus
    return left, shift, bus + shift


def _fits(spec: Spec, width: int) -> bool:
    chain = spec.chain()
    left, _shift, bus = _origin(spec, width)
    needed = max(bus + 1, left + width) + spec.indent
    arrow = left + width // 2
    for index in range(1, len(chain)):
        label = spec.edge_into(index).ascii_label()
        if label:
            needed = max(needed, arrow + 1 + LABEL_GUTTER + len(label) + spec.indent)
    for _parent, edge, side in spec.branches():
        reach = left + width + _branch_gap(edge.ascii_label()) + _box_width([side])
        needed = max(needed, reach + spec.indent)
    return needed <= BUDGET


def _render_route(spec: Spec) -> str:
    canvas = Canvas()
    chain = spec.chain()
    width = _chain_width(spec)
    left, first_top = _draw_inputs(canvas, spec, width)
    port = left + width // 2

    for index, node in enumerate(chain):
        top = first_top + index * (BOX_ROWS + GAP_ROWS)
        _box(canvas, left, top, width, node.title, node.sub)

        if index + 1 < len(chain):
            canvas.put(port, top + BOX_ROWS - 1, GLYPH_PORT)

        branch = spec.branch_at(index)
        if branch is not None:
            _branch(canvas, left + width, top, *branch)

        edge = spec.edge_into(index)
        if edge is None:
            continue
        canvas.put(port, top, GLYPH_PORT)
        _connector(canvas, port, top - GAP_ROWS, edge.ascii_label())

    if spec.inputs():
        canvas.put(port, first_top, GLYPH_PORT)
    return canvas.render(spec.indent)


def _draw_inputs(canvas: Canvas, spec: Spec, width: int) -> tuple[int, int]:
    """Stack the inputs above the chain and join them on one bus.

    Each input leaves a port on its right border along its title row and meets
    the bus at a `+`. The bus then drops, as one arrow, onto the port of the
    first chain box. Returns (chain left, first chain row).
    """
    inputs = spec.inputs()
    if not inputs:
        return 0, 0
    left, shift, bus = _origin(spec, width)
    box = _box_width([node for _edge, node in inputs])
    for number, (_edge, node) in enumerate(inputs):
        top = number * (BOX_ROWS + 1)
        _box(canvas, shift, top, box, node.title, node.sub)
        canvas.put(shift + box - 1, top + 1, GLYPH_PORT)
        canvas.text(shift + box, top + 1, "-" * (bus - shift - box))
        canvas.put(bus, top + 1, GLYPH_PORT)
    last_join = (len(inputs) - 1) * (BOX_ROWS + 1) + 1
    first_top = (len(inputs) - 1) * (BOX_ROWS + 1) + BOX_ROWS + GAP_ROWS
    for row in range(2, first_top - 1):
        if (row - 1) % (BOX_ROWS + 1) or row > last_join:
            canvas.put(bus, row, GLYPH_DOWN)
    canvas.put(bus, first_top - 1, GLYPH_ARROW)
    return left, first_top


def _branch(canvas: Canvas, right: int, top: int, edge, side) -> None:
    """A side box level with its parent, joined across the title row.

    The arrow leaves a port on the parent's right border and its label sits on
    the row beneath it, between the two boxes, so a branch reads as a turn off
    the path rather than as another step down it.
    """
    label = edge.ascii_label()
    gap = _branch_gap(label)
    side_left = right + gap
    canvas.put(right - 1, top + 1, GLYPH_PORT)
    canvas.text(right, top + 1, "-" * (gap - 1) + ">")
    if label:
        canvas.text(right + 2, top + 2, label)
    _box(canvas, side_left, top, _box_width([side]), side.title, side.sub)


def _render_layers(spec: Spec) -> str:
    """Nested boxes, outermost first, each naming its layer on one row.

    The subtitle is set flush right, so the descriptions form a column that
    steps inward with the nesting and the eye reads each layer across one row.
    """
    layers = list(reversed(spec.nodes))
    width = max(
        len(node.title) + (len(node.sub) + 2 if node.sub else 0) + 4 + 4 * level
        for level, node in enumerate(layers)
    )
    if width + spec.indent > BUDGET:
        raise ValueError(f"{spec.name}: ASCII layers exceed the {BUDGET}-column budget; shorten the labels")

    def nested(level: int, text: str) -> str:
        return "| " * level + text + " |" * level

    lines: list[str] = []
    for level, node in enumerate(layers):
        inner = width - 4 * level
        lines.append(nested(level, "+" + "-" * (inner - 2) + "+"))
        text = node.title + node.sub.rjust(inner - 4 - len(node.title)) if node.sub else node.title
        lines.append(nested(level, "| " + text.ljust(inner - 4) + " |"))
    for level in reversed(range(len(layers))):
        inner = width - 4 * level
        lines.append(nested(level, "+" + "-" * (inner - 2) + "+"))
    pad = " " * spec.indent
    return "\n".join(pad + line for line in lines) + "\n"


# A sequence draws each message as a shaft between two lifelines, in the
# character its channel implies. A tunnel names YUME at its tail, which is
# what the route form's ==YUME==> token says, so a terminal reader can tell
# the carrier from an ordinary connection.
SHAFTS = {"plain": "-", "tunnel": "=", "onion": "."}
TUNNEL_TAIL = "==YUME"
TUNNEL_HEAD_LEFT = "YUME=="

# Columns a label keeps clear of the lifelines on either side of it.
MESSAGE_PAD = 4

# A step one party takes alone is a small loop beside its lifeline, with the
# label beyond the loop. The loop is three columns wide plus a space.
SELF_LOOP = 5


def _render_sequence(spec: Spec) -> str:
    """Parties across the top, their lifelines down, and each message in turn.

        +---------+              +---------+
        |  yume   |              |  yumed  |
        +---------+              +---------+
             |                        |
             |  TLS 1.3, ALPN h2      |
             |----------------------->|
             |                        |
             |  AUTH CHALLENGE        |
             |<==YUME=================|

    A message between parties further apart passes over the lifelines between
    them. A step a party takes alone loops beside its lifeline, towards the
    middle of the figure, with its label past the loop.
    """
    parties = spec.nodes
    width = _box_width(parties)
    lines = _lifelines(spec, width)
    canvas = Canvas()
    for index, node in enumerate(parties):
        _box(canvas, lines[index] - width // 2, 0, width, node.title, node.sub)

    row = BOX_ROWS
    for edge in spec.edges:
        source, target = spec.column(edge.source), spec.column(edge.target)
        if source == target:
            left = source == len(parties) - 1
            _self_step(canvas, lines[source], row + 1, edge.label, left)
            row += 4
            continue
        low, high = sorted((lines[source], lines[target]))
        canvas.text(low + 3, row + 1, edge.label)
        shaft = SHAFTS[edge.channel] * (high - low - 2)
        if edge.channel == "tunnel":
            if source < target:
                shaft = TUNNEL_TAIL + shaft[len(TUNNEL_TAIL):]
            else:
                shaft = shaft[: len(shaft) - len(TUNNEL_TAIL)] + TUNNEL_HEAD_LEFT
        arrow = shaft + ">" if source < target else "<" + shaft
        canvas.text(low + 1, row + 2, arrow)
        row += 3
    for column in lines:
        for y in range(BOX_ROWS, row + 1):
            if (y, column) not in canvas.cells:
                canvas.put(column, y, GLYPH_DOWN)
    if canvas.width() + spec.indent > BUDGET:
        raise ValueError(
            f"{spec.name}: ASCII sequence exceeds the {BUDGET}-column budget; shorten the labels"
        )
    return canvas.render(spec.indent)


def _lifelines(spec: Spec, width: int) -> list[int]:
    """Each party's lifeline column, spaced so every label fits its message.

    Boxes start two columns apart. A message then needs its label plus a pad
    between the two lifelines it joins, and a step needs its loop and label
    before the neighbouring lifeline. Widening only the last gap of a span
    never undoes an earlier fit, so one pass in message order is enough.
    """
    count = len(spec.nodes)
    gaps = [width + 2] * (count - 1)
    for edge in spec.edges:
        source, target = spec.column(edge.source), spec.column(edge.target)
        if source == target:
            low, high = (source - 1, source) if source == count - 1 else (source, source + 1)
            needed = SELF_LOOP + len(edge.label) + 2
        else:
            low, high = sorted((source, target))
            needed = len(edge.label) + MESSAGE_PAD + 1
            if edge.channel == "tunnel":
                needed = max(needed, len(TUNNEL_TAIL) + MESSAGE_PAD)
        span = sum(gaps[low:high])
        if span < needed:
            gaps[high - 1] += needed - span
    lines = [width // 2]
    for gap in gaps:
        lines.append(lines[-1] + gap)
    return lines


def _self_step(canvas: Canvas, column: int, top: int, label: str, left: bool) -> None:
    """A loop off one lifeline and back, with the label past the loop."""
    if left:
        canvas.text(column - 3, top, ".--")
        canvas.put(column - 3, top + 1, "|")
        canvas.text(column - 3, top + 2, "'->")
        canvas.text(column - 4 - len(label) - 1, top + 1, label)
    else:
        canvas.text(column + 1, top, "--.")
        canvas.put(column + 3, top + 1, "|")
        canvas.text(column + 1, top + 2, "<-'")
        canvas.text(column + SELF_LOOP, top + 1, label)


def _box(canvas: Canvas, left: int, top: int, width: int, title: str, sub: str) -> None:
    border = "+" + "-" * (width - 2) + "+"
    canvas.text(left, top, border)
    canvas.text(left, top + 1, _row(title, width))
    canvas.text(left, top + 2, _row(sub, width))
    canvas.text(left, top + 3, border)


def _row(text: str, width: int) -> str:
    """One boxed line: two spaces of pad, the text, then the right border."""
    return "|" + ("  " + text).ljust(width - 2) + "|"


def _connector(canvas: Canvas, column: int, top: int, label: str) -> None:
    """One hop down the gap rows: a shaft, then the arrow head and its label.

    The label sits beside the head, so every label in a figure starts in the
    same column and reads as a caption for the hop it ends.
    """
    for row in range(GAP_ROWS - 1):
        canvas.put(column, top + row, GLYPH_DOWN)
    canvas.put(column, top + GAP_ROWS - 1, GLYPH_ARROW)
    if label:
        canvas.text(column + 1 + LABEL_GUTTER, top + GAP_ROWS - 1, label)
