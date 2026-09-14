#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Draw a diagram specification as the ASCII form manuals and fences carry.

The figure is drawn on a character canvas rather than assembled from rows of
equal boxes, so a hop runs at whatever angle the layout gives it:

    +-------------------------+
    |  HUMAN APP              |
    |  browser / curl         |
    +-------------------------+
              \\
               \\
                v
       +-------------------------+
       |  YUME CLIENT            |
       |  TLS / H2 / YUME frames |
       +-------------------------+

A route descends across the page instead of straight down it. That shape is
what a reader already recognises from a manual such as ffmpeg's, and it says
something the stacked form could not: each hop is a step away from the one
before rather than another equal box in a column.

Two rules keep the drawing honest. A box is sized to the longest label in its
own figure, so a diagram that says less is narrower. The whole block stays
inside `BUDGET` columns, because a manual indents a literal region and a
terminal at eighty columns must not fold it. Where the staircase would not
fit, the layout falls back to a straight descent rather than overflowing.

Output is deterministic, so regeneration is a byte comparison.
"""

from __future__ import annotations

from yume_diagram_spec import Spec

# The widest block this renderer will emit. A manual indents a literal region
# by seven columns, so this leaves a terminal at eighty columns some room.
BUDGET = 68

# One box is a border, a title, a subtitle, and a border.
BOX_ROWS = 4

# Rows between two boxes. Three is the smallest that fits a connector, a
# label beside it, and an arrow head.
GAP_ROWS = 3

# Columns a hop travels sideways while it descends. The run leaves the tee
# on the border and advances one column per row, so a step equal to the gap
# is a clean forty-five degrees rather than a stepped approximation.
STEP = GAP_ROWS

# Space between the arrow head and the text describing that hop.
LABEL_GUTTER = 2

GLYPH_DOWN = "|"
GLYPH_RIGHT = "\\"
GLYPH_LEFT = "/"
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
    if spec.type not in ("route", "flow"):
        raise ValueError(f"no ASCII renderer for diagram type {spec.type!r}")
    if not _fits(spec, _chain_width(spec), 0):
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


def step_for(spec: Spec) -> int:
    """The sideways travel per hop that keeps this figure inside the budget.

    A figure only leans when leaning fits. Falling back to a straight descent
    is better than a drawing a terminal folds, and it is what a long route of
    wide boxes gets.
    """
    width = _chain_width(spec)
    hops = len(spec.chain()) - 1
    if hops < 1:
        return 0
    for candidate in range(STEP, 0, -1):
        if _fits(spec, width, candidate):
            return candidate
    return 0


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


def _fits(spec: Spec, width: int, step: int) -> bool:
    chain = spec.chain()
    hops = len(chain) - 1
    left, _shift, bus = _origin(spec, width)
    needed = max(bus + 1, left + width + step * hops) + spec.indent
    for index in range(1, len(chain)):
        label = spec.edge_into(index).ascii_label()
        if not label:
            continue
        arrow = left + index * step + width // 2
        needed = max(needed, arrow + LABEL_GUTTER + len(label) + spec.indent)
    for parent, edge, side in spec.branches():
        reach = left + parent * step + width + _branch_gap(edge.ascii_label()) + _box_width([side])
        needed = max(needed, reach + spec.indent)
    return needed <= BUDGET


def _render_route(spec: Spec) -> str:
    canvas = Canvas()
    chain = spec.chain()
    width = _chain_width(spec)
    step = step_for(spec)
    origin, first_top = _draw_inputs(canvas, spec, width)

    for index, node in enumerate(chain):
        left = origin + index * step
        top = first_top + index * (BOX_ROWS + GAP_ROWS)
        _box(canvas, left, top, width, node.title, node.sub)

        port = left + width // 2
        if index + 1 < len(chain):
            canvas.put(port, top + BOX_ROWS - 1, GLYPH_PORT)

        branch = spec.branch_at(index)
        if branch is not None:
            _branch(canvas, left + width, top, *branch)

        edge = spec.edge_into(index)
        if edge is None:
            continue
        canvas.put(port, top, GLYPH_PORT)
        _connector(
            canvas,
            source_column=origin + (index - 1) * step + width // 2,
            target_column=port,
            top=top - GAP_ROWS,
            label=edge.ascii_label(),
        )

    if spec.inputs():
        canvas.put(origin + width // 2, first_top, GLYPH_PORT)
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


def _box(canvas: Canvas, left: int, top: int, width: int, title: str, sub: str) -> None:
    border = "+" + "-" * (width - 2) + "+"
    canvas.text(left, top, border)
    canvas.text(left, top + 1, _row(title, width))
    canvas.text(left, top + 2, _row(sub, width))
    canvas.text(left, top + 3, border)


def _row(text: str, width: int) -> str:
    """One boxed line: two spaces of pad, the text, then the right border."""
    return "|" + ("  " + text).ljust(width - 2) + "|"


def _connector(
    canvas: Canvas, source_column: int, target_column: int, top: int, label: str
) -> None:
    """Draw one hop across the gap rows, ending in an arrow head.

    The column at each row is interpolated between the two connection points,
    and the glyph at a row says which way the next row moves. A hop that does
    not move sideways is the straight descent the stacked form always drew.
    """
    travel = target_column - source_column
    last = GAP_ROWS - 1
    # Row zero already sits one row below the tee it left, so the run has
    # GAP_ROWS steps to cover the travel and the head lands on the last one.
    columns = [
        source_column + ((row + 1) * travel + GAP_ROWS // 2) // GAP_ROWS
        for row in range(GAP_ROWS)
    ]
    # The head has to sit exactly on the target's connection column. Rounding
    # a middle row is a drawing choice, but rounding the endpoint would point
    # the arrow at a column the box does not occupy.
    columns[last] = target_column

    previous = source_column
    for row in range(GAP_ROWS):
        if row == last:
            canvas.put(target_column, top + row, GLYPH_ARROW)
            continue
        moved = columns[row] - previous
        if moved > 0:
            glyph = GLYPH_RIGHT
        elif moved < 0:
            glyph = GLYPH_LEFT
        else:
            glyph = GLYPH_DOWN
        canvas.put(columns[row], top + row, glyph)
        previous = columns[row]

    if label:
        # The label sits beside the arrow head rather than beside the middle
        # of the run, so every label in a figure starts from the same kind of
        # anchor whatever angle its hop took.
        canvas.text(target_column + LABEL_GUTTER, top + GAP_ROWS - 1, label)
