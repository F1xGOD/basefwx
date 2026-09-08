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
    if spec.type != "route":
        raise ValueError(f"no ASCII renderer for diagram type {spec.type!r}")
    if not _fits(spec, spec.ascii_width(), 0):
        raise ValueError(f"{spec.name}: ASCII labels exceed the {BUDGET}-column budget; shorten the labels")
    return _render_route(spec)


def step_for(spec: Spec) -> int:
    """The sideways travel per hop that keeps this figure inside the budget.

    A figure only leans when leaning fits. Falling back to a straight descent
    is better than a drawing a terminal folds, and it is what a long route of
    wide boxes gets.
    """
    width = spec.ascii_width()
    hops = len(spec.nodes) - 1
    if hops < 1:
        return 0
    for candidate in range(STEP, 0, -1):
        if _fits(spec, width, candidate):
            return candidate
    return 0


def _fits(spec: Spec, width: int, step: int) -> bool:
    hops = len(spec.nodes) - 1
    needed = width + step * hops + spec.indent
    for index in range(1, len(spec.nodes)):
        label = spec.edge_into(index).ascii_label() if spec.edge_into(index) else ""
        if not label:
            continue
        arrow = index * step + width // 2
        needed = max(needed, arrow + LABEL_GUTTER + len(label) + spec.indent)
    return needed <= BUDGET


def _render_route(spec: Spec) -> str:
    canvas = Canvas()
    width = spec.ascii_width()
    step = step_for(spec)

    for index, node in enumerate(spec.nodes):
        left = index * step
        top = index * (BOX_ROWS + GAP_ROWS)
        _box(canvas, left, top, width, node.title, node.sub)

        port = left + width // 2
        if index + 1 < len(spec.nodes):
            canvas.put(port, top + BOX_ROWS - 1, GLYPH_PORT)

        edge = spec.edge_into(index)
        if edge is None:
            continue
        canvas.put(port, top, GLYPH_PORT)
        _connector(
            canvas,
            source_column=(index - 1) * step + width // 2,
            target_column=port,
            top=top - GAP_ROWS,
            label=edge.ascii_label(),
        )

    return canvas.render(spec.indent)


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
