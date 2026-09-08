#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render a `.doc` source as the roff manual a terminal displays.

Unlike the Markdown renderer this one refills the text. A manual fills lines
itself, so an authored break carries no meaning here, and a font change is
the only thing that forces a line of its own. That difference is the whole
reason both layers can come from one source: each keeps the convention its
own readers expect.

A table becomes an aligned literal region rather than a `tbl` block. `tbl`
needs a preprocessor line and a working pipeline, and a terminal that lacks
one silently prints the table source. An aligned region always renders.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_doc_inline as inline
from yume_doc_spec import SYNOPSIS_LITERAL, Doc, Block, table_cells

BANNER = '.\\" Generated from {source} by scripts/yume_docs.py. Edit that file, not this one.'

# A literal region inside a section body. Wider than this and a terminal at
# the traditional 80 columns wraps the region, which destroys an aligned
# table or a diagram.
LITERAL_WIDTH = 72


def render(doc: Doc, layer: str = "man") -> str:
    """The complete roff manual for one document, ending in a newline."""
    from yume_doc_spec import relative

    lines: list[str] = [
        BANNER.format(source=relative(doc.path)),
        _title_line(doc),
        ".SH NAME",
        f"{inline.escape_roff(doc.title)} \\- {inline.escape_roff(doc.summary)}",
    ]

    # `first_in_section` is what decides whether a paragraph opens with `.PP`.
    # The first paragraph of a section already starts on a new line, so a
    # break there only adds vertical space a manual did not ask for.
    first_in_section = False
    for block in doc.blocks:
        if not block.reaches(layer):
            continue
        if block.kind == "heading":
            lines.extend(_heading(block))
            first_in_section = True
            continue
        rendered = _block(block, first_in_section, doc.language)
        if not rendered:
            continue
        lines.extend(rendered)
        first_in_section = False

    return "\n".join(lines).rstrip("\n") + "\n"


def _title_line(doc: Doc) -> str:
    name = inline.escape_roff(doc.title.upper())
    def quoted(value: str) -> str:
        return inline.escape_roff(value).replace('"', r'\(dq')
    return (
        f'.TH {name} {doc.man_section} "{quoted(doc.man_date)}" '
        f'"{quoted(doc.man_source)}" "{quoted(doc.man_manual)}"'
    )


def _heading(block: Block) -> list[str]:
    """A section heading as authored. The parser holds the case convention."""
    text = inline.escape_roff(inline.plain(block.text))
    return [f".SH {text}" if block.level == 2 else f".SS {text}"]


def _block(block: Block, first_in_section: bool, language: str) -> list[str]:
    if block.kind in ("paragraph", "quote"):
        body = _strip_quote(block.lines) if block.kind == "quote" else block.lines
        rendered = inline.to_roff(body)
        return rendered if first_in_section else [".PP", *rendered]
    if block.kind == "synopsis":
        # The heading belongs to the renderer, not the source. A manual that
        # named its own SYNOPSIS could also forget to, and the section is not
        # optional.
        if block.text == SYNOPSIS_LITERAL:
            return [".SH SYNOPSIS", *_literal(block.lines, first_in_section=True)]
        # Each authored line is one way to invoke the command, so the forms
        # are kept apart rather than filled into a single paragraph.
        out = [".SH SYNOPSIS"]
        for position, form in enumerate(line for line in block.lines if line.strip()):
            if position:
                out.append(".PP")
            out.extend(inline.to_roff([form]))
        return out
    if block.kind == "bullets":
        return _bullets(block)
    if block.kind == "ordered":
        return _ordered(block)
    if block.kind == "code":
        return _literal(block.lines, first_in_section)
    if block.kind == "table":
        return _literal(_align(block.lines), first_in_section)
    if block.kind == "options":
        return _options(block)
    if block.kind == "diagram":
        return _diagram(block, language)
    raise ValueError(f"no roff rendering for block kind {block.kind!r}")


def _strip_quote(lines: list[str]) -> list[str]:
    """A blockquote is an aside in Markdown and an ordinary paragraph here."""
    return [line.lstrip(">").strip() for line in lines]


def _bullets(block: Block) -> list[str]:
    output: list[str] = []
    for item in _items(block.lines, marker=("- ", "* ")):
        output.append(".IP \\(bu 2")
        output.extend(inline.to_roff(item))
    return output


def _ordered(block: Block) -> list[str]:
    output: list[str] = []
    for position, item in enumerate(_items(block.lines, marker=None), start=1):
        output.append(f'.IP "{position}." 4')
        output.extend(inline.to_roff(item))
    return output


def _items(lines: list[str], marker: tuple[str, ...] | None) -> list[list[str]]:
    """Group list lines into items, joining each item's continuations."""
    items: list[list[str]] = []
    for line in lines:
        stripped = line.strip()
        starts = (
            any(stripped.startswith(entry) for entry in marker)
            if marker
            else bool(stripped and stripped[0].isdigit() and ". " in stripped[:4])
        )
        if starts:
            body = stripped.split(" ", 1)[1] if " " in stripped else ""
            items.append([body])
        elif items:
            items[-1].append(stripped)
    return items


def _literal(lines: list[str], first_in_section: bool) -> list[str]:
    """A region roff prints exactly, guarded against control characters."""
    body = [inline.escape_roff(line) for line in lines]
    protected = ["\\&" + line if line.startswith((".", "'")) else line for line in body]
    opening = [".nf"] if first_in_section else [".PP", ".nf"]
    return [*opening, *protected, ".fi"]


def _align(rows: list[str]) -> list[str]:
    """Turn a Markdown table into aligned columns a terminal can read."""
    parsed: list[list[str]] = []
    for row in rows:
        if not row.strip():
            continue
        cells = [cell.strip() for cell in table_cells(row)]
        # A terminal has no escaping to preserve, so an escaped pipe is shown
        # as the pipe the reader is meant to see.
        parsed.append([inline.plain(cell).replace("\\|", "|") for cell in cells])

    alignment = [
        "right" if cell.endswith(":") and not cell.startswith(":") else "left"
        for cell in parsed[1]
    ]
    header, body = parsed[0], parsed[2:]

    widths = [len(cell) for cell in header]
    for row in body:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(cells: list[str]) -> str:
        parts: list[str] = []
        for index, cell in enumerate(cells):
            if alignment[index] == "right":
                parts.append(cell.rjust(widths[index]))
            else:
                parts.append(cell.ljust(widths[index]))
        return "  ".join(parts).rstrip()

    rule = "  ".join("-" * width for width in widths)
    return [format_row(header), rule, *(format_row(row) for row in body)]


def _options(block: Block) -> list[str]:
    output: list[str] = []
    for option in block.options:
        output.append(".TP")
        output.append(inline.signature_to_roff(option.signature))
        output.extend(inline.to_roff(option.body))
    return output


def _diagram(block: Block, language: str) -> list[str]:
    """Emit the marker pair scripts/yume_diagrams.py owns, holding the ASCII."""
    import yume_diagrams
    from yume_diagram_spec import load

    spec = load(block.text, language)
    target = Path("generated.1")
    body = yume_diagrams.render_block(spec, target, language)
    return [
        yume_diagrams.ROFF_OPEN.format(name=block.text),
        *body,
        yume_diagrams.ROFF_CLOSE,
    ]
