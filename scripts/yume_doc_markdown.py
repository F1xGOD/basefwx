#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render a `.doc` source as the Markdown a reader opens in a clone.

The web publisher calls the same renderer with the web filter, then rewrites
links and embeds enabled figures. Clone-only and web-only blocks are selected
before either output is written.

Authored line breaks are kept. Markdown reflows in a browser, so where the
author broke a line says nothing to a reader, but it says a great deal to
whoever reviews the diff. Keeping the breaks is what lets a document move
into this format without a single word of its output changing.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_doc_inline as inline
from yume_doc_spec import Doc, Block

# The width a generated list body wraps to. Only text this renderer had to
# re-indent is wrapped, because that text has no authored break to keep.
MARKDOWN_WIDTH = 78

BANNER = (
    "<!-- Generated from {source} by scripts/yume_docs.py. "
    "Edit that file, not this one. -->"
)


def banner(doc: Doc) -> str:
    from yume_doc_spec import relative

    return BANNER.format(source=relative(doc.path))


def render(doc: Doc, layer: str = "markdown") -> str:
    """The complete Markdown file for one document, ending in a newline."""
    from yume_doc_spec import REPO_ROOT

    lines: list[str] = [banner(doc), f"# {inline.to_markdown(doc.title)}"]
    if doc.kind == "man":
        lines.extend(("", inline.to_markdown(doc.summary)))
    target = REPO_ROOT / dict(doc.outputs()).get("markdown", doc.markdown)

    for block in doc.blocks:
        if not block.reaches(layer):
            continue
        rendered = _block(block, target, doc.language)
        if not rendered:
            continue
        lines.append("")
        lines.extend(rendered)

    return "\n".join(lines).rstrip("\n") + "\n"


def _block(block: Block, target: Path, language: str) -> list[str]:
    if block.kind == "heading":
        return [f"{'#' * block.level} {inline.to_markdown(block.text)}"]
    if block.kind in ("paragraph", "bullets", "ordered", "quote"):
        return [inline.to_markdown(line) for line in block.lines]
    if block.kind == "table":
        return [inline.to_markdown(line) for line in block.lines]
    if block.kind == "code":
        pad = " " * block.indent
        return [f"{pad}```{block.text}", *block.lines, f"{pad}```"]
    if block.kind == "synopsis":
        body = (["```text", *block.lines, "```"] if block.text == "literal"
                else [inline.to_markdown(line) for line in block.lines])
        return ["## SYNOPSIS", "", *body]
    if block.kind == "options":
        return _options(block)
    if block.kind == "diagram":
        return _diagram(block, target, language)
    raise ValueError(f"no Markdown rendering for block kind {block.kind!r}")


def _options(block: Block) -> list[str]:
    """An option list becomes a loose bullet list.

    The blank line inside each item is what keeps the signature on a line of
    its own once GitHub renders it. Bodies are re-wrapped because this
    renderer chose their indent, so the authored break no longer applies.
    """
    lines: list[str] = []
    for position, option in enumerate(block.options):
        if position:
            lines.append("")
        lines.append(f"- {inline.signature_to_markdown(option.signature)}")
        lines.append("")
        text = " ".join(line.strip() for line in option.body if line.strip())
        for wrapped in inline.wrap(inline.to_markdown(text), MARKDOWN_WIDTH - 2):
            lines.append(f"  {wrapped}")
    return lines


def _diagram(block: Block, target: Path, language: str) -> list[str]:
    """Emit the marker pair with the figure scripts/yume_diagrams.py owns.

    The diagram tooling remains the single owner of what sits between the
    markers. Calling it here means one `yume_docs.py sync` writes the final
    bytes, and a later `yume_diagrams.py sync` changes nothing. The target
    path matters, because the figure points at a tracked SVG relative to the
    document that shows it.
    """
    import yume_diagrams
    from yume_diagram_spec import load

    spec = load(block.text, language)
    body = yume_diagrams.render_block(spec, target, language)
    return [
        yume_diagrams.MARKDOWN_OPEN.format(name=block.text),
        *body,
        yume_diagrams.MARKDOWN_CLOSE,
    ]
