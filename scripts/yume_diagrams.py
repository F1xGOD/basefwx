#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render the YUME diagrams from docs/diagrams into every place they appear.

One JSON specification per diagram drives three outputs:

  * the fixed-width ASCII block in the man pages,
  * the same block inside a Markdown fence in the documentation,
  * an animated SVG the website inlines in place of that fence.

Editing the specification and running `sync` updates all three. `check` proves
they are current without writing, which is what CI runs.

Usage:
    scripts/yume_diagrams.py list
    scripts/yume_diagrams.py render <name> [--svg]
    scripts/yume_diagrams.py sync
    scripts/yume_diagrams.py check
    scripts/yume_diagrams.py svg
    scripts/yume_diagrams.py preview
    scripts/yume_diagrams.py embed <file|->

Blocks are delimited by markers that neither roff nor Markdown renders:

    <!-- yume-diagram: direct_route -->
    ```text
    ...
    ```
    <!-- /yume-diagram -->

    .\\" yume-diagram: direct_route
    .nf
    ...
    .fi
    .\\" /yume-diagram
"""

from __future__ import annotations

import argparse
import html
import os
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_diagram_ascii
import yume_diagram_preview
from yume_diagram_spec import (
    REPO_ROOT,
    SOURCE_LANGUAGE,
    Spec,
    SpecError,
    load,
    load_all,
    load_strings,
    missing_strings,
)

# The rendered SVG is tracked beside the specification that produced it, so a
# Markdown document can point at it and GitHub can draw it. The website needs
# the same bytes under _includes to inline them, and that copy stays ignored.
SVG_DIR = REPO_ROOT / "docs" / "diagrams"
INCLUDE_DIR = REPO_ROOT / "website" / "_includes" / "diagrams"

# A Markdown document shows the figure and keeps the ASCII one click away.
# The layout is the stacked one, which fits a reading column at its own size.
MARKDOWN_LAYOUT = "vertical"

MARKDOWN_OPEN = "<!-- yume-diagram: {name} -->"
MARKDOWN_CLOSE = "<!-- /yume-diagram -->"
MARKDOWN_FENCE = "```text"
MARKDOWN_FENCE_END = "```"

ROFF_OPEN = '.\\" yume-diagram: {name}'
ROFF_CLOSE = '.\\" /yume-diagram'
ROFF_FENCE = ".nf"
ROFF_FENCE_END = ".fi"

# Every file that may carry a marker. A marker outside this set would never be
# regenerated, so the scan below refuses to leave one unnoticed.
SCANNED_GLOBS = (
    "docs/*.md",
    "docs/protocol/*.md",
    "docs/release/*.md",
    "docs/development/**/*.md",
    "docs/man/*",
    "docs/development/**/man/*",
    "README.md",
    "CONTRIBUTING.md",
)


class DiagramError(RuntimeError):
    """A marker or a target file is inconsistent with the specifications."""


@dataclass
class Block:
    name: str
    open_index: int
    close_index: int
    body: list[str]
    line_number: int


def _markers(path: Path) -> tuple[str, str, str, str]:
    if path.suffix == ".md":
        return MARKDOWN_OPEN, MARKDOWN_CLOSE, MARKDOWN_FENCE, MARKDOWN_FENCE_END
    return ROFF_OPEN, ROFF_CLOSE, ROFF_FENCE, ROFF_FENCE_END


def find_blocks(path: Path, lines: list[str]) -> list[Block]:
    """Locate every marked diagram block in one file."""
    open_template, close_marker, fence, fence_end = _markers(path)
    prefix = open_template.split("{name}")[0]
    suffix = open_template.split("{name}")[1]
    blocks: list[Block] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not (line.startswith(prefix) and line.endswith(suffix) and line != close_marker):
            index += 1
            continue
        name = line[len(prefix): len(line) - len(suffix)].strip()
        location = f"{_relative(path)}:{index + 1}"
        if not name:
            raise DiagramError(f"{location}: diagram marker names no diagram")
        close = index + 1
        while close < len(lines) and lines[close].strip() != close_marker:
            close += 1
        if close >= len(lines):
            raise DiagramError(f"{location}: diagram block is not closed by {close_marker!r}")
        body = lines[index + 1: close]
        _require_fence(body, fence, fence_end, location)
        blocks.append(
            Block(
                name=name,
                open_index=index,
                close_index=close,
                body=body,
                line_number=index + 1,
            )
        )
        index = close + 1
    return blocks


def _require_fence(body: list[str], fence: str, fence_end: str, location: str) -> None:
    """A filled block carries exactly one literal region for the ASCII form.

    An empty pair of markers is how a new diagram is placed, so it is accepted
    and `sync` writes the body.
    """
    if not any(line.strip() for line in body):
        return
    opens = [i for i, line in enumerate(body) if line.strip() == fence]
    if len(opens) != 1:
        raise DiagramError(f"{location}: diagram block needs one {fence!r} line")
    closes = [i for i, line in enumerate(body) if i > opens[0] and line.strip() == fence_end]
    if not closes:
        raise DiagramError(f"{location}: diagram block is not closed by {fence_end!r}")


def svg_dir(language: str) -> Path:
    """Where one language's rendered figures live.

    The source language keeps the paths documents already point at. Another
    language needs its own drawings, because the labels inside them are the
    thing being translated.
    """
    return SVG_DIR if language == SOURCE_LANGUAGE else SVG_DIR / language


def include_dir(language: str) -> Path:
    return INCLUDE_DIR if language == SOURCE_LANGUAGE else INCLUDE_DIR / language


def render_block(spec: Spec, path: Path, language: str = SOURCE_LANGUAGE) -> list[str]:
    """Everything between the two markers, for the kind of file it lands in."""
    pad = " " * spec.indent
    ascii_lines = yume_diagram_ascii.render(spec).rstrip("\n").split("\n")
    if path.suffix != ".md":
        # roff reads a backslash as the start of an escape, and one at the end
        # of a line joins that line to the next. A diagonal hop is drawn with
        # backslashes, so an unescaped figure loses every hop that leans right
        # and leaves its arrow head in a column nothing points at.
        return [ROFF_FENCE, *(_roff_literal(line) for line in ascii_lines), ROFF_FENCE_END]

    if not spec.web:
        return [f"{pad}{MARKDOWN_FENCE}", *ascii_lines, f"{pad}{MARKDOWN_FENCE_END}"]

    source = os.path.relpath(
        svg_dir(language) / include_name(spec.name, MARKDOWN_LAYOUT), path.parent
    )
    import yume_diagram_svg
    width, height = yume_diagram_svg.dimensions(spec, MARKDOWN_LAYOUT)
    return [
        f'{pad}<img src="{source}" alt="{html.escape(spec.title, quote=True)}"'
        f' width="{width}" height="{height}">',
        "",
        f"{pad}<details>",
        f"{pad}<summary>Text version</summary>",
        "",
        f"{pad}{MARKDOWN_FENCE}",
        *ascii_lines,
        f"{pad}{MARKDOWN_FENCE_END}",
        "",
        f"{pad}</details>",
    ]


def _roff_literal(line: str) -> str:
    """One figure line as roff prints it, backslashes and all."""
    return line.replace("\\", "\\e")


def rewrite(path: Path, specs: dict[str, Spec]) -> tuple[str, list[str]]:
    """Return the file content with every marked block regenerated."""
    original = path.read_text(encoding="utf-8")
    lines = original.split("\n")
    blocks = find_blocks(path, lines)
    stale: list[str] = []
    output = list(lines)
    for block in reversed(blocks):
        spec = specs.get(block.name)
        if spec is None:
            raise DiagramError(
                f"{_relative(path)}:{block.line_number}: no specification named {block.name!r}"
            )
        rendered = render_block(spec, path)
        if rendered != block.body:
            stale.append(f"{_relative(path)}:{block.line_number}: {block.name} is stale")
        output[block.open_index + 1: block.close_index] = rendered
    return "\n".join(output), stale


def scanned_files() -> list[Path]:
    found: set[Path] = set()
    for pattern in SCANNED_GLOBS:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file():
                found.add(path)
    return sorted(found)


def declared_targets(specs: list[Spec]) -> dict[Path, set[str]]:
    """Which diagram each specification claims to own in which file."""
    declared: dict[Path, set[str]] = {}
    for spec in specs:
        for target in spec.man_targets + spec.markdown_targets:
            declared.setdefault(REPO_ROOT / target, set()).add(spec.name)
    return declared


def verify_targets(specs: list[Spec]) -> list[str]:
    """Every declared target carries its marker and every marker is declared."""
    problems: list[str] = []
    declared = declared_targets(specs)
    present: dict[Path, list[str]] = {}
    for path in scanned_files():
        names = [block.name for block in find_blocks(path, path.read_text(encoding="utf-8").split("\n"))]
        if names:
            present[path] = names

    for path, names in present.items():
        for name in names:
            if name not in declared.get(path, set()):
                problems.append(
                    f"{_relative(path)}: carries a {name!r} marker that "
                    f"docs/diagrams/{name}.json does not declare as a target"
                )
        duplicates = sorted({name for name in names if names.count(name) > 1})
        for name in duplicates:
            problems.append(f"{_relative(path)}: has more than one {name!r} marker")

    for path, names in declared.items():
        for name in sorted(names):
            if name not in present.get(path, []):
                problems.append(
                    f"docs/diagrams/{name}.json declares {_relative(path)} as a "
                    "target but that file carries no marker for it"
                )
    return problems


LAYOUTS = ("vertical", "horizontal")


def include_name(name: str, layout: str) -> str:
    return f"{name}-{layout}.svg"


def write_includes(specs: list[Spec], write: bool, language: str = SOURCE_LANGUAGE) -> list[str]:
    """Write every rendered SVG. Returns stale entries when checking.

    The same bytes land in both trees: `docs/diagrams` is tracked so Markdown
    and GitHub can point at a file, and `website/_includes/diagrams` is the
    ignored copy Jekyll inlines. One renderer produces both.
    """
    stale: list[str] = []
    tracked, inlined = svg_dir(language), include_dir(language)
    wanted = {
        include_name(spec.name, layout)
        for spec in specs
        if spec.web
        for layout in LAYOUTS
    }
    if write:
        for directory in (tracked, inlined):
            directory.mkdir(parents=True, exist_ok=True)
    for spec in specs:
        if not spec.web:
            continue
        for layout in LAYOUTS:
            import yume_diagram_svg
            rendered = yume_diagram_svg.render(spec, layout)
            if not write:
                # Only the tracked tree is checked. The ignored copy is
                # rebuilt by every sync, so a fresh checkout that has never
                # built the website must still pass.
                path = tracked / include_name(spec.name, layout)
                if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
                    stale.append(f"{_relative(path)} is missing or stale")
                continue
            for directory in (tracked, inlined):
                (directory / include_name(spec.name, layout)).write_text(
                    rendered, encoding="utf-8"
                )
    if write:
        for directory in (tracked, inlined):
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.svg")):
                if path.name not in wanted:
                    path.unlink()
    return stale


def embed(path: Path, text: str, specs: dict[str, Spec], language: str = SOURCE_LANGUAGE) -> str:
    """Replace each marked block with the website figure for that diagram."""
    lines = text.split("\n")
    blocks = find_blocks(path, lines)
    output = list(lines)
    for block in reversed(blocks):
        spec = specs.get(block.name)
        if spec is None:
            raise DiagramError(
                f"{_relative(path)}:{block.line_number}: no specification named {block.name!r}"
            )
        if not spec.web:
            continue
        ascii_text = html.escape(yume_diagram_ascii.render(spec).rstrip("\n"))
        prefix = "" if language == SOURCE_LANGUAGE else language + "/"
        figure = [
            f'<figure class="diagram" data-diagram="{spec.name}">',
            f"{{% include diagrams/{prefix}{include_name(spec.name, 'vertical')} %}}",
            f"<figcaption>{html.escape(spec.summary)}</figcaption>",
            '<details class="diagram-text">',
            "<summary>Text version</summary>",
            f"<pre>{ascii_text}</pre>",
            "</details>",
            "</figure>",
        ]
        output[block.open_index: block.close_index + 1] = figure
    return "\n".join(output)


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def command_list(_args: argparse.Namespace) -> int:
    for spec in load_all():
        targets = spec.man_targets + spec.markdown_targets
        web = "web" if spec.web else "no web"
        print(f"{spec.name}: {spec.type}, {web}, {len(spec.nodes)} nodes")
        for target in targets:
            print(f"    {target}")
    return 0


def command_render(args: argparse.Namespace) -> int:
    spec = load(args.name, args.language)
    if args.svg:
        import yume_diagram_svg
        sys.stdout.write(yume_diagram_svg.render(spec, args.layout))
    else:
        sys.stdout.write(yume_diagram_ascii.render(spec))
    return 0


def command_sync(args: argparse.Namespace) -> int:
    specs = load_all()
    index = {spec.name: spec for spec in specs}
    problems = verify_targets(specs)
    if problems:
        for problem in problems:
            print(f"diagrams: {problem}", file=sys.stderr)
        return 1

    stale: list[str] = []
    for path in sorted(declared_targets(specs)):
        content, file_stale = rewrite(path, index)
        stale.extend(file_stale)
        if not args.check and content != path.read_text(encoding="utf-8"):
            path.write_text(content, encoding="utf-8")
    stale.extend(write_includes(specs, write=not args.check))

    if args.check and stale:
        for entry in stale:
            print(f"diagrams: {entry}", file=sys.stderr)
        print("diagrams: run scripts/yume_diagrams.py sync", file=sys.stderr)
        return 1
    print(f"diagrams: {len(specs)} specifications {'checked' if args.check else 'synced'}")
    return 0


def command_svg(args: argparse.Namespace) -> int:
    language = getattr(args, "language", SOURCE_LANGUAGE)
    specs = load_all(language)
    write_includes(specs, write=True, language=language)
    written = sum(len(LAYOUTS) for spec in specs if spec.web)
    print(f"diagrams: wrote {written} inline SVG includes ({language})")
    return 0


def command_translations(args: argparse.Namespace) -> int:
    """Report how much of each diagram one language has translated."""
    language = args.language
    if language == SOURCE_LANGUAGE:
        print(f"diagrams: {SOURCE_LANGUAGE} is the source language, so its strings are the specifications")
        return 0
    document = load_strings(language)
    specs = load_all(SOURCE_LANGUAGE)
    total = gaps = 0
    for spec in specs:
        missing = missing_strings(spec, document)
        drawn = len(missing_strings(spec, {}))
        total += drawn
        gaps += len(missing)
        state = "complete" if not missing else f"{drawn - len(missing)} of {drawn}"
        print(f"{spec.name}: {state}")
        for entry in missing:
            print(f"    missing  {entry}")
    print(f"diagrams: {total - gaps} of {total} strings translated ({language})")
    return 0


def command_preview(_args: argparse.Namespace) -> int:
    specs = load_all()
    write_includes(specs, write=True)
    entries = [
        (
            spec.name,
            spec.summary,
            [
                (
                    layout,
                    include_name(spec.name, layout),
                    (INCLUDE_DIR / include_name(spec.name, layout)).read_text(
                        encoding="utf-8"
                    ),
                )
                for layout in LAYOUTS
            ],
        )
        for spec in specs
        if spec.web
    ]
    path = INCLUDE_DIR / yume_diagram_preview.PAGE_NAME
    path.write_text(yume_diagram_preview.page(entries), encoding="utf-8")
    print(f"diagrams: {_relative(path)}")
    return 0


def command_embed(args: argparse.Namespace) -> int:
    specs = {spec.name: spec for spec in load_all()}
    if args.file == "-":
        path = Path("<stdin>")
        text = sys.stdin.read()
    else:
        path = Path(args.file).resolve()
        text = path.read_text(encoding="utf-8")
    # The embedded form is decided by the marker, and a mirror of a Markdown
    # document keeps Markdown markers whatever its temporary name is.
    sys.stdout.write(embed(path.with_suffix(".md"), text, specs))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list the specifications and their targets").set_defaults(
        handler=command_list
    )

    render = sub.add_parser("render", help="print one diagram")
    render.add_argument("name")
    render.add_argument("--language", default=SOURCE_LANGUAGE)
    render.add_argument("--svg", action="store_true", help="print the animated SVG")
    render.add_argument(
        "--layout", choices=LAYOUTS, default="vertical", help="SVG layout to print"
    )
    render.set_defaults(handler=command_render)

    sync = sub.add_parser("sync", help="write every ASCII block and inline SVG")
    sync.set_defaults(handler=command_sync, check=False)

    check = sub.add_parser("check", help="verify every output without writing")
    check.set_defaults(handler=command_sync, check=True)

    svg = sub.add_parser("svg", help="write only the website SVG includes")
    svg.add_argument("--language", default=SOURCE_LANGUAGE)
    svg.set_defaults(handler=command_svg)

    translations = sub.add_parser(
        "translations", help="report the translated strings for one language"
    )
    translations.add_argument("--language", default=SOURCE_LANGUAGE)
    translations.set_defaults(handler=command_translations)

    sub.add_parser(
        "preview", help="write every SVG and a page that shows both renderings"
    ).set_defaults(handler=command_preview)

    embed_parser = sub.add_parser("embed", help="substitute website figures into Markdown")
    embed_parser.add_argument("file", help="Markdown file, or - for standard input")
    embed_parser.set_defaults(handler=command_embed)

    args = parser.parse_args(argv[1:])
    try:
        return args.handler(args)
    except (SpecError, DiagramError, OSError, ValueError) as exc:
        print(f"diagrams: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
