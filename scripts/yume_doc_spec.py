#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Parse and validate the `.doc` sources under docs/src/<language>.

One `.doc` file describes one aspect of YUME. The same file drives every
layer that publishes it: the Markdown a reader opens in a clone, the roff
manual a terminal renders, and the website page. Every renderer reads the
same parsed blocks and applies its explicit layer filter.

The format is line oriented on purpose. A documentation change has to be
reviewable as a diff, and a structured block that starts at column zero keeps
the review honest about which layer a claim reaches.

    #!yume-doc 1
    name:     security_modes
    kind:     page
    title:    YUME security modes
    summary:  One sentence, used as the web card subtitle.
    markdown: docs/SECURITY_MODES.md
    web:      yes
    ---
    ## Overview

    Text with **bold**, *italic*, `code`, [links](THREAT_MODEL.md) and
    man:yumed(8) cross references.

    @table
    | Mode | Epoch bytes |
    | --- | ---: |
    @end

Key tables are closed. An unknown header key, an unknown block directive, a
layer name no renderer implements, or a body that claims an output no header
declares is a hard error rather than a silently dropped field.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "docs" / "src"

# The first language. The tree is partitioned by language from the start so
# that adding one is a new directory rather than a change to every renderer.
DEFAULT_LANGUAGE = "en_US"
LANGUAGE_RE = re.compile(r"^[a-z]{2}(_[A-Z]{2})?$")

MAGIC = "#!yume-doc 1"

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# A layer is one published form. Website and clone Markdown are rendered
# separately from the parsed source so @only never relies on recovering text
# that a previous rendering discarded.
LAYERS = ("markdown", "man", "web")

KINDS = ("page", "man")

# Header keys, closed. `man-*` keys are only meaningful for kind: man and are
# rejected on a page so a stray key cannot look like it did something.
COMMON_KEYS = {"name", "kind", "title", "summary", "markdown", "man", "web"}
MAN_KEYS = {"man-section", "man-date", "man-source", "man-manual"}
WEB_KEYS = {"web-path", "web-title", "catalog-title", "catalog-group", "catalog-home", "catalog-order"}
HEADER_KEYS = COMMON_KEYS | MAN_KEYS | WEB_KEYS

MAN_SECTIONS = ("1", "3", "5", "7", "8")

# The date printed in a manual footer. It is a display string, so both the
# ISO form and the conventional "Month YYYY" a manual traditionally carries
# are accepted. Anything else is a typo rather than a style choice.
MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)
MAN_DATE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}|(?:" + "|".join(MONTHS) + r") \d{4})$"
)

# Block directives. `@end` closes every block that takes a body.
DIRECTIVES = (
    "@code",
    "@table",
    "@diagram",
    "@include",
    "@options",
    "@opt",
    "@cli",
    "@only",
    "@synopsis",
    "@end",
)

# A fragment holds body blocks and no header, so it cannot be published on
# its own and cannot claim an output. The distinct suffix is what keeps
# `load_all` from mistaking one for a document.
PART_SUFFIX = ".part"

# Every fragment lives under this directory inside a language. An include
# path is written relative to it, so `shared/limits.part` reads the same way
# from a page and from a manual however deep either one sits.
PART_DIR = "parts"

# `@synopsis literal` keeps its lines exactly, for a manual whose synopsis is
# an include line or a build command rather than a command invocation.
SYNOPSIS_LITERAL = "literal"

# How deep an include chain may go. A document assembled from parts is meant
# to be read, and a reader who has to follow six files to find one sentence
# is worse off than one reading a single long file.
MAX_INCLUDE_DEPTH = 4

# Fence languages the published Markdown may use. Closed so a new one is a
# deliberate choice: CONTRIBUTING requires every published fence to carry a
# tag, and the roff renderer has to know whether a block is filled text or a
# literal region.
#
# The table is shared with the BaseFWX copy of this tooling rather than split
# per repository, because two tables that drift are worse than one that is
# wider than either repository needs. A tag no renderer knows is still an
# error, which is what the table is for.
CODE_LANGUAGES = (
    "bash",
    "c",
    "cmake",
    "cpp",
    "css",
    "ini",
    "java",
    "json",
    "jsonc",
    "markdown",
    "python",
    "roff",
    "sh",
    "text",
    "yaml",
)

# What an option carries for the command-line interface, as opposed to the
# prose a manual prints. The keys are closed for the same reason the header
# keys are: a misspelled one has to be an error, because the help text and the
# completion script are generated from this table, and a key that quietly did
# nothing would publish an option with no description.
#
# The table splits in two. Completion keys describe the option itself and may
# appear once. Printing keys describe one line of the help text, and `spell`
# opens a new one, because a single option can print more than one entry:
# yumed(8) documents --listen once and prints a port form and an address form.
CLI_COMPLETION_KEYS = {"flags", "file", "values", "complete"}
CLI_PRINT_KEYS = {"spell", "help", "indent", "column", "continuation"}
CLI_KEYS = CLI_COMPLETION_KEYS | CLI_PRINT_KEYS

# Keys that may repeat inside one printed entry.
CLI_REPEATABLE = {"help"}

# A flag as the shell sees it, plus the two bare subcommands YUME accepts in
# the same position. `--` is the service-safe launch separator and is spelled
# out rather than matched, because a pattern loose enough to accept it would
# accept most punctuation.
CLI_FLAG_RE = re.compile(r"^(--?[A-Za-z0-9][A-Za-z0-9_-]*|export|import|--)$")

BOOLEANS = {"yes": True, "no": False}


class DocError(ValueError):
    """A `.doc` source is malformed. The message names the file and line."""


@dataclass
class Option:
    """One entry of an option or term list.

    `signature` carries inline markup, because a manual sets the option name
    in bold and its argument in italic, and the two fonts alternate inside a
    single term. `body` is the description as authored.
    """

    signature: str
    body: list[str] = field(default_factory=list)
    line: int = 0
    # Command-line interface metadata, absent for an option a manual
    # describes but no generated help or completion script mentions.
    # `cli` holds the completion keys, `cli_print` one entry per help line.
    cli: dict[str, str] = field(default_factory=dict)
    cli_print: list[dict] = field(default_factory=list)
    cli_line: int = 0


@dataclass
class Block:
    """One structural element of a document body.

    `layers` is the set this block reaches. A block carrying every layer is
    the normal case, and `@only` narrows it.
    """

    kind: str
    line: int
    layers: tuple[str, ...] = LAYERS
    level: int = 0
    # Columns this block is inset by. A fenced example inside a numbered step
    # belongs to that step, and emitting it at column zero would end the list.
    indent: int = 0
    text: str = ""
    lines: list[str] = field(default_factory=list)
    options: list[Option] = field(default_factory=list)

    def reaches(self, layer: str) -> bool:
        return layer in self.layers


@dataclass
class Doc:
    name: str
    kind: str
    title: str
    summary: str
    path: Path
    language: str
    markdown: str = ""
    man: str = ""
    web: bool = False
    site: dict[str, str] = field(default_factory=dict)
    man_section: str = ""
    man_date: str = ""
    man_source: str = ""
    man_manual: str = ""
    blocks: list[Block] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)

    def outputs(self) -> list[tuple[str, str]]:
        """Every (layer, repository-relative path) this document writes.

        The header names the path for the source language. A translation
        declares the same path and lands beside it under its own language, so
        a translated document never has to restate where it goes and can
        never collide with the original.
        """
        written: list[tuple[str, str]] = []
        if self.markdown:
            written.append(("markdown", localized(self.markdown, self.language, "markdown")))
        if self.man:
            written.append(("man", localized(self.man, self.language, "man")))
        return written

    def declared(self) -> list[tuple[str, str]]:
        """The paths as written in the header, before the language applies."""
        written: list[tuple[str, str]] = []
        if self.markdown:
            written.append(("markdown", self.markdown))
        if self.man:
            written.append(("man", self.man))
        return written

    def diagrams(self) -> list[str]:
        return [block.text for block in self.blocks if block.kind == "diagram"]


def localized(target: str, language: str, layer: str) -> str:
    """Where one declared output lands for a given language.

    The source language keeps the paths readers already link to. Every other
    language is a sibling directory, which is what keeps a second translation
    from being a second set of header edits in every file.

        docs/SECURITY_MODES.md   ->  docs/de_DE/SECURITY_MODES.md
        docs/protocol/YTP_1.md   ->  docs/de_DE/protocol/YTP_1.md
        docs/man/yume.1          ->  docs/man/de_DE/yume.1
        README.md                ->  docs/de_DE/root/README.md
    """
    if language == DEFAULT_LANGUAGE:
        return target
    if layer == "man":
        parts = Path(target).parts
        # docs/man/<name> becomes docs/man/<language>/<name>, which is the
        # shape `man` itself looks for under a localized manual root.
        position = len(parts) - 1
        return str(Path(*parts[:position], language, parts[-1]))
    if not target.startswith("docs/"):
        return f"docs/{language}/root/{target}"
    return f"docs/{language}/{target[len('docs/'):]}"


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _fail(path: Path, line: int, message: str) -> None:
    raise DocError(f"{relative(path)}:{line}: {message}")


def _require(condition: bool, path: Path, line: int, message: str) -> None:
    if not condition:
        _fail(path, line, message)


def parse(path: Path, language: str = DEFAULT_LANGUAGE) -> Doc:
    """Read one `.doc` source and return a validated document."""
    check_language(language)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DocError(f"{relative(path)}: cannot read: {exc}") from exc

    lines = text.split("\n")
    _require(bool(lines) and lines[0] == MAGIC, path, 1, f"the first line must be {MAGIC!r}")

    header, body_start = _parse_header(path, lines)
    doc = _build(path, language, header, body_start)
    root = SOURCE_ROOT / language
    doc.blocks, doc.includes = _parse_body(path, lines, body_start, root, (path,))
    _check_body(doc, path)
    return doc


def _parse_header(path: Path, lines: list[str]) -> tuple[dict[str, tuple[str, int]], int]:
    """Read `key: value` lines up to the `---` separator."""
    header: dict[str, tuple[str, int]] = {}
    index = 1
    while index < len(lines):
        raw = lines[index]
        number = index + 1
        if raw.strip() == "---":
            return header, index + 1
        if raw.strip() == "":
            index += 1
            continue
        match = re.match(r"^([a-z][a-z0-9-]*):[ \t]*(.*)$", raw)
        _require(match is not None, path, number, f"expected 'key: value' or '---', got {raw!r}")
        assert match is not None
        key, value = match.group(1), match.group(2).strip()
        _require(key in HEADER_KEYS, path, number, f"unknown header key {key!r}")
        _require(key not in header, path, number, f"duplicate header key {key!r}")
        _require(bool(value), path, number, f"{key} must not be empty; omit optional fields")
        header[key] = (value, number)
        index += 1
    _fail(path, len(lines), "the header is not closed by a '---' line")
    raise AssertionError("unreachable")


def _build(path: Path, language: str, header: dict[str, tuple[str, int]], start: int) -> Doc:
    def value(key: str, required: bool = True) -> tuple[str, int]:
        if key in header:
            return header[key]
        if required:
            _fail(path, start, f"the header has no {key!r}")
        return "", start

    name, name_line = value("name")
    _require(bool(NAME_RE.match(name)), path, name_line, f"name {name!r} must be lowercase with underscores")
    _require(name == path.stem, path, name_line, f"name {name!r} must match the file name {path.stem!r}")

    kind, kind_line = value("kind")
    _require(kind in KINDS, path, kind_line, f"unknown kind {kind!r}, expected one of {', '.join(KINDS)}")

    title, title_line = value("title")
    summary, summary_line = value("summary")
    _require(bool(title), path, title_line, "title must not be empty")
    _require(bool(summary), path, summary_line, "summary must not be empty")

    doc = Doc(
        name=name,
        kind=kind,
        title=title,
        summary=summary,
        path=path,
        language=language,
    )

    markdown, markdown_line = value("markdown", required=False)
    if markdown:
        _check_output(path, markdown_line, markdown, ".md")
        doc.markdown = markdown

    man, man_line = value("man", required=False)
    if man:
        _check_output(path, man_line, man, "")
        doc.man = man

    web, web_line = value("web", required=False)
    if web:
        _require(web in BOOLEANS, path, web_line, f"web must be yes or no, got {web!r}")
        doc.web = BOOLEANS[web]
    doc.site = {key: header[key][0] for key in WEB_KEYS & set(header)}
    for key, entry in doc.site.items():
        _require(bool(entry), path, header[key][1], f"{key} must not be empty")
    if "catalog-order" in doc.site:
        _require(doc.site["catalog-order"].isdigit(), path, header["catalog-order"][1],
                 "catalog-order must be a non-negative integer")
        _require("catalog-group" in doc.site, path, start, "catalog-order needs catalog-group")
    else:
        _require(not any(key.startswith("catalog-") for key in doc.site), path, start,
                 "catalog fields need catalog-order")
    if "web-path" in doc.site:
        route = doc.site["web-path"]
        _require(bool(re.fullmatch(r"docs/[A-Za-z0-9_./-]+\.md", route))
                 and ".." not in Path(route).parts, path, header["web-path"][1],
                 "web-path must be a Markdown path under website/docs")
    _require(doc.web or not any(key.startswith("web-") for key in doc.site), path, start,
             "web fields need web: yes")
    _require(
        not (doc.web and not doc.markdown),
        path,
        web_line,
        "web: yes needs a markdown output to define the document's repository link location",
    )

    present_man_keys = MAN_KEYS & set(header)
    if kind == "man":
        _require(bool(doc.man), path, start, "kind: man needs a man output path")
        missing = sorted(MAN_KEYS - present_man_keys)
        _require(not missing, path, start, f"kind: man needs {', '.join(missing)}")
        doc.man_section = header["man-section"][0]
        _require(
            doc.man_section in MAN_SECTIONS,
            path,
            header["man-section"][1],
            f"man-section {doc.man_section!r} must be one of {', '.join(MAN_SECTIONS)}",
        )
        _require(Path(doc.man).suffix == "." + doc.man_section, path, man_line,
                 "man output suffix must match man-section")
        doc.man_date = header["man-date"][0]
        _require(
            bool(MAN_DATE_RE.match(doc.man_date)),
            path,
            header["man-date"][1],
            "man-date must be YYYY-MM-DD or a 'Month YYYY' form",
        )
        doc.man_source = header["man-source"][0]
        doc.man_manual = header["man-manual"][0]
    else:
        for key in sorted(present_man_keys):
            _fail(path, header[key][1], f"{key} is only meaningful for kind: man")
        _require(not doc.man, path, start, "a page cannot write a man output, so use kind: man")

    _require(bool(doc.outputs()), path, start, "the document declares no output")
    return doc


def _check_output(path: Path, line: int, target: str, suffix: str) -> None:
    parts = Path(target).parts
    _require(".." not in parts, path, line, f"output {target!r} escapes the repository")
    _require(not Path(target).is_absolute(), path, line, f"output {target!r} must be repository relative")
    _require(
        bool(re.fullmatch(r"[A-Za-z0-9_./-]+", target))
        and (len(parts) == 1 or parts[0] in ("docs", "cpp", "java", "examples", "testdata", "tools"))
        and not target.startswith("docs/src/"),
        path,
        line,
        f"output {target!r} must land in a public documentation directory or the repository root",
    )
    _require((REPO_ROOT / target).resolve().is_relative_to(REPO_ROOT.resolve()), path, line,
             f"output {target!r} escapes the repository through a symlink")
    if suffix:
        _require(target.endswith(suffix), path, line, f"output {target!r} must end in {suffix!r}")
    else:
        _require(target.startswith("docs/") and Path(target).parent.name == "man"
                 and Path(target).suffix[1:] in MAN_SECTIONS,
                 path, line, "manual output must be under a public docs/.../man/ directory")


def _parse_body(
    path: Path,
    lines: list[str],
    start: int,
    root: Path,
    stack: tuple[Path, ...],
) -> tuple[list[Block], list[str]]:
    """Parse one file's body, splicing in every fragment it includes.

    `stack` is the chain of files being read, which both bounds the depth and
    names the cycle when a fragment includes something already open.
    """
    blocks: list[Block] = []
    includes: list[str] = []
    index = start
    layers: tuple[str, ...] = LAYERS
    only_line = 0

    while index < len(lines):
        raw = lines[index]
        number = index + 1
        stripped = raw.strip()

        if stripped == "":
            index += 1
            continue

        body_indent = len(raw) - len(raw.lstrip(" "))
        opener = raw.lstrip(" ")
        if opener.startswith("@"):
            raw = opener
            directive = raw.split(" ", 1)[0].strip()
            _require(directive in DIRECTIVES, path, number, f"unknown block directive {directive!r}")

            if directive == "@only":
                _require(only_line == 0, path, number, "@only blocks do not nest")
                names = raw[len("@only"):].split()
                _require(bool(names), path, number, "@only needs at least one layer name")
                for entry in names:
                    _require(entry in LAYERS, path, number, f"unknown layer {entry!r}")
                _require(len(set(names)) == len(names), path, number, "@only repeats a layer")
                layers = tuple(name for name in LAYERS if name in names)
                only_line = number
                index += 1
                continue

            if directive == "@end":
                _require(only_line != 0, path, number, "@end closes no open block")
                layers = LAYERS
                only_line = 0
                index += 1
                continue

            if directive == "@diagram":
                target = raw[len("@diagram"):].strip()
                _require(bool(NAME_RE.match(target)), path, number, f"@diagram needs a diagram name, got {target!r}")
                blocks.append(Block(kind="diagram", line=number, layers=layers, text=target))
                index += 1
                continue

            if directive == "@include":
                _require(
                    only_line == 0,
                    path,
                    number,
                    "@include may not sit inside an @only block; put the @only in the fragment",
                )
                fragment, nested = _read_fragment(
                    path, number, raw[len("@include"):].strip(), root, stack
                )
                blocks.extend(fragment)
                includes.extend(nested)
                index += 1
                continue

            block, index = _parse_container(
                path, lines, index, directive, layers, body_indent
            )
            blocks.append(block)
            continue

        block, index = _parse_prose(path, lines, index, layers)
        blocks.append(block)

    _require(only_line == 0, path, only_line, "@only block is not closed by @end")
    return blocks, includes


def _read_fragment(
    path: Path, line: int, target: str, root: Path, stack: tuple[Path, ...]
) -> tuple[list[Block], list[str]]:
    """Read one `.part` fragment and return its blocks and its own includes."""
    _require(bool(target), path, line, "@include needs a fragment path")
    _require(
        target.endswith(PART_SUFFIX),
        path,
        line,
        f"@include needs a {PART_SUFFIX} fragment, got {target!r}",
    )
    parts = Path(target).parts
    _require(".." not in parts, path, line, f"@include {target!r} escapes the language tree")
    _require(
        not Path(target).is_absolute(),
        path,
        line,
        f"@include takes a path under the language's {PART_DIR}/ directory",
    )

    fragment = root / PART_DIR / target
    if not fragment.is_file() and root.name != DEFAULT_LANGUAGE:
        # A translation may translate its fragments one at a time. Falling
        # back to the source language keeps a partly translated document
        # readable instead of refusing to build it, which is the same rule
        # the diagram strings follow.
        fallback = root.parent / DEFAULT_LANGUAGE / PART_DIR / target
        if fallback.is_file():
            fragment = fallback
    _require(
        fragment.is_file(),
        path,
        line,
        f"@include names no such fragment: {PART_DIR}/{target}",
    )

    resolved = fragment.resolve()
    _require(resolved.is_relative_to(SOURCE_ROOT.resolve()), path, line,
             f"@include {target!r} escapes the source tree through a symlink")
    _require(
        resolved not in {entry.resolve() for entry in stack},
        path,
        line,
        f"@include {target!r} is already open, so the chain is a cycle",
    )
    _require(
        len(stack) < MAX_INCLUDE_DEPTH,
        path,
        line,
        f"@include nests deeper than {MAX_INCLUDE_DEPTH} files",
    )

    text = fragment.read_text(encoding="utf-8")
    _require(
        not text.startswith(MAGIC),
        fragment,
        1,
        "a fragment carries body blocks and no header, so it cannot start with the document magic",
    )
    blocks, nested = _parse_body(
        fragment, text.split("\n"), 0, root, stack + (fragment,)
    )
    _require(bool(blocks), fragment, 1, "a fragment with no blocks includes nothing")
    return blocks, [relative(fragment), *nested]


def _parse_container(
    path: Path,
    lines: list[str],
    index: int,
    directive: str,
    layers: tuple[str, ...],
    indent: int = 0,
) -> tuple[Block, int]:
    """Read one `@directive ... @end` block."""
    number = index + 1
    raw = lines[index].lstrip(" ")
    argument = raw[len(directive):].strip()

    if directive == "@code":
        _require(
            argument in CODE_LANGUAGES,
            path,
            number,
            f"@code needs a language from {', '.join(CODE_LANGUAGES)}, got {argument!r}",
        )
    elif directive == "@opt":
        _fail(path, number, "@opt is only valid inside an @options block")
    elif directive == "@synopsis":
        # A command's synopsis alternates fonts, and a library's is an
        # include line and a build command that have to survive verbatim.
        _require(
            argument in ("", SYNOPSIS_LITERAL),
            path,
            number,
            f"@synopsis takes no argument or {SYNOPSIS_LITERAL!r}, got {argument!r}",
        )
    else:
        _require(argument == "", path, number, f"{directive} takes no argument, got {argument!r}")

    body: list[str] = []
    cursor = index + 1
    while cursor < len(lines) and lines[cursor].strip() != "@end":  # any indent

        _require(
            not lines[cursor].startswith("@only"),
            path,
            cursor + 1,
            "@only may not open inside another block",
        )
        body.append(lines[cursor])
        cursor += 1
    _require(cursor < len(lines), path, number, f"{directive} is not closed by @end")

    kind = directive[1:]
    block = Block(kind=kind, line=number, layers=layers, text=argument, indent=indent)
    _require(
        indent == 0 or kind == "code",
        path,
        number,
        f"only @code may be inset, and {directive} is inset by {indent} columns",
    )

    if kind == "options":
        block.options = _parse_options(path, body, index + 1)
        _require(bool(block.options), path, number, "@options holds no @opt entries")
    else:
        while body and body[-1].strip() == "":
            body.pop()
        _require(bool(body), path, number, f"{directive} block is empty")
        block.lines = body
        if kind == "table":
            _check_table(path, number, body)

    return block, cursor + 1


def _parse_options(path: Path, body: list[str], offset: int) -> list[Option]:
    options: list[Option] = []
    # `@cli` lines are an unbroken run directly under their `@opt`, so the
    # prose an option carries starts where the metadata stops. Allowing them
    # anywhere in the body would make "is this line a description or a key?"
    # depend on spelling, and a description that happens to start with `@cli`
    # would silently become metadata.
    accepting_cli = False
    for position, raw in enumerate(body):
        number = offset + position + 1
        if raw == "@opt" or raw.startswith("@opt "):
            signature = raw[len("@opt"):].strip()
            _require(bool(signature), path, number, "@opt needs a signature")
            options.append(Option(signature=signature, line=number))
            accepting_cli = True
            continue
        if raw == "@cli" or raw.startswith("@cli "):
            _require(bool(options), path, number, "@cli precedes any @opt")
            _require(
                accepting_cli,
                path,
                number,
                "@cli must directly follow its @opt, before the description",
            )
            _parse_cli(path, number, raw[len("@cli"):], options[-1])
            continue
        _require(
            not raw.startswith("@"),
            path,
            number,
            f"unexpected directive inside @options: {raw.split(' ', 1)[0]!r}",
        )
        if raw.strip() == "" and not options:
            continue
        _require(bool(options), path, number, "text inside @options precedes any @opt")
        # A blank line ends the run too. The description begins after it, and
        # a key that drifted below the blank would read as prose here and as
        # metadata one line higher.
        accepting_cli = False
        options[-1].body.append(raw)
    for option in options:
        while option.body and option.body[-1].strip() == "":
            option.body.pop()
        _require(bool(option.body), path, option.line, f"@opt {option.signature!r} has no description")
        _check_cli(path, option)
    return options


def _parse_cli(path: Path, number: int, rest: str, option: Option) -> None:
    """Read one `@cli key: value` line into its option."""
    match = re.match(r"^[ \t]+([a-z][a-z-]*):[ \t]?(.*)$", rest)
    _require(match is not None, path, number, f"expected '@cli key: value', got '@cli{rest}'")
    assert match is not None
    key, value = match.group(1), match.group(2).rstrip()
    _require(key in CLI_KEYS, path, number, f"unknown @cli key {key!r}")
    if key != "help":
        _require(bool(value), path, number, f"@cli {key} needs a value")
    if not option.cli_line:
        option.cli_line = number

    if key in CLI_COMPLETION_KEYS:
        _require(
            key not in option.cli,
            path,
            number,
            f"duplicate @cli key {key!r}",
        )
        _require(
            not option.cli_print,
            path,
            number,
            f"@cli {key} describes the option, so it belongs before the first "
            "'@cli spell' rather than inside a printed entry",
        )
        option.cli[key] = value
        return

    if key == "spell":
        option.cli_print.append({"spell": value, "help": [], "line": number})
        return

    _require(
        bool(option.cli_print),
        path,
        number,
        f"@cli {key} has no '@cli spell' to attach to",
    )
    entry = option.cli_print[-1]
    if key == "help":
        entry["help"].append(value)
        return
    _require(key not in entry, path, number, f"duplicate @cli key {key!r}")
    entry[key] = value


def _check_cli(path: Path, option: Option) -> None:
    """Validate one option's CLI table once every key has been read.

    The checks here are the ones that need the whole table. A generated help
    entry with no description, or a completion rule for an option that takes
    no argument, would each publish something wrong rather than fail.
    """
    if not option.cli and not option.cli_print:
        return
    line = option.cli_line
    table = option.cli

    for key in ("file", "complete"):
        if key in table:
            _require(table[key] in BOOLEANS, path, line,
                     f"@cli {key} must be yes or no, got {table[key]!r}")
    if table.get("complete") == "no":
        _require("values" not in table and table.get("file") != "yes", path, line,
                 "@cli complete: no cannot declare argument completions")
    if "values" in table:
        _require(
            bool(table["values"].split()),
            path,
            line,
            "@cli values needs at least one completion word",
        )
        _require(
            "file" not in table or not BOOLEANS[table["file"]],
            path,
            line,
            "@cli values and file both claim the argument, so pick one",
        )

    declared = cli_flags(option)
    _require(
        bool(declared),
        path,
        line,
        f"@opt {option.signature!r} declares no flag the shell could complete",
    )
    for flag in sorted(declared):
        _require(
            bool(CLI_FLAG_RE.match(flag)),
            path,
            line,
            f"@cli flag {flag!r} is not a flag or subcommand spelling",
        )

    # An option describes itself once. A `spell` may carry no help text when a
    # later entry of the same option carries it, which is how yume(1) prints
    # the min-port and max-port terms above one shared description.
    if option.cli_print:
        _require(
            any(
                text.strip()
                for entry in option.cli_print
                for text in entry["help"]
            ),
            path,
            option.cli_print[0]["line"],
            f"@opt {option.signature!r} prints help entries but no help text",
        )

    for entry in option.cli_print:
        entry_line = entry["line"]
        for key in ("indent", "column", "continuation"):
            if key in entry:
                _require(
                    entry[key].isdigit() and 0 < int(entry[key]) < 80,
                    path,
                    entry_line,
                    f"@cli {key} must be a column below 80, got {entry[key]!r}",
                )

        # The spelling a manual sets and the spelling help prints have to name
        # the same option. Without this, renaming the flag in the `@opt`
        # signature and forgetting the `@cli spell` line would publish a manual
        # and a help text that disagree, which is the drift this model exists
        # to prevent.
        printed = {
            token
            for token in re.split(r"[,\s]+", _strip_markup(entry["spell"]))
            if CLI_FLAG_RE.match(token)
        }
        missing = sorted(printed - declared)
        _require(
            not missing,
            path,
            entry_line,
            f"@cli spell names {', '.join(missing)}, which neither the @opt "
            f"signature {option.signature!r} nor '@cli flags' declares",
        )


def _strip_markup(text: str) -> str:
    """Drop inline markers so a spelling can be compared token by token."""
    return re.sub(r"[*`\[\]<>]", " ", text)


def signature_flags(signature: str) -> set[str]:
    """Every flag or subcommand an `@opt` signature names.

    A manual sets an option name in bold and its argument in italic, so the
    bold runs are the names. A run may hold several, as `-i, --auth` does.
    """
    found: set[str] = set()
    for run in re.findall(r"\*\*(.+?)\*\*", signature):
        for token in re.split(r"[,\s]+", _strip_markup(run)):
            if CLI_FLAG_RE.match(token):
                found.add(token)
    return found


def cli_flags(option: Option) -> set[str]:
    """The flags one option contributes to a completion script.

    `@cli flags` widens the set rather than replacing it, because one printed
    entry can stand for several options and the shell still has to complete
    every one of them.
    """
    declared = signature_flags(option.signature)
    if "flags" in option.cli:
        declared = declared | {token for token in option.cli["flags"].split() if token}
    return declared


def table_cells(row: str) -> list[str]:
    """Split one table row into cells the way GitHub does.

    A pipe splits a cell wherever it appears, including inside a code span,
    unless it is escaped. Counting any other way would accept a row that the
    renderer silently truncates, which is the defect this check exists for.
    """
    body = row.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]

    cells: list[str] = []
    current = ""
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\" and index + 1 < len(body) and body[index + 1] == "|":
            current += "\\|"
            index += 2
            continue
        if character == "|":
            cells.append(current)
            current = ""
            index += 1
            continue
        current += character
        index += 1
    cells.append(current)
    return cells


def _check_table(path: Path, number: int, body: list[str]) -> None:
    rows = [line for line in body if line.strip()]
    _require(len(rows) >= 2, path, number, "@table needs a header row and an alignment row")
    for offset, row in enumerate(rows):
        _require(
            row.lstrip().startswith("|") and row.rstrip().endswith("|"),
            path,
            number + offset,
            f"table row must start and end with '|': {row!r}",
        )
    columns = len(table_cells(rows[0]))
    _require(
        all(re.match(r"^:?-+:?$", cell.strip()) for cell in table_cells(rows[1])),
        path,
        number + 1,
        "the second table row must be the alignment row",
    )
    for offset, row in enumerate(rows[1:], start=1):
        found = len(table_cells(row))
        _require(
            found == columns,
            path,
            number + offset,
            f"table row has {found} columns but the header has {columns}. "
            "A pipe inside a code span still splits a cell, so escape it as '\\|'",
        )


def _parse_prose(
    path: Path, lines: list[str], index: int, layers: tuple[str, ...]
) -> tuple[Block, int]:
    """Read a heading, list, quote, or paragraph up to the next blank line."""
    number = index + 1
    raw = lines[index]

    heading = re.match(r"^(#{2,4}) (.+)$", raw)
    if heading:
        _require(
            raw.rstrip() == raw,
            path,
            number,
            "a heading may not carry trailing whitespace",
        )
        return (
            Block(
                kind="heading",
                line=number,
                layers=layers,
                level=len(heading.group(1)),
                text=heading.group(2).strip(),
            ),
            index + 1,
        )

    _require(
        not raw.startswith("# "),
        path,
        number,
        "the document title comes from the header, so body headings start at '##'",
    )

    body: list[str] = []
    cursor = index
    while (
        cursor < len(lines)
        and lines[cursor].strip() != ""
        and not _opens_block(lines[cursor])
    ):
        _require(
            "\t" not in lines[cursor],
            path,
            cursor + 1,
            "a tab renders differently in every layer, so use spaces",
        )
        _require(
            lines[cursor].rstrip() == lines[cursor],
            path,
            cursor + 1,
            "trailing whitespace changes the rendered bytes",
        )
        body.append(lines[cursor])
        cursor += 1

    first = body[0]
    if re.match(r"^\s*[-*] ", first):
        kind = "bullets"
    elif re.match(r"^\s*\d+\. ", first):
        kind = "ordered"
    elif first.startswith(">"):
        kind = "quote"
    else:
        kind = "paragraph"

    if kind == "bullets":
        for offset, line in enumerate(body):
            _require(
                line.startswith(("- ", "* ", "  ")),
                path,
                number + offset,
                "a bullet continues with two spaces of indent",
            )
    return Block(kind=kind, line=number, layers=layers, lines=body), cursor


def _opens_block(line: str) -> bool:
    """Whether this line starts a directive, at column zero or inset.

    Any line opening with `@` counts, not only a known one. Text is never
    meant to start that way, and letting an unknown directive fall through to
    prose would publish the directive itself instead of reporting the typo.
    """
    return line.lstrip(" ").startswith("@")


def _check_body(doc: Doc, path: Path) -> None:
    """A body may not address a layer the header does not publish."""
    for layer in LAYERS:
        figures = [block.text for block in doc.blocks if block.kind == "diagram" and block.reaches(layer)]
        _require(len(figures) == len(set(figures)), path, 1,
                 f"a diagram may appear only once per {layer} output")
    published = {layer for layer, _ in doc.outputs()}
    if doc.web:
        published.add("web")
    for block in doc.blocks:
        if block.layers == LAYERS:
            continue
        unreachable = sorted(set(block.layers) - published)
        _require(
            not unreachable,
            path,
            block.line,
            f"@only names {', '.join(unreachable)} but the header publishes no such output",
        )
    synopsis = [block for block in doc.blocks if block.kind == "synopsis"]
    if doc.kind == "man":
        # A manual names its sections in capitals, and the roff renderer
        # writes the heading as authored rather than changing its case, so
        # the convention is checked at the source where it can be corrected.
        for block in doc.blocks:
            if block.kind == "heading" and block.level == 2:
                _require(
                    block.text == block.text.upper(),
                    path,
                    block.line,
                    f"a manual section heading is capitalised: {block.text!r}",
                )
        _require(len(synopsis) == 1, path, 1, "kind: man needs exactly one @synopsis block")
        _require(
            doc.blocks and doc.blocks[0].kind == "synopsis",
            path,
            doc.blocks[0].line if doc.blocks else 1,
            "@synopsis comes first, because it follows the generated NAME section",
        )
    else:
        for block in synopsis:
            _fail(path, block.line, "@synopsis is only meaningful for kind: man")


def languages() -> list[str]:
    """Every language directory present under docs/src, ordered."""
    if not SOURCE_ROOT.is_dir():
        return []
    found = [
        entry.name
        for entry in sorted(SOURCE_ROOT.iterdir())
        if entry.is_dir() and LANGUAGE_RE.match(entry.name)
    ]
    return found


def check_language(language: str) -> None:
    if not LANGUAGE_RE.fullmatch(language):
        raise DocError(f"invalid language {language!r}; expected a locale such as en_US")


def load_all(language: str = DEFAULT_LANGUAGE) -> list[Doc]:
    """Every `.doc` source for one language, ordered by name."""
    check_language(language)
    root = SOURCE_ROOT / language
    if not root.is_dir():
        raise DocError(f"docs/src/{language}: no such language directory")
    docs = [parse(path, language) for path in sorted(root.rglob("*.doc"))]

    names = [doc.name for doc in docs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise DocError(f"docs/src/{language}: duplicate document names: {', '.join(duplicates)}")

    claimed: dict[str, str] = {}
    for doc in docs:
        for _, target in doc.outputs():
            if target in claimed:
                raise DocError(
                    f"{relative(doc.path)}: output {target} is already written by {claimed[target]}"
                )
            claimed[target] = relative(doc.path)
    return docs


def load(name: str, language: str = DEFAULT_LANGUAGE) -> Doc:
    check_language(language)
    if not NAME_RE.fullmatch(name):
        raise DocError(f"invalid document name {name!r}")
    root = SOURCE_ROOT / language
    matches = sorted(root.rglob(f"{name}.doc")) if root.is_dir() else []
    if not matches:
        raise DocError(f"no such document: {name} ({language})")
    return parse(matches[0], language)
