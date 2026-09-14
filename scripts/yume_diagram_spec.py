#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Parse and validate the diagram specifications in docs/diagrams.

One JSON file describes one diagram. The same file drives the ASCII block in
the man pages and the Markdown documentation and the animated SVG on the
website, so every renderer reads its input through this module.

The key tables are closed. An unknown key, an unknown node kind, an edge that
names a missing node, or a label that cannot fit an SVG card tier is
a hard error rather than a silently dropped field.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = REPO_ROOT / "docs" / "diagrams"

# A specification holds the topology and the source-language strings. A
# translation supplies only the strings, for every diagram at once, so adding
# a language adds one file rather than one file per figure.
SOURCE_LANGUAGE = "en_US"
STRINGS_DIR = REPO_ROOT / "docs" / "src"
STRINGS_NAME = "diagrams.json"

STRINGS_KEYS = {"title", "summary", "nodes", "edges", "groups"}
STRINGS_NODE_KEYS = {"title", "sub", "note"}
STRINGS_EDGE_KEYS = {"label"}

# SVG card tiers. ASCII uses content-sized boxes and a separate terminal budget.
NARROW_WIDTH = 34
WIDE_WIDTH = 72

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# `route` is one ordered chain. `flow` is a chain whose nodes may each send one
# branch to a side node, such as a front door turning away a request. `layers`
# is one wrapping, listed from the innermost layer outwards, with no edges.
DIAGRAM_TYPES = ("route", "flow", "layers")

# Both layouts are rendered for every web diagram. A page picks the one that
# suits its shape, so the specification never has to guess where it is used.
LAYOUTS = ("vertical", "horizontal")

# The glyph drawn beside a node in the SVG. The ASCII renderer ignores it.
NODE_KINDS = (
    "app",
    "client",
    "server",
    "gate",
    "key",
    "target",
    "site",
    "relay",
    "tor",
    "tun",
    "cloud",
    "process",
    "file",
)

# The kinds that are YUME software. The SVG gives those cards the accent rule
# so a reader can see at a glance which hops this project runs and which it
# only talks to. It is a software boundary, not a trust claim: yumed still
# terminates the tunnel and sees the traffic it forwards.
YUME_OWNED_KINDS = ("client", "server", "gate", "relay", "tun")

# A role is what a node's colour means. Every rendering that colours a node
# (the website figure, companion pages, the explainer video) reads the same
# role, so one colour carries one meaning everywhere. The colours themselves
# are website tokens, and a site without role tokens draws every role in its
# accent. `neutral` is for plumbing a reader should not have to decode.
ROLES = ("client", "server", "data", "disguise", "keys", "outside", "refused", "neutral")

# The role a kind has when the specification does not name one.
KIND_ROLES = {
    "app": "data",
    "client": "client",
    "tun": "client",
    "server": "server",
    "gate": "server",
    "key": "keys",
    "relay": "server",
    "target": "outside",
    "site": "disguise",
    "tor": "outside",
    "cloud": "outside",
    "process": "neutral",
    "file": "data",
}

# A note is the plain-language sentence a first-time reader gets beside the
# figure. It is not drawn inside the SVG or the ASCII form, so its length is
# bounded by what reads as one short explanation rather than by a card.
NOTE_LIMIT = 280

# A source is a repository-relative file or directory that backs a node's
# claim. `check` fails when one disappears, which is how a renamed file shows
# up as a figure that needs review instead of a silently stale pointer.
SOURCE_RE = re.compile(r"^(?!/)(?!.*(^|/)\.\.(/|$))[A-Za-z0-9_.\-/]+$")
SOURCE_LIMIT = 4

# A group title is drawn above the nodes it encloses, so it has to stay short
# enough not to widen the figure past the run it names.
GROUP_TITLE_LIMIT = 28

# A channel says what kind of link an edge is. It selects the ASCII arrow
# token and the SVG stroke treatment together, so the two renderings cannot
# disagree about the nature of a hop.
CHANNEL_TOKENS = {
    "plain": "",
    "tunnel": "==YUME==>",
    "onion": "...>",
}

SPEC_KEYS = {
    "name",
    "type",
    "title",
    "summary",
    "comment",
    "width",
    "indent",
    "targets",
    "nodes",
    "edges",
}
TARGET_KEYS = {"web"}
NODE_KEYS = {"id", "kind", "title", "sub", "group", "role", "note", "source", "side"}
EDGE_KEYS = {"from", "to", "label", "channel"}


class SpecError(ValueError):
    """A specification is malformed. The message names the file."""


@dataclass
class Node:
    id: str
    kind: str
    title: str
    sub: str = ""
    group: str = ""
    role: str = ""
    note: str = ""
    sources: list[str] = field(default_factory=list)
    side: bool = False

    @property
    def tone(self) -> str:
        """The declared role, or the one this node's kind implies."""
        return self.role or KIND_ROLES.get(self.kind, "neutral")


@dataclass
class Edge:
    source: str
    target: str
    label: str = ""
    channel: str = "plain"

    def ascii_label(self) -> str:
        """The text printed on the ASCII arrow entering the target node.

        A channel token leads, because ASCII has no stroke treatment to carry
        it. The SVG draws the channel instead and prints only the label.
        """
        return f"{CHANNEL_TOKENS[self.channel]} {self.label}".strip()


@dataclass
class Spec:
    name: str
    type: str
    title: str
    summary: str
    path: Path
    width: int = 0
    indent: int = 0
    comment: list[str] = field(default_factory=list)
    man_targets: list[str] = field(default_factory=list)
    markdown_targets: list[str] = field(default_factory=list)
    web: bool = True
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def box_width(self) -> int:
        """The card size tier, either declared or picked from the labels.

        Two tiers, because the SVG sizes a card without font metrics and has
        to pick between two drawn widths. The ASCII form sizes each figure to
        its own longest label instead, which is what `ascii_width` returns.
        """
        longest = max(max(len(n.title), len(n.sub)) for n in self.nodes)
        if self.width:
            return self.width
        return NARROW_WIDTH if longest <= NARROW_WIDTH - 4 else WIDE_WIDTH

    def ascii_width(self) -> int:
        """The drawn box width for the ASCII form, sized to this figure.

        A terminal has no font metrics to worry about, so a figure that says
        less should be narrower rather than padded out to a shared tier. The
        five columns are the two borders, the two-space left pad, and the
        single trailing space before the right border.
        """
        longest = max(max(len(n.title), len(n.sub)) for n in self.nodes)
        return longest + 5

    def chain(self) -> list[Node]:
        """The nodes the main path runs through, in order."""
        return [node for node in self.nodes if not node.side]

    def chain_edges(self) -> list[Edge]:
        """The hops along the main path, one per consecutive pair of chain nodes."""
        chain = self.chain()
        by_pair = {(edge.source, edge.target): edge for edge in self.edges}
        return [by_pair[(a.id, b.id)] for a, b in zip(chain, chain[1:])]

    def branches(self) -> list[tuple[int, Edge, Node]]:
        """Each side branch as (chain index of its parent, edge, side node)."""
        chain_index = {node.id: index for index, node in enumerate(self.chain())}
        sides = {node.id: node for node in self.nodes if node.side}
        return [
            (chain_index[edge.source], edge, sides[edge.target])
            for edge in self.edges
            if edge.target in sides
        ]

    def inputs(self) -> list[tuple[Edge, Node]]:
        """Each side node that feeds the first chain node, in edge order."""
        sides = {node.id: node for node in self.nodes if node.side}
        return [(edge, sides[edge.source]) for edge in self.edges if edge.source in sides]

    def branch_at(self, index: int) -> tuple[Edge, Node] | None:
        for parent, edge, node in self.branches():
            if parent == index:
                return edge, node
        return None

    def edge_into(self, index: int) -> Edge | None:
        """The edge entering chain()[index], or None for the first node."""
        if index == 0:
            return None
        return self.chain_edges()[index - 1]


def _require(condition: bool, path: Path, message: str) -> None:
    if not condition:
        raise SpecError(f"{_relative(path)}: {message}")


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _closed(document: dict, allowed: set[str], path: Path, where: str) -> None:
    unknown = sorted(set(document) - allowed)
    _require(not unknown, path, f"{where} has unknown keys: {', '.join(unknown)}")


def _string(document: dict, key: str, path: Path, where: str, required: bool = True) -> str:
    value = document.get(key, "")
    if required:
        _require(isinstance(value, str) and value.strip() != "", path, f"{where} has no {key}")
    else:
        _require(isinstance(value, str), path, f"{where} field {key} must be a string")
    return value


def parse(path: Path) -> Spec:
    """Read one specification file and return a validated Spec."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SpecError(f"{_relative(path)}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SpecError(f"{_relative(path)}: invalid JSON: {exc}") from exc

    _require(isinstance(document, dict), path, "the specification must be a JSON object")
    _closed(document, SPEC_KEYS, path, "the specification")

    name = _string(document, "name", path, "the specification")
    _require(bool(NAME_RE.match(name)), path, f"name {name!r} must be lowercase with underscores")
    _require(name == path.stem, path, f"name {name!r} must match the file name {path.stem!r}")

    diagram_type = _string(document, "type", path, "the specification")
    _require(diagram_type in DIAGRAM_TYPES, path, f"unknown type {diagram_type!r}")

    width = document.get("width", 0)
    _require(isinstance(width, int) and not isinstance(width, bool), path, "width must be an integer")
    _require(
        width in (0, NARROW_WIDTH, WIDE_WIDTH),
        path,
        f"width must be {NARROW_WIDTH} or {WIDE_WIDTH}, got {width}",
    )

    indent = document.get("indent", 0)
    _require(
        isinstance(indent, int) and not isinstance(indent, bool) and 0 <= indent <= 8,
        path,
        "indent must be an integer between 0 and 8",
    )

    comment = document.get("comment", [])
    _require(
        isinstance(comment, list) and all(isinstance(line, str) for line in comment),
        path,
        "comment must be a list of strings",
    )

    spec = Spec(
        name=name,
        type=diagram_type,
        title=_string(document, "title", path, "the specification"),
        summary=_string(document, "summary", path, "the specification"),
        path=path,
        width=width,
        indent=indent,
        comment=list(comment),
    )

    _parse_targets(document, spec, path)
    _parse_nodes(document, spec, path)
    _parse_edges(document, spec, path)
    _check_widths(spec, path)
    _check_groups(spec, path)
    return spec


def _parse_targets(document: dict, spec: Spec, path: Path) -> None:
    targets = document.get("targets")
    _require(isinstance(targets, dict), path, "targets must be an object")
    _closed(targets, TARGET_KEYS, path, "targets")

    web = targets.get("web", True)
    _require(isinstance(web, bool), path, "targets.web must be true or false")
    spec.web = web


def _parse_nodes(document: dict, spec: Spec, path: Path) -> None:
    nodes = document.get("nodes")
    _require(isinstance(nodes, list) and len(nodes) >= 2, path, "nodes must list at least two nodes")
    seen: set[str] = set()
    for index, entry in enumerate(nodes, start=1):
        where = f"node {index}"
        _require(isinstance(entry, dict), path, f"{where} must be an object")
        _closed(entry, NODE_KEYS, path, where)
        node_id = _string(entry, "id", path, where)
        _require(bool(NAME_RE.match(node_id)), path, f"{where} id {node_id!r} must be lowercase with underscores")
        _require(node_id not in seen, path, f"duplicate node id {node_id!r}")
        seen.add(node_id)
        # A layer has no glyph, so it names its role instead of a kind.
        kind = _string(entry, "kind", path, where, required=spec.type != "layers")
        _require(kind == "" or kind in NODE_KINDS, path, f"{where} has unknown kind {kind!r}")
        role = _string(entry, "role", path, where, required=spec.type == "layers")
        _require(role == "" or role in ROLES, path, f"{where} has unknown role {role!r}")
        note = _string(entry, "note", path, where, required=False)
        _require(
            len(note) <= NOTE_LIMIT,
            path,
            f"{where} note is {len(note)} characters; keep it under {NOTE_LIMIT}",
        )
        sources = entry.get("source", [])
        _require(
            isinstance(sources, list)
            and len(sources) <= SOURCE_LIMIT
            and all(isinstance(item, str) and SOURCE_RE.match(item) for item in sources),
            path,
            f"{where} source must list at most {SOURCE_LIMIT} repository-relative paths",
        )
        side = entry.get("side", False)
        _require(isinstance(side, bool), path, f"{where} side must be true or false")
        _require(not side or spec.type == "flow", path, f"{where} is a side node, which only a flow has")
        spec.nodes.append(
            Node(
                id=node_id,
                kind=kind,
                title=_string(entry, "title", path, where),
                sub=_string(entry, "sub", path, where, required=False),
                group=_string(entry, "group", path, where, required=False),
                role=role,
                note=note,
                sources=list(sources),
                side=side,
            )
        )


def _parse_edges(document: dict, spec: Spec, path: Path) -> None:
    edges = document.get("edges")
    _require(isinstance(edges, list), path, "edges must be a list")
    ids = [node.id for node in spec.nodes]
    if spec.type == "layers":
        _require(not edges, path, "a layers diagram has no edges; list its layers innermost first")
        for node in spec.nodes:
            _require(not node.group, path, f"layer {node.id!r} cannot join a group")
        return
    for index, entry in enumerate(edges, start=1):
        where = f"edge {index}"
        _require(isinstance(entry, dict), path, f"{where} must be an object")
        _closed(entry, EDGE_KEYS, path, where)
        source = _string(entry, "from", path, where)
        target = _string(entry, "to", path, where)
        _require(source in ids, path, f"{where} names unknown node {source!r}")
        _require(target in ids, path, f"{where} names unknown node {target!r}")
        channel = entry.get("channel", "plain")
        _require(channel in CHANNEL_TOKENS, path, f"{where} has unknown channel {channel!r}")
        spec.edges.append(
            Edge(
                source=source,
                target=target,
                label=_string(entry, "label", path, where, required=False),
                channel=channel,
            )
        )

    if spec.type == "route":
        # A route is one ordered chain. The ASCII renderer walks the node list
        # and prints the edge entering each node, so anything else would render
        # a diagram the specification does not describe.
        _require(
            len(spec.edges) == len(spec.nodes) - 1,
            path,
            f"a route needs {len(spec.nodes) - 1} edges for {len(spec.nodes)} nodes, got {len(spec.edges)}",
        )
        for index, edge in enumerate(spec.edges):
            _require(
                edge.source == ids[index] and edge.target == ids[index + 1],
                path,
                f"edge {index + 1} must join {ids[index]!r} to {ids[index + 1]!r} for a route",
            )
        return

    # A flow is a chain in node order, written first, followed by one edge per
    # side node. A side node is either a branch, reached from one chain node
    # that sends no other branch, or an input that feeds the first chain node.
    # Inputs converge on one bus in every renderer, so they carry no label and
    # no channel. Their words belong in the input's own title and sub.
    chain = [node.id for node in spec.nodes if not node.side]
    sides = [node.id for node in spec.nodes if node.side]
    _require(len(chain) >= 2, path, "a flow needs at least two chain nodes")
    expected = len(chain) - 1 + len(sides)
    _require(
        len(spec.edges) == expected,
        path,
        f"a flow with {len(chain)} chain and {len(sides)} side nodes needs {expected} edges, got {len(spec.edges)}",
    )
    for index, edge in enumerate(spec.edges[: len(chain) - 1]):
        _require(
            edge.source == chain[index] and edge.target == chain[index + 1],
            path,
            f"edge {index + 1} must join {chain[index]!r} to {chain[index + 1]!r}; chain edges come first",
        )
    parents: set[str] = set()
    joined: list[str] = []
    for index, edge in enumerate(spec.edges[len(chain) - 1:], start=len(chain)):
        branch = edge.source in chain and edge.target in sides
        feeds = edge.source in sides and edge.target == chain[0]
        _require(
            branch or feeds,
            path,
            f"edge {index} must run from a chain node to a side node, or from a side node into {chain[0]!r}",
        )
        if branch:
            _require(edge.source not in parents, path, f"{edge.source!r} sends more than one branch")
            parents.add(edge.source)
            joined.append(edge.target)
            continue
        _require(
            not edge.label and edge.channel == "plain",
            path,
            f"edge {index} is an input to {chain[0]!r}. Inputs take no label or channel, so put the words in the input's sub",
        )
        joined.append(edge.source)
    _require(
        sorted(joined) == sorted(sides),
        path,
        "every side node needs exactly one edge, as a branch or as an input",
    )
    for node in spec.nodes:
        _require(not (node.side and node.group), path, f"side node {node.id!r} sits with its parent and takes no group")


def _check_widths(spec: Spec, path: Path) -> None:
    chosen = spec.box_width()
    usable = chosen - 4
    for node in spec.nodes:
        for label in (node.title, node.sub):
            _require(
                len(label) <= usable,
                path,
                f"label {label!r} is {len(label)} characters but only {usable} fit width {chosen}",
            )


def is_yume_owned(kind: str) -> bool:
    """Whether a node kind is YUME software rather than something it reaches."""
    return kind in YUME_OWNED_KINDS


def missing_sources(spec: Spec, root: Path | None = None) -> list[str]:
    """Every declared source path that does not exist in the repository."""
    base = root or REPO_ROOT
    return [
        f"{_relative(spec.path)}: node {node.id!r} names missing source {source!r}"
        for node in spec.nodes
        for source in node.sources
        if not (base / source.rstrip("/")).exists()
    ]


def _check_groups(spec: Spec, path: Path) -> None:
    """A group encloses a run of adjacent nodes and names what it encloses.

    The drawing is a chain, so members have to be adjacent. The title is drawn
    on the enclosure in the SVG and nowhere in the ASCII, which means it may
    name the nodes it holds and may not carry a claim they do not already
    make.
    """
    seen: list[str] = []
    chain = spec.chain()
    for index, node in enumerate(chain):
        if not node.group:
            continue
        if index and chain[index - 1].group == node.group:
            continue
        _require(
            node.group not in seen,
            path,
            f"group {node.group!r} is split; its members must be adjacent",
        )
        seen.append(node.group)
    for group in seen:
        members = [node for node in spec.nodes if node.group == group]
        _require(
            len(members) >= 2,
            path,
            f"group {group!r} has one member; a group encloses at least two",
        )
        _require(
            len(group) <= GROUP_TITLE_LIMIT,
            path,
            f"group title {group!r} is longer than {GROUP_TITLE_LIMIT} characters",
        )


def groups(spec: Spec) -> list[tuple[int, int, str]]:
    """Each run of adjacent chain nodes sharing a group, as (first, last, title)."""
    runs: list[tuple[int, int, str]] = []
    chain = spec.chain()
    index = 0
    while index < len(chain):
        title = chain[index].group
        if not title:
            index += 1
            continue
        last = index
        while last + 1 < len(chain) and chain[last + 1].group == title:
            last += 1
        runs.append((index, last, title))
        index = last + 1
    return runs


def strings_path(language: str) -> Path:
    if not re.fullmatch(r"[a-z]{2}(_[A-Z]{2})?", language):
        raise SpecError(f"invalid language {language!r}")
    return STRINGS_DIR / language / STRINGS_NAME


def load_strings(language: str) -> dict:
    """The translated strings for one language, or an empty set.

    The source language keeps its strings in the specifications themselves,
    so there is one place a label is written and no copy to fall out of step.
    """
    if language == SOURCE_LANGUAGE:
        return {}
    path = strings_path(language)
    if not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SpecError(f"{_relative(path)}: invalid JSON: {exc}") from exc
    _require(isinstance(document, dict), path, "the translation must be a JSON object")
    return document


def apply_strings(spec: Spec, document: dict, language: str) -> Spec:
    """Replace a specification's drawn text with one language's strings.

    A missing entry keeps the source string rather than failing, so a partly
    finished translation still renders. `translations` reports what is
    missing, which is where an incomplete language belongs.
    """
    entry = document.get(spec.name)
    if entry is None:
        return spec
    path = strings_path(language)
    _require(isinstance(entry, dict), path, f"{spec.name} must be a JSON object")
    _closed(entry, STRINGS_KEYS, path, spec.name)

    spec.title = _string(entry, "title", path, spec.name, required=False) or spec.title
    spec.summary = _string(entry, "summary", path, spec.name, required=False) or spec.summary

    nodes = entry.get("nodes", {})
    _require(isinstance(nodes, dict), path, f"{spec.name}.nodes must be an object")
    known = {node.id for node in spec.nodes}
    for node_id, values in nodes.items():
        _require(node_id in known, path, f"{spec.name}.nodes names unknown node {node_id!r}")
        _require(isinstance(values, dict), path, f"{spec.name}.nodes.{node_id} must be an object")
        _closed(values, STRINGS_NODE_KEYS, path, f"{spec.name}.nodes.{node_id}")
        for node in spec.nodes:
            if node.id != node_id:
                continue
            node.title = values.get("title", node.title)
            node.sub = values.get("sub", node.sub)
            node.note = values.get("note", node.note)

    edges = entry.get("edges", {})
    _require(isinstance(edges, dict), path, f"{spec.name}.edges must be an object")
    pairs = {f"{edge.source}->{edge.target}": edge for edge in spec.edges}
    for key, values in edges.items():
        _require(key in pairs, path, f"{spec.name}.edges names unknown hop {key!r}")
        _require(isinstance(values, dict), path, f"{spec.name}.edges.{key} must be an object")
        _closed(values, STRINGS_EDGE_KEYS, path, f"{spec.name}.edges.{key}")
        pairs[key].label = values.get("label", pairs[key].label)

    groups = entry.get("groups", {})
    _require(isinstance(groups, dict), path, f"{spec.name}.groups must be an object")
    titles = {node.group for node in spec.nodes if node.group}
    for title, replacement in groups.items():
        _require(title in titles, path, f"{spec.name}.groups names unknown group {title!r}")
        _require(isinstance(replacement, str), path, f"{spec.name}.groups.{title} must be a string")
        for node in spec.nodes:
            if node.group == title:
                node.group = replacement

    _check_widths(spec, path)
    _check_groups(spec, path)
    return spec


def missing_strings(spec: Spec, document: dict) -> list[str]:
    """Every drawn string in one diagram that a translation has not supplied."""
    entry = document.get(spec.name) or {}
    gaps: list[str] = []
    if "title" not in entry:
        gaps.append(f"{spec.name}.title")
    if "summary" not in entry:
        gaps.append(f"{spec.name}.summary")
    nodes = entry.get("nodes", {})
    for node in spec.nodes:
        values = nodes.get(node.id, {})
        if "title" not in values:
            gaps.append(f"{spec.name}.nodes.{node.id}.title")
        if node.sub and "sub" not in values:
            gaps.append(f"{spec.name}.nodes.{node.id}.sub")
        if node.note and "note" not in values:
            gaps.append(f"{spec.name}.nodes.{node.id}.note")
    edges = entry.get("edges", {})
    for edge in spec.edges:
        if not edge.label:
            continue
        key = f"{edge.source}->{edge.target}"
        if "label" not in edges.get(key, {}):
            gaps.append(f"{spec.name}.edges.{key}.label")
    groups = entry.get("groups", {})
    for title in sorted({node.group for node in spec.nodes if node.group}):
        if title not in groups:
            gaps.append(f"{spec.name}.groups.{title}")
    return gaps


def load_all(language: str = SOURCE_LANGUAGE) -> list[Spec]:
    """Every specification in docs/diagrams, ordered by name."""
    document = load_strings(language)
    specs = [
        apply_strings(parse(path), document, language)
        for path in sorted(SPEC_DIR.glob("*.json"))
    ]
    names = [spec.name for spec in specs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SpecError(f"duplicate diagram names: {', '.join(duplicates)}")
    unknown = sorted(set(document) - set(names))
    if unknown:
        raise SpecError(
            f"{_relative(strings_path(language))}: names unknown diagrams: {', '.join(unknown)}"
        )
    # Documents own placement. A figure source never repeats its consumers.
    import yume_doc_spec
    for doc in yume_doc_spec.load_all(language):
        for spec in specs:
            if spec.name not in doc.diagrams():
                continue
            for layer, target in doc.outputs():
                if any(block.kind == "diagram" and block.text == spec.name and block.reaches(layer) for block in doc.blocks):
                    (spec.man_targets if layer == "man" else spec.markdown_targets).append(target)
    return specs


def load(name: str, language: str = SOURCE_LANGUAGE) -> Spec:
    if not NAME_RE.fullmatch(name):
        raise SpecError(f"invalid diagram name {name!r}")
    path = SPEC_DIR / f"{name}.json"
    if not path.is_file():
        raise SpecError(f"no such diagram: {name}")
    return apply_strings(parse(path), load_strings(language), language)
