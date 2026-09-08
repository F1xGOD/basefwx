#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Inline markup shared by every `.doc` renderer.

A line of `.doc` text is a sequence of runs. Markdown writes a run with the
punctuation a reader already knows, and roff writes it by switching fonts,
which it can only do on a macro line of its own. Both readings come from one
tokenizer here, so a phrase set in bold on the website cannot be plain in the
terminal.

    **bold**            .B bold                 **bold**
    *italic*            .I italic               *italic*
    `code`              .B code                 `code`
    [text](target)      text                    [text](target)
    man:yumed(8)        .BR yumed (8)           `yumed(8)`

Backticks become bold in roff because a manual has no third font and the
project uses code spans for option names, file names, and literal values,
which manuals set in bold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Where a manual breaks a filled line. roff refills the text when it renders,
# so this width decides how the generated source reads in a diff rather than
# how a terminal displays it. The hand-written pages it replaced wrapped
# anywhere between 69 and 76 columns, which is exactly the inconsistency
# generating them removes.
MAN_WIDTH = 72

# Punctuation a manual appends to a font macro rather than starting a new
# line for. `.BR name (8),` is one macro call, not a macro and a stray comma.
TRAILING_PUNCTUATION = ",.;:)?!"

TOKEN_RE = re.compile(
    r"""
    (?P<code>`[^`]+`)
  | (?P<bold>\*\*(?:[^*]|\*(?!\*))+\*\*)
  | (?P<italic>\*(?:\\.|[^*\s])(?:(?:\\.|[^*])*(?:\\.|[^*\s]))?\*)
  | (?P<link>\[[^\]]+\]\([^)]+\))
  | (?P<manref>man:[a-z][a-z0-9_.-]*\(\d\))
    """,
    re.VERBOSE,
)

LINK_RE = re.compile(r"^\[([^\]]+)\]\(([^)]+)\)$")
MANREF_RE = re.compile(r"^man:([a-z][a-z0-9_.-]*)\((\d)\)$")

# A marker character that is part of the text rather than markup. Without
# these a phrase such as `*.http` could not be set in italic at all, because
# its own first character would close the run.
INLINE_ESCAPES = {"*": "*", "`": "`", "\\": "\\"}
ESCAPE_RE = re.compile(r"\\([*`\\])")


def unescape_inline(text: str) -> str:
    """Resolve `\\*` and friends to the character they stand for."""
    return ESCAPE_RE.sub(lambda match: INLINE_ESCAPES[match.group(1)], text)


class InlineError(ValueError):
    """A line carries markup no renderer can express."""


@dataclass
class Run:
    """One inline run. `kind` is text, bold, italic, or manref."""

    kind: str
    text: str
    # Only a manref uses this: the section digit set outside the bold name.
    section: str = ""

    def is_text(self) -> bool:
        return self.kind == "text"


def tokenize(line: str) -> list[Run]:
    """Split one source line into runs, preserving every character."""
    runs: list[Run] = []
    position = 0
    for match in TOKEN_RE.finditer(line):
        if match.start() > position:
            runs.append(Run("text", unescape_inline(line[position:match.start()])))
        token = match.group(0)
        if match.lastgroup == "code":
            runs.append(Run("bold", unescape_inline(token[1:-1])))
        elif match.lastgroup == "bold":
            runs.append(Run("bold", unescape_inline(token[2:-2])))
        elif match.lastgroup == "italic":
            runs.append(Run("italic", unescape_inline(token[1:-1])))
        elif match.lastgroup == "link":
            link = LINK_RE.match(token)
            assert link is not None
            runs.append(Run("text", link.group(1)))
        elif match.lastgroup == "manref":
            reference = MANREF_RE.match(token)
            assert reference is not None
            runs.append(Run("manref", reference.group(1), reference.group(2)))
        position = match.end()
    if position < len(line):
        runs.append(Run("text", unescape_inline(line[position:])))
    return runs


def to_markdown(line: str) -> str:
    """Markdown keeps the authored punctuation and only resolves man refs."""
    return MANREF_RE.sub(
        lambda match: f"`{match.group(1)}({match.group(2)})`",
        _replace_manrefs(line),
    )


def _replace_manrefs(line: str) -> str:
    return re.sub(
        r"man:([a-z][a-z0-9_.-]*)\((\d)\)",
        lambda match: f"`{match.group(1)}({match.group(2)})`",
        line,
    )


def escape_roff(text: str) -> str:
    """Make one text run safe for roff without changing what it says."""
    return text.replace("\\", "\\e")


def _protect(line: str) -> str:
    """A rendered line that begins with a control character needs `\\&`."""
    if line.startswith(".") or line.startswith("'"):
        return "\\&" + line
    return line


SENTENCE_END = (".", "?", "!")

# A word ending in one of these looks like a sentence end but is not. An
# initial such as `e.g.` ends in a single letter and a stop, and a version
# such as `0.3.0-dev1.` would break mid-thought, so both are held back.
INITIAL_RE = re.compile(r"(^|\.)[A-Za-z]\.$")


def ends_sentence(word: str) -> bool:
    """Whether filling should start a new line after this word.

    roff sets a wider space after a sentence, and it decides where a sentence
    ended from the input line break rather than from the text. Breaking here
    is what makes that spacing come out the same on every run.
    """
    if not word.endswith(SENTENCE_END):
        return False
    if INITIAL_RE.search(word):
        return False
    body = word.rstrip("".join(SENTENCE_END))
    return len(body) > 1


def wrap(text: str, width: int = MAN_WIDTH, sentences: bool = False) -> list[str]:
    """Greedy fill, optionally starting each sentence on a line of its own."""
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        if sentences and ends_sentence(current):
            lines.append(current)
            current = word
        elif len(current) + 1 + len(word) <= width:
            current = f"{current} {word}"
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def to_roff(source: list[str], width: int = MAN_WIDTH) -> list[str]:
    """Render authored lines as filled roff, one macro line per font change.

    The source lines are joined first. A manual fills text itself, so where
    the author wrapped says nothing about where the terminal will break, and
    only a font change forces a line of its own.
    """
    runs = tokenize(" ".join(line.strip() for line in source if line.strip()))
    return _emit_runs(runs, width)


def _segments(runs: list[Run]) -> list[tuple[str, str]]:
    """Flatten runs into (kind, text) segments, expanding a man reference.

    A reference sets the name in bold and the section in the roman font, so it
    is two segments rather than one, exactly as `.BR name (8)` writes it.
    """
    out: list[tuple[str, str]] = []
    for run in runs:
        if run.kind == "manref":
            out.append(("bold", run.text))
            out.append(("text", f"({run.section})"))
        else:
            out.append((run.kind, run.text))
    return out


def _words(segments: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    """Group segments into words, where a word may change font inside itself.

    `**1**-**64**,` is one word. Emitting its three pieces as three macro
    lines would let roff fill a space into each join and publish `1 - 64,`,
    so the word has to stay one macro call.
    """
    words: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for kind, text in segments:
        pieces = re.split(r"(\s+)", text)
        for piece in pieces:
            if piece == "":
                continue
            if piece.isspace():
                if current:
                    words.append(current)
                    current = []
                continue
            if current and current[-1][0] == kind:
                current[-1] = (kind, current[-1][1] + piece)
            else:
                current.append((kind, piece))
    if current:
        words.append(current)
    return words


LETTERS = {"bold": "B", "italic": "I", "text": "R"}


# A token longer than this cannot be fitted into a filled line, and roff
# reports that it cannot adjust the line it lands on.
LONG_TOKEN = 40

# Where a long token may be broken. These are the separators inside the URL
# and specification strings that make a token long in the first place, so a
# break lands between two parts a reader already reads separately.
BREAK_AFTER = "&?/=,;:"


def _breakable(word: str) -> str:
    """Offer roff somewhere to break a token it otherwise cannot fit.

    `\\:` is a zero-width break opportunity, so this changes where a line may
    end and nothing else. The hand-written manuals carried these by hand,
    which is a formatting decision this renderer now makes for itself.
    """
    if len(word) <= LONG_TOKEN:
        return word
    out = ""
    for index, character in enumerate(word):
        out += character
        if character in BREAK_AFTER and index + 1 < len(word):
            out += "\\:"
    return out


def _word_macro(word: list[tuple[str, str]]) -> str:
    """One macro call for a word that changes font inside itself."""
    kinds = [kind for kind, _ in word]
    letters = [LETTERS[kind] for kind in kinds]
    if len(word) == 1:
        return f".{letters[0]} {_quote(_breakable(escape_roff(word[0][1])))}"

    # A two-letter macro alternates its fonts, so any word that alternates
    # between exactly two of them is one call.
    alternating = all(letters[i] == letters[i % 2] for i in range(len(letters)))
    if alternating and letters[0] != letters[1]:
        args = " ".join(_quote(_breakable(escape_roff(text))) for _, text in word)
        return f".{letters[0]}{letters[1]} {args}"

    # Anything else needs inline font escapes, which take any sequence.
    body = "".join(f"\\f{LETTERS[kind]}{escape_roff(text)}" for kind, text in word)
    return _protect(body + "\\fR")


def _emit_runs(runs: list[Run], width: int) -> list[str]:
    output: list[str] = []
    pending: list[str] = []

    def flush() -> None:
        if not pending:
            return
        for line in wrap(" ".join(pending), width, sentences=True):
            output.append(_protect(line))
        pending.clear()

    for word in _words(_segments(runs)):
        if all(kind == "text" for kind, _ in word):
            pending.append(_breakable(escape_roff("".join(text for _, text in word))))
            continue
        flush()
        output.append(_word_macro(word))

    flush()
    return output


def macro_line(run: Run, tail: str = "") -> str:
    """One font macro call for a single run, with any swallowed punctuation."""
    if run.kind == "manref":
        name = escape_roff(run.text)
        return f".BR {name} ({run.section}){tail}"
    letter = "B" if run.kind == "bold" else "I"
    body = escape_roff(run.text)
    if tail:
        return f".{letter}R {_quote(body)} {_quote(tail)}"
    if " " in body:
        return f".{letter} {body}"
    return f".{letter} {body}"


def _quote(text: str) -> str:
    return f'"{text}"' if " " in text else text


def _merge_same_font(runs: list[Run]) -> list[Run]:
    """Join runs of one font that are separated only by spaces.

    `**--keys-alias** *id* *alias*` is two arguments in one italic field, not
    two italic fields, and a manual has one macro call for it. Merging here
    means a source can be written either way and still render.
    """
    merged: list[Run] = []
    for run in runs:
        if (
            len(merged) >= 2
            and merged[-1].is_text()
            and merged[-1].text.strip() == ""
            and merged[-2].kind == run.kind
            and run.kind in ("bold", "italic")
        ):
            gap = merged.pop().text
            previous = merged.pop()
            merged.append(Run(run.kind, previous.text + gap + run.text))
            continue
        merged.append(run)
    return merged


def signature_to_roff(signature: str) -> str:
    """Render an option or term signature as its roff macro line.

    A manual sets an option name in bold and its argument in italic, and it
    does that in one call so the two sit together without a space it did not
    ask for. Macro arguments are concatenated with nothing between them, so a
    space that belongs in the term is carried inside the argument before it.
    """
    runs = _merge_same_font(tokenize(signature))
    segments = _absorb_spacing(_segments(runs))
    if not segments:
        raise InlineError(f"signature {signature!r} has no content")

    if len(segments) == 1:
        kind, text = segments[0]
        return f".{LETTERS[kind]} {escape_roff(text.strip())}"

    letters = [LETTERS[kind] for kind, _ in segments]
    alternating = all(letters[i] == letters[i % 2] for i in range(len(letters)))
    if alternating and letters[0] != letters[1]:
        args = " ".join(_quote(escape_roff(text)) for _, text in segments)
        return f".{letters[0]}{letters[1]} {args}"

    body = "".join(f"\\f{LETTERS[kind]}{escape_roff(text)}" for kind, text in segments)
    return _protect(body + "\\fR")


def _absorb_spacing(segments: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Fold whitespace-only segments into the argument that precedes them.

    A macro call joins its arguments with nothing between them, so a space
    between an option and its value has to travel inside the option's own
    argument.
    """
    out: list[tuple[str, str]] = []
    for kind, text in segments:
        if kind == "text" and text.strip() == "":
            if out:
                out[-1] = (out[-1][0], out[-1][1] + text)
            continue
        if out and out[-1][0] == kind:
            out[-1] = (kind, out[-1][1] + text)
            continue
        out.append((kind, text))
    while out and out[-1][1].strip() == "":
        out.pop()
    return out


def signature_to_markdown(signature: str) -> str:
    """Markdown keeps a signature as authored, with man refs resolved."""
    return to_markdown(signature)


def plain(line: str) -> str:
    """The text of a line with every marker removed, for widths and titles."""
    return "".join(
        run.text if run.kind != "manref" else f"{run.text}({run.section})"
        for run in tokenize(line)
    )
