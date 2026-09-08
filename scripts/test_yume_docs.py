#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Tests for the `.doc` source format and its renderers.

Run with `python3 scripts/test_yume_docs.py`.

The cases below fall into three groups. The grammar has to reject a malformed
source rather than drop a field. The two renderers have to keep each layer's
own conventions. The tracked sources have to stay renderable and current.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_doc_inline as inline
import yume_doc_man
import yume_doc_markdown
import yume_doc_spec
import yume_docs
from yume_doc_spec import DocError

PAGE = """#!yume-doc 1
name:     sample
kind:     page
title:    Sample page
summary:  One sentence of summary.
markdown: docs/SAMPLE.md
web:      yes
---
## First section

A paragraph with **bold**, *italic*, `code` and a man:yumed(8) reference.
"""

MANUAL = """#!yume-doc 1
name:        sample
kind:        man
title:       sample-tool
summary:     an example command
man:         docs/man/sample.1
man-section: 1
man-date:    2026-01-02
man-source:  YUME 0.3.0-dev1
man-manual:  YUME Manual
---
@synopsis
**sample-tool** [ *options* ]
@end

## DESCRIPTION

**sample-tool** does one thing.
"""


def write(root: Path, text: str, name: str = "sample.doc", where: str = "pages") -> Path:
    target = root / "en_US" / where / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def part(root: Path, relative: str, text: str) -> Path:
    target = root / "en_US" / "parts" / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


class Grammar(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_doc_spec.SOURCE_ROOT
        yume_doc_spec.SOURCE_ROOT = self.root
        self.addCleanup(setattr, yume_doc_spec, "SOURCE_ROOT", self._saved)

    def parse(self, text: str, **kwargs) -> yume_doc_spec.Doc:
        return yume_doc_spec.parse(write(self.root, text, **kwargs))

    def test_a_valid_page_parses(self) -> None:
        doc = self.parse(PAGE)
        self.assertEqual(doc.name, "sample")
        self.assertEqual(doc.markdown, "docs/SAMPLE.md")
        self.assertTrue(doc.web)

    def test_the_magic_line_is_required(self) -> None:
        with self.assertRaisesRegex(DocError, "first line"):
            self.parse(PAGE.replace("#!yume-doc 1", "# not a doc"))

    def test_an_unknown_header_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "unknown header key 'author'"):
            self.parse(PAGE.replace("kind:     page", "author:   nobody"))

    def test_a_duplicate_header_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "duplicate header key"):
            self.parse(PAGE.replace("kind:     page", "title:    Twice"))

    def test_the_name_must_match_the_file(self) -> None:
        with self.assertRaisesRegex(DocError, "must match the file name"):
            self.parse(PAGE.replace("name:     sample", "name:     other"))

    def test_an_output_may_not_escape_the_repository(self) -> None:
        with self.assertRaisesRegex(DocError, "escapes the repository"):
            self.parse(PAGE.replace("docs/SAMPLE.md", "docs/../../SAMPLE.md"))

    def test_web_without_markdown_is_rejected(self) -> None:
        text = PAGE.replace("markdown: docs/SAMPLE.md\n", "")
        with self.assertRaisesRegex(DocError, "web: yes needs a markdown output"):
            self.parse(text)

    def test_a_page_may_not_carry_man_keys(self) -> None:
        with self.assertRaisesRegex(DocError, "only meaningful for kind: man"):
            self.parse(PAGE.replace("web:      yes", "man-section: 1"))

    def test_a_manual_needs_its_title_page_fields(self) -> None:
        with self.assertRaisesRegex(DocError, "kind: man needs man-date"):
            self.parse(MANUAL.replace("man-date:    2026-01-02\n", ""), where="man")

    def test_a_manual_section_heading_is_capitalised(self) -> None:
        with self.assertRaisesRegex(DocError, "capitalised"):
            self.parse(MANUAL.replace("## DESCRIPTION", "## Description"), where="man")

    def test_a_manual_needs_a_synopsis(self) -> None:
        text = MANUAL.replace("@synopsis\n**sample-tool** [ *options* ]\n@end\n\n", "")
        with self.assertRaisesRegex(DocError, "exactly one @synopsis"):
            self.parse(text, where="man")

    def test_a_page_may_not_carry_a_synopsis(self) -> None:
        text = PAGE.replace("## First section", "@synopsis\n**x**\n@end\n\n## First section")
        with self.assertRaisesRegex(DocError, "only meaningful for kind: man"):
            self.parse(text)

    def test_a_body_title_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "body headings start at"):
            self.parse(PAGE.replace("## First section", "# First section"))

    def test_a_tab_in_text_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "tab renders differently"):
            self.parse(PAGE.replace("A paragraph", "A\tparagraph"))

    def test_trailing_whitespace_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "trailing whitespace"):
            self.parse(PAGE + "\nA line ending in a space. \n")

    def test_an_unknown_directive_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "unknown block directive"):
            self.parse(PAGE + "\n@sidebar\nx\n@end\n")

    def test_an_unknown_code_language_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "@code needs a language"):
            self.parse(PAGE + "\n@code brainfuck\n+++\n@end\n")

    def test_an_unclosed_block_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "not closed by @end"):
            self.parse(PAGE + "\n@code bash\nls\n")

    def test_a_table_needs_an_alignment_row(self) -> None:
        with self.assertRaisesRegex(DocError, "alignment row"):
            self.parse(PAGE + "\n@table\n| a | b |\n| 1 | 2 |\n@end\n")

    def test_a_ragged_table_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "columns but the header"):
            self.parse(PAGE + "\n@table\n| a | b |\n| --- | --- |\n| 1 |\n@end\n")

    def test_an_option_needs_a_description(self) -> None:
        with self.assertRaisesRegex(DocError, "has no description"):
            self.parse(PAGE + "\n@options\n@opt **--flag**\n@end\n")

    def test_an_unknown_layer_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "unknown layer 'pdf'"):
            self.parse(PAGE + "\n@only pdf\nx\n@end\n")

    def test_a_layer_the_header_does_not_publish_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "@only names man"):
            self.parse(PAGE + "\n@only man\nx\n@end\n")

    def test_an_unclosed_only_block_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "not closed by @end"):
            self.parse(PAGE + "\n@only markdown\nx\n")


OPTION_MANUAL = MANUAL.replace(
    "**sample-tool** does one thing.",
    """@options
@opt **-s, --sample** *path*
@cli file: yes
@cli spell: -s, --sample <path>
@cli help: Read the sample from a file

Read the sample from a file.
@end""",
)


class CliMetadata(unittest.TestCase):
    """The `@cli` keys an option carries for the generated command line."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_doc_spec.SOURCE_ROOT
        yume_doc_spec.SOURCE_ROOT = self.root
        self.addCleanup(setattr, yume_doc_spec, "SOURCE_ROOT", self._saved)

    def parse(self, text: str) -> yume_doc_spec.Doc:
        return yume_doc_spec.parse(write(self.root, text, name="sample"))

    def option(self, text: str) -> yume_doc_spec.Option:
        doc = self.parse(text)
        blocks = [block for block in doc.blocks if block.kind == "options"]
        return blocks[0].options[0]

    def test_the_keys_are_read_into_the_option(self) -> None:
        option = self.option(OPTION_MANUAL)
        self.assertEqual(option.cli["file"], "yes")
        self.assertEqual(len(option.cli_print), 1)
        self.assertEqual(option.cli_print[0]["spell"], "-s, --sample <path>")
        self.assertEqual(option.cli_print[0]["help"], ["Read the sample from a file"])

    def test_the_renderers_ignore_them(self) -> None:
        option = self.option(OPTION_MANUAL)
        self.assertNotIn("@cli", "\n".join(option.body))

    def test_an_unknown_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "unknown @cli key"):
            self.option(OPTION_MANUAL.replace("@cli file: yes", "@cli colour: red"))

    def test_a_duplicate_completion_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "duplicate @cli key"):
            self.option(OPTION_MANUAL.replace("@cli file: yes", "@cli file: yes\n@cli file: no"))

    def test_disabling_completion_rejects_bad_values_and_argument_rules(self) -> None:
        for setting in ("@cli complete: maybe", "@cli complete: no\n@cli file: yes",
                        "@cli complete: no\n@cli values: first second"):
            with self.subTest(setting=setting), self.assertRaises(DocError):
                self.option(OPTION_MANUAL.replace("@cli file: yes", setting))

    def test_a_key_must_follow_its_option_directly(self) -> None:
        with self.assertRaisesRegex(DocError, "directly follow"):
            self.option(
                OPTION_MANUAL.replace(
                    "@cli help: Read the sample from a file\n\nRead the sample",
                    "@cli help: Read the sample from a file\n\n@cli values: a b\nRead the sample",
                )
            )

    def test_a_completion_key_may_not_sit_inside_a_printed_entry(self) -> None:
        with self.assertRaisesRegex(DocError, "before the first"):
            self.option(
                OPTION_MANUAL.replace(
                    "@cli spell: -s, --sample <path>",
                    "@cli spell: -s, --sample <path>\n@cli values: a b",
                )
            )

    def test_a_printed_entry_needs_help_text(self) -> None:
        with self.assertRaisesRegex(DocError, "no help text"):
            self.option(OPTION_MANUAL.replace("@cli help: Read the sample from a file", "@cli help:"))

    def test_values_and_file_may_not_both_claim_the_argument(self) -> None:
        with self.assertRaisesRegex(DocError, "pick one"):
            self.option(OPTION_MANUAL.replace("@cli file: yes", "@cli file: yes\n@cli values: a b", 1))

    def test_a_spelling_may_not_name_an_undeclared_flag(self) -> None:
        with self.assertRaisesRegex(DocError, "neither the @opt signature"):
            self.option(
                OPTION_MANUAL.replace("@cli spell: -s, --sample <path>", "@cli spell: --other <path>")
            )

    def test_declaring_the_flag_accepts_the_spelling(self) -> None:
        option = self.option(
            OPTION_MANUAL.replace(
                "@cli spell: -s, --sample <path>",
                "@cli flags: --other\n@cli spell: --sample --other <path>",
            )
        )
        self.assertIn("--other", yume_doc_spec.cli_flags(option))
        self.assertIn("--sample", yume_doc_spec.cli_flags(option))

    def test_one_option_may_print_several_entries(self) -> None:
        option = self.option(
            OPTION_MANUAL.replace(
                "@cli help: Read the sample from a file",
                "@cli help: Read the sample from a file\n"
                "@cli spell: --sample <addr>:<port>\n"
                "@cli help: Read the sample from a socket",
            )
        )
        self.assertEqual(len(option.cli_print), 2)

    def test_a_term_may_share_the_next_entry_description(self) -> None:
        option = self.option(
            OPTION_MANUAL.replace(
                "@cli spell: -s, --sample <path>\n@cli help: Read the sample from a file",
                "@cli spell: -s, --sample <path>\n"
                "@cli spell: --sample <addr>\n"
                "@cli help: Read the sample",
            )
        )
        self.assertEqual(option.cli_print[0]["help"], [])

    def test_an_option_printing_no_help_text_at_all_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "no help text"):
            self.option(
                OPTION_MANUAL.replace(
                    "@cli spell: -s, --sample <path>\n@cli help: Read the sample from a file",
                    "@cli spell: -s, --sample <path>",
                )
            )

    def test_a_column_override_must_be_a_column(self) -> None:
        with self.assertRaisesRegex(DocError, "must be a column"):
            self.option(
                OPTION_MANUAL.replace(
                    "@cli help: Read the sample from a file",
                    "@cli help: Read the sample from a file\n@cli column: wide",
                )
            )

    def test_an_option_with_no_cli_keys_carries_none(self) -> None:
        option = self.option(
            OPTION_MANUAL.replace("@cli spell: -s, --sample <path>\n", "")
            .replace("@cli help: Read the sample from a file\n", "")
            .replace("@cli file: yes\n", "")
        )
        self.assertEqual(option.cli, {})
        self.assertEqual(option.cli_print, [])


class Includes(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_doc_spec.SOURCE_ROOT
        yume_doc_spec.SOURCE_ROOT = self.root
        self.addCleanup(setattr, yume_doc_spec, "SOURCE_ROOT", self._saved)

    def parse(self, text: str) -> yume_doc_spec.Doc:
        return yume_doc_spec.parse(write(self.root, text))

    def test_a_fragment_is_spliced_in_place(self) -> None:
        part(self.root, "shared/limits.part", "## Limits\n\nThe bound is four.\n")
        doc = self.parse(PAGE + "\n@include shared/limits.part\n")
        headings = [block.text for block in doc.blocks if block.kind == "heading"]
        self.assertEqual(headings, ["First section", "Limits"])
        self.assertIn("parts/shared/limits.part", doc.includes[0])

    def test_one_fragment_serves_several_documents(self) -> None:
        # This is the reason fragments exist: a fact is written once and every
        # document that states it picks up the correction.
        part(self.root, "shared/limits.part", "The bound is four.\n")
        first = self.parse(PAGE + "\n@include shared/limits.part\n")
        second = yume_doc_spec.parse(
            write(
                self.root,
                PAGE.replace("sample", "second").replace("SAMPLE", "SECOND")
                + "\n@include shared/limits.part\n",
                name="second.doc",
            )
        )
        self.assertEqual(first.blocks[-1].lines, second.blocks[-1].lines)

    def test_a_missing_fragment_is_rejected(self) -> None:
        with self.assertRaisesRegex(DocError, "no such fragment"):
            self.parse(PAGE + "\n@include shared/absent.part\n")

    def test_a_fragment_must_use_the_part_suffix(self) -> None:
        with self.assertRaisesRegex(DocError, "needs a .part fragment"):
            self.parse(PAGE + "\n@include shared/limits.doc\n")

    def test_a_fragment_may_not_escape_the_language_tree(self) -> None:
        with self.assertRaisesRegex(DocError, "escapes the language tree"):
            self.parse(PAGE + "\n@include ../../../etc/passwd.part\n")

    def test_a_fragment_may_not_carry_a_header(self) -> None:
        part(self.root, "shared/bad.part", PAGE)
        with self.assertRaisesRegex(DocError, "cannot start with the document magic"):
            self.parse(PAGE + "\n@include shared/bad.part\n")

    def test_a_cycle_is_rejected(self) -> None:
        part(self.root, "a.part", "@include b.part\n")
        part(self.root, "b.part", "@include a.part\n")
        with self.assertRaisesRegex(DocError, "already open, so the chain is a cycle"):
            self.parse(PAGE + "\n@include a.part\n")

    def test_an_over_deep_chain_is_rejected(self) -> None:
        for step in range(yume_doc_spec.MAX_INCLUDE_DEPTH + 1):
            part(self.root, f"n{step}.part", f"@include n{step + 1}.part\n")
        part(self.root, f"n{yume_doc_spec.MAX_INCLUDE_DEPTH + 1}.part", "Text.\n")
        with self.assertRaisesRegex(DocError, "nests deeper than"):
            self.parse(PAGE + "\n@include n0.part\n")

    def test_an_include_inside_only_is_rejected(self) -> None:
        part(self.root, "shared/limits.part", "Text.\n")
        with self.assertRaisesRegex(DocError, "may not sit inside an @only"):
            self.parse(PAGE + "\n@only markdown\n@include shared/limits.part\n@end\n")

    def test_an_error_names_the_fragment_not_the_document(self) -> None:
        part(self.root, "shared/bad.part", "@table\n| a |\n@end\n")
        with self.assertRaisesRegex(DocError, r"parts/shared/bad\.part:1"):
            self.parse(PAGE + "\n@include shared/bad.part\n")


class Inline(unittest.TestCase):
    def test_markdown_keeps_the_authored_markers(self) -> None:
        self.assertEqual(inline.to_markdown("a **b** and `c`"), "a **b** and `c`")

    def test_markdown_resolves_a_man_reference(self) -> None:
        self.assertEqual(inline.to_markdown("see man:yumed(8)"), "see `yumed(8)`")

    def test_roff_gives_each_font_change_its_own_macro(self) -> None:
        # The closing stop rides on the macro rather than becoming a line of
        # its own, which is the idiom every hand-written manual follows.
        self.assertEqual(
            inline.to_roff(["**yume** is a *tool*."]),
            [".B yume", "is a", ".IR tool ."],
        )

    def test_roff_swallows_punctuation_after_a_macro(self) -> None:
        self.assertEqual(
            inline.to_roff(["run man:yumed(8), then stop"]),
            ["run", ".BR yumed (8),", "then stop"],
        )

    def test_a_code_span_becomes_bold(self) -> None:
        self.assertEqual(inline.to_roff(["use `--flag` now"]), ["use", ".B --flag", "now"])

    def test_a_link_keeps_only_its_text(self) -> None:
        self.assertEqual(inline.to_roff(["see [the page](X.md) now"]), ["see the page now"])

    def test_a_line_starting_with_a_control_character_is_protected(self) -> None:
        self.assertEqual(inline.to_roff(["./run.sh does it"]), ["\\&./run.sh does it"])

    def test_each_sentence_starts_a_new_line(self) -> None:
        # roff sets a wider space after a sentence and takes the cue from the
        # input break, so the break has to be where the sentence ends.
        self.assertEqual(
            inline.to_roff(["One thing. Another thing."]),
            ["One thing.", "Another thing."],
        )

    def test_an_initial_does_not_end_a_sentence(self) -> None:
        self.assertFalse(inline.ends_sentence("e.g."))
        self.assertTrue(inline.ends_sentence("stop."))

    def test_a_plain_signature_is_bold(self) -> None:
        self.assertEqual(inline.signature_to_roff("**--headless**"), ".B --headless")

    def test_an_argument_signature_alternates_fonts(self) -> None:
        self.assertEqual(
            inline.signature_to_roff("**--client-config** *path*"),
            '.BI "--client-config " path',
        )

    def test_a_file_signature_is_italic(self) -> None:
        self.assertEqual(inline.signature_to_roff("*~/.yume/keys/*"), ".I ~/.yume/keys/")


class ManRendering(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_doc_spec.SOURCE_ROOT
        yume_doc_spec.SOURCE_ROOT = self.root
        self.addCleanup(setattr, yume_doc_spec, "SOURCE_ROOT", self._saved)
        self.doc = yume_doc_spec.parse(write(self.root, MANUAL, where="man"))

    def render(self) -> list[str]:
        return yume_doc_man.render(self.doc).split("\n")

    def test_the_title_line_comes_from_the_header(self) -> None:
        self.assertEqual(
            self.render()[1],
            '.TH SAMPLE-TOOL 1 "2026-01-02" "YUME 0.3.0-dev1" "YUME Manual"',
        )

    def test_the_name_section_is_generated(self) -> None:
        lines = self.render()
        self.assertEqual(lines[2], ".SH NAME")
        self.assertEqual(lines[3], "sample-tool \\- an example command")

    def test_the_synopsis_heading_is_generated(self) -> None:
        self.assertIn(".SH SYNOPSIS", self.render())

    def test_the_first_paragraph_of_a_section_has_no_break(self) -> None:
        lines = self.render()
        self.assertEqual(lines[lines.index(".SH DESCRIPTION") + 1], ".B sample-tool")

    def test_a_later_paragraph_opens_with_a_break(self) -> None:
        doc = yume_doc_spec.parse(
            write(self.root, MANUAL + "\nA second paragraph.\n", where="man")
        )
        self.assertIn(".PP", yume_doc_man.render(doc))

    def test_an_option_list_becomes_indented_paragraphs(self) -> None:
        doc = yume_doc_spec.parse(
            write(
                self.root,
                MANUAL + "\n@options\n@opt **--flag** *value*\nDoes a thing.\n@end\n",
                where="man",
            )
        )
        lines = yume_doc_man.render(doc).split("\n")
        index = lines.index(".TP")
        self.assertEqual(lines[index + 1], '.BI "--flag " value')
        self.assertEqual(lines[index + 2], "Does a thing.")

    def test_a_table_becomes_an_aligned_literal_region(self) -> None:
        doc = yume_doc_spec.parse(
            write(
                self.root,
                MANUAL + "\n@table\n| Mode | Bytes |\n| --- | ---: |\n| soft | 256 |\n@end\n",
                where="man",
            )
        )
        lines = yume_doc_man.render(doc).split("\n")
        self.assertIn(".nf", lines)
        self.assertIn("Mode  Bytes", lines)
        self.assertIn("soft    256", lines)

    def test_a_man_only_block_is_kept(self) -> None:
        doc = yume_doc_spec.parse(
            write(self.root, MANUAL + "\n@only man\nTerminal only.\n@end\n", where="man")
        )
        self.assertIn("Terminal only.", yume_doc_man.render(doc))


class MarkdownRendering(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_doc_spec.SOURCE_ROOT
        yume_doc_spec.SOURCE_ROOT = self.root
        self.addCleanup(setattr, yume_doc_spec, "SOURCE_ROOT", self._saved)
        self.doc = yume_doc_spec.parse(write(self.root, PAGE))

    def test_the_banner_names_the_source(self) -> None:
        first = yume_doc_markdown.render(self.doc).split("\n")[0]
        self.assertIn("sample.doc", first)
        self.assertIn("scripts/yume_docs.py", first)

    def test_the_title_becomes_the_level_one_heading(self) -> None:
        self.assertEqual(yume_doc_markdown.render(self.doc).split("\n")[1], "# Sample page")

    def test_authored_line_breaks_are_kept(self) -> None:
        # Markdown reflows in a browser, so a break says nothing to a reader
        # but everything to whoever reviews the diff.
        doc = yume_doc_spec.parse(write(self.root, PAGE + "\nOne\nbroken\nparagraph.\n"))
        self.assertIn("One\nbroken\nparagraph.", yume_doc_markdown.render(doc))

    def test_a_man_only_block_is_dropped(self) -> None:
        doc = yume_doc_spec.parse(write(self.root, PAGE))
        doc.blocks.append(
            yume_doc_spec.Block(kind="paragraph", line=1, layers=("man",), lines=["Hidden."])
        )
        self.assertNotIn("Hidden.", yume_doc_markdown.render(doc))

    def test_an_option_list_becomes_a_loose_bullet_list(self) -> None:
        doc = yume_doc_spec.parse(
            write(self.root, PAGE + "\n@options\n@opt **--flag**\nDoes a thing.\n@end\n")
        )
        rendered = yume_doc_markdown.render(doc)
        self.assertIn("- **--flag**\n\n  Does a thing.", rendered)

    def test_a_fence_keeps_its_language_tag(self) -> None:
        doc = yume_doc_spec.parse(write(self.root, PAGE + "\n@code bash\nls -l\n@end\n"))
        self.assertIn("```bash\nls -l\n```", yume_doc_markdown.render(doc))

    def test_rendering_is_stable(self) -> None:
        self.assertEqual(
            yume_doc_markdown.render(self.doc), yume_doc_markdown.render(self.doc)
        )


class Translation(unittest.TestCase):
    """A second language is a directory, and nothing else changes."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_doc_spec.SOURCE_ROOT
        yume_doc_spec.SOURCE_ROOT = self.root
        self.addCleanup(setattr, yume_doc_spec, "SOURCE_ROOT", self._saved)

    def both(self, text: str = PAGE, **kwargs) -> tuple[yume_doc_spec.Doc, yume_doc_spec.Doc]:
        source = yume_doc_spec.parse(write(self.root, text, **kwargs), "en_US")
        path = self.root / "de_DE" / kwargs.get("where", "pages") / kwargs.get("name", "sample.doc")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return source, yume_doc_spec.parse(path, "de_DE")

    def test_the_source_language_keeps_the_paths_readers_link_to(self) -> None:
        source, _ = self.both()
        self.assertEqual(source.outputs(), [("markdown", "docs/SAMPLE.md")])

    def test_a_translation_lands_beside_it(self) -> None:
        # The header is identical in both, which is the point: translating a
        # document is translating its text, not restating where it goes.
        _, translated = self.both()
        self.assertEqual(translated.outputs(), [("markdown", "docs/de_DE/SAMPLE.md")])

    def test_a_translated_manual_lands_under_a_language_root(self) -> None:
        _, translated = self.both(MANUAL, where="man")
        self.assertEqual(translated.outputs(), [("man", "docs/man/de_DE/sample.1")])

    def test_both_declare_the_same_output(self) -> None:
        source, translated = self.both()
        self.assertEqual(source.declared(), translated.declared())

    def test_a_translation_renders_through_the_same_renderer(self) -> None:
        _, translated = self.both()
        rendered = yume_doc_markdown.render(translated)
        self.assertIn("# Sample page", rendered)
        self.assertIn("de_DE", rendered.split("\n")[0])

    def test_a_language_directory_is_discovered(self) -> None:
        self.both()
        self.assertEqual(yume_doc_spec.languages(), ["de_DE", "en_US"])

    def test_a_language_with_no_directory_is_an_error(self) -> None:
        with self.assertRaisesRegex(DocError, "no such language directory"):
            yume_doc_spec.load_all("fr_FR")


class TrackedSources(unittest.TestCase):
    """The real docs/src tree has to stay renderable and current."""

    def test_every_source_parses(self) -> None:
        docs = yume_doc_spec.load_all()
        self.assertTrue(docs, "docs/src/en_US holds no sources")
        for doc in docs:
            self.assertTrue(doc.title, doc.name)
            self.assertTrue(doc.summary, doc.name)

    def test_no_two_sources_write_the_same_file(self) -> None:
        targets = [
            target for doc in yume_doc_spec.load_all() for _, target in doc.outputs()
        ]
        self.assertEqual(len(targets), len(set(targets)))

    def test_every_generated_file_is_current(self) -> None:
        # The same comparison `scripts/yume_docs.py check` runs in CI.
        for doc in yume_doc_spec.load_all():
            for target, content in yume_docs.rendered(doc):
                path = yume_doc_spec.REPO_ROOT / target
                self.assertTrue(path.is_file(), target)
                self.assertEqual(
                    path.read_text(encoding="utf-8"),
                    content,
                    f"{target} is stale, so run scripts/yume_docs.py sync",
                )

    def test_every_generated_file_carries_the_banner(self) -> None:
        for doc in yume_doc_spec.load_all():
            for target, content in yume_docs.rendered(doc):
                self.assertIn("scripts/yume_docs.py", content.split("\n")[0], target)

    def test_the_default_language_is_present(self) -> None:
        self.assertIn(yume_doc_spec.DEFAULT_LANGUAGE, yume_doc_spec.languages())


if __name__ == "__main__":
    unittest.main(verbosity=1)
