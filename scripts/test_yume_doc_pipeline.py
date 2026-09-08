#!/usr/bin/env python3
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Publication regressions using isolated, independently editable source trees."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yume_doc_markdown
import yume_doc_spec as spec
import yume_doc_web as web
import yume_docs as docs


class Pipeline(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = self.root / "docs/src"
        self.sources.mkdir(parents=True)
        (self.root / "website").mkdir()
        (self.root / "website/_config.yml").write_text("repo_url: https://github.com/example/project\n")
        (self.sources / "site.json").write_text(json.dumps({
            "schema": 1, "catalog_groups": {"group": ["Reference"]},
            "mirror_tracked": True, "cli": False,
        }))
        for module in (spec, web, docs):
            self.enterContext(patch.object(module, "REPO_ROOT", self.root))
        for module in (spec, docs):
            self.enterContext(patch.object(module, "SOURCE_ROOT", self.sources))
        self.page()

    def page(self, name: str = "sample", language: str = "en_US", body: str = "A fact.", header: str = "") -> Path:
        path = self.sources / language / "pages" / (name + ".doc")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"""#!yume-doc 1
name: {name}
kind: page
title: A title: with "quotes" & <text>
summary: A precise description.
markdown: docs/{name.upper()}.md
web: yes
{header}---
{body}
""")
        return path

    def run_command(self, *args: str) -> tuple[int, str]:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            result = docs.main(["docs", *args])
        return result, stream.getvalue()

    def sync(self) -> None:
        result, output = self.run_command("sync", "--all-languages")
        self.assertEqual(result, 0, output)

    def test_one_edit_updates_h1_frontmatter_description_and_catalog(self) -> None:
        self.page(header="catalog-group: Reference\ncatalog-order: 10\n")
        self.sync()
        source = self.sources / "en_US/pages/sample.doc"
        source.write_text(source.read_text().replace("A title:", "Edited title:").replace("A precise", "An edited"))
        self.sync()
        markdown = (self.root / "docs/SAMPLE.md").read_text()
        website = (self.root / "website/docs/SAMPLE.md").read_text()
        catalog = json.loads((self.root / "website/_data/docs.json").read_text())
        self.assertIn('# Edited title: with "quotes" & <text>', markdown)
        title_line = next(line for line in website.splitlines() if line.startswith("title: "))
        self.assertEqual(json.loads(title_line[7:]), catalog[0]["title"])
        self.assertIn("An edited description.", website)
        self.assertEqual(catalog[0]["summary"], "An edited description.")

    def test_layer_filters_reach_the_actual_website(self) -> None:
        self.page(body="@only markdown\nClone only.\n@end\n\n@only web\nWebsite only.\n@end")
        self.sync()
        markdown = (self.root / "docs/SAMPLE.md").read_text()
        website = (self.root / "website/docs/SAMPLE.md").read_text()
        self.assertIn("Clone only.", markdown)
        self.assertNotIn("Website only.", markdown)
        self.assertIn("Website only.", website)
        self.assertNotIn("Clone only.", website)

    def test_code_links_and_liquid_are_literal(self) -> None:
        self.page(body="@code text\n[example](missing.md)\n{{ site.secret }}\n@end")
        self.sync()
        website = (self.root / "website/docs/SAMPLE.md").read_text()
        self.assertIn("{% raw %}\n```text\n[example](missing.md)\n{{ site.secret }}", website)

    def test_links_with_code_labels_are_rewritten_but_code_examples_are_not(self) -> None:
        self.page("second")
        (self.root / "example.txt").write_text("Repository asset.")
        self.page(body="See [`SECOND.md`](SECOND.md) and [`example.txt`](../example.txt).\n"
                       "Keep `[example](missing.md)` and ``a `tick` [example](missing.md)`` literal.")
        self.sync()
        website = (self.root / "website/docs/SAMPLE.md").read_text()
        self.assertIn("[`SECOND.md`]({{ '/docs/SECOND/' | relative_url }})", website)
        self.assertIn("[`example.txt`](https://github.com/example/project/blob/main/example.txt)", website)
        self.assertIn("`[example](missing.md)`", website)
        self.assertIn("``a `tick` [example](missing.md)``", website)

    def test_web_no_removes_the_page_from_publication(self) -> None:
        path = self.page()
        path.write_text(path.read_text().replace("web: yes", "web: no"))
        self.sync()
        self.assertFalse((self.root / "website/docs/SAMPLE.md").exists())

    def test_invalid_late_source_writes_nothing(self) -> None:
        self.sync()
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file() and not path.is_relative_to(self.sources)}
        self.page(body="Changed valid document.")
        self.page("zzz", body="@typo")
        self.assertEqual(self.run_command("sync")[0], 1)
        self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))

    def test_invalid_translation_is_a_failure(self) -> None:
        self.page(language="de_DE", body="@typo")
        result, output = self.run_command("translations", "--language", "de_DE")
        self.assertEqual(result, 1)
        self.assertIn("unknown block directive", output)

    def test_language_before_subcommand_is_not_discarded(self) -> None:
        self.page(language="de_DE", body="Translated text.")
        result, output = self.run_command("--language", "de_DE", "render", "sample")
        self.assertEqual(result, 0, output)
        self.assertIn("Translated text.", output)
        result, output = self.run_command("--language", "de_DE", "translations")
        self.assertEqual(result, 0, output)
        self.assertIn("de_DE: 1 of 1 documents", output)

    def test_translation_links_use_available_locale_and_source_fallback(self) -> None:
        self.page("second")
        self.page("third")
        self.page("second", "de_DE")
        self.page(language="de_DE", body="[Two](SECOND.md#section) and [Three](THIRD.md).")
        self.sync()
        body = (self.root / "website/docs/de_DE/SAMPLE.md").read_text()
        self.assertIn("/docs/de_DE/SECOND/", body)
        self.assertIn("/docs/THIRD/", body)
        self.assertIn("#section", body)

    def test_root_readme_translation_does_not_collide_with_docs_readme(self) -> None:
        self.assertNotEqual(spec.localized("README.md", "de_DE", "markdown"),
                            spec.localized("docs/README.md", "de_DE", "markdown"))

    def test_translation_cannot_retarget_an_output(self) -> None:
        path = self.page(language="de_DE")
        path.write_text(path.read_text().replace("docs/SAMPLE.md", "docs/OTHER.md"))
        self.assertEqual(self.run_command("check", "--all-languages")[0], 1)

    def test_a_deleted_source_is_reported_even_when_no_sources_remain(self) -> None:
        self.sync()
        (self.sources / "en_US/pages/sample.doc").unlink()
        result, output = self.run_command("check")
        self.assertEqual(result, 1)
        self.assertIn("no source claims", output)

    def test_check_is_read_only_and_detects_catalog_drift(self) -> None:
        self.sync()
        path = self.root / "website/_data/docs.json"
        path.write_text("[]\n# wrong\n")
        result, _ = self.run_command("check")
        self.assertEqual(result, 1)
        self.assertEqual(path.read_text(), "[]\n# wrong\n")

    def test_output_symlink_cannot_write_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (self.root / "docs/SAMPLE.md").symlink_to(Path(directory) / "outside.md")
            result, output = self.run_command("sync")
            self.assertEqual(result, 1)
            self.assertIn("symlink", output)
            self.assertFalse((Path(directory) / "outside.md").exists())

    def test_include_symlink_cannot_read_outside_source_tree(self) -> None:
        (self.root / "outside.part").write_text("Outside content.")
        parts = self.sources / "en_US/parts"
        parts.mkdir()
        (parts / "outside.part").symlink_to(self.root / "outside.part")
        self.page(body="@include outside.part")
        self.assertEqual(self.run_command("sync")[0], 1)

    def test_all_layers_filter_still_requires_its_end(self) -> None:
        self.page(body="@only markdown man web\nMissing end.")
        self.assertEqual(self.run_command("sync")[0], 1)

    def test_misspelled_option_directive_is_rejected(self) -> None:
        self.page(body="@options\n@option **--thing**\nDescription.\n@end")
        self.assertEqual(self.run_command("sync")[0], 1)


if __name__ == "__main__":
    unittest.main()
