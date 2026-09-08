#!/usr/bin/env python3
"""Check BaseFWX's ASCII diagrams and the deferred SVG theme boundary."""

from __future__ import annotations

import unittest
from pathlib import Path

import yume_diagram_ascii as ascii_renderer
import yume_diagram_spec as spec
import yume_diagram_svg as svg_renderer
import yume_diagrams
import yume_doc_spec


class Diagrams(unittest.TestCase):
    def test_every_placed_diagram_has_a_readable_ascii_form(self) -> None:
        for diagram in spec.load_all():
            with self.subTest(diagram=diagram.name):
                drawing = ascii_renderer.render(diagram)
                self.assertLessEqual(max(map(len, drawing.splitlines())), ascii_renderer.BUDGET)
                self.assertIn("\\", drawing)
                for node in diagram.nodes:
                    self.assertIn(node.title, drawing)
                self.assertFalse(diagram.web, "BaseFWX SVG styling is deferred")
                markdown = "\n".join(yume_diagrams.render_block(diagram, Path("reference.md")))
                self.assertNotIn("<img", markdown)
                self.assertIn(drawing.strip(), markdown)

    def test_basefwx_processing_is_not_labelled_as_yume_software(self) -> None:
        for diagram in spec.load_all():
            for node in diagram.nodes:
                self.assertFalse(spec.is_yume_owned(node.kind), (diagram.name, node.title))

    def test_manual_and_web_publish_the_same_diagrams(self) -> None:
        for name in ("basefwx_1", "basefwx_7"):
            doc = yume_doc_spec.load(name)
            self.assertTrue(doc.web)
            self.assertTrue(doc.man)
            self.assertTrue(doc.markdown)
            self.assertTrue(doc.diagrams())
        self.assertEqual(yume_diagrams.verify_targets(spec.load_all()), [])

    def test_future_svg_renderer_can_read_basefwx_tokens(self) -> None:
        tokens = (Path(__file__).resolve().parents[1] / "website/assets/tokens.css").read_text()
        for _, token, light, dark in svg_renderer.PALETTE:
            self.assertIn(token + ":", tokens)
            self.assertNotEqual(light, dark)
        self.assertIn("Archivo", svg_renderer.DISPLAY_FACES)


if __name__ == "__main__":
    unittest.main()
