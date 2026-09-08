#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Build the contact sheet that proves a diagram renders the same either way.

A figure reaches a reader by two routes. The website inlines it, so the page's
tokens and its theme control reach into the SVG. Markdown, GitHub, and a file
viewer load it as an image, where no page stylesheet reaches it and it has to
paint itself. Both are shown here, one above the other, so a difference is
visible rather than discovered later on a published page.
"""

from __future__ import annotations

import html

PAGE_NAME = "preview.html"

DOT = "·"

STYLE = """
  :root {
    color-scheme: light;
    --gutter: clamp(1rem, 4vw, 2.5rem);
  }

  :root[data-theme="dark"] { color-scheme: dark; }

  body {
    margin: 0;
    padding: 0 var(--gutter) 6rem;
    background: var(--color-paper);
    color: var(--color-ink);
    font-family: var(--font-body);
    line-height: 1.6;
  }

  header {
    position: sticky;
    top: 0;
    z-index: 2;
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem 2rem;
    align-items: baseline;
    padding: 1.25rem 0;
    border-block-end: 1px solid var(--color-rule);
    background: var(--color-paper);
  }

  h1 {
    margin: 0;
    font-family: var(--font-display);
    font-size: 1.25rem;
    font-weight: 700;
  }

  .note {
    flex: 1 1 32ch;
    max-width: 68ch;
    margin: 0;
    color: var(--color-muted);
    font-size: 0.8125rem;
  }

  .themes {
    display: flex;
    gap: 0.25rem;
    padding: 0.25rem;
    border: 1px solid var(--color-rule);
    border-radius: 999px;
  }

  .themes button {
    border: 0;
    border-radius: 999px;
    padding: 0.3rem 0.85rem;
    background: transparent;
    color: var(--color-muted);
    font: inherit;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .themes button:focus-visible {
    outline: 2px solid var(--color-focus);
    outline-offset: 2px;
  }

  .themes button[aria-pressed="true"] {
    background: var(--color-accent-soft);
    color: var(--color-ink);
  }

  .index {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin: 1.5rem 0 0;
    padding: 0;
    list-style: none;
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .index a {
    display: block;
    padding: 0.2rem 0.6rem;
    border: 1px solid var(--color-rule);
    border-radius: 999px;
    color: var(--color-muted);
    text-decoration: none;
  }

  .index a:hover,
  .index a:focus-visible { color: var(--color-ink); }

  section { padding-block-start: 3.5rem; }

  h2 {
    margin: 0;
    color: var(--color-accent-strong);
    font-family: var(--font-mono);
    font-size: 0.8125rem;
    font-weight: 500;
  }

  h2 + p {
    max-width: 68ch;
    margin: 0.35rem 0 1.25rem;
    color: var(--color-muted);
    font-size: 0.875rem;
  }

  .pair {
    display: grid;
    gap: 1px;
    margin-block-end: 1.5rem;
    border: 1px solid var(--color-rule);
    border-radius: 1rem;
    background: var(--color-rule);
    overflow: hidden;
  }

  figure {
    margin: 0;
    background: var(--color-paper);
  }

  figcaption {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.5rem 0.9rem;
    border-block-end: 1px solid var(--color-rule);
    color: var(--color-muted);
    font-family: var(--font-mono);
    font-size: 0.6875rem;
  }

  .canvas {
    overflow-x: auto;
    padding: 1rem;
  }

  .canvas > svg,
  .canvas > img { display: block; }
"""

SCRIPT = """
  const root = document.documentElement;
  const buttons = [...document.querySelectorAll('.themes button')];
  const apply = (choice) => {
    if (choice === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', choice);
    buttons.forEach((b) =>
      b.setAttribute('aria-pressed', String(b.dataset.theme === choice)));
  };
  buttons.forEach((b) => b.addEventListener('click', () => apply(b.dataset.theme)));
  const asked = new URLSearchParams(location.search).get('theme');
  apply(['light', 'dark'].includes(asked) ? asked : 'system');
"""

INTRO = (
    "Every diagram twice. Inlined is how the website uses it. As an image is "
    "how Markdown, GitHub and a file viewer load it, with no page stylesheet "
    "reaching inside. Both follow the control on the right, because a figure "
    "loaded as an image takes the colour scheme of the page holding it. Add "
    "?theme=dark to the address to open straight into one."
)


def page(entries: list[tuple[str, str, list[tuple[str, str, str]]]]) -> str:
    """The contact sheet.

    `entries` is one tuple per diagram: its name, its summary, and a list of
    (layout, file name, SVG markup) for the layouts it renders.
    """
    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>YUME diagrams</title>",
        '<link rel="stylesheet" href="../../assets/tokens.css">',
        f"<style>{STYLE}</style>",
        "</head>",
        "<body>",
        "<header>",
        "<h1>YUME diagrams</h1>",
        f'<p class="note">{INTRO}</p>',
        '<div class="themes" role="group" aria-label="Theme">',
        '<button type="button" data-theme="light">Light</button>',
        '<button type="button" data-theme="dark">Dark</button>',
        '<button type="button" data-theme="system">System</button>',
        "</div>",
        "</header>",
        '<ul class="index">',
    ]
    for name, _summary, _layouts in entries:
        parts.append(f'<li><a href="#{name}">{name}</a></li>')
    parts.append("</ul>")

    for name, summary, layouts in entries:
        parts.append(f'<section id="{name}">')
        parts.append(f"<h2>{html.escape(name)}</h2>")
        parts.append(f"<p>{html.escape(summary)}</p>")
        for layout, file_name, markup in layouts:
            parts.append('<div class="pair">')
            parts.append(
                _figure(
                    f"{layout} {DOT} inlined, page tokens",
                    file_name,
                    f'<div class="canvas">{markup}</div>',
                )
            )
            parts.append(
                _figure(
                    f"{layout} {DOT} as an image, no page CSS",
                    file_name,
                    f'<div class="canvas"><img src="{html.escape(file_name)}" '
                    f'alt="{html.escape(name)} {layout}"></div>',
                )
            )
            parts.append("</div>")
        parts.append("</section>")

    parts.extend([f"<script>{SCRIPT}</script>", "</body>", "</html>", ""])
    return "\n".join(parts)


def _figure(caption: str, file_name: str, canvas: str) -> str:
    return (
        "<figure>"
        f"<figcaption><span>{caption}</span>"
        f"<span>{html.escape(file_name)}</span></figcaption>"
        f"{canvas}</figure>"
    )
