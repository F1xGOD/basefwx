# BaseFWX website

The release portal, published to GitHub Pages by `.github/workflows/static.yml`.
Jekyll builds this directory. `actions/configure-pages` injects the correct
`baseurl`, which is why every internal link goes through `relative_url` rather
than a hand-written `../` path.

## Where things live

| Path | What it is |
| --- | --- |
| `_config.yml` | Site settings. `asset_version` is the cache buster for CSS and JS. |
| `_data/nav.yml` | The header and footer link lists. Edit here, not in the pages. |
| `_includes/` | Shared chrome: `head`, `brand`, `site-header`, `section-nav`, `site-footer`, `theme-toggle`. |
| `_layouts/page.html` | Wrapper for the hand-written pages. |
| `_layouts/doc.html` | Wrapper for the Markdown docs. |
| `assets/tokens.css` | Colour, type, spacing, and motion tokens for both themes. |
| `assets/site.css` | Everything else. One pass, no override layer. |
| `assets/site.js` | Release metadata, hashes, VirusTotal, benchmarks, theme toggle. |
| `docs/*.md` | Documentation pages. Front matter picks the layout and the permalink. |

## Common edits

**Add or rename a nav link.** Edit `_data/nav.yml`. Both the header and the
footer read from it, and every page picks the change up.

**Add a documentation page.** Drop a Markdown file in `docs/` with front matter:

```yaml
---
layout: doc
title: Short title
permalink: /docs/SHORT_TITLE/
---
```

The on-page table of contents builds itself from the `h2` and `h3` headings, so
there is nothing to register. Link it from the Docs grid in `index.html` if it
should be discoverable from the portal.

**Add a page.** Create an HTML file with `layout: page` front matter and a
`title`. Optional keys: `description`, `nav_current` (marks a header link as the
current page), `section_nav` (the on-page anchor strip), and `results_base` if
the page reads JSON from `results/`.

**Change a colour.** Edit `assets/tokens.css`. Every value is OKLCH on one
violet axis at hue 305 to 306, taken from the mark's primary fill. Both themes
are defined there and nowhere else. Never write a colour literal into
`site.css`.

**Ship a CSS or JS change.** Bump `asset_version` in `_config.yml` so returning
visitors are not served a cached stylesheet against new markup.

## Rules worth keeping

Hover and focus states must not change an element's box. A previous version
added left padding on card hover, which reflowed the card text under the
pointer.

Use explicit grid column counts when a section holds a known number of peers.
`auto-fit` leaves an empty track at the wide end, which is what made the
download and docs grids look ragged.

There is one `:root`, in `tokens.css`. Do not start a second palette at the
bottom of `site.css` and override the first, which is how the previous
stylesheet reached 2000 lines with most of its first half unreachable.

Motion is limited to the four cases documented at the top of the Motion section
in `site.css`. Scroll-triggered reveals on ordinary sections are deliberately
absent.

Do not invent numbers. The container diagram is labelled schematic because its
proportions are chosen for legibility, and headings state only what the copy
underneath can support.

## Working on it locally

```sh
jekyll build -d /tmp/basefwx-site
python3 -m http.server 8000 -d /tmp/basefwx-site
```

To check the project-page mount that Pages actually serves:

```sh
jekyll build --baseurl /basefwx -d /tmp/basefwx-site
```

Before pushing, confirm there is no horizontal scroll at 320, 375, 414, and 768
pixels, that the theme toggle round-trips and survives a reload, and that both
themes still pass contrast.
