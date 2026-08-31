# BaseFWX website design

This file locks the visual system for the BaseFWX portal and documentation.

## Genre

Technical and brutal. BaseFWX reads like a bare-metal workbench: graphite,
steel-like rules, square controls, dense evidence, and a precise violet signal.
Dark mode carries the identity. Light mode remains a supported reading option.

## Macrostructure family

- Homepage: Catalogue. Downloads, evidence, and docs read as inventory.
- Utility pages: Workbench-like tables and manifests.
- Documentation: Long Document with a persistent contents rail.

## Theme

- Paper: `oklch(14.5% 0.014 305)`
- Sunk paper: `oklch(10.8% 0.012 305)`
- Surface: `oklch(18.8% 0.016 305)`
- Ink: `oklch(95.5% 0.01 305)`
- Muted ink: `oklch(63.5% 0.016 305)`
- Rule: `oklch(31% 0.02 305)`
- Violet accent: `oklch(74% 0.155 306)`

The complete dark and light ramps live in `assets/tokens.css`. Do not add colour
literals to `assets/site.css`.

## Typography

- Display: Archivo, weight 700, normal style
- Body: IBM Plex Sans, weight 400 or 600
- Mono: IBM Plex Mono, weight 400 or 600
- Display tracking: `-0.03em`
- Display size: `clamp(2.75rem, 6.2vw, 4.75rem)`

## Spacing and shape

Use the named 4-point scale in `assets/tokens.css`. Corners stay between 0 and
4 px. Surfaces use rules and lightness, not blur or glow.

## Motion

- Header: static brutal slab
- Homepage: selected racks enter once from the inline axis
- Container diagram: fields scan in wire order
- Documentation: the reading progress bar is functional motion
- Reduced motion: content renders immediately, with no spatial travel

Animate only `transform` and `opacity`. Scroll reveals use
`IntersectionObserver`. If JavaScript fails, all content stays visible.

## CTA voice

Buttons use short commands: “Download CLI”, “Read docs”, “View source”. Controls
are square, uppercase, and compact. Violet marks the active or primary action.

## Page allowances

The homepage may use the CSS container schematic. Documentation uses typography
only. All pages share the slab header, dense colophon, focus treatment, fonts,
and colour tokens.

## Exports

`assets/tokens.css` is the canonical export. The equivalent portable core is:

```css
:root {
  --color-paper: oklch(14.5% 0.014 305);
  --color-ink: oklch(95.5% 0.01 305);
  --color-rule: oklch(31% 0.02 305);
  --color-accent: oklch(74% 0.155 306);
  --color-focus: oklch(84% 0.115 306);
  --font-display: "Archivo", ui-sans-serif, sans-serif;
  --font-body: "IBM Plex Sans", ui-sans-serif, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, monospace;
}
```
