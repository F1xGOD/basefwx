# BaseFWX diagrams

Each JSON specification owns an ordered flow's nodes, edges, labels, accessible
title and caption. A `.doc` places it with `@diagram <name>`. The common ASCII
renderer draws connected diagonal hops within a 68-column budget, using a
straight descent when necessary and rejecting labels that still overflow.
BaseFWX publishes ASCII only while its own SVG design is deferred. Keep
`targets.web` false; the common SVG module is available for future style
work, with colors and fonts derived from this site's tokens.

```sh
python3 scripts/yume_docs.py sync --all-languages
python3 scripts/yume_docs.py check --all-languages
python3 scripts/test_doc_diagrams.py
python3 scripts/yume_diagrams.py render live_streams
```

When SVG publication is enabled, generated `docs/diagrams/*.svg` belongs
in Git and the identical Jekyll includes are ignored. No BaseFWX diagram SVG
is currently published. The native manuals also
produce Markdown and web pages. Package branches and container-field layouts
remain literal text: an ordered chain must not replace their different
semantics. Diagram `targets` contains only `web`; documents own placement.

`process` and `file` are neutral glyphs. YUME-specific client/server/relay/tun
kinds denote YUME software and must not label BaseFWX processing steps.
Diagrams are schematic, not byte layouts or additional cryptographic claims.
The topology does not change with a translation; only strings are translated
in `docs/src/<locale>/diagrams.json`. `en_US` is the only active locale.

See [the source guide](../src/README.md) for ownership and validation.
