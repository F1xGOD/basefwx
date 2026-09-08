# Documentation sources

Edit a document under `en_US/`, then run these commands from the repository
root. They work in both YUME and the separate BaseFWX checkout:

```sh
python3 scripts/yume_docs.py sync --all-languages
python3 scripts/yume_docs.py check --all-languages
python3 scripts/check_website_catalog.py
```

`sync` renders the Markdown, roff manuals, website pages, website catalog,
and enabled diagram SVGs. In YUME it also renders the CLI help and Bash completion
headers. `check` compares all tracked outputs without writing. YUME's website
mirror is ignored; BaseFWX's is tracked. `check_website_catalog.py` checks the
complete website mirror after it has been generated, including titles and
summaries. CI checks tracked outputs **before** generating ignored site files.

A generated Markdown or manual file opens with its editable source path. A
website page records `doc_source` in its front matter. Keep generated outputs
in the same change as their sources; readers and builds need no Python to use
the checked-in Markdown, manuals, SVGs, or help headers.

When removing or renaming a document, diagram or locale, remove its retired
outputs in the same change. Use `list` before removing the source, and review
`docs/diagrams/` and `website/_data/` for obsolete SVGs and locale catalogs.
The unified sync does not silently delete retired files.

## Ownership

| Edit | Owner |
| --- | --- |
| A document's text, heading, summary and publication settings | One `en_US/pages/<aspect>.doc` or `en_US/man/<command>.doc` |
| A fact repeated by several documents | One `en_US/parts/shared/<aspect>.part`, included by those documents |
| A diagram's topology, labels, accessible title and caption | One `docs/diagrams/<name>.json` |
| Where a diagram appears | `@diagram <name>` in the document; no second target list |
| Website page title | `title:`; optional `web-title:` in the same document for a different web heading |
| Website card title | The web title; optional `catalog-title:` in the same document for a shorter navigation label |
| Website card summary and page description | `summary:` in the document |
| Catalog grouping and order | `catalog-group:`, optional `catalog-home:`, and `catalog-order:` in the document |
| Available catalog groups and repository-specific output policy | `docs/src/site.json` |
| Diagram colors and fonts | `website/assets/tokens.css`; standalone SVG values are derived from it |
| Site navigation, landing-page copy and layout | `website/_data/nav.yml`, HTML pages and `_includes/` |
| YUME option help and completion metadata | `@opt` and `@cli` entries in its manual sources |

BaseFWX currently publishes generated ASCII figures. Its own animated SVG
style is deferred; keep diagram `targets.web` false until that work is
reviewed. The common rendering modules can be extended without changing
source ownership, document placement, or translations.

The `.doc` source is the home of an aspect. Keep its sections together unless
a fragment has several consumers. Do not split a document merely to meet a
line-count target: that multiplies the files a translator or agent must edit.
`list` prints each document's source, included fragments, and outputs.

The generators synchronize presentation. They cannot establish that a security
claim agrees with executable code. Verify changed claims against source and
focused tests. Preserve YUME's transport-v2 versus YTP/1 boundaries and
independent versions, and BaseFWX's runtime and format compatibility limits.
An intentional web title may clarify those boundaries; do not replace it with
a filename-derived title.

The format guide, diagram guide, agent instructions, website design guides,
and private notes are edited directly. Product documents and changelogs are
`.doc` sources. Site landing-page prose is still authored HTML; review its
claims with a behavior change. BaseFWX's native help is runtime code, while
its manual and web reference share a source. The tooling does not claim to
derive either project's parser behavior from documentation.

## Source format

```text
#!yume-doc 1
name: security
kind: page
title: Security model
summary: Authentication, recovery and publication boundaries.
markdown: docs/SECURITY.md
web: yes
catalog-group: Reference
catalog-order: 30
---
## Authentication

Text with **bold**, *italic*, `code`, [links](OTHER.md), and
man:basefwx(1) references.
```

`name` matches the filename and uses lowercase letters, digits, and underscores.
Header keys and directives are closed: an unknown spelling fails generation.

| Header | Meaning |
| --- | --- |
| `kind` | `page` or `man` |
| `title`, `summary` | Required text; a manual's NAME section also comes from these |
| `markdown` | Public repository-relative `.md` output path |
| `man` | `docs/man/<name>.<section>`, or the separate `docs/development/ytp1/man/` design references, for `kind: man` |
| `web` | `yes` publishes a page; requires a Markdown output |
| `web-path` | Optional path under `website/docs/`, written as `docs/<name>.md`; preserves routes such as BaseFWX's `SECURITY_MODEL` |
| `web-title` | Optional web H1 and browser title, co-located with the document title |
| `catalog-title` | Optional card title; defaults to the web title |
| `catalog-group`, `catalog-home`, `catalog-order` | Index placement; omit them for a published page without a card |
| `man-section` | `1`, `3`, `5`, `7`, or `8` |
| `man-date` | `YYYY-MM-DD` or `Month YYYY` |
| `man-source`, `man-manual` | Product/version and manual collection strings |

A manual requires all `man-*` fields and exactly one leading `@synopsis`.
Its level-two headings are uppercase. It may also declare `markdown` and
`web: yes`; BaseFWX's native CLI and library references use this form.

## Body blocks

Headings use `##`, `###`, and `####`. Paragraphs, lists and block quotes use
Markdown punctuation. Directives start at column zero. Containers close with
`@end`; `@diagram` and `@include` are single-line directives.

| Directive | Markdown / web | Manual |
| --- | --- | --- |
| `@code bash` (or another supported language) | Tagged fenced example | Literal region with roff escapes protected |
| `@table` | Pipe table | Aligned text columns |
| `@options` with `@opt **--flag** *argument*` | Option list | Hanging `.TP` entries |
| `@synopsis` | SYNOPSIS heading and invocation forms | SYNOPSIS with one invocation per paragraph |
| `@synopsis literal` | Fenced synopsis | Literal include/build or command examples |
| `@diagram <name>` | SVG and expandable ASCII | ASCII from the same topology |
| `@include shared/<aspect>.part` | Shared parsed blocks | The same blocks |
| `@only markdown`, `@only web`, `@only man` | Content addressed to that layer | Content addressed to that layer |

`@only` closes with `@end` and may name several layers. It does not nest.
Web pages are rendered from the parsed source with the `web` filter, then
links are rewritten by the common website renderer. Markdown-only syntax is
never used as roff input. Code examples keep their bytes, including links and
Liquid expressions that Jekyll must not evaluate.

Use `\|` for a literal pipe in a table cell, even in backticks. Escape a
literal asterisk or backtick when it could become a font marker. Manuals set
code spans in bold and links as their label. Do not rely on a hidden link
target for information a terminal reader needs.

An included `.part` contains body blocks and no header. Includes are resolved
under the locale's `parts/`; traversal, symlink escapes, cycles, and chains
beyond four open files fail. Errors identify the offending file and line.

An indented `@code` may sit within a numbered step. Keep the directive,
example and `@end` at that step's text indent. A hand-drawn diagram may remain
in `@code text` when its geometry is not an ordered flow, such as a package
dependency branch or a field-layout table. Do not turn those into a chain and
change what their arrows mean.

## YUME command-line help

The manual's `@opt` signature owns option spellings. Directly following `@cli`
lines supply short help and completion details:

```text
@opt **--relay-mode** *mode*
@cli values: untrusted trusted
@cli spell: --relay-mode <mode>
@cli help: untrusted or trusted

Whether this client accepts relayed streams from peers it has not pinned.
```

`flags`, `file` (`yes`/`no`), and `values` describe completion. `spell` starts
a printed entry; repeated `help` lines supply its text. `indent`, `column`,
and `continuation` may adjust columns. Printed flags must belong to the
option. The closed `{{name}}` interpolation table supplies runtime constants.
Use `complete: no` for a documented, rejected option that should not be
suggested by the shell; it cannot also declare file or value completions.

`en_US/cli/*.cli` owns help grouping and free text, referencing options by
flag. Every printed option must be referenced exactly once. `sync` writes
`src/client/cli/display/help_text.hpp` and `src/server/cli/help_text.hpp`.
Use `python3 scripts/yume_cli.py render yume --layer help` to preview.

## Languages

`en_US` is the only active locale. The directory structure supports later
translations; language selection in the site chrome and native CLI is not
implemented. Do not advertise another language until its content and user
navigation have been reviewed.

A translated source lives at the same relative path under a sibling locale.
Translate `title`, `summary`, optional title overrides, and body text. Keep its
name, kind, declared output paths and web publication boundary unchanged.

| Declared output | `en_US` | Example `de_DE` output |
| --- | --- | --- |
| `docs/SECURITY.md` | `docs/SECURITY.md` | `docs/de_DE/SECURITY.md` |
| `docs/protocol/YTP_1.md` | `docs/protocol/YTP_1.md` | `docs/de_DE/protocol/YTP_1.md` |
| `README.md` | `README.md` | `docs/de_DE/root/README.md` |
| `docs/man/yume.1` | `docs/man/yume.1` | `docs/man/de_DE/yume.1` |

The root namespace prevents `README.md` and `docs/README.md` translations
from claiming the same path. Website paths receive the locale under `/docs/`.
Website links prefer a translated target when one exists and otherwise use
the source-language page. Diagram image paths are relative to the actual
localized Markdown location.

Only diagram strings are translated, in one `docs/src/<locale>/diagrams.json`
per locale. The topology remains in `docs/diagrams/*.json`. Missing fragments
and diagram strings use the `en_US` source and are reported by:

```sh
python3 scripts/yume_docs.py translations --language de_DE
python3 scripts/yume_diagrams.py translations --language de_DE
```

These commands inventory missing content; they do not prove that an existing
translation is semantically current. `check --all-languages` verifies generated
bytes and output ownership. A translation review remains necessary after its
source changes. No second locale is committed.

## Validation and shared tooling

```sh
python3 scripts/test_yume_docs.py
python3 scripts/test_yume_doc_pipeline.py
python3 scripts/yume_docs.py check --all-languages
python3 scripts/check_website_catalog.py
```

YUME also runs `scripts/test_yume_cli.py` and `scripts/test_yume_diagrams.py`.
BaseFWX runs `scripts/test_doc_diagrams.py`. Render manuals through `groff`
or `man` when changing formatting, and build Jekyll when changing web output.
Compare the displayed words and code examples, not only raw roff bytes.

YUME and BaseFWX carry identical common tooling so either standalone checkout
works. In the parent workspace, `python3 scripts/check_doc_tooling_parity.py`
checks the shared modules and tests. It reports a skip if the separate BaseFWX
checkout is absent; it does not claim cross-repository parity in that case.
Update both copies together. Product-specific CLI generation and site policy
remain in their owning repository.
