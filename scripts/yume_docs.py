#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render the YUME documentation from docs/src into every layer it reaches.

One `.doc` source per aspect drives every published form of that aspect:

  * the Markdown a reader opens in a clone or on GitHub,
  * the roff manual a terminal renders,
  * website pages and their catalog, rendered with the web layer filter,
  * enabled diagram SVGs and the repository's generated CLI help headers.

Editing the source and running `sync` moves all of them together. `check`
proves they are current without writing, which is what CI runs.

The tree is partitioned by language from the start, so adding one is a new
directory rather than a change to any renderer:

    docs/src/en_US/pages/security_modes.doc   ->  docs/SECURITY_MODES.md
    docs/src/en_US/man/yume_gui.doc           ->  docs/man/yume-gui.1

Usage:
    scripts/yume_docs.py list
    scripts/yume_docs.py render security_modes [--layer man]
    scripts/yume_docs.py sync
    scripts/yume_docs.py check
    scripts/yume_docs.py languages
"""

from __future__ import annotations

import argparse
import os
import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_doc_man
import yume_doc_markdown
from yume_doc_spec import (
    DEFAULT_LANGUAGE,
    SOURCE_ROOT,
    check_language,
    REPO_ROOT,
    Doc,
    DocError,
    languages,
    load,
    load_all,
    relative,
)

RENDERERS = {
    "markdown": yume_doc_markdown.render,
    "man": yume_doc_man.render,
}


def rendered(doc: Doc) -> list[tuple[str, str]]:
    """Every (repository-relative path, content) this document produces."""
    return [(target, RENDERERS[layer](doc, layer)) for layer, target in doc.outputs()]


def command_list(args: argparse.Namespace) -> int:
    docs = load_all(args.language)
    if not docs:
        print(f"docs: no sources under docs/src/{args.language}")
        return 0
    for doc in docs:
        figures = doc.diagrams()
        detail = f"{doc.kind}, {len(doc.blocks)} blocks"
        if figures:
            detail += f", figures: {', '.join(figures)}"
        print(f"{doc.name}: {detail}")
        print(f"    source  {relative(doc.path)}")
        for fragment in doc.includes:
            print(f"    part    {fragment}")
        for _, target in doc.outputs():
            print(f"    writes  {target}")
        if doc.web:
            print("    writes  website page and metadata from the same parsed source")
    return 0


def command_render(args: argparse.Namespace) -> int:
    doc = load(args.name, args.language)
    layer = args.layer
    if layer == "man" and not doc.man:
        print(f"docs: {doc.name} publishes no manual", file=sys.stderr)
        return 1
    if layer == "markdown" and not doc.markdown:
        print(f"docs: {doc.name} publishes no Markdown", file=sys.stderr)
        return 1
    sys.stdout.write(RENDERERS[layer](doc, layer))
    return 0


def command_translations(args: argparse.Namespace) -> int:
    """Report which documents one language has, and which it still needs.

    A translation is a document with the same name under another language.
    Reporting the gap is what keeps a partly finished language from looking
    finished, and what stops a second language from becoming an unreviewable
    pile of files nobody can tell apart.
    """
    language = args.language
    source = {doc.name: doc for doc in load_all(DEFAULT_LANGUAGE)}
    if language == DEFAULT_LANGUAGE:
        print(f"docs: {DEFAULT_LANGUAGE} is the source language, {len(source)} documents")
        return 0

    check_language(language)
    translated = {doc.name: doc for doc in load_all(language)} if (SOURCE_ROOT / language).is_dir() else {}

    missing = sorted(set(source) - set(translated))
    extra = sorted(set(translated) - set(source))
    mismatched = [
        name
        for name in sorted(set(source) & set(translated))
        if source[name].declared() != translated[name].declared()
    ]

    print(f"{language}: {len(translated)} of {len(source)} documents")
    for name in missing:
        print(f"    missing     {name}")
    for name in extra:
        print(f"    unmatched   {name} has no {DEFAULT_LANGUAGE} counterpart")
    for doc in translated.values():
        for fragment in sorted(set(doc.includes)):
            if f"/{DEFAULT_LANGUAGE}/" in fragment:
                print(f"    source text {doc.name}: {fragment}")
    for name in mismatched:
        print(f"    mismatched  {name} declares a different output than its source")

    return 1 if extra or mismatched else 0


def command_languages(_args: argparse.Namespace) -> int:
    found = languages()
    if not found:
        print("docs: no language directories under docs/src")
        return 0
    for language in found:
        docs = load_all(language)
        outputs = sum(len(doc.outputs()) for doc in docs)
        marker = " (default)" if language == DEFAULT_LANGUAGE else ""
        print(f"{language}{marker}: {len(docs)} sources, {outputs} generated files")
    return 0


def all_documents() -> list[Doc]:
    if DEFAULT_LANGUAGE not in languages():
        raise DocError(f"docs/src/{DEFAULT_LANGUAGE}: source language directory is missing")
    docs = [doc for language in languages() for doc in load_all(language)]
    originals = {doc.name: doc for doc in docs if doc.language == DEFAULT_LANGUAGE}
    claimed: set[str] = set()
    for doc in docs:
        if doc.language != DEFAULT_LANGUAGE:
            source = originals.get(doc.name)
            if (source is None or source.declared() != doc.declared() or source.web != doc.web
                    or source.site.get("web-path") != doc.site.get("web-path")):
                raise DocError(f"{relative(doc.path)}: translation has no matching source outputs")
        for _, target in doc.outputs():
            if target in claimed:
                raise DocError(f"{relative(doc.path)}: duplicate output {target}")
            claimed.add(target)
    return docs


def artifacts(docs: list[Doc], selected: list[str], check: bool, website_only: bool = False) -> dict[str, str]:
    import yume_doc_web

    config = yume_doc_web.settings()
    outputs: dict[str, str] = {}

    def add(target: str, content: str) -> None:
        if target in outputs:
            raise DocError(f"duplicate generated output {target}")
        path = REPO_ROOT / target
        if not path.resolve().is_relative_to(REPO_ROOT.resolve()):
            raise DocError(f"output escapes repository through a symlink: {target}")
        outputs[target] = content

    for language in selected:
        if not website_only:
            for doc in docs:
                if doc.language == language:
                    for target, content in rendered(doc):
                        add(target, content)
        for target, content in yume_doc_web.rendered(docs, language, config).items():
            if not check or website_only or config["mirror_tracked"] or not target.startswith("website/docs/"):
                add(target, content)
        if (REPO_ROOT / "docs/diagrams").is_dir():
            import yume_diagram_spec
            import yume_diagrams
            for spec in yume_diagram_spec.load_all(language):
                if not spec.web:
                    continue
                import yume_diagram_svg
                for layout in yume_diagrams.LAYOUTS:
                    content = yume_diagram_svg.render(spec, layout)
                    name = yume_diagrams.include_name(spec.name, layout)
                    if not website_only:
                        add(relative(yume_diagrams.svg_dir(language) / name), content)
                    if not check or website_only:
                        add(relative(yume_diagrams.include_dir(language) / name), content)
    if config["cli"] and not website_only and DEFAULT_LANGUAGE in selected:
        import yume_cli
        for layout in yume_cli.load_layouts():
            add(layout.output, yume_cli.build(layout))
    return outputs


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        temporary.chmod(path.stat().st_mode & 0o777 if path.exists() else 0o644)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def command_sync(args: argparse.Namespace) -> int:
    check_language(args.language)
    selected = languages() if getattr(args, "all_languages", False) else [args.language]
    if args.language not in languages() and not getattr(args, "all_languages", False):
        raise DocError(f"docs/src/{args.language}: no such language directory")
    docs = all_documents()
    website_only = args.command == "website"
    # Parse and render the complete candidate before writing any artifact.
    # A late invalid source must not leave an apparently synchronized prefix.
    outputs = artifacts(docs, selected, args.check, website_only)
    orphans = _orphans(docs)
    if orphans:
        raise DocError("; ".join(orphans))
    changed = [target for target, content in outputs.items()
               if not (REPO_ROOT / target).is_file()
               or (REPO_ROOT / target).read_text(encoding="utf-8") != content]
    if args.check and changed:
        for target in changed:
            print(f"docs: {target} is missing or stale", file=sys.stderr)
        print("docs: run python3 scripts/yume_docs.py sync --all-languages", file=sys.stderr)
        return 1
    for target in changed:
        atomic_write(REPO_ROOT / target, outputs[target])
    verb = "checked" if args.check else "synced"
    print(f"docs: {len(outputs)} artifacts {verb}; {len(changed)} changed ({', '.join(selected)})")
    return 0


def _orphans(docs: list[Doc] | None = None) -> list[str]:
    docs = all_documents() if docs is None else docs
    claimed = {target for doc in docs for _, target in doc.outputs()}
    # Never rglob the repository root: it includes ignored checkouts, build
    # directories and private evidence. Search only public document locations.
    candidates = set(REPO_ROOT.glob("*.md"))
    for directory, children, names in os.walk(REPO_ROOT / "docs", followlinks=False):
        children[:] = [name for name in children if name not in ("src", "diagrams") and not name.startswith(".")]
        candidates.update(Path(directory) / name for name in names if Path(name).suffix in (".md", ".1", ".3", ".5", ".7", ".8"))
    for target in claimed:
        candidates.update((REPO_ROOT / target).parent.glob("*.md"))
    found = []
    for path in sorted(candidates):
        if relative(path) in claimed or not path.is_file():
            continue
        with path.open(encoding="utf-8") as stream:
            head = stream.readline()
        if "yume_docs.py" in head and "Generated from" in head:
            found.append(f"{relative(path)} is generated but no source claims it; delete it or restore its source")
    import yume_doc_web
    web_claimed = {"website/" + yume_doc_web.output(doc) for doc in docs if doc.web}
    for path in (REPO_ROOT / "website/docs").rglob("*.md"):
        if relative(path) in web_claimed:
            continue
        if not path.resolve().is_relative_to(REPO_ROOT.resolve()):
            raise DocError(f"website output escapes repository: {relative(path)}")
        head = path.read_text(encoding="utf-8").split("---", 2)
        if len(head) > 2 and any(key in head[1] for key in ("generated_from:", "canonical_source:")):
            found.append(f"{relative(path)} is generated but no source claims it; delete it or restore its source")
    return found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    # `--language` is accepted before or after the subcommand, because both
    # readings are natural and refusing one is a papercut on every call.
    def language_flag(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--language",
            default=argparse.SUPPRESS,
            help=f"language directory under docs/src (default {DEFAULT_LANGUAGE})",
        )

    language_flag(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    _p = sub.add_parser("list", help="list the sources and what each one writes")
    language_flag(_p)
    _p.set_defaults(
        handler=command_list
    )

    render = sub.add_parser("render", help="print one rendering")
    render.add_argument("name")
    render.add_argument(
        "--layer", choices=sorted(RENDERERS), default="markdown", help="which layer to print"
    )
    language_flag(render)
    render.set_defaults(handler=command_render)

    sync = sub.add_parser("sync", help="write every generated file")
    language_flag(sync)
    sync.add_argument("--all-languages", action="store_true", help="every language, not one")
    sync.set_defaults(handler=command_sync, check=False)

    check = sub.add_parser("check", help="verify every generated file without writing")
    language_flag(check)
    check.add_argument("--all-languages", action="store_true", help="every language, not one")
    check.set_defaults(handler=command_sync, check=True)

    _p = sub.add_parser("languages", help="list the language directories")
    language_flag(_p)
    _p.set_defaults(
        handler=command_languages
    )

    translations = sub.add_parser(
        "translations", help="report what one language has translated and what it needs"
    )
    language_flag(translations)
    translations.set_defaults(handler=command_translations)

    website = sub.add_parser("website", help="generate or check the complete website mirror")
    language_flag(website)
    website.add_argument("--check", action="store_true")
    website.add_argument("--all-languages", action="store_true")
    website.set_defaults(handler=command_sync)

    args = parser.parse_args(argv[1:])
    if getattr(args, "language", None) is None:
        args.language = DEFAULT_LANGUAGE
    try:
        return args.handler(args)
    except (DocError, OSError, UnicodeError, ValueError) as exc:
        print(f"docs: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
