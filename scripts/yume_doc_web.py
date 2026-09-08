#!/usr/bin/env python3
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Publish documentation and its catalog from the same parsed sources."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yume_doc_inline as inline
import yume_doc_markdown
from yume_doc_spec import DEFAULT_LANGUAGE, Doc, DocError, REPO_ROOT, localized, relative

LINK_RE = re.compile(r"(?P<open>!?\[[^\]]*\]\()(?P<target>[^)\s]+)(?P<end>\))")
# Match a whole link before inspecting its label: [`file`](path) is a link,
# while `[example](path)` enclosed in a code span is literal example text.
INLINE_RE = re.compile(r"(?P<code>(?P<ticks>`+)(?!`).*?(?<!`)(?P=ticks)(?!`))|" + LINK_RE.pattern)
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")


def settings() -> dict:
    path = REPO_ROOT / "docs/src/site.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    keys = {"schema", "catalog_groups", "mirror_tracked", "cli"}
    if not isinstance(data, dict) or set(data) != keys or data["schema"] != 1:
        raise DocError(f"{relative(path)}: expected site schema 1 with {sorted(keys)}")
    if any(type(data[key]) is not bool for key in ("mirror_tracked", "cli")):
        raise DocError(f"{relative(path)}: mirror_tracked and cli must be booleans")
    groups = data["catalog_groups"]
    if not isinstance(groups, dict) or set(groups) not in ({"group"}, {"landing_group", "home_group"}):
        raise DocError(f"{relative(path)}: invalid catalog_groups")
    for values in groups.values():
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
            raise DocError(f"{relative(path)}: groups must be nonempty string lists")
    return data


def repository_url() -> str:
    config = (REPO_ROOT / "website/_config.yml").read_text(encoding="utf-8")
    match = re.search(r"^repo_url: (https://github.com/[\w.-]+/[\w.-]+)\s*$", config, re.M)
    if not match:
        raise DocError("website/_config.yml: expected an unquoted GitHub repo_url")
    return match.group(1)


def output(doc: Doc) -> str:
    declared = doc.site.get("web-path", doc.markdown if doc.markdown.startswith("docs/") else "docs/" + doc.markdown)
    return localized(declared, doc.language, "markdown")


def route(doc: Doc) -> str:
    return "/" + output(doc).removesuffix(".md") + "/"


def site_url(route: str) -> str:
    return "{{ '" + route + "' | relative_url }}"


def transform_markdown(text: str, doc: Doc, docs: list[Doc]) -> str:
    """Resolve links from the authored output location, outside code examples.

    A translated page links to a translated target when present and otherwise
    to its source-language page. Repository files keep their original paths.
    """
    repo = repository_url()
    routes = {d.markdown: route(d) for d in docs if d.web and d.language == DEFAULT_LANGUAGE}
    routes.update({d.markdown: route(d) for d in docs if d.web and d.language == doc.language})
    origin = REPO_ROOT / doc.markdown

    def replace(match: re.Match[str]) -> str:
        target = match.group("target")
        path_text, separator, anchor = target.partition("#")
        fragment = "#" + anchor if separator else ""
        if not path_text or path_text.startswith("/") or urlsplit(path_text).scheme:
            return match.group(0)
        candidate = (origin.parent / path_text).resolve()
        if not candidate.is_relative_to(REPO_ROOT):
            raise DocError(f"{relative(doc.path)}: link escapes repository: {target}")
        key = relative(candidate)
        if key in routes:
            replacement = site_url(routes[key]) + fragment
        else:
            if not candidate.exists():
                raise DocError(f"{relative(doc.path)}: linked path does not exist: {target}")
            # A diagram image is replaced by embed() before this transform.
            # Other repository assets retain a resolvable source URL.
            replacement = repo + ("/tree/main/" if candidate.is_dir() else "/blob/main/") + key + fragment
        return match.group("open") + replacement + match.group("end")

    lines: list[str] = []
    fence: tuple[str, int] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE_RE.match(line)
        if match:
            marker, info = match.groups()
            if fence is None:
                if not re.fullmatch(r"[\w+.-]+", info.strip()):
                    raise DocError(f"{relative(doc.path)}:{number}: code fence needs a language")
                fence = (marker[0], len(marker))
                lines.append("{% raw %}")
                lines.append(line)
                continue
            if marker[0] == fence[0] and len(marker) >= fence[1] and not info.strip():
                fence = None
                lines.extend((line, "{% endraw %}"))
                continue
        if fence:
            lines.append(line)
        else:
            lines.append(INLINE_RE.sub(lambda match: match.group(0) if match.group("code") else replace(match), line))
    if fence:
        raise DocError(f"{relative(doc.path)}: unclosed code fence")
    return "\n".join(lines).rstrip() + "\n"


def render(doc: Doc, docs: list[Doc]) -> str:
    title = inline.plain(doc.site.get("web-title", doc.title))
    body = yume_doc_markdown.render(doc, "web").split("\n", 2)[2]
    body = "# " + inline.to_markdown(doc.site.get("web-title", doc.title)) + "\n" + body
    if doc.diagrams():
        import yume_diagrams
        from yume_diagram_spec import load_all
        specs = {spec.name: spec for spec in load_all(doc.language)}
        body = yume_diagrams.embed(REPO_ROOT / doc.markdown, body, specs, doc.language)
    body = transform_markdown(body, doc, docs)
    fields = {
        "layout": "doc", "title": title, "description": inline.plain(doc.summary),
        "permalink": route(doc), "generated_from": doc.markdown,
        "doc_source": relative(doc.path), "lang": doc.language.replace("_", "-"),
        "doc_locale": doc.language,
    }
    front = "\n".join(f"{key}: {json.dumps(value, ensure_ascii=False)}" for key, value in fields.items())
    return "---\n" + front + "\n---\n\n" + body


def catalog(docs: list[Doc], language: str, config: dict) -> list[dict]:
    entries: list[dict] = []
    groups = config["catalog_groups"]
    group_key = "landing_group" if "landing_group" in groups else "group"
    for doc in docs:
        if doc.language != language or "catalog-order" not in doc.site:
            continue
        entry = {
            "title": inline.plain(doc.site.get("catalog-title", doc.site.get("web-title", doc.title))),
            "summary": inline.plain(doc.summary),
            "url": route(doc) if doc.web else repository_url() + "/blob/main/" + dict(doc.outputs())["markdown"],
            "source": dict(doc.outputs())["markdown"],
            group_key: doc.site["catalog-group"],
            "order": int(doc.site["catalog-order"]),
        }
        if "catalog-home" in doc.site:
            entry["home_group"] = doc.site["catalog-home"]
        for key in (group_key, "home_group"):
            if key in entry and entry[key] not in groups.get(key, []):
                raise DocError(f"{relative(doc.path)}: unknown {key} {entry[key]!r}")
        entries.append(entry)
    for key in ("order", "url"):
        values = [entry[key] for entry in entries]
        if len(values) != len(set(values)):
            raise DocError(f"{language}: duplicate catalog {key}")
    return sorted(entries, key=lambda entry: entry["order"])


def rendered(docs: list[Doc], language: str, config: dict) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for doc in docs:
        if doc.language != language or not doc.web:
            continue
        target = "website/" + output(doc)
        if target in outputs:
            raise DocError(f"{relative(doc.path)}: duplicate website output {target}")
        outputs[target] = render(doc, docs)
    suffix = "" if language == DEFAULT_LANGUAGE else "_" + language
    outputs[f"website/_data/docs{suffix}.json"] = json.dumps(catalog(docs, language, config), indent=2, ensure_ascii=False) + "\n"
    if language == DEFAULT_LANGUAGE:
        outputs["website/_data/doc_groups.json"] = json.dumps(config["catalog_groups"], indent=2, ensure_ascii=False) + "\n"
    return outputs
