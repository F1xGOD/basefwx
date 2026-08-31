#!/usr/bin/env python3
"""Generate Jekyll documentation pages from canonical repository Markdown."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WEBSITE_DOCS = REPO_ROOT / "website" / "docs"
GITHUB_BLOB = "https://github.com/F1xGOD/basefwx/blob/main/"
GITHUB_TREE = "https://github.com/F1xGOD/basefwx/tree/main/"
SITE_DOC_PREFIX = "https://basefwx.fixcraft.jp/docs/"
LINK_RE = re.compile(
    r"(?P<label>!?\[[^\]]*\]\()"
    r"(?P<target>[^)\s]+)"
    r"(?P<title>\s+(?:\"[^\"]*\"|'[^']*'))?"
    r"(?P<close>\))"
)
FENCE_RE = re.compile(r"^(?P<indent>\s*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")


@dataclass(frozen=True)
class Page:
    source: str
    output: str
    title: str
    permalink: str


PAGES = (
    Page("README.md", "README.md", "Start with BaseFWX", "/docs/README/"),
    Page("docs/EXPLAINED.md", "EXPLAINED.md", "BaseFWX explained", "/docs/EXPLAINED/"),
    Page("docs/CLI.md", "CLI.md", "CLI and API reference", "/docs/CLI/"),
    Page("SECURITY.md", "SECURITY_MODEL.md", "Security policy", "/docs/SECURITY_MODEL/"),
    Page("COMPATIBILITY.md", "COMPATIBILITY.md", "Compatibility", "/docs/COMPATIBILITY/"),
    Page("ABI.md", "ABI.md", "Native ABI policy", "/docs/ABI/"),
    Page("docs/TESTING.md", "TESTING.md", "Testing", "/docs/TESTING/"),
    Page("CONTRIBUTING.md", "CONTRIBUTING.md", "Contributing", "/docs/CONTRIBUTING/"),
    Page(
        "RELEASE-NOTES-3.7.0.md",
        "RELEASE-NOTES-3.7.0.md",
        "BaseFWX 3.7.0 release notes",
        "/docs/RELEASE-NOTES-3.7.0/",
    ),
    Page(
        "RELEASE-NOTES-3.6.4.md",
        "RELEASE-NOTES-3.6.4.md",
        "BaseFWX 3.6.4 release notes",
        "/docs/RELEASE-NOTES-3.6.4/",
    ),
)

ROUTES_BY_SOURCE = {page.source: page.permalink for page in PAGES}
ROUTES_BY_PUBLIC_URL = {
    f"{SITE_DOC_PREFIX}{page.permalink.removeprefix('/docs/')}": page.permalink
    for page in PAGES
}


def relative_url(route: str) -> str:
    return "{{ '" + route + "' | relative_url }}"


def split_anchor(target: str) -> tuple[str, str]:
    path, separator, fragment = target.partition("#")
    return path, f"#{fragment}" if separator else ""


def rewrite_target(target: str, source: Path) -> str:
    wrapped = target.startswith("<") and target.endswith(">")
    plain = target[1:-1] if wrapped else target

    if plain.startswith(SITE_DOC_PREFIX):
        path, anchor = split_anchor(plain)
        route = ROUTES_BY_PUBLIC_URL.get(path)
        return relative_url(route) + anchor if route else target
    if plain.startswith(("#", "/", "https://", "http://", "mailto:")):
        return target

    path_text, anchor = split_anchor(plain)
    candidate = (source.parent / path_text).resolve()
    try:
        repo_path = candidate.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(f"{source.relative_to(REPO_ROOT)}: link escapes repository: {target}") from exc

    source_key = repo_path.as_posix()
    route = ROUTES_BY_SOURCE.get(source_key)
    if route:
        return relative_url(route) + anchor
    if candidate == source.resolve():
        return anchor or relative_url(ROUTES_BY_SOURCE[source.relative_to(REPO_ROOT).as_posix()])
    if not candidate.exists():
        raise ValueError(
            f"{source.relative_to(REPO_ROOT)}: linked path does not exist: {target}"
        )

    base = GITHUB_TREE if candidate.is_dir() else GITHUB_BLOB
    rendered = base + repo_path.as_posix() + anchor
    return f"<{rendered}>" if wrapped else rendered


def rewrite_links(line: str, source: Path) -> str:
    def replace(match: re.Match[str]) -> str:
        return (
            match.group("label")
            + rewrite_target(match.group("target"), source)
            + (match.group("title") or "")
            + match.group("close")
        )

    return LINK_RE.sub(replace, line)


def transform_markdown(source: Path) -> str:
    raw = source.read_text(encoding="utf-8")
    if raw.startswith("---\n"):
        raise ValueError(f"{source.relative_to(REPO_ROOT)} must not contain Jekyll front matter")

    output: list[str] = []
    open_fence: tuple[str, int] | None = None
    for line_number, line in enumerate(raw.splitlines(keepends=True), start=1):
        fence_match = FENCE_RE.match(line.rstrip("\n"))
        if fence_match:
            marker = fence_match.group("fence")
            info = fence_match.group("info").strip()
            if open_fence is None:
                if not info:
                    raise ValueError(
                        f"{source.relative_to(REPO_ROOT)}:{line_number}: fenced block needs a language"
                    )
                if not re.fullmatch(r"[A-Za-z0-9_+.-]+", info):
                    raise ValueError(
                        f"{source.relative_to(REPO_ROOT)}:{line_number}: invalid fence language {info!r}"
                    )
                open_fence = (marker[0], len(marker))
            elif marker[0] == open_fence[0] and len(marker) >= open_fence[1] and not info:
                open_fence = None
            output.append(line)
            continue

        output.append(line if open_fence else rewrite_links(line, source))

    if open_fence is not None:
        raise ValueError(f"{source.relative_to(REPO_ROOT)}: unclosed fenced code block")
    return "".join(output).rstrip() + "\n"


def render(page: Page) -> str:
    source = REPO_ROOT / page.source
    if not source.is_file():
        raise ValueError(f"canonical source does not exist: {page.source}")
    body = transform_markdown(source)
    return (
        "---\n"
        "layout: doc\n"
        f'title: "{page.title}"\n'
        f"permalink: {page.permalink}\n"
        f"canonical_source: {page.source}\n"
        "---\n\n"
        "<!-- Generated by scripts/sync_website_docs.py. Edit the canonical source above. -->\n\n"
        + body
    )


def check_or_write(check: bool) -> int:
    drift: list[tuple[Path, str, str]] = []
    for page in PAGES:
        destination = WEBSITE_DOCS / page.output
        expected = render(page)
        actual = destination.read_text(encoding="utf-8") if destination.exists() else ""
        if actual == expected:
            continue
        if check:
            drift.append((destination, actual, expected))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(expected, encoding="utf-8")

    if drift:
        print("website documentation drift detected:", file=sys.stderr)
        for destination, actual, expected in drift:
            name = destination.relative_to(REPO_ROOT).as_posix()
            print(f"  {name}", file=sys.stderr)
            diff = difflib.unified_diff(
                actual.splitlines(),
                expected.splitlines(),
                fromfile=name,
                tofile=f"generated:{name}",
                n=2,
            )
            for line in list(diff)[:24]:
                print(line, file=sys.stderr)
        print("run: python3 scripts/sync_website_docs.py", file=sys.stderr)
        return 1

    action = "current" if check else "generated"
    print(f"website docs: {action} ({len(PAGES)} pages)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when checked-in Jekyll pages differ from canonical Markdown",
    )
    args = parser.parse_args()
    try:
        return check_or_write(args.check)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"website docs: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
