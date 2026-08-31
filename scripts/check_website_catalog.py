#!/usr/bin/env python3
"""Validate the website documentation catalog against the live tree."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "website" / "_data" / "docs.json"
REQUIRED_FIELDS = ("title", "summary", "url", "source", "group", "order")
GROUPS = {"Understand", "Use", "Reference", "Contribute"}


def fail(message: str) -> None:
    raise ValueError(message)


def load_catalog() -> list[dict[str, Any]]:
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {CATALOG_PATH.relative_to(REPO_ROOT)}: {exc}")
    if not isinstance(data, list):
        fail("documentation catalog must be a JSON array")
    return data


def local_page_path(url: str) -> Path | None:
    route = url.split("#", 1)[0].strip("/")
    if not route:
        path = REPO_ROOT / "website" / "index.html"
        return path if path.is_file() else None
    route_path = Path(route)
    candidates = (
        REPO_ROOT / "website" / f"{route_path}.md",
        REPO_ROOT / "website" / f"{route_path}.html",
        REPO_ROOT / "website" / route_path / "index.html",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def generated_source(page_path: Path) -> str | None:
    if page_path.suffix != ".md":
        return None
    for line in page_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("canonical_source:"):
            return line.partition(":")[2].strip()
        if line and line != "---" and not line.startswith(("layout:", "title:", "permalink:")):
            break
    return None


def validate() -> None:
    seen_urls: set[str] = set()
    seen_orders: set[int] = set()
    seen_groups: set[str] = set()
    previous_order = -1
    for index, entry in enumerate(load_catalog(), start=1):
        if not isinstance(entry, dict):
            fail(f"entry {index} must be an object")
        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if value is None or isinstance(value, str) and not value.strip():
                fail(f"entry {index} has no {field}")

        for field in ("title", "summary", "url", "source", "group"):
            if not isinstance(entry[field], str):
                fail(f"entry {index} field {field} must be a string")

        title = entry["title"]
        url = entry["url"]
        source = (REPO_ROOT / entry["source"]).resolve()
        group = entry["group"]
        order = entry["order"]
        if not isinstance(order, int) or order < 0:
            fail(f"{title}: order must be a non-negative integer")
        if order <= previous_order:
            fail(f"{title}: order values must increase through the catalog")
        if url in seen_urls:
            fail(f"{title}: duplicate URL {url}")
        if order in seen_orders:
            fail(f"{title}: duplicate order {order}")
        if not source.is_relative_to(REPO_ROOT):
            fail(f"{title}: source escapes the repository")
        if source.is_relative_to(REPO_ROOT / "website"):
            fail(f"{title}: source must be canonical repository Markdown, not website output")
        if not source.is_file():
            fail(f"{title}: source does not exist: {source.relative_to(REPO_ROOT)}")
        if not (url.startswith("/") or url.startswith("https://")):
            fail(f"{title}: URL must be a local route or HTTPS URL")
        if url.startswith("/"):
            page_path = local_page_path(url)
            if page_path is None:
                fail(f"{title}: local page does not exist for {url}")
            declared_source = generated_source(page_path)
            expected_source = source.relative_to(REPO_ROOT).as_posix()
            if declared_source != expected_source:
                fail(
                    f"{title}: {page_path.relative_to(REPO_ROOT)} was not generated "
                    f"from {expected_source}"
                )
        if group not in GROUPS:
            fail(f"{title}: unknown group {group!r}")
        seen_urls.add(url)
        seen_orders.add(order)
        seen_groups.add(group)
        previous_order = order

    missing = GROUPS - seen_groups
    if missing:
        fail(f"group has no entries for: {', '.join(sorted(missing))}")


def main() -> int:
    try:
        validate()
    except ValueError as exc:
        print(f"website catalog: {exc}", file=sys.stderr)
        return 1
    print("website catalog: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
