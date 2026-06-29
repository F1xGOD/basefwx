#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""
Submit BaseFWX release artifacts to VirusTotal and record public report links.

No detection counts, thresholds, or release gating — maintainers review reports
on VirusTotal directly. Windows zips are scanned as the inner .exe payload.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request


VT_API = "https://www.virustotal.com/api/v3"
MIN_REQUEST_INTERVAL_SEC = 16.0


@dataclass(frozen=True)
class ScanTarget:
    release_name: str
    upload_path: Path


class VtClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._last_request_ts = 0.0

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < MIN_REQUEST_INTERVAL_SEC:
            time.sleep(MIN_REQUEST_INTERVAL_SEC - elapsed)
        self._last_request_ts = time.monotonic()

    def _request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        hdrs = {"accept": "application/json", "x-apikey": self.api_key}
        if content_type:
            hdrs["content-type"] = content_type

        for attempt in range(2):
            self._rate_limit()
            req = request.Request(url, data=data, headers=hdrs, method=method)
            try:
                with request.urlopen(req, timeout=300) as resp:
                    payload = resp.read().decode("utf-8")
                    return json.loads(payload) if payload else {}
            except error.HTTPError as exc:
                if exc.code == 429 and attempt == 0:
                    time.sleep(65)
                    continue
                detail = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"VirusTotal {method} {url} failed ({exc.code}): {detail}") from exc
        raise RuntimeError(f"VirusTotal {method} {url} failed after retry")

    def upload_file(self, path: Path) -> dict[str, Any]:
        boundary = "----basefwx-vt-boundary"
        file_bytes = path.read_bytes()
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
        return self._request(
            "POST",
            f"{VT_API}/files",
            data=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )


    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        return self._request("GET", f"{VT_API}/analyses/{analysis_id}")


def sha256_from_analysis_id(analysis_id: str) -> str:
    """Best-effort parse when the analyses payload has no file_info yet."""
    if not analysis_id:
        return ""
    padded = analysis_id + "=" * (-len(analysis_id) % 4)
    try:
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""
    sha, _, _ = decoded.partition(":")
    if len(sha) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in sha):
        return sha.lower()
    return ""


def resolve_gui_url(client: VtClient, analysis_id: str, upload_response: dict[str, Any]) -> str:
    """Return a public VT GUI URL for the uploaded payload."""
    meta_sha = str(upload_response.get("meta", {}).get("file_info", {}).get("sha256") or "")
    if len(meta_sha) == 64:
        return gui_url_for_sha256(meta_sha.lower())

    try:
        analysis = client.get_analysis(analysis_id)
    except RuntimeError:
        analysis = {}

    meta_sha = str(analysis.get("meta", {}).get("file_info", {}).get("sha256") or "")
    if len(meta_sha) == 64:
        return gui_url_for_sha256(meta_sha.lower())

    item_url = str(analysis.get("data", {}).get("links", {}).get("item") or "")
    if "/files/" in item_url:
        file_id = item_url.rsplit("/files/", 1)[-1].split("?", 1)[0]
        if len(file_id) == 64:
            return gui_url_for_sha256(file_id.lower())

    partial = sha256_from_analysis_id(analysis_id)
    if partial:
        return gui_url_for_sha256(partial)
    return ""


def gui_url_for_sha256(sha256: str) -> str:
    if not sha256:
        return ""
    return f"https://www.virustotal.com/gui/file/{sha256}"


def resolve_scan_targets(dist_dir: Path) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    specs = [
        ("basefwx-linux-amd64", None),
        ("basefwx-linux-arm64", None),
        ("basefwx-windows-amd64.zip", "basefwx-windows-amd64.exe"),
        ("basefwx-windows-x86.zip", "basefwx-windows-x86.exe"),
        ("basefwx-mac-amd64", None),
        ("basefwx-mac-arm64", None),
        ("basefwx-java.jar", None),
    ]
    for release_name, inner_exe in specs:
        release_path = dist_dir / release_name
        if not release_path.is_file():
            raise FileNotFoundError(f"Missing release artifact: {release_path}")
        if inner_exe is None:
            targets.append(ScanTarget(release_name=release_name, upload_path=release_path))
            continue
        extract_dir = dist_dir / ".vt-extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        exe_path = extract_dir / inner_exe
        with zipfile.ZipFile(release_path) as zf:
            if inner_exe not in zf.namelist():
                raise RuntimeError(
                    f"{release_name} does not contain {inner_exe}; found: {zf.namelist()}"
                )
            exe_path.write_bytes(zf.read(inner_exe))
        targets.append(ScanTarget(release_name=release_name, upload_path=exe_path))
    return targets


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: virustotal_release_scan.py <dist_dir> <output.json>", file=sys.stderr)
        return 2

    dist_dir = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    release_tag = os.environ.get("RELEASE_TAG") or os.environ.get("GITHUB_REF_NAME", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        print("VIRUSTOTAL_API_KEY is not set; writing empty link manifest", file=sys.stderr)
        payload = {
            "generated_at": generated_at,
            "release_tag": release_tag,
            "repository": repository,
            "note": "VirusTotal scan skipped (no API key).",
            "files": [],
        }
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return 0

    client = VtClient(api_key)
    files_out: list[dict[str, Any]] = []

    try:
        targets = resolve_scan_targets(dist_dir)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"VirusTotal scan skipped: {exc}", file=sys.stderr)
        payload = {
            "generated_at": generated_at,
            "release_tag": release_tag,
            "repository": repository,
            "note": str(exc),
            "files": [],
        }
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return 0

    for target in targets:
        print(f"Submitting {target.release_name} (payload: {target.upload_path.name})...")
        entry: dict[str, Any] = {
            "name": target.release_name,
            "scanned_payload": target.upload_path.name,
            "status": "error",
            "gui_url": "",
            "analysis_url": "",
        }
        try:
            submit = client.upload_file(target.upload_path)
            analysis_id = str(submit.get("data", {}).get("id") or "")
            analysis_url = str(submit.get("data", {}).get("links", {}).get("self") or "")
            gui_url = resolve_gui_url(client, analysis_id, submit)
            if not analysis_id or not gui_url:
                raise RuntimeError(f"unexpected upload response: {json.dumps(submit)}")
            entry.update(
                {
                    "status": "submitted",
                    "gui_url": gui_url,
                    "analysis_url": analysis_url,
                }
            )
            print(f"  {target.release_name}: {gui_url}")
        except Exception as exc:  # noqa: BLE001 — keep release moving; log per file
            entry["status"] = "error"
            entry["error"] = str(exc)
            print(f"  {target.release_name}: upload failed ({exc})", file=sys.stderr)
        files_out.append(entry)

    payload = {
        "generated_at": generated_at,
        "release_tag": release_tag,
        "repository": repository,
        "files": files_out,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print("VirusTotal link manifest written (no automated verdict).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
