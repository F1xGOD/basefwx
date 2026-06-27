#!/usr/bin/env python3
"""
Submit BaseFWX release artifacts to VirusTotal and gate the release on
consensus detections — not zip-wrapper or heuristic noise.

Canonical stats come from the VirusTotal *file* object (last_analysis_stats),
which matches what the public GUI shows. Per-upload analysis stats are kept
for diagnostics only.
"""

from __future__ import annotations

import hashlib
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
    """Release asset name (for manifest / website) and bytes to upload."""

    release_name: str
    release_path: Path
    upload_path: Path


@dataclass(frozen=True)
class Policy:
    block_release: bool
    min_completed_engines: int
    block_malicious_min: int
    block_malicious_ratio: float
    block_suspicious_min: int
    block_suspicious_ratio: float
    poll_attempts: int
    poll_sleep_sec: int
    initial_wait_sec: int


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return float(raw)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def load_policy() -> Policy:
    return Policy(
        block_release=_env_bool("VT_BLOCK_RELEASE", True),
        min_completed_engines=_env_int("VT_MIN_COMPLETED_ENGINES", 15),
        block_malicious_min=_env_int("VT_BLOCK_MALICIOUS_MIN", 8),
        block_malicious_ratio=_env_float("VT_BLOCK_MALICIOUS_RATIO", 0.15),
        block_suspicious_min=_env_int("VT_BLOCK_SUSPICIOUS_MIN", 12),
        block_suspicious_ratio=_env_float("VT_BLOCK_SUSPICIOUS_RATIO", 0.20),
        poll_attempts=_env_int("VT_POLL_ATTEMPTS", 12),
        poll_sleep_sec=_env_int("VT_POLL_SLEEP_SEC", 60),
        initial_wait_sec=_env_int("VT_INITIAL_WAIT_SEC", 60),
    )


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
        headers: dict[str, str] | None = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        hdrs = {"accept": "application/json", "x-apikey": self.api_key}
        if headers:
            hdrs.update(headers)
        if content_type:
            hdrs["content-type"] = content_type

        body = data
        for attempt in range(2):
            self._rate_limit()
            req = request.Request(url, data=body, headers=hdrs, method=method)
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

    def get_file(self, sha256: str) -> dict[str, Any]:
        return self._request("GET", f"{VT_API}/files/{sha256}")


def load_allowlist(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"rules": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"Warning: invalid allowlist JSON at {path}; ignoring", file=sys.stderr)
        return {"rules": []}
    if not isinstance(data, dict):
        return {"rules": []}
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        rules = []
    return {"rules": [r for r in rules if isinstance(r, dict)]}


def digest_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_scan_targets(dist_dir: Path) -> list[ScanTarget]:
    """Map release asset names to the payload VirusTotal should scan."""
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
            targets.append(
                ScanTarget(
                    release_name=release_name,
                    release_path=release_path,
                    upload_path=release_path,
                )
            )
            continue
        extract_dir = dist_dir / ".vt-extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        exe_path = extract_dir / inner_exe
        with zipfile.ZipFile(release_path) as zf:
            names = zf.namelist()
            if inner_exe not in names:
                raise RuntimeError(
                    f"{release_name} does not contain {inner_exe}; found: {names}"
                )
            exe_path.write_bytes(zf.read(inner_exe))
        targets.append(
            ScanTarget(
                release_name=release_name,
                release_path=release_path,
                upload_path=exe_path,
            )
        )
    return targets


def completed_engine_count(stats: dict[str, Any]) -> int:
    return int(
        sum(int(stats.get(key, 0) or 0) for key in ("malicious", "suspicious", "undetected", "harmless"))
    )


def apply_allowlist(
    release_name: str,
    stats: dict[str, Any],
    engine_results: dict[str, Any],
    allowlist: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    import re

    effective = {key: int(stats.get(key, 0) or 0) for key in (
        "malicious", "suspicious", "undetected", "harmless",
        "timeout", "failure", "type-unsupported",
    )}
    known_false_positives: list[dict[str, str]] = []
    rules = allowlist.get("rules", [])

    for engine_name, value in engine_results.items():
        if not isinstance(value, dict):
            continue
        category = str(value.get("category") or "")
        result_name = str(value.get("result") or "")
        if category not in {"malicious", "suspicious"}:
            continue

        matched_rule = None
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            engine_pat = str(rule.get("engine") or "")
            file_pat = str(rule.get("file_regex") or ".*")
            result_pat = str(rule.get("result_regex") or ".*")
            if engine_pat and engine_name != engine_pat:
                continue
            try:
                if not re.search(file_pat, release_name):
                    continue
                if result_name and not re.search(result_pat, result_name, re.IGNORECASE):
                    continue
            except re.error:
                continue
            matched_rule = rule
            break

        if matched_rule is not None:
            known_false_positives.append(
                {
                    "engine": engine_name,
                    "category": category,
                    "result": result_name,
                    "rule_id": str(matched_rule.get("id") or ""),
                    "reason": str(matched_rule.get("reason") or ""),
                }
            )
            effective[category] = max(0, effective[category] - 1)

    return effective, known_false_positives


def canonical_file_record(
    client: VtClient, sha256: str
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    """Return (stats, engine_results, item_url, attributes) from the file object."""
    file_info = client.get_file(sha256)
    attrs = file_info.get("data", {}).get("attributes", {})
    if not isinstance(attrs, dict):
        attrs = {}
    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}
    item_url = file_info.get("data", {}).get("links", {}).get("self", "")
    if not isinstance(stats, dict):
        stats = {}
    if not isinstance(results, dict):
        results = {}
    return stats, results, item_url, attrs


def should_block(stats: dict[str, Any], policy: Policy) -> tuple[bool, str]:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    completed = completed_engine_count(stats)

    if completed < policy.min_completed_engines:
        return False, (
            f"only {completed} engines reported a verdict "
            f"(need {policy.min_completed_engines}); not blocking"
        )

    mal_ratio = malicious / completed if completed else 0.0
    sus_ratio = suspicious / completed if completed else 0.0

    if malicious >= policy.block_malicious_min and mal_ratio >= policy.block_malicious_ratio:
        return True, (
            f"malicious={malicious}/{completed} "
            f"({mal_ratio:.1%} >= {policy.block_malicious_ratio:.0%} "
            f"with floor {policy.block_malicious_min})"
        )
    if suspicious >= policy.block_suspicious_min and sus_ratio >= policy.block_suspicious_ratio:
        return True, (
            f"suspicious={suspicious}/{completed} "
            f"({sus_ratio:.1%} >= {policy.block_suspicious_ratio:.0%} "
            f"with floor {policy.block_suspicious_min})"
        )
    return False, "within consensus policy"


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "Usage: virustotal_release_scan.py <dist_dir> <output.json> <allowlist.json>",
            file=sys.stderr,
        )
        return 2

    dist_dir = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    allowlist_path = Path(sys.argv[3])

    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        print("VIRUSTOTAL_API_KEY is not set", file=sys.stderr)
        return 1

    policy = load_policy()
    allowlist = load_allowlist(allowlist_path)
    client = VtClient(api_key)

    print(
        "VirusTotal policy: "
        f"block_release={policy.block_release}, "
        f"malicious>={policy.block_malicious_min} @ {policy.block_malicious_ratio:.0%}, "
        f"suspicious>={policy.block_suspicious_min} @ {policy.block_suspicious_ratio:.0%}, "
        f"min_completed_engines={policy.min_completed_engines}"
    )

    targets = resolve_scan_targets(dist_dir)
    pending: list[dict[str, Any]] = []

    for target in targets:
        print(f"Submitting {target.release_name} (payload: {target.upload_path.name})...")
        submit = client.upload_file(target.upload_path)
        analysis_id = submit.get("data", {}).get("id", "")
        meta = submit.get("meta", {}).get("file_info", {})
        sha256 = str(meta.get("sha256") or "")
        if not analysis_id or not sha256:
            print(f"VirusTotal upload failed for {target.release_name}: {json.dumps(submit)}", file=sys.stderr)
            return 1
        pending.append(
            {
                "release_name": target.release_name,
                "release_path": str(target.release_path),
                "upload_name": target.upload_path.name,
                "analysis_id": analysis_id,
                "scanned_sha256": sha256,
                "analysis": None,
                "analysis_status": "queued",
            }
        )

    if policy.initial_wait_sec > 0:
        time.sleep(policy.initial_wait_sec)

    for attempt in range(1, policy.poll_attempts + 1):
        still_pending = False
        for entry in pending:
            if entry["analysis_status"] == "completed":
                continue
            analysis = client.get_analysis(entry["analysis_id"])
            entry["analysis"] = analysis
            status = analysis.get("data", {}).get("attributes", {}).get("status", "")
            entry["analysis_status"] = status or "unknown"
            if entry["analysis_status"] != "completed":
                still_pending = True
        if not still_pending:
            break
        if attempt < policy.poll_attempts:
            print(f"Waiting for VirusTotal analyses ({attempt}/{policy.poll_attempts})...")
            time.sleep(policy.poll_sleep_sec)

    release_tag = os.environ.get("GITHUB_REF_NAME", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    files_out: list[dict[str, Any]] = []
    violations: list[str] = []

    for entry in pending:
        release_name = entry["release_name"]
        release_path = Path(entry["release_path"])
        scanned_sha256 = entry["scanned_sha256"]
        analysis = entry["analysis"] or {}
        analysis_attrs = analysis.get("data", {}).get("attributes", {})
        analysis_stats = analysis_attrs.get("stats") or {}
        analysis_url = analysis.get("data", {}).get("links", {}).get("self", "")
        analysis_results = analysis_attrs.get("results") or {}

        file_stats, file_results, item_url, file_attrs = canonical_file_record(
            client, scanned_sha256
        )
        if completed_engine_count(file_stats) == 0 and isinstance(analysis_stats, dict):
            # Fall back to the upload analysis only when the file record is empty.
            file_stats = analysis_stats
            if isinstance(analysis_results, dict) and analysis_results:
                file_results = analysis_results

        effective_stats, known_false_positives = apply_allowlist(
            release_name, file_stats, file_results, allowlist
        )
        block, reason = should_block(effective_stats, policy)
        if policy.block_release and block:
            violations.append(f"{release_name} ({reason})")

        release_sha256 = digest_file(release_path, "sha256")
        release_md5 = digest_file(release_path, "md5")

        files_out.append(
            {
                "name": release_name,
                "scanned_payload": entry["upload_name"],
                "scanned_sha256": scanned_sha256,
                "analysis_id": entry["analysis_id"],
                "analysis_url": analysis_url,
                "item_url": item_url,
                "sha256": release_sha256,
                "md5": release_md5,
                "sha1": str(file_attrs.get("sha1") or ""),
                "status": entry["analysis_status"],
                "stats": file_stats,
                "analysis_stats": analysis_stats,
                "effective_stats": effective_stats,
                "known_false_positives": known_false_positives,
                "policy_decision": {
                    "block": block,
                    "reason": reason,
                },
            }
        )

        mal = int(effective_stats.get("malicious", 0))
        sus = int(effective_stats.get("suspicious", 0))
        completed = completed_engine_count(effective_stats)
        print(
            f"  {release_name}: GUI stats malicious={mal}, suspicious={sus}, "
            f"completed={completed}, status={entry['analysis_status']}"
        )

    payload = {
        "generated_at": generated_at,
        "release_tag": release_tag,
        "repository": repository,
        "policy": {
            "block_release": policy.block_release,
            "min_completed_engines": policy.min_completed_engines,
            "block_malicious_min": policy.block_malicious_min,
            "block_malicious_ratio": policy.block_malicious_ratio,
            "block_suspicious_min": policy.block_suspicious_min,
            "block_suspicious_ratio": policy.block_suspicious_ratio,
        },
        "files": files_out,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if violations:
        print("VirusTotal consensus threshold exceeded for:", file=sys.stderr)
        for line in violations:
            print(f" - {line}", file=sys.stderr)
        return 1

    print("VirusTotal scan complete — all artifacts within policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
