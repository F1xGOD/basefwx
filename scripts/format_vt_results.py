import json
import sys
from datetime import datetime, timezone


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "dist_out/virustotal-results.json"
    dst = sys.argv[2] if len(sys.argv) > 2 else "dist_out/virustotal-results.txt"

    with open(src, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    lines = []
    lines.append("BaseFWX VirusTotal Results")
    lines.append(f"Release: {data.get('release_tag', 'unknown')}")
    lines.append(
        f"Generated: {data.get('generated_at', datetime.now(timezone.utc).isoformat())}"
    )
    lines.append(f"Repository: {data.get('repo', '')}")
    lines.append("")

    for entry in data.get("files", []):
        lines.append(f"File: {entry.get('name', '')}")
        lines.append(f"  Status: {entry.get('status', '')}")
        lines.append(f"  VirusTotal analysis: {entry.get('analysis_url', '')}")
        lines.append(f"  VirusTotal file: {entry.get('item_url', '')}")
        stats = entry.get("stats", {})
        lines.append(
            "  Stats: "
            f"malicious={stats.get('malicious', 0)}, "
            f"suspicious={stats.get('suspicious', 0)}, "
            f"undetected={stats.get('undetected', 0)}, "
            f"harmless={stats.get('harmless', 0)}, "
            f"timeout={stats.get('timeout', 0)}, "
            f"failure={stats.get('failure', 0)}, "
            f"type-unsupported={stats.get('type-unsupported', 0)}"
        )
        lines.append(f"  SHA256: {entry.get('sha256', '')}")
        lines.append(f"  SHA1: {entry.get('sha1', '')}")
        lines.append(f"  MD5: {entry.get('md5', '')}")
        lines.append("")

    with open(dst, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
