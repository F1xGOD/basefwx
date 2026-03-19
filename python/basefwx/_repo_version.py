"""Build-time version loader sourced from local project VERSION files."""

from pathlib import Path


def _load_version() -> str:
    candidates = (
        Path(__file__).resolve().parents[1] / "VERSION",
        Path(__file__).resolve().parents[2] / "VERSION",
    )
    for candidate in candidates:
        try:
            value = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return "0.0.0"


__version__ = _load_version()
