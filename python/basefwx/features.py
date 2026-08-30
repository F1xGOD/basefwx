# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Build/runtime capability switches for optional compatibility modules."""

from __future__ import annotations

import os


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


RETIRED_MEDIA_ENABLED = _enabled(
    os.getenv("BASEFWX_ENABLE_RETIRED_MEDIA")
)


def load_retired_cli():
    """Load CLI registration only for compatibility-enabled runs."""
    if not RETIRED_MEDIA_ENABLED:
        return None
    from .retired import cli

    return cli
