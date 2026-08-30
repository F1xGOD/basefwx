# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Optional compatibility modules excluded from default artifacts."""

from __future__ import annotations

from typing import Any, MutableMapping


def install_public_api(
    namespace: MutableMapping[str, Any], public_names: list[str]
) -> None:
    """Install compatibility-only names on the historical top-level API."""
    from .api_media import jMGd, jMGe, kFAd, kFAe, kFMd, kFMe
    from .api_strings import (
        a512decode,
        a512encode,
        b256decode,
        b256encode,
        bi512encode,
        uhash513,
    )

    exported = {
        "a512decode": a512decode,
        "a512encode": a512encode,
        "b256decode": b256decode,
        "b256encode": b256encode,
        "bi512encode": bi512encode,
        "jMGd": jMGd,
        "jMGe": jMGe,
        "kFAd": kFAd,
        "kFAe": kFAe,
        "kFMd": kFMd,
        "kFMe": kFMe,
        "uhash513": uhash513,
    }
    namespace.update(exported)
    public_names.extend(exported)
