# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Core CPU execution-plan reporting without optional media dependencies."""

from __future__ import annotations

import os
import sys
from typing import Any, Optional


def resolve_worker_count() -> int:
    """Resolve the bounded CPU worker limit once for the active process."""
    available = max(1, os.cpu_count() or 1)
    if (os.getenv("BASEFWX_FORCE_SINGLE_THREAD") or "").strip() == "1":
        return 1
    configured = (os.getenv("BASEFWX_MAX_THREADS") or "").strip()
    if not configured or not configured.isascii() or not configured.isdigit():
        return available
    try:
        requested = max(1, int(configured, 10))
    except (ValueError, OverflowError):
        return available
    return min(available, requested)


def _aes_acceleration_state() -> str:
    try:
        if sys.platform.startswith("linux"):
            with open(
                "/proc/cpuinfo", "r", encoding="utf-8", errors="ignore"
            ) as handle:
                flags = f" {handle.read().lower().replace(chr(10), ' ')} "
            return "aesni" if " aes " in flags else "unknown"
        if sys.platform == "darwin":
            import subprocess

            for key in ("machdep.cpu.features", "machdep.cpu.leaf7_features"):
                result = subprocess.run(
                    ["sysctl", "-n", key],
                    capture_output=True,
                    text=True,
                    timeout=1,
                    check=False,
                )
                if "AES" in (result.stdout or "").upper():
                    return "aesni"
    except Exception:
        pass
    return "unknown"


def build_cpu_execution_plan(
    operation: str,
    *,
    stream_type: str = "bytes",
    workers: Optional[int] = None,
) -> dict[str, Any]:
    if workers is None:
        workers = resolve_worker_count()
    workers = max(1, int(workers))
    return {
        "op_name": operation,
        "stream_type": stream_type,
        "selected_accel": None,
        "encode_device": "cpu",
        "decode_device": "cpu",
        "pixel_backend": "cpu",
        "parallel_enabled": workers > 1,
        "parallel_workers": workers,
        "crypto_device": "cpu",
        "aes_accel_state": _aes_acceleration_state(),
        "reasons": [
            "core byte pipeline uses CPU crypto",
            "AES acceleration is provided by the cryptography backend",
        ],
    }


def log_execution_plan(plan: dict[str, Any]) -> None:
    workers = int(plan.get("parallel_workers") or 1)
    parallel = f"ON({workers}w)" if plan.get("parallel_enabled") else "OFF"
    message = (
        "🎛️ [basefwx.hw] "
        f"op={plan.get('op_name', 'unknown')} "
        "encode=CPU decode=CPU pixels=CPU "
        f"parallel={parallel} crypto=CPU "
        f"aes_accel={plan.get('aes_accel_state', 'unknown')}"
    )
    if (os.getenv("BASEFWX_VERBOSE") or "").strip().lower() in {
        "1", "true", "yes", "on"
    }:
        message += "\n   reason: " + "; ".join(plan.get("reasons", []))
    try:
        print(message, file=sys.stderr)
    except Exception:
        pass
