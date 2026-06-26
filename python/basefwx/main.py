# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""Compatibility module for the historical monolithic implementation.

The full implementation now lives in `legacy.py` so the package can be
organized into smaller modules without changing public imports.
"""

from .legacy import basefwx
from ._cli import cli, main

__all__ = ["basefwx", "cli", "main"]
