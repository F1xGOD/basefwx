# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# SPDX-License-Identifier: LGPL-3.0-or-later AND GPL-3.0-or-later

"""Compatibility module for the historical monolithic implementation.

The full implementation now lives in `legacy.py` so the package can be
organized into smaller modules without changing public imports.
"""

from .legacy import basefwx


def cli(*args, **kwargs):
    from ._cli import cli as _cli

    return _cli(*args, **kwargs)


def main(*args, **kwargs):
    from ._cli import main as _main

    return _main(*args, **kwargs)

__all__ = ["basefwx", "cli", "main"]
