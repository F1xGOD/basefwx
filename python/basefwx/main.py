# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# SPDX-License-Identifier: LGPL-3.0-or-later AND GPL-3.0-or-later

"""Stable import facade for the modular BaseFWX Python engine.

The historical ``basefwx`` class is assembled in :mod:`basefwx.legacy` to
preserve public imports, while its maintained implementations live in focused
``crypto``, ``file``, and ``runtime`` modules.
"""

from .legacy import basefwx


def cli(*args, **kwargs):
    from .runtime._cli import cli as _cli

    return _cli(*args, **kwargs)


def main(*args, **kwargs):
    from .runtime._cli import main as _main

    return _main(*args, **kwargs)

__all__ = ["basefwx", "cli", "main"]
