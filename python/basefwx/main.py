"""Compatibility module for the historical monolithic implementation.

The full implementation now lives in `legacy.py` so the package can be
organized into smaller modules without changing public imports.
"""

from .legacy import basefwx, cli, main

__all__ = ["basefwx", "cli", "main"]
