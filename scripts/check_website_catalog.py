#!/usr/bin/env python3
"""Verify published pages and catalog metadata against their .doc owners."""
import sys
import yume_docs


def main() -> int:
    return yume_docs.main([sys.argv[0], "website", "--check", "--all-languages"])


if __name__ == "__main__":
    raise SystemExit(main())
