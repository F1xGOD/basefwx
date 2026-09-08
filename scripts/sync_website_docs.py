#!/usr/bin/env python3
"""Website entry point used by the BaseFWX CI and Pages workflows."""
import sys
import yume_docs

if __name__ == "__main__":
    raise SystemExit(yume_docs.main([sys.argv[0], "website", "--all-languages", *sys.argv[1:]]))
