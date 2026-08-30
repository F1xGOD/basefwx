#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Compatibility-only jMG commands used by scripts/test_all.sh."""

import sys

from basefwx.main import basefwx

def cmd_jmg_roundtrip(args: list[str]) -> int:
    inp, enc, dec, pw = args
    basefwx.MediaCipher.encrypt_media(inp, pw, output=enc, archive_original=True)
    basefwx.MediaCipher.decrypt_media(enc, pw, output=dec)
    return 0

def cmd_jmg_roundtrip_no_archive(args: list[str]) -> int:
    inp, enc, dec, pw = args
    basefwx.MediaCipher.encrypt_media(inp, pw, output=enc, archive_original=False)
    basefwx.MediaCipher.decrypt_media(enc, pw, output=dec)
    return 0

def cmd_jmg_enc(args: list[str]) -> int:
    inp, enc, pw = args
    basefwx.MediaCipher.encrypt_media(inp, pw, output=enc, archive_original=True)
    return 0

def cmd_jmg_dec(args: list[str]) -> int:
    inp, dec, pw = args
    basefwx.MediaCipher.decrypt_media(inp, pw, output=dec)
    return 0

def main() -> int:
    if len(sys.argv) < 2:
        return 2
    command = sys.argv[1]
    args = sys.argv[2:]
    handlers = {
        "jmg-roundtrip": cmd_jmg_roundtrip,
        "jmg-roundtrip-no-archive": cmd_jmg_roundtrip_no_archive,
        "jmg-enc": cmd_jmg_enc,
        "jmg-dec": cmd_jmg_dec,
    }
    handler = handlers.get(command)
    return 2 if handler is None else handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
