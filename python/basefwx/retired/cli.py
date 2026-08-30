# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""CLI registration and dispatch for all retired compatibility features."""

from __future__ import annotations

from ..legacy import basefwx


def configure_parser(subparsers, cryptin) -> None:
    retired_text_commands = {
        "b256-enc": "Retired: encode text with b256",
        "b256-dec": "Retired: decode a b256 payload",
        "a512-enc": "Retired: encode text with A512",
        "a512-dec": "Retired: decode an A512 payload",
        "bi512-enc": "Retired: hash text with Bi512",
        "uhash513": "Retired: hash text with Uhash513",
    }
    for command, help_text in retired_text_commands.items():
        parser = subparsers.add_parser(command, help=help_text)
        parser.add_argument("text", help="Input text or encoded payload")

    cryptin.add_argument(
        "--ignore-media",
        action="store_true",
        help="Disable retired media auto-detection for fwxAES",
    )
    cryptin.add_argument(
        "--keep-meta",
        action="store_true",
        help="Preserve media metadata when using retired jMG compatibility",
    )
    cryptin.add_argument(
        "--no-archive",
        dest="archive_original",
        action="store_false",
        help="jMG compatibility: omit the byte-identical original payload",
    )
    cryptin.add_argument(
        "--archive",
        dest="archive_original",
        action="store_true",
        help="jMG compatibility: embed the original payload for exact restore",
    )
    cryptin.set_defaults(archive_original=False)

    kfme = subparsers.add_parser(
        "kFMe",
        help="Retired: encode data into a BaseFWX media carrier",
    )
    kfme.add_argument("input", help="Input file path")
    kfme.add_argument("-o", "--output", default=None)
    kfme.add_argument("--bw", action="store_true")

    kfmd = subparsers.add_parser(
        "kFMd",
        help="Retired: decode a BaseFWX media carrier",
    )
    kfmd.add_argument("input", help="Input carrier file path")
    kfmd.add_argument("-o", "--output", default=None)
    kfmd.add_argument("--bw", action="store_true")

    kfae = subparsers.add_parser("kFAe", help="Retired kFMe alias")
    kfae.add_argument("input", help="Input file path")
    kfae.add_argument("-o", "--output", default=None)
    kfae.add_argument("--bw", action="store_true")

    kfad = subparsers.add_parser("kFAd", help="Retired kFMd alias")
    kfad.add_argument("input", help="Input carrier file path")
    kfad.add_argument("-o", "--output", default=None)


def handle_command(args, theme) -> int | None:
    text_handlers = {
        "b256-enc": basefwx.b256encode,
        "b256-dec": basefwx.b256decode,
        "a512-enc": basefwx.a512encode,
        "a512-dec": basefwx.a512decode,
        "bi512-enc": basefwx.bi512encode,
        "uhash513": basefwx.uhash513,
    }
    text_handler = text_handlers.get(args.command)
    if text_handler is not None:
        try:
            print(text_handler(args.text))
            return 0
        except Exception as exc:
            print(theme.err(f"{args.command} failed: {exc}"))
            return 1

    handlers = {
        "kFMe": lambda: basefwx.kFMe(
            args.input, args.output, bw_mode=args.bw
        ),
        "kFMd": lambda: basefwx.kFMd(
            args.input, args.output, bw_mode=args.bw
        ),
        "kFAe": lambda: basefwx.kFAe(
            args.input, args.output, bw_mode=args.bw
        ),
        "kFAd": lambda: basefwx.kFAd(args.input, args.output),
    }
    handler = handlers.get(args.command)
    if handler is None:
        return None
    try:
        output = handler()
        print(theme.ok(f"Wrote {output}"))
        return 0
    except Exception as exc:
        print(theme.err(f"{args.command} failed: {exc}"))
        return 1


def feature_text() -> str:
    pillow = "ON" if basefwx.Image is not None else "OFF"
    basefwx._ensure_cp()
    cupy = "ON" if basefwx.cp is not None else "OFF"
    return f"retired_media=ON pillow={pillow} cupy={cupy}"
