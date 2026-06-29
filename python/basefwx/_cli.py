# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations

import os as _os_module
import sys as _sys_module

from . import _primitives as _prim
from .legacy import basefwx
from ._primitives import (
    _enable_large_int_string_conversion_for_cli,
    _python_build_origin_label,
    _runtime_arch_label,
)

def cli(argv=None) -> int:
    _enable_large_int_string_conversion_for_cli()
    import argparse

    def _cli_config_path() -> "basefwx.pathlib.Path":
        cfg = _os_module.getenv("BASEFWX_CLI_CONFIG")
        if cfg:
            return basefwx.pathlib.Path(cfg).expanduser()
        xdg = _os_module.getenv("XDG_CONFIG_HOME")
        if xdg:
            return basefwx.pathlib.Path(xdg) / "basefwx" / "cli.conf"
        appdata = _os_module.getenv("APPDATA")
        if appdata:
            return basefwx.pathlib.Path(appdata) / "basefwx" / "cli.conf"
        return basefwx.pathlib.Path("~/.config/basefwx/cli.conf").expanduser()

    def _cli_plain_mode() -> bool:
        if _os_module.getenv("BASEFWX_CLI_PLAIN"):
            return True
        if _os_module.getenv("NO_COLOR"):
            return True
        style = (_os_module.getenv("BASEFWX_CLI_STYLE") or "").strip().lower()
        if style in {"plain", "boring", "0", "false", "off"}:
            return True
        if style in {"color", "emoji", "on"}:
            return False
        cfg_path = _cli_config_path()
        try:
            if cfg_path.exists():
                data = cfg_path.read_text(encoding="utf-8").lower()
                if "plain=1" in data or "plain=true" in data:
                    return True
                if "style=plain" in data or "mode=plain" in data or "boring=1" in data:
                    return True
        except OSError:
            pass
        return False

    class _CliTheme:
        def __init__(self, plain: bool):
            self.plain = plain
            self.reset = "" if plain else "\033[0m"
            self.bold = "" if plain else "\033[1m"
            self.red = "" if plain else "\033[31m"
            self.green = "" if plain else "\033[32m"
            self.yellow = "" if plain else "\033[33m"
            self.cyan = "" if plain else "\033[36m"

        def _wrap(self, msg: str, color: str, emoji: str | None = None) -> str:
            if self.plain:
                return msg
            prefix = f"{emoji} " if emoji else ""
            return f"{self.bold}{color}{prefix}{msg}{self.reset}"

        def ok(self, msg: str) -> str:
            return self._wrap(msg, self.green, "✅")

        def warn(self, msg: str) -> str:
            return self._wrap(msg, self.yellow, "⚠️")

        def err(self, msg: str) -> str:
            return self._wrap(msg, self.red, "❌")

        def info(self, msg: str) -> str:
            return self._wrap(msg, self.cyan, "✨")

    theme = _CliTheme(_cli_plain_mode())

    def _confirm_single_thread_cli() -> None:
        # Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
        if not basefwx._SINGLE_THREAD_OVERRIDE:
            return
        if _os_module.getenv("BASEFWX_ALLOW_SINGLE_THREAD") == "1" or _os_module.getenv("BASEFWX_NONINTERACTIVE") == "1":
            # Non-interactive bypass: warn but do not prompt
            warning = "WARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION"
            security = "WARN: SINGLE-THREAD MODE REDUCES SIDE-CHANNEL RESILIENCE"
            orange = "\033[38;5;208m"
            reset = "\033[0m"
            decorated = f"{orange}{warning}\n{security}{reset}" if not theme.plain else f"{warning}\n{security}"
            print(decorated, file=basefwx.sys.stderr)
            return
        warning = "WARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION"
        security = "WARN: SINGLE-THREAD MODE REDUCES SIDE-CHANNEL RESILIENCE"
        orange = "\033[38;5;208m"
        reset = "\033[0m"
        decorated = f"{orange}{warning}\n{security}{reset}" if not theme.plain else f"{warning}\n{security}"
        print(decorated, file=basefwx.sys.stderr)
        prompt = "Type YES to continue with single-thread mode: "
        response = input(prompt)
        if response.strip() != "YES":
            raise SystemExit(theme.err("Aborted: multi-thread disabled by user override"))

    def _decode_pack_mode(flag: str) -> str:
        if flag == "g":
            return "tgz"
        if flag == "x":
            return "txz"
        return "none"

    def _is_fwx_raw(blob: bytes) -> bool:
        return len(blob) >= 16 and blob[:4] == basefwx.FWXAES_MAGIC

    def _inspect_raw_fwx(blob: bytes) -> dict:
        if not _is_fwx_raw(blob):
            raise ValueError("not raw FWX1")
        algo = blob[4]
        kdf = blob[5]
        salt_len = blob[6]
        iv_len = blob[7]
        kdf_param = int.from_bytes(blob[8:12], "big")
        ciphertext_len = int.from_bytes(blob[12:16], "big")
        variable_len = kdf_param if kdf == 0x02 else salt_len
        expected_len = 16 + int(variable_len) + int(iv_len) + int(ciphertext_len)
        total_len = len(blob)
        if total_len < expected_len:
            state = "truncated"
        elif total_len > expected_len:
            state = "extra-bytes"
        else:
            state = "exact"
        return {
            "format": "fwxaes-raw",
            "algo": algo,
            "kdf": kdf,
            "salt_len": int(salt_len),
            "iv_len": int(iv_len),
            "kdf_param": int(kdf_param),
            "ciphertext_len": int(ciphertext_len),
            "total_len": int(total_len),
            "expected_len": int(expected_len),
            "container_state": state,
        }

    def _inspect_basefwx_blob(path: "basefwx.pathlib.Path", blob: bytes) -> dict:
        total = len(blob)
        if total < 12:
            raise ValueError("too short")
        offset = 0
        len_user = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        if offset + len_user + 4 > total:
            raise ValueError("Malformed length-prefixed blob (truncated part)")
        user_blob = blob[offset:offset + len_user]
        offset += len_user
        len_master = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        if offset + len_master + 4 > total:
            raise ValueError("Malformed length-prefixed blob (truncated part)")
        master_blob = blob[offset:offset + len_master]
        offset += len_master
        payload_len_header = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4

        payload_len = basefwx._resolve_payload_length_from_file_size(
            path,
            len_user,
            len_master,
            payload_len_header
        )
        actual_payload_len = total - offset
        if payload_len < 0 or payload_len > actual_payload_len:
            raise ValueError("Malformed length-prefixed blob (truncated part)")
        if actual_payload_len > payload_len:
            state = "extra-bytes"
        elif actual_payload_len < payload_len:
            state = "truncated"
        else:
            state = "exact"

        payload = blob[offset:offset + payload_len]
        metadata_len = 0
        metadata_blob = ""
        metadata_map = {}
        if len(payload) >= 4:
            metadata_len_candidate = int.from_bytes(payload[:4], "big")
            if 4 + metadata_len_candidate <= len(payload):
                metadata_bytes = payload[4:4 + metadata_len_candidate]
                metadata_blob_candidate = metadata_bytes.decode("utf-8", errors="replace") if metadata_bytes else ""
                metadata_map_candidate = basefwx._decode_metadata(metadata_blob_candidate)
                if metadata_len_candidate == 0 or metadata_map_candidate:
                    metadata_len = int(metadata_len_candidate)
                    metadata_blob = metadata_blob_candidate
                    metadata_map = metadata_map_candidate
        return {
            "format": "basefwx",
            "user_blob_len": len(user_blob),
            "master_blob_len": len(master_blob),
            "payload_len": int(payload_len),
            "payload_len_header": int(payload_len_header),
            "metadata_len": int(metadata_len),
            "metadata_blob": metadata_blob,
            "metadata": metadata_map,
            "container_state": state,
        }

    def _kdf_label(kdf_id: int) -> str:
        if kdf_id == 0x01:
            return "pbkdf2"
        if kdf_id == 0x02:
            return "keywrap"
        return f"unknown(0x{kdf_id:02x})"

    def _algo_label(algo_id: int) -> str:
        if algo_id == 0x01:
            return "aes-256-gcm"
        return f"unknown(0x{algo_id:02x})"

    def _run_inspect(command: str, file_path: str, include_json: bool) -> int:
        path_obj = basefwx.pathlib.Path(file_path)
        if not path_obj.exists():
            print(theme.err(f"File not found: {path_obj}"))
            return 1
        blob = path_obj.read_bytes()

        base_info = None
        raw_info = None
        try:
            base_info = _inspect_basefwx_blob(path_obj, blob)
        except Exception:
            base_info = None
        if base_info is None:
            try:
                raw_info = _inspect_raw_fwx(blob)
            except Exception:
                raw_info = None
        if base_info is None and raw_info is None:
            print(theme.err("Not a recognizable BaseFWX payload"))
            return 1

        if base_info is not None:
            meta = base_info["metadata"] or {}
            if command == "info":
                print(f"user_blob_len: {base_info['user_blob_len']} bytes")
                print(f"master_blob_len: {base_info['master_blob_len']} bytes")
                print(f"payload_len: {base_info['payload_len']} bytes")
                if base_info["metadata_len"] > 0:
                    print(f"metadata_len: {base_info['metadata_len']} bytes")
                if base_info["metadata_blob"]:
                    print(f"metadata_json: {base_info['metadata_blob']}")
                else:
                    print("metadata_json: <unavailable>")
                return 0

            print(f"file: {path_obj}")
            print("format: basefwx")
            print(f"user_blob_len: {base_info['user_blob_len']} bytes")
            print(f"master_blob_len: {base_info['master_blob_len']} bytes")
            print(f"payload_len: {base_info['payload_len']} bytes")
            print(f"engine_version: {meta.get('ENC-VERSION', 'unknown')}")
            print(f"method: {meta.get('ENC-METHOD', 'unknown')}")
            print(f"time_utc: {meta.get('ENC-TIME', 'unknown')}")
            kdf_line = f"kdf: {meta.get('ENC-KDF', 'unknown')}"
            if meta.get("ENC-KDF-ITER"):
                kdf_line += f" iter={meta.get('ENC-KDF-ITER')}"
            if meta.get("ENC-ARGON2-TC") or meta.get("ENC-ARGON2-MEM") or meta.get("ENC-ARGON2-PAR"):
                kdf_line += (
                    f" argon2(tc={meta.get('ENC-ARGON2-TC', '?')},"
                    f"mem={meta.get('ENC-ARGON2-MEM', '?')},"
                    f"par={meta.get('ENC-ARGON2-PAR', '?')})"
                )
            print(kdf_line)
            print(f"aead: {meta.get('ENC-AEAD', 'unknown')}")
            print(f"obfuscation: {meta.get('ENC-OBF', 'unknown')}")
            print(f"master_mode: {meta.get('ENC-MASTER', 'unknown')}")
            print(f"kem: {meta.get('ENC-KEM', 'unknown')}")
            print(f"pack_mode: {_decode_pack_mode(str(meta.get('ENC-P', '')))}")
            if include_json:
                if base_info["metadata_blob"]:
                    print(f"metadata_json: {base_info['metadata_blob']}")
                else:
                    print("metadata_json: <unavailable>")
            return 0

        if command == "info":
            print("format: fwxaes-raw")
            print(f"algo: {_algo_label(raw_info['algo'])}")
            print(f"kdf: {_kdf_label(raw_info['kdf'])}")
            if raw_info["kdf"] == 0x01:
                print(f"kdf_iters: {raw_info['kdf_param']}")
            elif raw_info["kdf"] == 0x02:
                print(f"key_header_len: {raw_info['kdf_param']} bytes")
            print(f"salt_len: {raw_info['salt_len']} bytes")
            print(f"iv_len: {raw_info['iv_len']} bytes")
            print(f"ciphertext_len: {raw_info['ciphertext_len']} bytes")
            print(f"container_len: {raw_info['total_len']} bytes")
            print(f"expected_len: {raw_info['expected_len']} bytes")
            print(f"container_state: {raw_info['container_state']}")
            if include_json:
                print("metadata_json: <unavailable>")
            return 0

        print(f"file: {path_obj}")
        print("format: fwxaes-raw")
        print("engine_version: n/a")
        print("method: fwxaes-raw")
        kdf_line = f"kdf: {_kdf_label(raw_info['kdf'])}"
        if raw_info["kdf"] == 0x01:
            kdf_line += f" iter={raw_info['kdf_param']}"
        elif raw_info["kdf"] == 0x02:
            kdf_line += f" key_header_len={raw_info['kdf_param']}"
        print(kdf_line)
        print(f"algo: {_algo_label(raw_info['algo'])}")
        print(f"salt_len: {raw_info['salt_len']} bytes")
        print(f"iv_len: {raw_info['iv_len']} bytes")
        print(f"ciphertext_len: {raw_info['ciphertext_len']} bytes")
        print("metadata: unavailable")
        print(f"container_state: {raw_info['container_state']}")
        if include_json:
            print("metadata_json: <unavailable>")
        return 0

    parser = argparse.ArgumentParser(
        prog="basefwx",
        description="BASEFWX encryption toolkit"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "version",
        help="Show engine and build/runtime information"
    )

    info_cmd = subparsers.add_parser(
        "info",
        help="Inspect container internals for a BaseFWX file"
    )
    info_cmd.add_argument("file", help="Input file path")
    info_cmd.add_argument("--json", action="store_true", help="Include metadata_json in output")

    probe_cmd = subparsers.add_parser(
        "probe",
        help="Identify file format and encryption metadata"
    )
    probe_cmd.add_argument("file", help="Input file path")
    probe_cmd.add_argument("--json", action="store_true", help="Include metadata_json in output")

    identify_cmd = subparsers.add_parser(
        "identify",
        help="Alias for probe"
    )
    identify_cmd.add_argument("file", help="Input file path")
    identify_cmd.add_argument("--json", action="store_true", help="Include metadata_json in output")

    cryptin = subparsers.add_parser(
        "cryptin",
        help="Encrypt/decrypt one or more files using a BASEFWX method"
    )
    cryptin.add_argument(
        "method",
        help="Method name: 512, b512, pb512, aes, aes-light, aes-heavy, fwxaes-heavy"
    )
    cryptin.add_argument(
        "paths",
        nargs='+',
        help="One or more file paths"
    )
    cryptin.add_argument(
        "-p", "--password",
        default="",
        help="Password text or path (leave blank to rely on the master key)"
    )
    cryptin.add_argument(
        "--strip", "--trim",
        dest="strip_metadata",
        action="store_true",
        help="Disable metadata emission and zero timestamps"
    )
    cryptin.add_argument(
        "--use-master",
        dest="use_master",
        action="store_true",
        help="Enable master key wrapping/unwrapping (off by default)"
    )
    cryptin.add_argument(
        "--no-master",
        dest="use_master",
        action="store_false",
        help="Opt out of master key wrapping/unwrapping"
    )
    cryptin.add_argument(
        "--no-obf",
        dest="obfuscate",
        action="store_false",
        help="Disable pre-AEAD obfuscation layers"
    )
    cryptin.set_defaults(use_master=False, obfuscate=True, archive_original=False)
    cryptin.add_argument(
        "--use-master-pub",
        dest="master_pub_path",
        default=None,
        help="Path to ML-KEM public key used for master key wrapping"
    )
    cryptin.add_argument(
        "--normalize",
        action="store_true",
        help="Wrap fwxAES output in zero-width cover text (fwxaes only)"
    )
    cryptin.add_argument(
        "--normalize-threshold",
        type=int,
        default=None,
        help="Max plaintext bytes for normalize wrapper (fwxaes only)"
    )
    cryptin.add_argument(
        "--cover-phrase",
        default="low taper fade",
        help="Cover phrase for normalize wrapper (fwxaes only)"
    )
    cryptin.add_argument(
        "--compress",
        action="store_true",
        help="Pack files/folders to tar.gz or tar.xz before encrypting; auto-unpack on decrypt"
    )
    cryptin.add_argument(
        "--ignore-media",
        action="store_true",
        help="Disable media auto-detection for fwxAES (use normal encryption)"
    )
    cryptin.add_argument(
        "--keep-meta",
        action="store_true",
        help="Preserve media metadata (encrypted) when using jMG media mode"
    )
    cryptin.add_argument(
        "--no-archive",
        dest="archive_original",
        action="store_false",
        help="jMG mode: do not embed full original payload (smaller output, non-byte-identical restore)"
    )
    cryptin.add_argument(
        "--archive",
        dest="archive_original",
        action="store_true",
        help="jMG mode: embed full original payload for exact restore"
    )
    cryptin.add_argument(
        "--keep-input",
        action="store_true",
        help="Do not delete the input after encryption"
    )
    cryptin.add_argument(
        "--no-stats",
        action="store_true",
        help="Disable live CPU/RAM/GPU telemetry in progress output"
    )
    cryptin.add_argument(
        "--stats",
        action="store_true",
        help="Force-enable live CPU/RAM/GPU telemetry in progress output"
    )

    n10_enc = subparsers.add_parser(
        "n10-enc",
        help="Encode UTF-8 text into a numeric n10 payload"
    )
    n10_enc.add_argument("text", help="Input text")

    n10_dec = subparsers.add_parser(
        "n10-dec",
        help="Decode an n10 numeric payload back to UTF-8 text"
    )
    n10_dec.add_argument("digits", help="n10 payload digits")

    n10file_enc = subparsers.add_parser(
        "n10file-enc",
        help="Encode a binary file into n10 digits"
    )
    n10file_enc.add_argument("input", help="Input file path")
    n10file_enc.add_argument("output", help="Output file path for digits")

    n10file_dec = subparsers.add_parser(
        "n10file-dec",
        help="Decode an n10 digit file back to binary"
    )
    n10file_dec.add_argument("input", help="Input n10 digit file")
    n10file_dec.add_argument("output", help="Output binary file path")

    kfme = subparsers.add_parser(
        "kFMe",
        help="Encode data into a BaseFWX carrier (image/media->WAV, audio->PNG)"
    )
    kfme.add_argument("input", help="Input file path (audio or image/media)")
    kfme.add_argument("-o", "--output", default=None, help="Output carrier path")
    kfme.add_argument(
        "--bw",
        action="store_true",
        help="When encoding audio->PNG, use black/white static mode"
    )

    kfmd = subparsers.add_parser(
        "kFMd",
        help="Decode BaseFWX carrier (audio/image) back to original payload"
    )
    kfmd.add_argument("input", help="Input carrier file path (audio/image)")
    kfmd.add_argument("-o", "--output", default=None, help="Output file path")
    kfmd.add_argument(
        "--bw",
        action="store_true",
        help="Deprecated no-op (kept for compatibility)"
    )

    kfae = subparsers.add_parser(
        "kFAe",
        help="Deprecated alias for kFMe (auto-detect)"
    )
    kfae.add_argument("input", help="Input file path")
    kfae.add_argument("-o", "--output", default=None, help="Output carrier path")
    kfae.add_argument("--bw", action="store_true", help="When encoding audio->PNG, use black/white static mode")

    kfad = subparsers.add_parser(
        "kFAd",
        help="Deprecated alias for kFMd (auto-detect)"
    )
    kfad.add_argument("input", help="Input carrier file path")
    kfad.add_argument("-o", "--output", default=None, help="Output file path")

    an7 = subparsers.add_parser(
        "an7",
        help="Apply AN7 stealth transform to an encrypted file"
    )
    an7.add_argument("input", help="Input file path")
    an7.add_argument("-p", "--password", required=True, help="Password")
    an7.add_argument("-o", "--out", default=None, help="Output file or directory path")
    an7.add_argument("--keep-input", action="store_true", help="Do not delete input file")
    an7.add_argument("--force-any", action="store_true", help="Allow non-.fwx inputs")

    dean7 = subparsers.add_parser(
        "dean7",
        help="Reverse AN7 stealth transform"
    )
    dean7.add_argument("input", help="Input file path")
    dean7.add_argument("-p", "--password", required=True, help="Password")
    dean7.add_argument("-o", "--out", default=None, help="Output file or directory path")
    dean7.add_argument("--keep-input", action="store_true", help="Do not delete input file")

    args = parser.parse_args(argv)

    _confirm_single_thread_cli()

    if args.command == "version":
        argon2_state = "ON" if basefwx.hash_secret_raw is not None else "OFF"
        pq_state = "ON" if getattr(basefwx.ml_kem_768, "CIPHERTEXT_SIZE", 0) else "OFF"
        lzma_state = "ON" if getattr(basefwx, "lzma", None) is not None else "OFF"
        pillow_state = "ON" if basefwx.Image is not None else "OFF"
        numpy_state = "ON" if basefwx.np is not None else "OFF"
        # Trigger lazy load so `version` accurately reports cupy availability.
        basefwx._ensure_cp()
        cupy_state = "ON" if basefwx.cp is not None else "OFF"
        build_utc = _os_module.getenv("BASEFWX_BUILD_UTC", "unavailable")
        print(f"basefwx_python {basefwx.ENGINE_VERSION}")
        print(f"build_time: {build_utc}")
        print(f"build_origin: {_python_build_origin_label()}")
        print(f"os: {_sys_module.platform}")
        print(f"arch: {_runtime_arch_label()}")
        print("linkage: python")
        print(f"python: {basefwx.sys.version.split()[0]}")
        print("gpg_fingerprint: none")
        print("gpg_signature: not checked (release signatures are detached)")
        print(
            "features: "
            f"argon2={argon2_state} oqs={pq_state} lzma={lzma_state} "
            f"pillow={pillow_state} numpy={numpy_state} cupy={cupy_state}"
        )
        return 0

    if args.command in {"info", "probe", "identify"}:
        return _run_inspect(args.command, args.file, bool(args.json))

    if args.command == "n10-enc":
        print(basefwx.n10encode(args.text))
        return 0

    if args.command == "n10-dec":
        try:
            print(basefwx.n10decode(args.digits))
            return 0
        except Exception as exc:
            print(theme.err(f"n10 decode failed: {exc}"))
            return 1

    if args.command == "n10file-enc":
        try:
            in_path = basefwx.pathlib.Path(args.input)
            out_path = basefwx.pathlib.Path(args.output)
            out_path.write_text(basefwx.n10encode_bytes(in_path.read_bytes()), encoding="utf-8")
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"n10 file encode failed: {exc}"))
            return 1

    if args.command == "n10file-dec":
        try:
            in_path = basefwx.pathlib.Path(args.input)
            out_path = basefwx.pathlib.Path(args.output)
            out_path.write_bytes(basefwx.n10decode_bytes(in_path.read_text(encoding="utf-8")))
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"n10 file decode failed: {exc}"))
            return 1

    if args.command == "kFMe":
        try:
            out_path = basefwx.kFMe(args.input, args.output, bw_mode=args.bw)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFMe failed: {exc}"))
            return 1

    if args.command == "kFMd":
        try:
            out_path = basefwx.kFMd(args.input, args.output, bw_mode=args.bw)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFMd failed: {exc}"))
            return 1

    if args.command == "kFAe":
        try:
            out_path = basefwx.kFAe(args.input, args.output, bw_mode=args.bw)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFAe failed: {exc}"))
            return 1

    if args.command == "kFAd":
        try:
            out_path = basefwx.kFAd(args.input, args.output)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFAd failed: {exc}"))
            return 1

    if args.command == "an7":
        try:
            out_path = basefwx.an7_file(
                args.input,
                args.password,
                out=args.out,
                keep_input=args.keep_input,
                force_any=args.force_any,
            )
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"an7 failed: {exc}"))
            return 1

    if args.command == "dean7":
        try:
            result = basefwx.dean7_file(
                args.input,
                args.password,
                out=args.out,
                keep_input=args.keep_input,
            )
            print(theme.ok(f"Wrote {result['output_path']}"))
            return 0
        except Exception as exc:
            print(theme.err(f"dean7 failed: {exc}"))
            return 1

    if args.command == "cryptin":
        prev_progress_telemetry = _os_module.getenv("BASEFWX_PROGRESS_TELEMETRY")
        prev_master_pub_override = getattr(basefwx, "_MASTER_PUBKEY_OVERRIDE", None)
        if args.no_stats:
            _os_module.environ["BASEFWX_PROGRESS_TELEMETRY"] = "0"
        elif args.stats:
            _os_module.environ["BASEFWX_PROGRESS_TELEMETRY"] = "1"
        try:
            method = args.method.lower()
            password = args.password or ""
            use_master = args.use_master
            if args.strip_metadata:
                use_master = False
            if not args.obfuscate:
                basefwx.ENABLE_OBFUSCATION = False
            try:
                master_pub_bytes = basefwx._resolve_master_pubkey_path(args.master_pub_path)
            except FileNotFoundError as exc:
                print(theme.err(f"Failed to load master public key: {exc}"))
                return 1
            basefwx._set_master_pubkey_override(master_pub_bytes)
            method_map = {
                "512": "b512",
                "b512": "b512",
                "fwx512": "b512",
                "fwxaes": "fwxaes",
                "fwxaes-light": "fwxaes",
                "fwxaes-heavy": "fwxaes-heavy",
                "aes": "aes-light",
                "aes-light": "aes-light",
                "256": "aes-light",
                "light": "aes-light",
                "aes-heavy": "fwxaes-heavy",
                "heavy": "fwxaes-heavy",
                "pb512": "fwxaes-heavy",
                "aes512": "fwxaes-heavy"
            }

            normalized = method_map.get(method)
            if not normalized:
                parser.error(f"Unsupported method '{args.method}'")

            if normalized in {"b512", "aes-light", "fwxaes-heavy"}:
                hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
                    f"cryptin-{normalized}",
                    stream_type="bytes",
                    allow_pixel_gpu=False,
                    prefer_cpu_decode=True,
                )
                basefwx.MediaCipher._log_hw_execution_plan(hw_plan)

            if normalized in {"fwxaes", "fwxaes-heavy"}:
                results = {}
                for raw_path in args.paths:
                    try:
                        basefwx.fwxAES_file(
                            raw_path,
                            password,
                            use_master=use_master,
                            heavy=(normalized == "fwxaes-heavy"),
                            strip_metadata=args.strip_metadata,
                            normalize=args.normalize,
                            normalize_threshold=args.normalize_threshold,
                            cover_phrase=args.cover_phrase,
                            compress=args.compress,
                            ignore_media=args.ignore_media,
                            keep_meta=args.keep_meta,
                            archive_original=args.archive_original,
                            keep_input=args.keep_input
                        )
                        results[str(raw_path)] = "SUCCESS!"
                    except Exception as exc:
                        results[str(raw_path)] = f"FAIL! {exc}"
                result = results if len(args.paths) > 1 else next(iter(results.values()))
            elif normalized == "b512":
                result = basefwx.b512file(
                    args.paths,
                    password,
                    strip_metadata=args.strip_metadata,
                    use_master=use_master,
                    master_pubkey=master_pub_bytes,
                    compress=args.compress,
                    keep_input=args.keep_input
                )
            elif normalized == "aes-light":
                result = basefwx.AESfile(
                    args.paths,
                    password,
                    light=True,
                    strip_metadata=args.strip_metadata,
                    use_master=use_master,
                    master_pubkey=master_pub_bytes,
                    compress=args.compress,
                    keep_input=args.keep_input
                )
            else:
                # parser.error() calls SystemExit; the return is for static-analysis
                # readability so 'result' is never reached uninitialised.
                parser.error(f"Unsupported method '{args.method}'")
                return 2

            if isinstance(result, dict):
                failures = 0
                for path, status in result.items():
                    if status == "SUCCESS!":
                        print(theme.ok(f"{path}: {status}"))
                    else:
                        print(theme.err(f"{path}: {status}"))
                    if status != "SUCCESS!":
                        failures += 1
                return 0 if failures == 0 else 1

            # Print an extra newline to ensure separation from progress output
            if result == "SUCCESS!":
                print(theme.ok(result))
            else:
                print(result)
            return 0 if result == "SUCCESS!" else 1
        finally:
            if prev_progress_telemetry is None:
                _os_module.environ.pop("BASEFWX_PROGRESS_TELEMETRY", None)
            else:
                _os_module.environ["BASEFWX_PROGRESS_TELEMETRY"] = prev_progress_telemetry
            basefwx._set_master_pubkey_override(prev_master_pub_override)

    return 0


def main(argv=None) -> int:
    try:
        return cli(argv)
    except KeyboardInterrupt:
        print("Exiting...")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
