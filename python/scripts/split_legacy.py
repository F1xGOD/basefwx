#!/usr/bin/env python3
"""Extract legacy.py clusters into organized implementation packages."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "basefwx"
LEGACY = PKG / "legacy.py"

HEADER = """# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

\"\"\"Extracted implementation cluster from legacy.py.\"\"\"

from __future__ import annotations

"""

LAZY_SHIM = """
class _LazyEngine:
    \"\"\"Resolve basefwx attributes after legacy finishes loading.\"\"\"

    def __getattr__(self, name: str):
        from ..legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

"""

# Batch 1 is standalone (no lazy shim). Others use lazy shim.
STANDALONE_MODULES = {"_primitives"}

BATCH_MODULES: dict[str, list[str]] = {
    "_primitives": [
        "_env_int",
        "_perf_mode_enabled",
        "_use_fast_obfuscation",
        "_get_available_ram_mib",
        "_check_ram_for_argon2",
        "_fast_b32hexencode",
        "_fast_b32hexdecode",
        "_require_pil",
        "_human_readable_size",
        "_del",
        "_hkdf",
        "_splitmix64",
        "_permute_inplace",
        "_unpermute_inplace",
        "_xor_keystream_inplace",
        "_hkdf_sha256",
        "_hkdf_stream_sha256",
        "_aead_encrypt",
        "_aead_decrypt",
        "generate_random_string",
        "b64encode",
        "b64decode",
        "hash512",
        "uhash513",
    ],
    "_codecs_str": [
        "_mdcode_ascii",
        "_mcode_digits",
        "_code_chunk",
        "_code_bytes",
        "code",
        "decode",
        "fwx256bin",
        "fwx256unbin",
        "_fwx256bin_bytes",
        "_b32_padding_count",
        "_coerce_text",
        "b256encode",
        "b256decode",
        "a512encode",
        "a512decode",
        "bi512encode",
        "_strip_leading_zeros",
        "_compare_magnitude",
        "_decimal_diff",
        "_add_magnitude",
        "_subtract_magnitude",
        "_add_signed",
    ],
    "_codecs_n10": [
        "_n10_mod_sub",
        "_n10_mix64",
        "_n10_offset",
        "_n10_ensure_offsets",
        "_n10_transform",
        "_n10_inverse_transform",
        "_n10_parse_fixed10",
        "_n10_fnv1a32",
        "n10encode",
        "n10encode_bytes",
        "n10decode",
        "n10decode_bytes",
    ],
    "_progress": ["_ProgressReporter"],
    "_obf": [
        "_obfuscate_bytes",
        "_deobfuscate_bytes",
        "_mask_payload",
        "_looks_like_base64",
        "_maybe_obfuscate_codecs",
        "_maybe_deobfuscate_codecs",
        "_bytes_to_bits",
        "_bits_to_bytes",
        "normalize_wrap",
        "normalize_unwrap",
        "_StreamObfuscator",
    ],
    "_kdf": [
        "_coerce_password_bytes",
        "_harden_kdf_params",
        "_fwxaes_iterations",
        "_kdf_pbkdf2_raw",
        "_derive_user_key_argon2id",
        "_derive_user_key_pbkdf2",
        "_derive_user_key",
        "_derive_key_material",
        "derive_key_from_text",
        "encryptAES",
        "decryptAES",
    ],
    "_file_ops": [
        "_build_metadata",
        "_decode_metadata",
        "_split_metadata",
        "_split_with_delims",
        "_apply_strip_attributes",
        "_remove_input",
        "_pack_mode_for_path",
        "_pack_input_to_archive",
        "_is_safe_tar_path",
        "_unpack_archive",
        "_pack_flag_from_meta",
        "_maybe_unpack_output",
        "_warn_on_metadata",
        "_normalize_path",
        "_ensure_existing_file",
        "_ensure_size_limit",
        "_resolve_password",
        "_coerce_file_list",
        "_is_seekable",
        "_is_pathlike_target",
        "_wrap_pack_header",
        "_unwrap_pack_header",
    ],
    "_an7": [
        "an7_file",
        "dean7_file",
    ],
    "_fwxaes": [
        "fwxAES_encrypt_raw",
        "fwxAES_decrypt_raw",
        "fwxAES_encrypt_stream",
        "fwxAES_decrypt_stream",
        "_live_nonce",
        "_live_aad",
        "_live_pack_frame",
        "LiveEncryptor",
        "LiveDecryptor",
        "fwxAES_live_encrypt_chunks",
        "fwxAES_live_decrypt_chunks",
        "fwxAES_live_encrypt_stream",
        "fwxAES_live_decrypt_stream",
        "fwxAES_live_encrypt_ffmpeg",
        "fwxAES_live_decrypt_ffmpeg",
        "fwxAES_file",
    ],
    "_kfm": [
        "_ensure_cp",
        "kFMe",
        "kFMd",
        "_kfae_legacy_encode",
        "kFAe",
        "kFAd",
    ],
    "_master_key": [
        "_decode_pubkey_bytes",
        "_set_master_pubkey_override",
        "_resolve_master_pubkey_path",
        "_load_master_pq_public",
        "_load_master_pq_private",
        "_load_master_ec_public",
        "_load_master_ec_private",
        "_write_ec_keypair",
        "_ec_kem_enc",
        "_ec_kem_dec",
        "_resolve_master_usage",
        "_kem_derive_key",
        "_prepare_mask_key",
        "_recover_mask_key_from_blob",
        "_kem_shared_to_digits",
        "_pq_wrap_secret",
        "_pq_unwrap_secret",
        "_pq_unwrap_secret_with_shared",
    ],
    "_jmg": [
        "_jmg_security_profile_id",
        "_jmg_video_enabled",
        "_jmg_stream_info_for_profile",
        "_jmg_archive_info_for_profile",
        "_jmg_build_key_header",
        "_jmg_profile_from_key_header",
        "_jmg_parse_key_header",
        "_jmg_prepare_keys",
        "_append_balanced_trailer",
        "_extract_balanced_trailer_from_bytes",
        "_extract_balanced_trailer_info",
    ],
    "_b512file": [
        "_pack_length_prefixed",
        "_unpack_length_prefixed",
        "_resolve_payload_length_from_file_size",
        "_estimate_aead_blob_size",
        "pb512encode",
        "pb512decode",
        "_pb512decode_legacy",
        "b512encode",
        "b512decode",
        "_b512decode_legacy",
        "_b512_encode_path",
        "_b512_encode_path_stream",
        "_b512_decode_path",
        "_b512_decode_path_stream",
        "_aes_heavy_encode_path_stream",
        "b512file_encode",
        "b512file",
        "b512file_decode",
        "b512file_encode_bytes",
        "b512file_decode_bytes",
        "pb512file_encode_bytes",
        "pb512file_decode_bytes",
    ],
    "_aes_file": [
        "_aes_light_encode_path",
        "_aes_light_decode_path",
        "_aes_heavy_encode_path",
        "_aes_heavy_decode_path",
        "_aes_heavy_decode_path_stream",
        "AESfile",
    ],
    "_media": ["ImageCipher", "MediaCipher"],
}

MODULE_PACKAGES = {
    "_aes_file": "crypto",
    "_an7": "crypto",
    "_codecs_n10": "crypto",
    "_codecs_str": "crypto",
    "_fwxaes": "crypto",
    "_jmg": "crypto",
    "_kdf": "crypto",
    "_kfm": "crypto",
    "_master_key": "crypto",
    "_obf": "crypto",
    "_primitives": "crypto",
    "_b512file": "file",
    "_file_ops": "file",
    "_media": "media",
    "_progress": "runtime",
}

# Class-body calls that must use _primitives directly after extraction.
CLASS_BODY_PRIM_CALLS = {
    "_env_int": "_prim._env_int",
    "_check_ram_for_argon2": "_prim._check_ram_for_argon2",
}


def unwrap_method(seg: str) -> str:
    lines = seg.splitlines()
    while lines and lines[0].strip().startswith("@"):
        lines.pop(0)
    if not lines:
        return ""
    wrapped = "class _Extract:\n" + "\n".join(
        line if line.startswith(" ") else "    " + line for line in lines
    )
    tree = ast.parse(wrapped)
    cls = tree.body[0]
    assert isinstance(cls, ast.ClassDef)
    for node in cls.body:
        if isinstance(node, ast.FunctionDef):
            return ast.unparse(node) + "\n"
    return seg + "\n"


def unwrap_inner_class(seg: str) -> str:
    lines = seg.splitlines()
    wrapped = "class _Extract:\n" + "\n".join(
        line if line.startswith(" ") else "    " + line for line in lines
    )
    tree = ast.parse(wrapped)
    cls = tree.body[0]
    assert isinstance(cls, ast.ClassDef)
    for node in cls.body:
        if isinstance(node, ast.ClassDef):
            return ast.unparse(node) + "\n"
    return seg + "\n"


def find_member(tree: ast.Module, source: str, name: str) -> tuple[str, bool] | None:
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "basefwx":
            continue
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.ClassDef)) and item.name == name:
                seg = ast.get_source_segment(source, item)
                if seg is None:
                    return None
                is_class = isinstance(item, ast.ClassDef)
                return (unwrap_inner_class(seg) if is_class else unwrap_method(seg), is_class)
    return None


MODULE_IMPORT_ALIAS = {
    "_primitives": "_prim",
}


def module_ref(mod: str) -> str:
    return MODULE_IMPORT_ALIAS.get(mod, mod)


def module_path(mod: str) -> Path:
    package = MODULE_PACKAGES[mod]
    target_dir = PKG / package
    target_dir.mkdir(exist_ok=True)
    (target_dir / "__init__.py").touch(exist_ok=True)
    return target_dir / f"{mod}.py"


def module_import_line(mod: str) -> str:
    package = MODULE_PACKAGES[mod]
    alias = " as _prim" if mod == "_primitives" else ""
    return f"from .{package} import {mod}{alias}"


def patch_legacy(source: str, delegations: dict[str, str]) -> str:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    replacements: list[tuple[int, int, str]] = []

    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "basefwx":
            continue
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.ClassDef)):
                continue
            if item.name not in delegations:
                continue
            mod = delegations[item.name]
            mref = module_ref(mod)
            indent = "    "
            if isinstance(item, ast.ClassDef):
                replacement = f"{indent}{item.name} = {mref}.{item.name}\n"
            elif any(
                isinstance(d, ast.Name) and d.id == "staticmethod"
                for d in getattr(item, "decorator_list", [])
            ):
                replacement = f"{indent}{item.name} = staticmethod({mref}.{item.name})\n"
            elif any(
                isinstance(d, ast.Name) and d.id == "classmethod"
                for d in getattr(item, "decorator_list", [])
            ):
                replacement = f"{indent}{item.name} = classmethod({mref}.{item.name})\n"
            else:
                replacement = f"{indent}{item.name} = {mref}.{item.name}\n"
            if isinstance(item, ast.FunctionDef) and item.decorator_list:
                start = min(d.lineno for d in item.decorator_list) - 1
            else:
                start = item.lineno - 1
            end = item.end_lineno
            replacements.append((start, end, replacement))
        break

    for start, end, replacement in sorted(replacements, key=lambda t: t[0], reverse=True):
        lines[start:end] = [replacement]

    patched = "".join(lines)

    # Class-body direct calls for primitives used during class definition.
    if "_prim._env_int" not in patched:
        patched = patched.replace(
            "_TEST_KDF_ITERS = _env_int(",
            "_TEST_KDF_ITERS = _prim._env_int(",
        )
        patched = patched.replace(
            "_USER_KDF_ITERS_ENV = _env_int(",
            "_USER_KDF_ITERS_ENV = _prim._env_int(",
        )
        patched = patched.replace(
            "_HEAVY_PBKDF2_ITERS_ENV = _env_int(",
            "_HEAVY_PBKDF2_ITERS_ENV = _prim._env_int(",
        )
        patched = patched.replace(
            "_FWXAES_PBKDF2_ITERS_ENV = _env_int(",
            "_FWXAES_PBKDF2_ITERS_ENV = _prim._env_int(",
        )
        patched = patched.replace(
            "_HAS_SUFFICIENT_RAM = _check_ram_for_argon2()",
            "_HAS_SUFFICIENT_RAM = _prim._check_ram_for_argon2()",
        )

    return patched


def add_imports(source: str, modules: list[str]) -> str:
    import_block = "\n".join(module_import_line(m) for m in modules)
    # Insert after version import block
    marker = "_BASEFWX_ENGINE_VERSION = \"0.0.0\"\n\n\n"
    if marker in source:
        return source.replace(marker, marker + import_block + "\n\n")
    marker2 = "except Exception:  # pragma: no cover - fallback for direct execution\n    _BASEFWX_ENGINE_VERSION = \"0.0.0\"\n\n\n"
    return source.replace(marker2, marker2 + import_block + "\n\n")


def fix_module_level_int_limit(source: str) -> str:
    old = """# Enable large integer string conversion for performance-critical decimal math
if hasattr(_sys_module, "set_int_max_str_digits"):
    _sys_module.set_int_max_str_digits(0)  # 0 = unlimited


"""
    return source.replace(old, "")


def remove_init_int_limit(source: str) -> str:
    return re.sub(
        r"\n    def __init__\(self\):\n        self\.sys\.set_int_max_str_digits\(2000000000\)\n        pass\n",
        "\n",
        source,
        count=1,
    )


def extract_cli(source: str) -> tuple[str, str]:
    """Move cli/main block to _cli.py."""
    idx = source.find("\ndef cli(argv=None)")
    if idx < 0:
        raise RuntimeError("cli() not found")
    head = source[:idx]
    tail = source[idx + 1 :]  # skip leading newline
    cli_mod = HEADER + "import os as _os_module\nimport sys as _sys_module\n\n"
    cli_mod += "from ..crypto._primitives import (\n"
    cli_mod += "    _enable_large_int_string_conversion_for_cli,\n"
    cli_mod += "    _python_build_origin_label,\n"
    cli_mod += "    _runtime_arch_label,\n"
    cli_mod += ")\n\n"
    cli_mod += "from ..legacy import basefwx\n\n"
    cli_mod += tail
    cli_mod = cli_mod.replace(
        "basefwx._warn_single_thread_api()",
        "",
    )
    # cli should call large-int helper at start
    cli_mod = cli_mod.replace(
        "def cli(argv=None) -> int:\n    import argparse",
        "def cli(argv=None) -> int:\n    _enable_large_int_string_conversion_for_cli()\n    import argparse",
    )
    head = head.rstrip() + "\n\nbasefwx._warn_single_thread_api()\n\nfrom .runtime._cli import cli, main\n"
    # Remove import-time warn call
    head = re.sub(
        r"\n# Emit a one-time warning at import if single-thread override is forced\nbasefwx\._warn_single_thread_api\(\)\n\n",
        "\n",
        head,
    )
    return head, cli_mod


def standalone_primitives_transform(body: str) -> str:
    """Transform extracted primitives to use stdlib/third-party imports."""
    extra_imports = """import base64
import hashlib
import hmac as stdlib_hmac
import os
import os as _os_module
import secrets
import string
import struct
import sys
import sys as _sys_module
import typing
from typing import Optional, Tuple

try:
    import numpy as np
except Exception:  # pragma: no cover
    np = None

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PERM_FAST_MIN = 4 * 1024
OFB_FAST_MIN = 64 * 1024
OBF_INFO_MASK = b'basefwx.obf.mask.v1'
PERF_OBFUSCATION_THRESHOLD = 1 << 20
_B32HEX_ALPHABET = b'0123456789ABCDEFGHIJKLMNOPQRSTUV'
_B32HEX_DECODE_LUT: bytes = bytes(
    [255] * 48 + list(range(10)) + [255] * 7 + list(range(10, 32)) + [255] * 6 +
    list(range(10, 32)) + [255] * 153
)

"""
    body = body.replace("basefwx.np", "np")
    body = body.replace("basefwx._B32HEX_ALPHABET", "_B32HEX_ALPHABET")
    body = body.replace("basefwx._B32HEX_DECODE_LUT", "_B32HEX_DECODE_LUT")
    body = body.replace("basefwx.PERM_FAST_MIN", "PERM_FAST_MIN")
    body = body.replace("basefwx.OFB_FAST_MIN", "OFB_FAST_MIN")
    body = body.replace("basefwx.OBF_INFO_MASK", "OBF_INFO_MASK")
    body = body.replace("basefwx.PERF_OBFUSCATION_THRESHOLD", "PERF_OBFUSCATION_THRESHOLD")
    body = body.replace("basefwx._splitmix64", "_splitmix64")
    body = body.replace("basefwx._hkdf", "_hkdf")
    body = body.replace("basefwx._permute_inplace", "_permute_inplace")
    body = body.replace("basefwx._unpermute_inplace", "_unpermute_inplace")
    body = body.replace("basefwx.hmac.HMAC", "hmac.HMAC")
    body = body.replace("basefwx.hashes.SHA256()", "hashes.SHA256()")
    body = body.replace("basefwx.HKDF(", "HKDF(")
    body = body.replace("basefwx.AESGCM", "AESGCM")
    body = body.replace("basefwx.os.urandom", "os.urandom")
    body = body.replace("basefwx.stdlib_hmac", "stdlib_hmac")
    body = body.replace("basefwx.hashlib", "hashlib")
    body = body.replace("basefwx.struct", "struct")
    body = body.replace("basefwx.base64", "base64")
    body = body.replace("basefwx.secrets", "secrets")
    body = body.replace("basefwx.string", "string")
    body = body.replace("basefwx.sys", "sys")
    body = body.replace("basefwx.Image", "Image")
    body = body.replace("basefwx.typing.Optional", "Optional")
    body = body.replace("basefwx.typing.Tuple", "Tuple")
    body = body.replace("basefwx._perf_mode_enabled()", "_perf_mode_enabled()")
    body = body.replace("basefwx.b512encode", "_lazy_b512encode")
    body = body.replace("basefwx.hashlib", "hashlib")
    body = body.replace("basefwx.os.getenv", "os.getenv")
    lazy_helper = """

def _lazy_b512encode(*args, **kwargs):
    from ..legacy import basefwx as _engine
    return _engine.b512encode(*args, **kwargs)

"""
    return extra_imports + body + lazy_helper


def main() -> int:
    source = LEGACY.read_text(encoding="utf-8")
    source = fix_module_level_int_limit(source)
    source = remove_init_int_limit(source)

    tree = ast.parse(source)
    all_delegations: dict[str, str] = {}
    modules_written: list[str] = []

    for mod, names in BATCH_MODULES.items():
        parts = [HEADER]
        if mod in STANDALONE_MODULES:
            parts.append(
                "import os as _os_module\nimport sys as _sys_module\n\n"
            )
        else:
            parts.append(LAZY_SHIM)
        found: list[str] = []
        missing: list[str] = []
        bodies: list[str] = []
        for name in names:
            hit = find_member(tree, source, name)
            if hit is None:
                missing.append(name)
                continue
            body, is_class = hit
            bodies.append(body)
            found.append(name)
            all_delegations[name] = mod
        if mod == "_primitives":
            rt = """
import os as _os_module
import sys as _sys_module


def _runtime_arch_label() -> str:
    try:
        machine = _os_module.uname().machine.lower()
    except AttributeError:
        machine = ""
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine.startswith("arm"):
        return "arm"
    if machine in ("i386", "i486", "i586", "i686", "x86"):
        return "x86"
    return machine or "unknown"


def _python_build_origin_label() -> str:
    return "GitHub Actions" if _os_module.getenv("GITHUB_ACTIONS") else "local/manual"


def _enable_large_int_string_conversion_for_cli() -> None:
    if hasattr(_sys_module, "set_int_max_str_digits"):
        _sys_module.set_int_max_str_digits(0)


"""
            content = HEADER + rt + standalone_primitives_transform("\n\n".join(bodies))
            module_path(mod).write_text(content, encoding="utf-8")
        else:
            module_path(mod).write_text("".join(parts) + "\n\n".join(bodies), encoding="utf-8")
        modules_written.append(mod)
        print(f"{mod}: {len(found)} ok, missing={missing}")

    # Patch legacy.py delegations (reverse order to preserve line numbers roughly)
    patched = source
    for mod in reversed(modules_written):
        names = [n for n, m in all_delegations.items() if m == mod]
        sub = {n: mod for n in names}
        patched = patch_legacy(patched, sub)

    import_lines = [module_import_line(m) for m in modules_written]
    patched = patched.replace(
        "class basefwx:",
        "\n".join(import_lines) + "\n\n\nclass basefwx:",
        1,
    )

    # Move runtime labels to primitives - remove from legacy top
    patched = re.sub(
        r"def _runtime_arch_label\(\)[\s\S]*?return machine or \"unknown\"\n\n\n",
        "",
        patched,
        count=1,
    )
    patched = re.sub(
        r"def _python_build_origin_label\(\)[\s\S]*?else \"local/manual\"\n\n\n",
        "",
        patched,
        count=1,
    )
    head, cli_mod = extract_cli(patched)
    runtime_dir = PKG / "runtime"
    runtime_dir.mkdir(exist_ok=True)
    (runtime_dir / "__init__.py").touch(exist_ok=True)
    (runtime_dir / "_cli.py").write_text(cli_mod, encoding="utf-8")
    LEGACY.write_text(head, encoding="utf-8")
    print("Wrote runtime/_cli.py and patched legacy.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
