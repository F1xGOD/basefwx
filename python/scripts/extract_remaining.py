#!/usr/bin/env python3
"""Extract leftover inline methods still in legacy.py into cluster modules."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "basefwx"
LEGACY = ROOT / "legacy.py"

# Import split_legacy helpers
sys.path.insert(0, str(Path(__file__).resolve().parent))
import split_legacy as sl  # noqa: E402

REMAINING: dict[str, list[str]] = {
    "_master_key": [
        "_default_master_ec_public_path",
        "_default_master_ec_private_path",
        "_decode_ec_public_key",
        "_decode_ec_private_key",
    ],
    "_an7": [
        "_an7_read_exact",
        "_an7_random_digits10",
        "_an7_same_path",
        "_an7_ensure_collision_suffix",
        "_an7_make_temp_path",
        "_an7_commit_temp_file",
        "_an7_chunk_bytes_at",
        "_an7_total_chunks",
        "_an7_hmac_sha256",
        "_an7_build_label",
        "_an7_derive_ctr_iv",
        "_an7_apply_xor_transform",
        "_an7_flip_start",
        "_an7_apply_sparse_flip",
        "_an7_build_permutation",
        "_an7_derive_keys",
        "_an7_serialize_trailer",
        "_an7_parse_trailer",
        "_an7_parse_footer_and_derive",
        "_an7_is_ascii_alnum",
        "_an7_sanitize_basename",
        "_an7_sanitize_extension",
        "_an7_resolve_output_path",
        "_an7_resolve_restored_name",
        "_an7_resolve_dean_output_path",
    ],
    "_kfm": [
        "_kfm_clean_ext",
        "_kfm_is_audio_ext",
        "_kfm_is_image_ext",
        "_kfm_warn",
        "_kfm_accel_mode",
        "_kfm_accel_min_bytes",
        "_kfm_should_use_cuda",
        "_kfm_paths_equal",
        "_kfm_default_output",
        "_kfm_resolve_output",
        "_kfm_keystream",
        "_kfm_xor",
        "_kfm_pack_container",
        "_kfm_unpack_container",
        "_kfm_bytes_to_wav",
        "_kfm_wav_to_bytes",
        "_kfm_pcm16le_to_bytes",
        "_kfm_ffmpeg_audio_to_bytes",
        "_kfm_audio_to_bytes",
        "_kfm_bytes_to_png",
        "_kfm_png_to_bytes",
        "_kfm_detect_carrier_kinds",
        "_kfm_decode_container",
    ],
}


def main() -> int:
    source = LEGACY.read_text(encoding="utf-8")
    tree = ast.parse(source)
    all_names: dict[str, str] = {}
    for mod, names in REMAINING.items():
        all_names.update({n: mod for n in names})

    for mod, names in REMAINING.items():
        path = ROOT / f"{mod}.py"
        existing = path.read_text(encoding="utf-8")
        chunks: list[str] = []
        for name in names:
            hit = sl.find_member(tree, source, name)
            if hit is None:
                print(f"missing {name}")
                continue
            body, _ = hit
            chunks.append(body)
        if chunks:
            path.write_text(existing.rstrip() + "\n\n" + "\n\n".join(chunks), encoding="utf-8")
            print(f"appended {len(chunks)} to {mod}.py")

    patched = sl.patch_legacy(source, all_names)
    LEGACY.write_text(patched, encoding="utf-8")
    print(f"legacy.py now {len(patched.splitlines())} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
