# Protocol known-answer tests (KATs)

Vectors in `vectors.json` are emitted by the C++ reference via
`scripts/gen_protocol_kats.py` → `cpp/tools/protocol_kat_gen.cpp`
(OpenSSL HKDF/X25519 + liboqs ML-KEM).

**Java and Python must match these bytes exactly.** Do not hand-edit
output fields; regenerate from C++ after changing the helpers.

Regeneration validates that both ML-KEM sections are present before it stages
either output. Each fixture is written to a same-directory temporary file and
atomically replaced. The root and Java copies are separate filesystem
operations rather than one transaction; an interruption between replacements
can leave drift, which `scripts/gen_protocol_kats.py --check-copies` detects.

Sections:

- `hkdf_sha256_salted` / `hkdf_sha256_empty_salt`
- `x25519` (plus `all_zero_shared_must_reject`)
- `ml_kem_768` / `ml_kem_1024` (generation fails without liboqs)
