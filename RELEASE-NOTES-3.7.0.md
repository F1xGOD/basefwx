# BaseFWX 3.7.0 — Release Notes

> **Headline:** the start of the "blackbox plugin" core **plus** the audit-driven
> hardening that was queued for 3.6.5. Callers can now ship a `.so` / `.dll`
> driver that wraps the AEAD payload with custom logic — open-source crypto
> core, closed-source obfuscation layer. The 3.6.5 security fixes (8 High,
> ~10 Medium audit findings) ride along.

> 3.6.x → 3.7.0 is **backwards-compatible on the wire** for blobs that
> don't opt into the plugin layer. Plugin-tagged blobs require a 3.7+
> peer with the matching plugin ID loaded. (3.6.5 was tagged in working
> trees but never released; the headline plugin work warrants the
> minor bump.)

## Plugin (blackbox) core — what's in 3.7.0 vs queued

3.7.0 ships the **public ABI header** (`basefwx/plugin.h`) and a
working example plugin (`examples/plugins/passthrough/`). The runtime
loader, the JNI bridge, the Python `ctypes` shim, the wire-format
plugin-tag bytes, and the `basefwx-plugin-verify` tool are scoped for
the next 3.7.x point releases (sequenced so reviewers can read the
ABI before any code commits to it). See
[examples/plugins/README.md](examples/plugins/README.md) for the
authoring contract.

## TL;DR (security/hardening track)

| What | Why |
| ---- | --- |
| **Password is always literal.** Auto-loading a password from a file path that happens to exist on disk is gone — use the explicit `file://<path>` / `password://<literal>` URI prefixes instead. | Removed a silent reinterpretation: the same user input could wrap two different secrets depending on filesystem state. |
| **PBKDF2-32k second-chance fallback removed.** | Every authenticator failure used to retry decryption with a 20× weaker derivation. Auth failure is now terminal. |
| **fwxAES parser bounds tightened** — `kKdfWrap` header capped at 64 KiB (was 4 MiB), `kKdfPbkdf2` iters must be ≥ 10 000. | The two fields used to share the same 4 bytes with no version byte; a `kdf` byte flip could try to reinterpret one as the other. Tightening the per-mode bounds makes the misinterpretation impossible regardless of AEAD authentication. |
| **`BASEFWX_TEST_KDF_ITERS` gated behind a compile-time flag.** Honored only when built with `-DBASEFWX_TESTING=ON` (C++) or run with `-Dbasefwx.testing=true` / `BASEFWX_TESTING=1` (Java). | In 3.6.4 a production shell that happened to have this env set silently produced low-cost ciphertext indistinguishable on the wire. |
| **Baked master ML-KEM-768 public key removed.** Set your own via build-time `-DBASEFWX_MASTER_PQ_PUB_B64=…` (C++ CMake option) or `-Dbasefwx.master.pq.public.b64=…` (Java sysprop), or runtime `BASEFWX_MASTER_PQ_PUB=<path>` (env). | Upstream artifacts no longer ship with a maintainer-held escrow key; the recovery path is opt-in per deployment. |
| **Removed `BASEFWX_MASTER_PQ_ALLOW_BAKED` / `ALLOW_BAKED_PUB` env knobs.** | They gated the deletion above; gone with the literal. |
| **Removed `BASEFWX_MASTER_EC_CREATE_IF_MISSING` silent EC auto-generation.** | Silently minting a fresh EC master keypair when the configured one was absent produced ciphertext that looked recoverable on the encrypt host and hard-failed everywhere else. |
| **Removed hardcoded Windows `W:\master_pq.sk` private-key path** in `pq.cpp`. Configure via `BASEFWX_MASTER_PQ_SK` or `~/master_pq.sk`. | Old maintainer-machine artifact. |
| **fwxaes key locals are now wiped.** `SecretGuard` threaded through every `Bytes key` / `mask_key` local in `EncryptRaw`, `DecryptRaw`, `EncryptStream`, `DecryptStream`. | 3.6.4 had zero `SecureClear` calls in `fwxaes.cpp` — every PBKDF2-derived AES key sat in the free-list until allocator reuse. |
| **Java `LiveEncryptor` / `LiveDecryptor` implement `AutoCloseable`** and zeroize `password`, `key`, `noncePrefix`, decrypt buffer. | Java mirror previously had no wipe at all. |
| **Java `KeyWrap` throws `UnsupportedKdfException`** for Argon2-wrapped blobs, with `getKdfLabel()` to route to a native helper. | Was an opaque `IllegalArgumentException` with a hand-parsed message. |
| **Format `UnpackLengthPrefixed` capped at 64 MiB total** (C++ matches the Java side that's had this cap since 3.4.x). | Previously a malformed blob declaring a 4 GiB part survived to the data.size() check — long enough for upstream pre-sizing code to OOM. |
| **`pq.cpp::ReadFileBytes` caps key files at 4 MiB.** | A symlink under `BASEFWX_MASTER_PQ_PUB` pointing at `/dev/zero` no longer OOMs the process. |
| **LiveCipher refuses to wrap the sequence counter** (C++ + Java). Throws when `sequence_` would advance past 2⁶⁴-1 (C++) / `Long.MAX_VALUE` (Java). | 2⁶⁴ frames is unreasonable, but the existing path silently wrapped → nonce reuse under the same key → breaks AES-GCM. |
| **Java now supports Argon2id** in the user-KDF wrap path via BouncyCastle's `Argon2BytesGenerator` (already a runtime dep). Three-way Argon2id cross-runtime parity verified end-to-end. The COMPATIBILITY.md Java row flips `❌ → ✅`. Typed `UnsupportedKdfException` retained for truly unknown labels. Parallelism follows `Runtime.availableProcessors()` to match the C++ side; pin `KdfOptions.argon2Parallelism` explicitly if you need Argon2 blobs to round-trip across machines with different core counts (see COMPATIBILITY.md "Argon2 parallelism portability"). |
| **`b1024` retired** in C++ / Java / Python. Was `Bi512Encode(A512Encode(input))` — no new behavior, ate cross-runtime test time. |

The full security-policy stance lives in [SECURITY.md](SECURITY.md);
this document focuses on **what changed in 3.7.0 and what it costs**.

---

## 1. Compatibility

- **Blob format unchanged.** Anything you encrypted with 3.6.4 (PBKDF2 or
  Argon2id, password or wrap, any algorithm tier) decrypts unchanged in 3.7.0,
  including with a `BASEFWX_USER_KDF` override. The bounds tightening only
  rejects pathological values (iteration counts < 10 000, wrap-header > 64 KiB)
  that no legitimate writer ever produced.
- **Old pre-3.x blobs** that relied on the silent PBKDF2-32k fallback during
  decryption no longer decrypt. Those formats were marked
  **"≤ 2.7: Treat as incompatible"** in `SECURITY.md` since 3.x; this release
  enforces that line.
- **CLI / API behavior changes** that may affect existing callers:
  - `--password "/some/path"` no longer reads the file — pass
    `--password "file:///some/path"` instead, or the literal string with
    `--password "password://literal"`.
  - `BASEFWX_MASTER_PQ_ALLOW_BAKED=1` is no longer recognized. Deployments
    that previously relied on it must either:
    - configure their own runtime key with `BASEFWX_MASTER_PQ_PUB=<path>`, or
    - rebuild with `-DBASEFWX_MASTER_PQ_PUB_B64=<base64-key>` (C++) /
      `-Dbasefwx.master.pq.public.b64=<base64-key>` (Java sysprop).
  - `BASEFWX_MASTER_EC_CREATE_IF_MISSING=1` is no longer recognized.
    Provision the EC master keypair out-of-band and point
    `BASEFWX_MASTER_EC_PUB` / `BASEFWX_MASTER_EC_PRIV` at it.
  - `BASEFWX_TEST_KDF_ITERS` is no longer honored in release builds. The
    test suite builds with `-DBASEFWX_TESTING=ON` (C++) and runs Java with
    `-Dbasefwx.testing=true` to keep its fast-path.

## 2. Why this is 3.7.0 and not 3.6.5

The security-fix track is byte-compatible with 3.6.4. On its own it
would have been 3.6.5 (and was, in working trees, briefly). The
**blackbox plugin** core changes the calculus — it's a new optional
wire-format layer that callers can opt into, with a non-trivial
public ABI (`basefwx/plugin.h`) that other people will compile
against. That's the right thing to gate behind a minor bump.

The ABI lands in 3.7.0; the runtime loader, verifier, and JNI/ctypes
bridges land in 3.7.x point releases — held back deliberately so the
header gets a review window before any code commits to it. Blobs
that don't opt into the plugin layer remain byte-identical to 3.6.4.

## 3. Provenance

This release was driven by a code-audit pass against the C++ and Java
trees. The audit findings, their severity ratings, and the rationale
for each fix are recorded in the git history; the audit document
itself lives outside the repository.

## Upgrade

Standard roll-forward — install 3.7.0 over 3.6.4, no migration step.

If you depended on:

- The `--password <path>` auto-load: replace with `--password file://<path>`.
- The baked master public key: configure your own via env or build-time option (see TL;DR).
- The `BASEFWX_MASTER_EC_CREATE_IF_MISSING` auto-generation: provision the EC keypair manually.
- The PBKDF2-32k decryption fallback: re-encrypt affected blobs with the current defaults; 32k-iter blobs are pre-3.x and out of the supported window.
