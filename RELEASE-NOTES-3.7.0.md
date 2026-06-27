# BaseFWX 3.7.0 — Release Notes

> **Release status:** loader + wire tag implemented on `main` (2026-06-26).
> Tag and publish only after remote `test_all.sh` passes — see
> [`PLUGIN_3.7.0_HANDOFF.md`](PLUGIN_3.7.0_HANDOFF.md).

> **Headline (when shipped):** blackbox plugin **in production encrypt/decrypt**
> through `basefwx fwxaes-enc/dec --plugin …` plus audit-driven hardening
> from the 3.6.5 queue. Callers ship a `.so` / `.dll` driver that wraps
> the AEAD payload — open-source crypto core, closed-source obfuscation layer.

> 3.6.x → 3.7.0 is **backwards-compatible on the wire** for blobs **without**
> a plugin tag. Plugin-tagged blobs (`algo=0x03`) require 3.7.0+ and the
> matching plugin loaded at decrypt time.

## Plugin (blackbox) core — what's in 3.7.0 vs queued

3.7.0 ships the **complete ABI surface** — the C ABI header
([plugin.h](cpp/include/basefwx/plugin.h)), the C++ helper layer
([plugin.hpp](cpp/include/basefwx/plugin.hpp)) with two macro
variants for Profile-A (`BASEFWX_PLUGIN_DEFINE`) and Profile-B
(`BASEFWX_PLUGIN_DEFINE_KEYED`), the static-embed Registry
([plugin_static.hpp](cpp/include/basefwx/plugin_static.hpp)), and
**five example plugins** covering all three usage profiles:

| Example | Profile | Demonstrates |
| --- | --- | --- |
| `passthrough/` | A | Pure-C minimal viable plugin |
| `xor-rotate/` | A | C++ helper layer + `BASEFWX_PLUGIN_DEFINE` |
| `aead-wrapped-keyed/` | B | Raw-mode-safe keyed plugin (HKDF + AES-256-CTR + HMAC-SHA256) |
| `time-tweak/` | B | Self-derived per-call entropy (unix time embedded in output) |
| `static-embed/` | C | Plugin compiled into host binary; no `.so` on disk |

[examples/plugins/THREAT_MODEL.md](examples/plugins/THREAT_MODEL.md)
is the authoritative document for what each profile defends against.
The short version: a deterministic plugin is fine for traffic-shaping
inside an AEAD layer (Profile A); a keyed plugin with `host_secret`
+ per-call tweak is required for raw-mode use without AEAD wrapping
(Profile B); static embedding is a deployment choice that raises the
cost of plugin extraction but does not provide cryptographic
security on its own (Profile C).

What is **in 3.7.0:** everything above **plus** the C++ host loader
(`cpp/src/plugin_loader.cpp`), fwxAES PRE/POST AEAD integration in C++ /
Java / Python, the wire-format plugin tag, CLI `--plugin` flags, and an
fwxAES round-trip step in `scripts/plugin-smoke.sh`.

Example (C++ CLI, xor-rotate plugin, PRE_AEAD):

```bash
# 32-byte plugin config (xor-rotate requires exactly 32 bytes)
python3 -c 'open("xor.cfg","wb").write(bytes([0x42^i for i in range(32)]))'

basefwx fwxaes-enc secret.txt -p 'your-password' \
  --legacy-pbkdf2 --no-master \
  --plugin /path/to/libbasefwx-xor-rotate.so \
  --plugin-pos pre --plugin-config xor.cfg \
  -o secret.fwx

basefwx fwxaes-dec secret.fwx -p 'your-password' --no-master \
  --plugin /path/to/libbasefwx-xor-rotate.so \
  -o secret.plain
```

What is **NOT** in 3.7.0 and is scoped for 3.7.x point releases:
plugin integration in b512file / pb512file / livecipher, streaming fwxAES
with plugins, the JNI bridge for native `.so` from Java, Profile B
parity on the Java/Python SPI, and the `basefwx-plugin-verify` tool.

### fwxAES plugin wire tag (algo `0x03`)

Immediately after the 16-byte FWX1 fixed header:

| Offset | Size | Field |
| --- | ---: | --- |
| +0 | 16 | `plugin_id` |
| +16 | 1 | `position` (`1` = PRE_AEAD, `2` = POST_AEAD) |
| +17 | 2 | `config_len` (big-endian) |
| +19 | `config_len` | opaque plugin config (passed to `init`) |

Then the usual salt/key_header, IV, and AES-GCM ciphertext follow.
Blobs with `algo=0x01` or `0x02` are unchanged from 3.6.4.

Wire format without a plugin tag is unchanged from 3.6.x.

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
| **Java `KeyWrap` throws typed `UnsupportedKdfException`** for unknown KDF labels, with `getKdfLabel()` for routing. Argon2id is supported since 3.7.0; the exception is only for unrecognized label strings. | Was an opaque `IllegalArgumentException` with a hand-parsed message. |
| **Java / Python KEM shared-secret and AES key wipes** in `KeyWrap`, `FwxAesCodec`, `livecipher.cpp`. | Mirrors C++ `SecureBytes` / `SecureClear` patterns from the audit pass. |
| **Python `BASEFWX_TEST_KDF_ITERS` gated** behind `BASEFWX_TESTING=1`. | Prevents accidental low-cost ciphertext in production shells. |
| **Format `UnpackLengthPrefixed` capped at 64 MiB total** (C++ matches the Java side that's had this cap since 3.4.x). | Previously a malformed blob declaring a 4 GiB part survived to the data.size() check — long enough for upstream pre-sizing code to OOM. |
| **`pq.cpp::ReadFileBytes` caps key files at 4 MiB.** | A symlink under `BASEFWX_MASTER_PQ_PUB` pointing at `/dev/zero` no longer OOMs the process. |
| **LiveCipher refuses to wrap the sequence counter** (C++ + Java). Throws when `sequence_` would advance past 2⁶⁴-1 (C++) / `Long.MAX_VALUE` (Java). | 2⁶⁴ frames is unreasonable, but the existing path silently wrapped → nonce reuse under the same key → breaks AES-GCM. |
| **Java now supports Argon2id** in the user-KDF wrap path via BouncyCastle's `Argon2BytesGenerator` (already a runtime dep). Three-way Argon2id cross-runtime parity verified end-to-end. The COMPATIBILITY.md Java row flips `❌ → ✅`. Typed `UnsupportedKdfException` retained for truly unknown labels. |
| **Argon2id parallelism default is hardcoded to 4** across C++, Java, and Python (`kArgon2Parallelism` / `ARGON2_PARALLELISM` / `basefwx.ARGON2_PARALLELISM`). The wire format does not carry the lane count; pre-3.7.0 each runtime defaulted to `std::thread::hardware_concurrency()` / `Runtime.availableProcessors()` / `os.cpu_count()`, so a blob encrypted on a 16-core machine could not be decrypted on a 4-core machine. Callers who want host-tuned parallelism can still set `KdfOptions.argon2Parallelism` explicitly before encrypt — the default just stops varying. |
| **`b1024` retired** in C++ / Java / Python. Was `Bi512Encode(A512Encode(input))` — no new behavior, ate cross-runtime test time. |
| **🫡 `b256` retired** in C++ / Java / Python. b256 was the very first encoding method in BaseFWX, born in V1 when this was a proof of concept and not a project. Marked deprecated; emits a one-time retirement notice (with ❤️) on first call. Existing blobs still decode. Use base64 / `Hash512` for new code. |
| **`uhash513` deprecated** in C++ / Java / Python. Non-standard chained hash with a SHA-1 hop and misleading "513" name (actual output is 256 bits). The SHA-1 step adds no security and uses a hash with known collision weaknesses. Use `Hash512` (SHA-512) or SHA3-512 for new code. Existing call sites continue to work. |
| **Resource guards for bench / test runners.** `scripts/lib/resource_guards.sh` caps the runner's CPU to `nproc - 1` and bounds virtual memory to 75 % of system RAM by default. `scripts/test_all.sh` and `scripts/plugin-smoke.sh` source it automatically; opt out with `--no-guards` or `BASEFWX_NO_GUARDS=1`. Stops the laptop-OOM failure mode where a bench process accumulates pool memory across heavy methods until KDE / sddm freeze. |
| **Memory-leak detection CI** (`.github/workflows/leak-detect.yml`). Three jobs that each fail the workflow on a leak: Python tracemalloc + RSS slope (`scripts/leak_detect.py`), C++ ASan/LSan probe (`scripts/leak_detect_cpp.sh`), Java heap-delta probe. Catches code-level leaks (missing free, unfreed JNI globalrefs); the resource guards above handle allocator-pool fragmentation at run time. |
| **Benchmark heaviness chips on the website.** `website/results/heaviness.json` classifies each benchmark method by typical peak RSS + wall time (`low` / `medium` / `high` / `extreme`); the Detailed Results panel now renders a colored chip next to each method so visitors can see at a glance which methods can run on a laptop and which need a build box. |

## Integrator / API changes

| What | Why |
| ---- | --- |
| **`BaseFwxImage.java` split from `BaseFwx.java`.** kFM/jMG image-carrier APIs (`kFMe`, `kFMd`, `kFAe`, `kFAd`, `jmgEncryptFile`, `jmgDecryptFile`) moved to `BaseFwxImage`. Core `BaseFwx` no longer imports AWT — Android Gradle sync enabler. **Source breaking:** `BaseFwx.kFMe(...)` → `BaseFwxImage.kFMe(...)`. Wire unchanged. | Desktop-only `MediaCipher.java` still uses AWT; Android sync excludes it. |
| **Monolith decomposition** (C++ filecodec/imagecipher/kfm/CLI; Java BaseFwx/CLI/MediaCipher; Python `legacy.py` modules). | Maintainability; no wire-format change. |
| **`SecureBytes` RAII wrapper** in C++ KEM sites (post-3.6.4 commits). | Replaces raw `SecretGuard` pointer pattern in hot paths. |

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

The ABI lands in 3.7.0 along with Java SPI and Python ctypes (Profile A);
the runtime loader inside CLI/fwxAES, wire-format plugin tags, verifier
tool, and JNI bridge land in 3.7.x point releases — held back deliberately
so the header gets a review window before any code commits to it. Blobs
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
