# BaseFWX — context for AI agents

> If you're an AI assistant landing in this repo with empty context,
> read this file first. It is intentionally short and points you at
> the right places to learn the rest. Humans can read it too, but
> the existing top-level `README.md` is the right entry point for
> human onboarding — this file is the agent-shaped index.

## 30-second pitch

BaseFWX is a cryptography library that encrypts and decrypts bytes
with a hybrid pipeline: AES-256-GCM AEAD inside, Argon2id / PBKDF2
key derivation, optional ML-KEM-768 master-key wrap on top, optional
AN7 / DEAN7 stealth anonymization layer. It ships in three runtimes —
**C++**, **Java**, **Python** — that all consume the same wire
format. The library is **dual-licensed**: free under GPL-3.0 +
Plugin Exception + Attribution requirement, or via a separate
commercial license sold by FixCraft Inc. for users who need to
opt out of attribution or copyleft. See `LICENCE` (legal text)
and `LICENSING.md` (practical guide). The project owner is
F1xGOD / FixCraft. The current target release is **3.7.0**; the
last shipped release was 3.6.4.

The headline 3.7.0 feature is the **blackbox plugin** core: callers
can ship a `.so` / `.dll` / `.jar` driver that wraps the AEAD payload
with custom obfuscation logic, keeping the crypto core open-source
while letting deployments add **closed-source plugin artifacts** on
top (see `LICENSING.md` for the safe-harbor rules — modifying the
core stays GPL-copyleft, only dynamically-loaded plugin artifacts
get the closed-source exemption).

## Three-tree layout

```
~/yume                        ← the YUME desktop project (C++ network transport)
   ├── src/                       transport code
   ├── basefwx/                   ← this repo, vendored as a sibling working
   │                                tree. NOT a git submodule. basefwx is
   │                                gitignored from yume.
   └── ...
~/AndroidStudioProjects/Yume  ← the Android client. Pulls C-shared engine
                                files + Java sources from ~/yume at Gradle
                                config time. Read-only consumer of basefwx.
```

You will almost always be working inside `~/yume/basefwx/`. The two
other trees consume the engine; edits flow basefwx → yume → Android,
never the other way.

See `../.claude/projects/.../memory/project_layout.md` for the full
explanation of the three-repo dance.

## What's where, in this repo

| Path | What |
| --- | --- |
| `cpp/include/basefwx/` | Public C / C++ headers. `plugin.h` is the C ABI for blackbox plugins, `plugin.hpp` is the C++ author-helper layer. |
| `cpp/src/` | C++ implementations. `crypto.cpp` (primitives), `keywrap.cpp` (password+ML-KEM wrap), `fwxaes.cpp` (the primary file format), `livecipher.cpp` (streaming AEAD), `an7.cpp` (stealth anon), `pq.cpp` (liboqs binding). |
| `java/src/main/java/com/fixcraft/basefwx/` | Java mirror of the same crypto primitives. Constants.java + Crypto.java + KeyWrap.java + FwxAES*.java + LiveCipher.java are the cross-language pairings. |
| `python/basefwx/` | Python runtime. `__init__.py` is the public API surface, `legacy.py` holds the big single-file impl. |
| `examples/plugins/` | Reference plugins for the blackbox system. `passthrough/` (pure C, identity transform) and `xor-rotate/` (C++, uses the helper layer). Read these to learn the ABI. |
| `tools/plugin-verifier/` | Design doc for the plugin verifier tool (`DESIGN.md`). |
| `scripts/test_all.sh` | The cross-runtime test orchestrator. Runs C++ + Java + Python suites and compares timings. |
| `SECURITY.md` | Cryptographic stance, support policy, master-key opt-in semantics. Read before changing anything in `keywrap.cpp` / `pq.cpp`. |
| `LICENCE` | Legal text — GPL-3.0 + Additional Terms (Plugin Exception, Attribution requirement, commercial-license notice). |
| `LICENSING.md` | Practical guide to the dual-license model + the plugin exception (what plugin authors can and cannot ship closed-source). |
| `CONTRIBUTING.md` | Contribution process + the one-page CLA every non-trivial contributor signs (keeps the dual-license model intact). |
| `COMPATIBILITY.md` | Runtime capability matrix (which runtime supports what). Argon2id parallelism portability note lives here. |
| `CHANGELOG.md` | Per-version changes. The "Unreleased" / "[v3.7.0]" section is the active work. |
| `RELEASE-NOTES-3.7.0.md` | Long-form notes for the upcoming release. |
| `VERSION` | Single-line version string. Currently `3.7.0`. All language runtimes read it at build time. |

## The crypto-conventions skill (cross-tree authoring rules)

A sibling skill lives in the Yume repo at
`~/yume/.claude/skills/crypto-conventions/SKILL.md`. It encodes the
twelve rules for writing or reviewing crypto changes across the C++,
Java, and Android trees. Read it before touching anything in
`crypto.cpp` / `keywrap.cpp` / `Crypto.java` / `KeyWrap.java` /
`fwxaes.cpp`. The rules with the highest blast-radius:

1. Use `basefwx::crypto::` / `Crypto.java` helpers, never raw OpenSSL or JCA.
2. Wipe key material — `SecretGuard` in C++, `Arrays.fill(…, (byte)0)` in Java, `SecretBuffer` for new plugin code.
3. Constants live in `constants.hpp` / `Constants.java` and must stay in sync.
4. HKDF info strings and AEAD AAD are versioned (`yume-inner-v1`, `basefwx.fwxaes.payload.aead.v1`). Bumping semantics under the same label silently breaks every peer.
5. Wire format is frozen at v1.x — changes require `kVersion` bump.
6. Java `KeyWrap` supports Argon2id since 3.7.0 (via BC's `Argon2BytesGenerator`). The legacy "Java rejects Argon2" line is gone; the parallelism quirk is documented in COMPATIBILITY.md.
7. Embedded master PQ key is OFF by default — `BASEFWX_MASTER_PQ_PUB=<path>` (runtime) or `-DBASEFWX_MASTER_PQ_PUB_B64=…` (build time) are the supported configuration paths.

## The blackbox plugin contract (new in 3.7.0)

The contract has three layers; pick the one that matches your task.

**Adding a plugin.** Start at `examples/plugins/README.md`. Copy
`passthrough/` (C) or `xor-rotate/` (C++) and edit. The plugin's
`forward` and `inverse` functions are the only required logic;
`BASEFWX_PLUGIN_DEFINE(...)` in `plugin.hpp` generates the C-ABI
glue for you.

**Implementing the host-side loader.** The C ABI is in
`cpp/include/basefwx/plugin.h`. The loader is responsible for:
`dlopen`, `dlsym basefwx_plugin_entry`, ABI version check, calling
`init` with the caller-supplied config, applying `forward` /
`inverse` at the chosen position, calling `destroy` at teardown.
The wire-format plugin tag (16-byte `plugin_id` + position bits) is
the receiver's hint for which plugin to load.

**Verifying a plugin.** `tools/plugin-verifier/DESIGN.md` is the
spec the `basefwx-plugin-verify` tool conforms to. Run it against
any `.so` to confirm ABI conformance, round-trip safety, and
metadata sanity.

## Where to start for common agent tasks

| If the user asks about… | Start in… |
| --- | --- |
| Fixing or auditing crypto code | `~/yume/.claude/skills/crypto-conventions/SKILL.md` — read the twelve rules first |
| Authoring a plugin | `examples/plugins/README.md` then `examples/plugins/xor-rotate/xor_rotate.cpp` |
| Cross-runtime parity issue | `scripts/test_all.sh` is the orchestrator; the file-by-file pairings table is in the crypto-conventions skill |
| Wire-format question | `SECURITY.md` ("default encryption" section) + `cpp/src/fwxaes.cpp` (the header layout is the most-used format) |
| Build / packaging | `cpp/CMakeLists.txt`, `java/build.gradle`, `python/pyproject.toml`. Heavy builds run on `192.168.1.165` per `dev_remote.md`. |
| Running tests | `scripts/test_all.sh` — but it's slow. For a quick smoke, build `cpp/build/basefwx` and do an `fwxaes-enc` / `fwxaes-dec` round-trip. |
| Java ↔ C++ Argon2 issue | COMPATIBILITY.md "Argon2 parallelism portability" section — parallelism follows host CPU count |
| What's changing in 3.7.0 | `CHANGELOG.md` "[v3.7.0]" + `RELEASE-NOTES-3.7.0.md` |

## Heavy builds — use the remote box

The user's laptop freezes under sustained CPU load. Heavy builds
and the full `test_all.sh` suite run on the remote at
`192.168.1.165` (hostname `raptorlake`, 32 cores, 62 GiB RAM, gcc 14,
javac 25, cmake 3.31). Passwordless SSH is set up from the laptop.

Typical flow:
```bash
rsync -az --delete \
  --exclude .git --exclude build --exclude build-fix --exclude build-remote \
  --exclude '.gradle' --exclude 'java/build' --exclude 'cpp/build' \
  --exclude '__pycache__' --exclude '*.pyc' --exclude '.tmp_basefwx_tests' \
  ~/yume/basefwx/ 192.168.1.165:~/yume/basefwx/
ssh 192.168.1.165 'cd ~/yume/basefwx && cmake -S cpp -B build-remote && cmake --build build-remote -j$(nproc)'
```

For one-shot smokes the laptop is fine. For anything larger, sync
and build remotely.

## Project memory — what's already documented

User-level memory for AI agents working on this repo lives under
`~/.claude/projects/-home-f1xgod-yume/memory/`. The current entries:

| File | Subject |
| --- | --- |
| `project_layout.md` | Three-repo layout, Android sync logic |
| `android_i18n.md` | Per-language Kotlin maps, English-as-key convention |
| `android_apk_size.md` | What shrank the APK |
| `user_preferences.md` | F1xGOD's collaboration style |
| `codeql_state.md` | What's fixed in source vs dismissed |
| `feedback_skill_purpose.md` | "A skill" here means code-writing, not run-skill-generator |
| `dev_remote.md` | The 192.168.1.165 remote build machine |

You can read and append to these. Keep them terse — the memory
system is for things that are surprising or not derivable from
the code itself. Anything that `git log` or `grep` can find belongs
in the code, not here.

## Anti-patterns specific to this project

- **Don't add a new `Bi512Encode` / `A512Encode` derivative.** Both
  are deprecated as of 3.7.0 — they're "SHA-256 with a custom
  prefilter" (bi512) and "reversible obfuscation with no security
  goal" (a512). Use `Hash512` / `Uhash513` for hashes; use base64
  or `B256Encode` for reversible encoding. The retired `b1024` was
  the canonical bad example — a one-line alias.
- **Don't add an env var that silently weakens crypto.** Anything
  that can downgrade a KDF cost has to be compile-time gated
  (`#ifdef BASEFWX_TESTING`) — see the 3.7.0 changelog for the
  `BASEFWX_TEST_KDF_ITERS` cleanup.
- **Don't write a `[[deprecated]]` without a migration path.** Each
  3.7.0 deprecation in `basefwx.hpp` says exactly what to use
  instead. Match that pattern.
- **Don't try to use `b1024` in tests.** It's gone. Look for the
  comment "b1024 retired in 3.6.5" — there are tombstones in
  `scripts/test_all.sh` and `legacy.py` so an agent re-adding it
  by mistake hits them immediately.

## Last thing — the README

The top-level `README.md` is human-targeted. It assumes you know
what BaseFWX is and want install / quick-start. This file
(`AGENTS.md`) is for agents starting from zero. If you need to
update one and the change is structural (file moved, contract
changed), update both.
