# BaseFWX — context for AI agents

> If you're an AI assistant landing in this repo with empty context,
> read this file first. It is intentionally short and points you at
> the right places to learn the rest. Humans can read it too, but
> the existing top-level `README.md` is the right entry point for
> human onboarding — this file is the agent-shaped index.

## ⚠️ READ FIRST — DO NOT RUN HEAVY WORK ON THIS MACHINE

**This is the user's daily-driver laptop, ~16 GiB RAM.** Do **not**
run `scripts/test_all.sh`, any benchmark phase, Argon2id at default
memory cost, `gradle test` cold-cache, multi-runtime parity sweeps
(C++ + Java + Python + PyPy together), or anything else that
sustains CPU for more than ~30s or pushes RAM past ~60 %. When you
ignore this, the laptop OOM-kills KDE / sddm / background apps,
TTY-switching hangs, and the offending process is very hard to
kill. There is an incident on record from a prior session that
caused exactly this.

**Where heavy work runs:** `192.168.1.165` (hostname `raptorlake`,
32 cores, 62 GiB RAM, passwordless SSH from this laptop). **Always
ask the user** which target to use before you `ssh` — they may have
a different host up, or want to skip the run.

**Mandatory workflow for heavy commands:**

1. **Stop, ask the user** "which host should I run this on?" — do
   not assume `192.168.1.165` is the right answer today.
2. After confirmation, rsync the active subtree:
   ```
   rsync -az --delete \
     --exclude .git --exclude build --exclude '.gradle' \
     --exclude 'cpp/build' --exclude 'java/build' \
     ~/yume/basefwx/ <host>:~/yume/basefwx/
   ```
3. Run the command over SSH on that host.
4. `rsync` artifacts back if needed.
5. Commit + push from this laptop, not the remote.

**OK locally (cheap, bounded):** source edits, single-plugin example
builds (`cmake --build` of one `examples/plugins/*/build`),
`scripts/plugin-smoke.sh` (15 steps in ~5 s), `scripts/check_version_sync.py`,
`grep`/`find`, `git`. The `static-embed/` example exercises the
full plugin contract end-to-end without invoking the heavy crypto
suite — prefer it for ABI-shape verification.

**NOT OK locally:** `scripts/test_all.sh` in any mode (the bench
phase runs `b256_py_correct` and similar memory-heavy paths that
push the laptop into OOM territory; `TEST_MODE=fast` does not
disable it), `gradle test` from cold cache, liboqs-from-source,
the full Python parity suite, Argon2id benches at default cost,
multi-GiB encrypt/decrypt timing runs.

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
6. Java `KeyWrap` supports Argon2id since 3.7.0 (via BC's `Argon2BytesGenerator`); the JNI bridge also in 3.7.0 makes it ~5-10× faster via libargon2. The legacy "Java rejects Argon2" line is gone.
7. Embedded master PQ key is OFF by default — `BASEFWX_MASTER_PQ_PUB=<path>` (runtime) or `-DBASEFWX_MASTER_PQ_PUB_B64=…` (build time) are the supported configuration paths.
8. **(3.7.0 new — Rule 13)** Argon2 parallelism is fixed at **4** across C++/Java/Python. The wire format doesn't carry the lane count; defaulting to `hardware_concurrency()` made blobs silently non-portable between machines with different core counts. Anyone "fixing" `DefaultArgon2Parallelism()` to go back to `hardware_concurrency()` is reintroducing the bug.

## The blackbox plugin contract (new in 3.7.0)

The contract has three layers; pick the one that matches your task.
Required reading before writing any plugin code:
`examples/plugins/THREAT_MODEL.md` — the five threat models the
ABI is designed against and the three plugin profiles to choose
between.

**Adding a plugin (Profile A — AEAD-wrapped).** Start at
`examples/plugins/README.md`. Copy `passthrough/` (C) or
`xor-rotate/` (C++) and edit. The plugin's `forward` and `inverse`
functions are the only required logic; `BASEFWX_PLUGIN_DEFINE(...)`
in `plugin.hpp` generates the C-ABI glue for you. Suitable for
traffic-shaping inside an AEAD layer; not suitable for raw-mode
use.

**Adding a plugin (Profile B — keyed, raw-mode safe).** Copy
`examples/plugins/aead-wrapped-keyed/` and edit. Plugin class
additionally implements `Capabilities()`, `ForwardKeyed`,
`InverseKeyed`; the host threads a per-call `tweak` and a
host-derived `host_secret` through the transform.
`BASEFWX_PLUGIN_DEFINE_KEYED(...)` generates the glue. Required
for any plugin that runs without an AEAD layer above or below it.
The self-derived-entropy variant is in `examples/plugins/time-tweak/`
(unix-time tweak embedded in the plugin's own output).

**Adding a plugin (Profile C — static-embedded).** Compile your
plugin source into the host binary, then register it at startup
with `BASEFWX_PLUGIN_REGISTER_STATIC(basefwx_plugin_entry())` from
`cpp/include/basefwx/plugin_static.hpp`. The host's loader resolves
the plugin by its 16-byte ID from the in-process Registry,
bypassing `dlopen`. `examples/plugins/static-embed/` is a complete
self-contained host that demonstrates the pattern. Statically
linking BaseFWX itself remains commercial-license-only — see
LICENSING.md.

**Implementing the host-side loader.** The C ABI is in
`cpp/include/basefwx/plugin.h`. The loader is responsible for:
checking `Registry::Find(plugin_id)` FIRST (so an embedded plugin
wins over a same-ID file on disk), then `dlopen` + `dlsym
basefwx_plugin_entry`, ABI version check, calling `init` with the
caller-supplied config, calling `capabilities()` once and storing
the result, applying `forward` / `inverse` (Profile A) or
`forward_keyed` / `inverse_keyed` (Profile B) at the chosen
position, calling `destroy` at teardown. **The host MUST refuse
`BASEFWX_PLUGIN_POS_RAW` for any plugin that does not declare
`BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE`** — fail closed, no flag, no
override. The wire-format plugin tag (16-byte `plugin_id` +
position bits) is the receiver's hint for which plugin to load.

**Verifying a plugin.** `scripts/plugin-smoke.sh` is the canonical
end-to-end smoke for the ABI surface; it builds all five example
plugins, exercises both `forward`/`inverse` and
`forward_keyed`/`inverse_keyed` via dlopen, runs the static-embed
binary, and runs the Java SPI and Python ctypes round-trips.
`tools/plugin-verifier/DESIGN.md` is the spec the
`basefwx-plugin-verify` tool conforms to (scoped for 3.7.x —
spec exists, runtime implementation deferred). Run smoke against
any new `.so` to confirm ABI conformance, round-trip safety, and
metadata sanity.

## Tools you have when working on this repo

The Yume parent repo (`~/yume/.claude/`) provides several skills and
one MCP server that auto-load when relevant. You don't need to
install or configure anything — they're available by default.

| Tool | What it does | Use when |
| --- | --- | --- |
| **Skill: `crypto-conventions`** | The thirteen-rule playbook for crypto changes across C++/Java/Python | Editing `crypto.cpp` / `keywrap.cpp` / `fwxaes.cpp` / `Crypto.java` / `KeyWrap.java` / anything that derives a key. Triggers on terms like AEAD, Argon2, HKDF, ML-KEM, wire format. |
| **Skill: `code-quality`** | Clean code / SOLID / refactoring review checklist | Any PR-style review or refactor sweep. |
| **Skill: `cpp`** | Modern C++ patterns (RAII, templates, STL idioms) | New C++ code, especially when reaching for `unique_ptr`, lifetime-tricky patterns, template work. |
| **Skill: `java-kotlin`** | JVM patterns (Java + Kotlin) | Java work in `java/src/main/java/com/fixcraft/basefwx/`. |
| **Skill: `python`** | Python idioms, typing, async, dataclasses | Editing `python/basefwx/legacy.py` or the `python/` API surface. |
| **MCP: `cpp`** (clangd-backed) | Semantic C++ symbol search and analysis. Three tools: `get_project_details`, `search_symbols`, `analyze_symbol_context`. | Faster + more accurate than `grep` for "where is this used", "what's the signature", "list all callers". Requires `cpp/build/compile_commands.json` — generated by `cmake -S cpp -B cpp/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`. |

The MCP server scans the parent yume root by default; for basefwx-only
analysis pass `build_directory: /home/f1xgod/yume/basefwx/cpp/build`
to its tool calls. The compile-commands DB needs to exist there
first — if it doesn't, run the cmake configure step above and retry.

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
  comment "b1024 retired in 3.7.0" — there are tombstones in
  `scripts/test_all.sh` and `legacy.py` so an agent re-adding it
  by mistake hits them immediately.

## Last thing — the README

The top-level `README.md` is human-targeted. It assumes you know
what BaseFWX is and want install / quick-start. This file
(`AGENTS.md`) is for agents starting from zero. If you need to
update one and the change is structural (file moved, contract
changed), update both.
