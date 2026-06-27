# BaseFWX 3.7.0 — agent handoff: finalize the plugin (do not release early)

> **Read this before touching plugin host code or tagging `v3.7.0`.**
> Index: [`AGENTS.md`](AGENTS.md) · [`LICENSING.md`](LICENSING.md) ·
> [`examples/plugins/THREAT_MODEL.md`](examples/plugins/THREAT_MODEL.md) ·
> [`examples/plugins/README.md`](examples/plugins/README.md)

## Situation (2026-06-26)

- **Why 3.7.0 exists:** the minor bump from the unreleased 3.6.5 track is the
  **blackbox plugin** — a user-visible, end-to-end feature, not ABI-only docs.
- **What happened:** audit hardening + plugin **authoring** surface landed on
  `main` (`f3f7dd8` and earlier). A `v3.7.0` tag and GitHub Release were created
  prematurely; the **Release was canceled** and the **`v3.7.0` tag was deleted**
  from GitHub because the headline feature (encrypt/decrypt **with** a plugin
  through official APIs) is **not implemented**.
- **Current `main` HEAD:** safe to keep — security fixes, secret wipes, doc
  alignment, Python ctypes vtable fix, EC autogen removal are all valid 3.7.0
  content. **Do not revert**; finish the loader on top.
- **`VERSION` file:** still `3.7.0` — correct for in-tree development. **Do not
  tag or `gh release create` until the Definition of Done below is met.**

## Definition of Done — what must work before `v3.7.0` ships

A user (or `test_all.sh`) must be able to:

1. **Load a plugin** from the BaseFWX C++ CLI (and Java/Python parity paths for
   fwxAES at minimum): `Registry::Find(id)` first, then `dlopen` +
   `dlsym("basefwx_plugin_entry")`, ABI check, `init`, cache `capabilities()`.
2. **Encrypt and decrypt fwxAES** with a plugin applied at a chosen position
   (PRE_AEAD or POST_AEAD for Profile A; keyed path for Profile B if raw-mode
   is in scope for v1 of the loader).
3. **Persist a wire-format plugin tag** on the blob so decrypt on another host
   fails closed unless the same `plugin_id` is loaded (receiver hint).
4. **Refuse `BASEFWX_PLUGIN_POS_RAW`** unless the plugin declares
   `BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE` — no flag, no override (see
   `plugin.h` + THREAT_MODEL TM-4).
5. **`scripts/plugin-smoke.sh`** still passes (ABI smoke) **plus** new integration
   tests: round-trip `xor-rotate` (or `passthrough`) through **`basefwx`
   fwxAES-enc/dec** with `--plugin` (or equivalent), C++ ↔ Java ↔ Python where
   applicable.
6. **Cross-runtime constants** for the new wire fields live in
   `constants.hpp` ↔ `Constants.java` ↔ Python (`legacy.py` / module constants).
7. **Docs** updated so RELEASE-NOTES / CHANGELOG / examples README no longer
   list “loader deferred” for items that now ship.

**Strongly recommended before release (can be 3.7.1 if timeboxed):**

- `basefwx-plugin-verify` per [`tools/plugin-verifier/DESIGN.md`](tools/plugin-verifier/DESIGN.md)
- JNI bridge for Java loading native `.so` plugins
- Java/Python SPI Profile B (`forward_keyed` / `capabilities`)

## Already shipped (do not re-build from scratch)

| Layer | Location | Notes |
| --- | --- | --- |
| C ABI v1 | `cpp/include/basefwx/plugin.h` | Positions, caps, keyed slots, err codes incl. `-6` |
| C++ author macros | `cpp/include/basefwx/plugin.hpp` | `BASEFWX_PLUGIN_DEFINE`, `_KEYED`, `SecretBuffer` |
| Static registry | `cpp/include/basefwx/plugin_static.hpp` | `Registry::Register` / `Find`; demo in `examples/plugins/static-embed/` |
| Examples | `examples/plugins/{passthrough,xor-rotate,aead-wrapped-keyed,time-tweak,static-embed,xor-rotate-java,xor-rotate-py}/` | All profiles documented in THREAT_MODEL |
| Java SPI (Profile A) | `java/.../com/fixcraft/basefwx/plugin/` | ServiceLoader; no fwxAES hook yet |
| Python SPI (Profile A) | `python/basefwx/plugin.py` | ctypes vtable matches `plugin.h` (fixed 2026-06-26) |
| ABI smoke | `scripts/plugin-smoke.sh` | 15 steps; runs at end of `test_all.sh` |
| Licensing | `LICENCE` clauses 1+5, `LICENSING.md` | Plugin Exception + Template Exception — complete |
| Audit hardening | `CHANGELOG.md` `[v3.7.0]` | Secret wipes, master-key opt-in, parser bounds, etc. |

## Not shipped — your job

| Gap | Where to implement | Notes |
| --- | --- | --- |
| **Host loader** | new `cpp/src/plugin_loader.cpp` + `cpp/include/basefwx/plugin_loader.hpp` (suggested) | Zero matches for `dlopen` / `Registry` in `cpp/src/` today |
| **Wire-format plugin tag** | `constants.hpp`, `fwxaes.cpp`, `FwxAesCodec.java`, Python `_fwxaes.py` | AGENTS.md: **16-byte `plugin_id` + position bits** in the tag; exact byte layout must be **designed and documented** before coding (Rule 5 — wire bump if wrong). Start from fwxAES fixed header after magic; add opt-in extension, not breaking 3.6.4 blobs without tag. |
| **fwxAES integration** | `cpp/src/fwxaes.cpp`, `java/.../FwxAesCodec.java`, `python/basefwx/_fwxaes.py` | Hook PRE/POST transform around AEAD; derive `host_secret` from password per THREAT_MODEL for keyed plugins |
| **CLI flags** | `cpp/src/cli/options.cpp`, `main.cpp`, Java CLI, Python CLI | e.g. `--plugin <path>`, `--plugin-id <hex>`, `--plugin-pos pre\|post`, optional `--plugin-config <file>`; mirror env vars if existing pattern (`BASEFWX_PLUGIN_PATH`) |
| **`fwxaes::Options` / Java/Python options** | `fwxaes.hpp`, callers | Thread plugin path, position, config blob through encrypt/decrypt |
| **Integration tests** | `scripts/test_all.sh` (new block or extend plugin-smoke) | Must run on **remote build host** — ask user before `test_all.sh` on laptop |
| **Verifier tool** | `tools/plugin-verifier/` + CMake target | Spec in DESIGN.md; optional for first release but spec says “incoming with loader” |

### Host loader checklist (from `AGENTS.md`)

Implement in order:

1. `Registry::Find(plugin_id)` — embedded plugin wins over same-ID file on disk.
2. `dlopen` + `dlsym("basefwx_plugin_entry")` + ABI version check.
3. `init(config)` → store instance; call `capabilities()` once and cache.
4. Dispatch `forward` / `inverse` or `forward_keyed` / `inverse_keyed` with
   host-supplied `tweak` + HKDF-derived `host_secret` when caps require it.
5. **Fail closed:** `POS_RAW` without `CAP_SAFE_RAW_MODE`; missing cap →
   `BASEFWX_PLUGIN_ERR_CAP_MISMATCH`.
6. `destroy` at teardown; wipe host-side secret buffers.

Copy patterns from:

- `scripts/plugin-smoke.sh` (dlopen probes, keyed probe)
- `examples/plugins/static-embed/static_embed_demo.cpp` (Registry round-trip)

## Wire format — design constraints

- **3.6.4 blobs without a plugin tag must still decrypt unchanged.**
- Plugin use is **opt-in at encrypt time**; tag bytes identify plugin + position.
- Constants must sync across C++/Java/Python (crypto-conventions Rule 3).
- Document the layout in `COMPATIBILITY.md` and `RELEASE-NOTES-3.7.0.md` once frozen.
- If the tag changes semantics of existing header fields, treat as a formal wire
  bump (Rule 5) — prefer an additive trailer or new header byte over reusing
  ambiguous `kdf` bytes.

Suggested starting point for design discussion (not yet code):

```
[existing fwxAES header ...]
[optional plugin extension when present:]
  tag_magic (2–4 B) | plugin_id (16 B) | position (1 B) | config_len (2–4 B) | config...
```

Validate against `fwxaes.cpp` parser bounds work done in the audit (64 KiB caps).

## Implementation order (recommended)

1. **Spec** — write the plugin tag byte layout; review against THREAT_MODEL + Rule 5.
2. **C++ loader** — isolated unit: load `.so`, round-trip bytes without fwxAES.
3. **C++ fwxAES** — PRE_AEAD POST_AEAD only first; `xor-rotate` round-trip via CLI.
4. **Wire tag** — encrypt writes tag; decrypt requires matching loaded plugin.
5. **Java fwxAES** — mirror C++; SPI or JNI for native `.so` (pick one for 3.7.0).
6. **Python fwxAES** — mirror C++; use existing `load_native_plugin`.
7. **test_all.sh** — cross-runtime parity block; run on remote host.
8. **Docs + release** — see below.

## Rules you must follow

- Load **`~/yume/.claude/skills/crypto-conventions/SKILL.md`** before crypto edits.
- **Secret hygiene:** wipe KEM shared secrets, AES keys, `host_secret` buffers
  (C++ `SecureClear` / `SecretGuard`, Java `Arrays.fill`, Python bytearray zero).
- **No heavy work on the laptop** — `test_all.sh`, release `--fbench`, cold Gradle:
  ask user for remote host (`192.168.1.165` typical); rsync per `AGENTS.md`.
- **Edits flow:** basefwx → yume → Android; bump YUME `config/refs/basefwx.ref`
  after tag, not before.
- **Do not tag `v3.7.0` again** until integration tests pass on the remote host.

## Verification

| Check | Command | Where |
| --- | --- | --- |
| Version sync | `python3 scripts/check_version_sync.py` | Laptop OK |
| ABI smoke | `scripts/plugin-smoke.sh --quiet` | Laptop OK (~7 s) |
| **Integration** | `basefwx fwxaes-enc … --plugin …` round-trip | After loader lands |
| Full suite | `scripts/test_all.sh --fbench` | **Remote only** |
| Release pipeline | GitHub Release **published** triggers `publish.yml` | After tag |

Extend `plugin-smoke.sh` or `test_all.sh` with at least one **CLI fwxAES +
plugin** step before release.

## Release process (when Done)

1. Confirm `main` HEAD passes remote `test_all.sh`.
2. `git tag -a v3.7.0 -m "BaseFWX 3.7.0"` at that commit; push tag + `main`.
3. **`gh release create`** — use the user's usual format (not the long marketing
   draft from the canceled release):

**Title:** `Version 3.7.0 2026-MM-DD`

**Description skeleton:**

```markdown
## [v3.7.0] - 2026-MM-DD

Compare: <https://github.com/F1xGOD/basefwx/compare/v3.6.4...v3.7.0>

See [`CHANGELOG.md`](https://github.com/F1xGOD/basefwx/blob/v3.7.0/CHANGELOG.md#v370---2026-mm-dd)
and [`RELEASE-NOTES-3.7.0.md`](https://github.com/F1xGOD/basefwx/blob/v3.7.0/RELEASE-NOTES-3.7.0.md).

### Headlines

- **Blackbox plugin in fwxAES/CLI.** Load `.so` / SPI / ctypes; PRE/POST (and
  keyed/raw per caps); wire-format plugin tag; `--plugin` on CLI. (Fill in exact
  flags and example command after implementation.)
- **Audit hardening.** (Keep bullets from CHANGELOG Security section — password
  URI, PBKDF2 fallback removed, master PQ opt-in, test KDF gate, parser bounds.)
- **Java Argon2id parity; Argon2 parallelism fixed at 4.**
- **`BaseFwxImage.java` split** (source breaking, wire unchanged).
- …

### Compatibility

- 3.6.4 blobs without plugin tag: unchanged.
- Plugin-tagged blobs: require 3.7.0+ peer with matching plugin loaded.

### Verifying

(same sha256/gpg block as 3.6.4 release notes)
```

4. Ensure `main` HEAD equals tag commit (`publish.yml` `sign-release` checks out
   `ref: main`).
5. Monitor Actions; user reports failures.

## Out of scope for first plugin release (OK as 3.7.1)

- Plugin integration in **b512file / pb512file / livecipher** (fwxAES first).
- Full `basefwx-plugin-verify` signed bundles.
- Profile B on Java/Python SPI (C++ keyed path via loader is enough for TM-4 demo).
- YUME / Android consumer updates (note required sync after basefwx tag).

## Files touched in the withheld release prep (reference)

Recent commit `Prepare BaseFWX 3.7.0 for release` (`f3f7dd8`): audit docs,
`KeyWrap`/`FwxAesCodec` wipes, `plugin.py` vtable, EC autogen removal,
`CHANGELOG`/`RELEASE-NOTES`/`LICENSING` plugin-scope wording. None of this
needs reverting — only **add** loader + wire tag + tests on top.

---

**Bottom line for the next agent:** 3.7.0 is **not** “plugin headers shipped.”
It is **“I can encrypt with my closed-source `.so` through BaseFWX and decrypt
on a peer that has the same plugin.”** Until that works, do not tag or release.
