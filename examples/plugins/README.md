# BaseFWX blackbox plugins — author guide

A blackbox plugin is a `.so` / `.dll` / `.dylib` (or `.jar` on Java)
that adds a custom byte-transform layer on top of the BaseFWX AEAD
payload. The crypto core stays open-source under GPL/AGPL; your
plugin code is **yours to license however you want** as long as
it's shipped as a separate dynamically-loaded artifact and doesn't
include any BaseFWX source beyond the public ABI headers. The
exact safe-harbor rules are in [LICENSING.md](../../LICENSING.md).

This directory contains:

| Path | What |
| --- | --- |
| `passthrough/` | Minimal viable plugin (pure C). Identity transforms. Use as a starting template for plain C plugins. |
| `xor-rotate/` | Slightly more interesting plugin (C++). Uses the `basefwx/plugin.hpp` helper layer + the `BASEFWX_PLUGIN_DEFINE` macro. **Recommended starting point** if you're writing the plugin in C++. |

> **Status (3.7.0):** the ABI header, C++ helper layer, and example
> plugins are committed. The runtime loader inside the BaseFWX CLI,
> the Java SPI for `.jar` plugins, the Python `ctypes` shim, the
> wire-format plugin tag, and the `basefwx-plugin-verify` tool all
> ship in this same 3.7.0 release cycle (separate files in the
> source tree, not separate version bumps). You can build and
> unit-test plugins against the ABI today.

## The thirty-second pitch

```text
   plaintext                                   ciphertext on the wire
       │                                              │
   [pre-AEAD plugin?]   ← your forward() runs here    │
       ↓                                              │
   AES-256-GCM encrypt                                │
       ↓                                              │
   [post-AEAD plugin?]  ← your forward() runs here    │
       ↓                                              │
   wire tag + blob ────────────────────────────────►──┤
                                                      │
   wire tag identifies your plugin by 16-byte ID.     │
   Decoder refuses the blob if your plugin isn't      │
   loaded on the receiving side.                      │
```

The plugin is two functions: `forward` (used at encrypt) and `inverse`
(used at decrypt). Length change is allowed. AES-GCM still wraps the
plaintext, so a buggy plugin produces a tag mismatch — your plaintext
stays confidential even if your transform is wrong.

## Authoring contract

1. **Pick a stable 16-byte ID.** Run `uuidgen`, write the bytes into
   `kVtable.plugin_id` (and a matching comment for humans). Never
   change it after release; the wire format identifies your plugin
   by this ID.
2. **`forward` and `inverse` must be exact inverses.** For any input
   `x`, `inverse(forward(x)) == x`. This is the single invariant.
   Test it. The example plugin has a `selftest` slot that does this
   against a fixed vector — fill yours in with whatever test vectors
   you trust.
3. **Be deterministic.** `forward(x)` must always produce the same
   output within an instance. If you need randomness, derive it
   from the input or from the config blob passed to `init()`; never
   call `rand()` or `getrandom()` inside `forward`.
4. **Be thread-safe per-instance OR document that you aren't.** The
   host calls one instance from one thread at a time by default.
   If your transform is cheap and you want to share an instance
   across threads, say so in your README; the host won't lock for you.
5. **Wipe sensitive state in `destroy()`.** If your plugin holds a
   key, zero the memory before `free()`. Use `OPENSSL_cleanse`,
   `memset_s`, or `explicit_bzero` — the compiler is allowed to
   elide a plain `memset` after the last use.
6. **Return clean error codes, not `abort()`.** The host catches
   `BASEFWX_PLUGIN_ERR_*` and surfaces them as normal errors.
   Crashing the host is a worse user experience.

## Vtable fields, slot by slot

```c
typedef struct {
    uint32_t api_version;                  // = BASEFWX_PLUGIN_API_VERSION
    uint8_t  plugin_id[16];                // unique, frozen
    const char* name;                      // human-readable
    const char* version;                   // your own semver
    uint32_t supported_positions;          // PRE_AEAD | POST_AEAD
    int  (*init)(...);                     // mandatory
    void (*destroy)(...);                  // mandatory
    int  (*forward)(...);                  // mandatory
    int  (*inverse)(...);                  // mandatory
    size_t (*max_output_for_input)(...);   // mandatory (return in_len if length-preserving)
    int  (*selftest)(...);                 // optional; return 0 if OK
    void (*reserved_1)(void);              // leave NULL
    void (*reserved_2)(void);              // leave NULL
    void (*reserved_3)(void);              // leave NULL
    void (*reserved_4)(void);              // leave NULL
} basefwx_plugin_vtable;
```

### `api_version`

Always `BASEFWX_PLUGIN_API_VERSION`. The host refuses plugins whose
ABI version doesn't match. Don't try to be cute — let the ABI bump
naturally when needed.

### `plugin_id`

The 16 bytes the host writes into the wire-format plugin tag.
Receivers use this to dispatch to the right plugin. Two rules:

- **Generate it from `uuidgen` exactly once.** Hardcode the bytes;
  never derive at runtime.
- **Don't reuse another plugin's ID.** If you fork `passthrough`,
  regenerate the ID.

### `supported_positions`

Bitwise OR of:

- `BASEFWX_PLUGIN_POS_PRE_AEAD` — your transform runs on plaintext.
- `BASEFWX_PLUGIN_POS_POST_AEAD` — your transform runs on ciphertext.

If your transform only makes sense in one position (e.g. it requires
text-like input), only set that bit. The host refuses to use you in
a position you didn't claim.

### `init` / `destroy`

`init` gets an optional `config` byte blob from the caller — opaque
to the host. Use it to pass a deployment-specific configuration
(a JSON snippet, a key file, your own framing). The host doesn't
parse it. `destroy` is paired with each successful `init` and is
the right place to wipe sensitive state.

### `forward` / `inverse`

The core. Signature is the same for both:

```c
int (*)(basefwx_plugin_ctx* ctx,
        const uint8_t* in, size_t in_len,
        uint8_t* out, size_t out_cap, size_t* out_len);
```

Output buffer is pre-sized by the host using `max_output_for_input`
— if your transform overruns it, return `BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL`
rather than writing past `out_cap`. Set `*out_len` to bytes written
on success.

### `max_output_for_input`

Worst-case output length for a given input length. For
length-preserving plugins return `in_len`. For length-changing
plugins, return your upper bound — the host allocates accordingly.

A worst-case ratio over 4× will print a warning at load time.
A ratio of more than ~64× will be refused.

### `selftest` (optional)

Return `BASEFWX_PLUGIN_OK` if your plugin's internal test vectors
pass. The host calls this:

- when `basefwx-plugin-verify` is invoked,
- when `BASEFWX_PLUGIN_SELFTEST=1` is set at host startup, and
- as part of the verifier-tool sign-off process (3.7.x).

If you don't have test vectors, set the pointer to `NULL` — the
host will fall back to a black-box round-trip on random bytes.

### `reserved_*`

Leave them `NULL`. Future ABI revisions may use these slots without
bumping `api_version`; setting them to anything other than `NULL`
in 3.7.0 will be treated as "feature not supported."

## Error codes

| Code | When to return it |
| --- | --- |
| `BASEFWX_PLUGIN_OK` (0) | Success. |
| `BASEFWX_PLUGIN_ERR_GENERIC` (-1) | Internal error you don't have a better code for. |
| `BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL` (-2) | `out_cap` is smaller than what you'd produce. (Host should never see this if `max_output_for_input` is honest.) |
| `BASEFWX_PLUGIN_ERR_BAD_INPUT` (-3) | Input is malformed or not what your `inverse` expects. The host surfaces this as a "plugin rejected payload" error. |
| `BASEFWX_PLUGIN_ERR_BAD_STATE` (-4) | Called before `init` or after `destroy`. Defensive check. |
| `BASEFWX_PLUGIN_ERR_NOT_SUPPORTED` (-5) | Asked for a position you didn't list in `supported_positions`. |

## Build

`passthrough/CMakeLists.txt` is your template. Three things to change:

1. `project(your-plugin-name C)` at the top.
2. Edit `passthrough.c` → your transform; rename the file.
3. `add_library(your-plugin-name SHARED your-file.c)`.

Then:

```bash
cmake -S . -B build -DBASEFWX_INCLUDE_DIR=/path/to/basefwx/cpp/include
cmake --build build -j
```

The output `.so` lives in `build/libyour-plugin-name.so` (or `.dll`
/ `.dylib` on the matching platform). Ship this single file plus
your README to deployments.

## Licensing your plugin (the safe-harbor rules)

BaseFWX itself is **dual-licensed**: GPL-3.0 + Plugin Exception +
Attribution requirement for free use, or a separate commercial
license sold by FixCraft Inc. for users who need different terms.
See [LICENCE](../../LICENCE) (legal text) and
[LICENSING.md](../../LICENSING.md) (practical guide).

Plugins compiled against the public ABI headers (`basefwx/plugin.h`,
`basefwx/plugin.hpp`, `com.fixcraft.basefwx.plugin`, `basefwx.plugin`)
and shipped as a separate dynamically-loaded artifact are NOT
considered derivative works of BaseFWX. **You can license your plugin
under any terms you want** — closed-source, commercial, MIT, GPL,
proprietary, anything.

The **attribution requirement** still applies to the *product that
embeds BaseFWX*. Your plugin isn't BaseFWX, but if your end-product
loads BaseFWX, that end-product must credit BaseFWX prominently
(`Powered by BaseFWX — https://github.com/F1xGOD/basefwx` on a
visible credits/about surface). See LICENSING.md for the exact
"prominent" definition. If attribution conflicts with your product's
branding, buy a commercial license: `admin@fixcraft.jp`.

You are in the safe harbor if **all four** of these hold:

1. Your plugin is shipped as a separate file (`.so`/`.dll`/`.dylib`/`.jar`)
   that the host loads dynamically — not built into the BaseFWX binary.
2. The host loads it via the documented entry points only
   (`basefwx_plugin_entry`, the Java SPI interface, or the Python
   bridge), not by injecting BaseFWX-internal symbols.
3. Your plugin source only includes the public ABI headers; it does
   not `#include` or `import` anything from BaseFWX beyond those.
4. Your plugin is dynamically linked, not statically linked, to any
   BaseFWX code.

The example plugins in this directory pass all four. If yours does
too, you're free to ship it under any license.

### Copying from `examples/plugins/` is explicitly allowed

The example files (`passthrough/`, `xor-rotate/`, `xor-rotate-java/`,
`xor-rotate-py/`) are GPL-3.0 like the rest of the project, BUT each
of them carries a header that invokes LICENCE **clause 5 — the
Plugin-Template Exception**:

> You may use this file as a starting template for your own Plugin
> under any license your Plugin chooses.

That means you can literally:

1. Copy `passthrough.c` (or any example file) into your own private repo.
2. Rename it, edit it, replace the identity transform with your real one.
3. Generate a fresh `plugin_id` (`uuidgen`).
4. Ship the resulting `.so` / `.dll` / `.jar` under **any license you
   want** — commercial, closed-source, MIT, MPL, anything — without
   GPL contaminating your derivative.

The catch is that the *result* must still qualify as a Plugin per the
four safe-harbor rules (separate artifact, ABI-only headers, dynamic
load, no static linking). Inside that envelope, you have full
licensing freedom.

The Attribution requirement on the end-product (the application that
loads BaseFWX) is unaffected by clause 5 — your plugin isn't
BaseFWX, but the host that loads it is, and that host has to credit
BaseFWX.

If unsure, read [LICENSING.md](../../LICENSING.md) — it has a
worked-examples table — or open an issue.

## What 3.7.0 ships

3.7.0 ships the plugin core end-to-end: the ABI header, the C++/Java/Python
loaders, the wire-format plugin tag (`plugin_id` + position bits), the
example plugin, the `basefwx-plugin-verify` tool, and the
`basefwx-plugin-build new <name>` scaffolder. The pieces in this directory
that read like "design only" notes (the verifier, the JVM/Python bridges)
are still being wired in this same release cycle — they're separate files
in the source tree, not separate version bumps.

ABI breaks, if any, will come with a `BASEFWX_PLUGIN_API_VERSION` bump.
Plugin authors should hardcode `BASEFWX_PLUGIN_API_VERSION` from the
header they compile against and treat a host mismatch as a hard refusal
to load.

## Security notes for plugin authors

- **Your plugin runs in-process.** Bugs can crash the host. Aim
  for "obviously correct" code; AEAD already provides the
  confidentiality guarantee, so your job is purely an
  obfuscation/format layer.
- **Don't roll your own crypto in the plugin.** If you want a
  cipher, link OpenSSL or BoringSSL. The host's AES-GCM is already
  authenticating your output.
- **Don't depend on shared global state.** Two callers with two
  different config blobs should both work concurrently if you
  give each its own instance.
- **Document your `plugin_id`.** Anyone receiving your blobs needs
  it to know which plugin to ask for.
- **Audit the source you ship.** A malicious plugin can read host
  memory; only load plugins you trust.

## Security notes for the host

The host treats every plugin as untrusted code that it nevertheless
agreed to run. The mitigations baked into the loader are:

- Path sandboxing via `BASEFWX_PLUGINS=` allowlist; no auto-discovery
  from `LD_LIBRARY_PATH` or process cwd.
- API-version gate refuses mismatched plugins.
- `selftest` called at load if `BASEFWX_PLUGIN_SELFTEST=1`.
- A loaded plugin's `forward(empty) → inverse → empty` round-trip
  is checked on every load.
- The wire tag's 16-byte `plugin_id` must match a loaded plugin
  before any byte of the underlying blob is touched.

There is **no sandbox** beyond that — the plugin is your code, in
your process. If you need stronger isolation, run plugins
out-of-process; the in-process loader trades sandbox for speed.
