# `basefwx-plugin-verify` — design

> Status: design + spec only. Implementation scoped for 3.7.x point
> releases alongside the CLI/fwxAES loader. This document is the
> contract the tool will conform to so reviewers can read what it'll
> do before it lands.

## Why

Plugins are caller-supplied native code that the BaseFWX host loads
in-process. We want a single command that a plugin author runs
locally and that downstream consumers can rerun to answer one
question:

> *"Is this `.so` a well-formed BaseFWX plugin that will keep working
> with my data?"*

If the answer is yes, the verifier prints a deterministic report
plus a signed bundle that the consumer can pin.

## Inputs

```
basefwx-plugin-verify <path-to-plugin.so>
    [--config <bytes-or-file>]      pass to plugin init()
    [--vectors <file>]              extra test vectors (default: built-in)
    [--positions pre,post,both]     which positions to exercise
    [--out <bundle.zip>]            write a signed report bundle
    [--sign-key <pem>]              GPG/Ed25519 signing key for the bundle
    [--strict]                      treat warnings as errors
    [--json]                        machine-readable output
```

Required positional: the plugin path. Everything else has sensible
defaults.

## Checks, in order

Each check has a stable name. The JSON output lists every check with
`pass | fail | skip` plus a short reason.

1. **`elf.format`** — file is a valid ELF / PE / Mach-O for the
   current platform. (Cross-platform via `binary-parse`-style
   library; the verifier itself stays single-binary.)
2. **`elf.exports.entry`** — `basefwx_plugin_entry` symbol exists and
   is exported with default visibility.
3. **`elf.imports.minimal`** — flag any unexpected library imports
   (e.g. `libcurl`, `libsqlite3`). Crypto plugins generally need
   only libc + libssl. Print the import list; warn on suspicious
   names; never block.
4. **`vtable.entry`** — `basefwx_plugin_entry()` is callable, returns
   a non-NULL pointer, and the pointer survives one `dlclose`/`dlopen`
   round-trip (catches plugins that return a stack buffer).
5. **`vtable.api_version`** — equals `BASEFWX_PLUGIN_API_VERSION` of
   the verifier build. Mismatch → hard fail.
6. **`vtable.required_fields`** — every non-reserved function pointer
   is non-NULL. Each `reserved_*` is NULL.
7. **`vtable.id_format`** — `plugin_id` is not all-zero, not the
   passthrough ID (if `--strict`), and decodes to a well-formed UUID
   when printed.
8. **`vtable.name_version`** — both strings are non-NULL, ≤ 64 bytes,
   ASCII-only, NUL-terminated.
9. **`vtable.positions`** — at least one position bit is set; no
   unknown bits.
10. **`lifecycle.init_destroy`** — `init` succeeds with the provided
    `--config`; `destroy` runs without crashing. Run 3× to catch
    double-free / leak smells.
11. **`lifecycle.idempotent_destroy`** — calling `destroy(NULL)` is
    a no-op (verifier passes NULL deliberately).
12. **`roundtrip.identity_random`** — generate 64 random buffers from
    1 byte to 1 MiB (geometric spacing), run `forward → inverse`,
    compare byte-for-byte. Any mismatch → hard fail. Includes empty
    input.
13. **`roundtrip.identity_fixed`** — same as above against the
    plugin's `selftest()` (if provided) and any `--vectors` file.
14. **`roundtrip.cross_position`** — if the plugin claims both
    PRE_AEAD and POST_AEAD, run the round-trip in both positions and
    require identical behavior (a plugin that lies about a position
    breaks the wire format).
15. **`bounds.max_output_for_input`** — call `max_output_for_input`
    for a range of `in_len` values; assert monotonic and ≥ in_len for
    length-preserving claims. Warn if the worst-case ratio exceeds 4×.
16. **`determinism.same_input_same_output`** — `forward(x)` called
    twice on a fresh instance must produce the same bytes. Run
    against a fixed buffer 50×.
17. **`safety.bad_input`** — feed `forward` and `inverse` malformed /
    truncated / huge inputs. Expect a clean error code, never a
    crash. Run under ASAN if available.
18. **`safety.constant_time_optional`** — informational only. Run the
    plugin's `forward` against two buffers that differ in one bit and
    measure timing variance. Print as a hint; never block (most
    plugins aren't constant-time and that's fine for an obfuscation
    layer).
19. **`thread.single_instance_single_thread`** — spawn 8 threads each
    holding their own instance; round-trip random buffers; require
    all complete. No global state is required to be thread-safe;
    we only check per-instance.

## Output

### Console (default)

```
basefwx-plugin-verify v1.0  ABI=1

   ./libbasefwx-passthrough.so
   name        passthrough
   version     1.0.0
   plugin_id   4e3a09b1-3c8c-4f1e-9c3d-4a8b3f0c1d7e
   positions   PRE_AEAD POST_AEAD
   ABI         1

✓  elf.format            ELF64 Linux x86_64
✓  elf.exports.entry     basefwx_plugin_entry @ 0x13aa
✓  elf.imports.minimal   2 imports: libc.so.6 libdl.so.2
✓  vtable.entry          stable across reload
✓  vtable.api_version    = 1
✓  vtable.required_fields all non-NULL
✓  vtable.id_format      UUID 4e3a09b1-…
✓  vtable.name_version   passthrough / 1.0.0
✓  vtable.positions      PRE_AEAD POST_AEAD
✓  lifecycle.init_destroy 3 cycles OK
✓  lifecycle.idempotent_destroy NULL OK
✓  roundtrip.identity_random  64/64
✓  roundtrip.identity_fixed   16/16 + selftest OK
✓  roundtrip.cross_position   PRE == POST
✓  bounds.max_output_for_input monotonic, ratio 1.0×
✓  determinism.same_input_same_output 50/50
✓  safety.bad_input           clean errors, no crash
ⓘ  safety.constant_time_optional  variance 4ns/byte (informational)
✓  thread.single_instance_single_thread 8 threads

19/19 checks passed.  Plugin is VALID for BaseFWX 3.7.x.

Bundle written to: passthrough-verify-2026-05-21T03-45Z.zip
```

### JSON (`--json`)

```json
{
  "verifier_version": "1.0",
  "abi_version": 1,
  "plugin": {
    "path": "./libbasefwx-passthrough.so",
    "name": "passthrough",
    "version": "1.0.0",
    "plugin_id": "4e3a09b1-3c8c-4f1e-9c3d-4a8b3f0c1d7e",
    "positions": ["pre_aead", "post_aead"],
    "abi_version": 1,
    "sha256": "…"
  },
  "checks": [
    {"name": "elf.format", "status": "pass", "detail": "ELF64 Linux x86_64"},
    …
  ],
  "summary": {"passed": 19, "failed": 0, "warnings": 0, "informational": 1},
  "verdict": "valid"
}
```

### Bundle (`--out bundle.zip`)

```
bundle.zip
├─ verify-report.json         (the JSON above)
├─ verify-report.txt          (the console output)
├─ plugin.sha256              (sha256 of the .so)
├─ plugin-id.txt              (the 16 bytes hex)
└─ verify-report.sig          (if --sign-key was passed)
```

The bundle is what deployments ship alongside the `.so` to prove a
specific build was verified. Consumers can re-run `basefwx-plugin-verify`
against the same bytes and expect bit-identical output.

## What the verifier deliberately does NOT do

- It does **not** declare the plugin "secure" or "constant-time."
  It checks that the plugin conforms to the BaseFWX ABI and that
  forward/inverse round-trip cleanly. Cryptographic strength is the
  author's responsibility.
- It does **not** signature-pin a plugin to a BaseFWX version. ABI
  compatibility within 3.7.x means a verified plugin works against
  any 3.7.x host.
- It does **not** mandate test vectors. `selftest()` is optional;
  the verifier's random round-trip catches the same regressions
  for most plugins.

## Build / packaging

Single C++17 binary, statically linked except for libc. Lives in
`tools/plugin-verifier/`. Built by the main basefwx CMake when
`-DBASEFWX_BUILD_TOOLS=ON`. Cross-compile targets match the main
CLI release matrix.

## Implementation notes

- Use `boost::dll::shared_library` for portable load.
- ELF inspection: `elfio` (header-only).
- PE inspection: `pe-parse` or `LIEF`.
- Mach-O: `LIEF`.
- ASAN runs are opt-in via `--asan` — the verifier itself stays
  ASAN-free in release.

## Future work (post-3.7.0)

- Reproducibility check: rebuild the plugin from its source and
  compare bytes (requires the author to ship sources; off by default).
- Cross-runtime parity: load the same `.so` from Java and Python
  via the bridges, run the same round-trip, compare byte-for-byte
  against the C++ host.
