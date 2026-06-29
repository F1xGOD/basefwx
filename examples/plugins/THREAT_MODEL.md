# BaseFWX plugin threat model

This document is the **authoritative answer** to the question
"is the BaseFWX plugin ABI secure?" The short version is: it depends
on which threat you are defending against, which functions your
plugin implements, and which pipeline position the host runs it in.

This is plain talk, not marketing. If your reading is "the plugin
makes my data secret" — keep reading; it depends.

## Why this matters

BaseFWX is open source under a split license: LGPL-3.0-or-later for
core library/API/runtime and plugin ABI/SPI code, GPL-3.0-or-later for
standalone tools, and MIT OR Apache-2.0 for example plugin templates
(see [LICENSING.md](../../LICENSING.md)).
An attacker can read every line of the core. The crypto stance is
deliberately **public**: AES-256-GCM, Argon2id, HKDF-SHA256, ML-KEM-768.
The security comes from the user's password and (optionally) a
master-key wrap — not from any code being hidden.

When a commercial deployment ships a closed-source plugin on top
of this open core, there is an instinct to imagine the plugin is
"the secret part." It is not. **What is hidden is irrelevant; what
is keyed is what matters.** A plugin shipped as a closed-source
`.so` is read by anyone who runs `objdump`, anyone who hooks
`dlopen`, and anyone willing to attach a debugger. Static-linking
the plugin into the host binary raises the cost of extraction; it
does not eliminate it. Treat the plugin code as public from day one
and design accordingly.

The job of this document is to make the line between
"obfuscation against traffic analysis" and "cryptographic
confidentiality" impossible to confuse.

---

## The five threat models

| ID | Adversary capability | What protects you |
| -- | -- | -- |
| TM-1 | Passive network observer; sees ciphertext on the wire | AES-256-GCM + good password |
| TM-2 | Adversary has the host binary + plugin `.so` + plugin config blob | KEYED plugin path with `host_secret` derived from the user password |
| TM-3 | Adversary can run the host as an encryption oracle (submits chosen plaintexts, observes outputs) | KEYED plugin path with per-call `tweak` (host-supplied or self-derived) |
| TM-4 | Malicious client wants to forge or tamper with blobs that a trusted server will accept | KEYED plugin path with an authentication tag the server checks |
| TM-5 | Adversary has live debugger or memory-read access to the running host | **NOTHING in BaseFWX or any plugin defends against this.** Out of scope. |

### TM-1 — passive network observer

The simplest case. The attacker captures network traffic, has no
host access, no plugin .so, no config, no live oracle access.

**Default BaseFWX without any plugin already defends against this.**
AES-256-GCM with a per-blob random IV and a 600 000-round PBKDF2 or
Argon2id user-key derivation makes brute force expensive and
ciphertext indistinguishable from random.

The plugin's job at TM-1 is not confidentiality (AEAD does that) but
**traffic-analysis resistance** — DPI evasion, byte-distribution
shaping, length-shaping, header-mimicry. A deterministic plugin
running PRE_AEAD or POST_AEAD is fine for this.

A keyless `xor-rotate` plugin used POST_AEAD is fine against TM-1.

### TM-2 — adversary has the plugin and its config

This is the threat the user typed: "decompile final exe from org →
get embedded basefwx and .so/.dll".

If the plugin transform is `out = F(in)` (deterministic), or
`out = F_k(in)` where `k` comes only from the static `config` blob
loaded at `init()`, the attacker now has BOTH `F` and `k`. They can
reproduce the transform offline on any input they like. The
**defense is to bind the transform to something the attacker does
NOT have** — namely the user's password.

The mechanism is `host_secret`. The host derives 32 bytes of key
material from the user's password via HKDF-SHA256 under a versioned
info string (e.g. `"basefwx.plugin.host_secret.v1"`) and passes them
to `forward_keyed` / `inverse_keyed`. The plugin uses these bytes
to mix into its transform — typically as the key to an
AES-CTR keystream that it XORs over the input, or as the key to an
HMAC the plugin appends.

Now the attacker who has the plugin and the config but **not the
user's password** cannot reproduce the transform. They are back to
attacking the password directly — which is what they were already
doing against AES-GCM, with the same cost curve.

To defend against TM-2 you must:

1. Implement `forward_keyed` / `inverse_keyed`, not just
   `forward` / `inverse`.
2. Set `BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY` in `capabilities()`.
3. Use the `host_secret` to derive the actual keystream / MAC key
   used by your transform. NEVER use the plugin's static `config`
   blob alone for keying anything that needs to resist a TM-2
   attacker.

The `aead-wrapped-keyed` example in this directory demonstrates
this pattern.

### TM-3 — oracle attack

The attacker can submit arbitrary plaintexts to the running host
and read the resulting ciphertexts. They are not extracting code;
they are extracting the table of `(in, out)` pairs that defines
the transform.

If the plugin is deterministic — `out = F(in)` — the attacker
submits `in = 0x00`, `0x01`, …, `0xff` and reads off `F`'s byte
table directly. Adding `host_secret` keying does NOT defend against
this: the oracle answers under the legitimate user's password, so
`F_{host_secret}` is observable byte-by-byte.

**The defense is per-call randomization.** Every blob's transform
must depend on a value that varies blob-to-blob. The plugin
contract supports two ways to do this:

- **Host-supplied tweak.** The host generates 16 (or N) random
  bytes per blob and passes them as `tweak` to
  `forward_keyed` / `inverse_keyed`. The plugin mixes them into
  the keystream / MAC. The host then either prepends `tweak` to
  the blob's wire format (so the decoder can recover it) or
  transmits it out-of-band. Set
  `BASEFWX_PLUGIN_CAP_REQUIRES_TWEAK`.

- **Self-derived tweak.** The plugin generates per-call entropy
  from a source the decoder can also recover. Common sources:
    - Unix time at encrypt, written into the head of the plugin's
      output and read back at decrypt.
    - A monotonic counter, same pattern.
    - A hash of the input itself plus a fresh nonce written to
      the output.
  Set `BASEFWX_PLUGIN_CAP_NONDETERMINISTIC` so the host does not
  treat your plugin as snapshot-test-friendly.

The `time-tweak` example demonstrates the self-derived approach.
The `aead-wrapped-keyed` example demonstrates the host-supplied
approach.

A plugin that defends against both TM-2 AND TM-3 uses BOTH
`host_secret` AND per-call tweak. Either alone has a hole.

### TM-4 — malicious client forging server-bound blobs

This is the HTTPS-server scenario the user described: a client app
ships an obfuscator plugin; the server validates incoming traffic;
a malicious or modified client wants to forge blobs that the server
will accept (or to tamper with legitimate blobs in transit).

The attacker here has everything from TM-2 (plugin, config) AND
oracle-style chosen-plaintext capability from TM-3 (they're
running the client). What they DON'T have is the server's secret.

The defense is the same shape as authenticated encryption: the
plugin's transform must include an **authentication tag keyed by a
secret only the server knows**. The host_secret in this case is a
shared client-server secret (derived from the server's master key,
not from the user's password). The plugin appends an
HMAC-SHA256(host_secret, tweak || input) tag to its output; the
server's plugin verifies the tag during `inverse_keyed` and
returns `BASEFWX_PLUGIN_ERR_BAD_INPUT` on mismatch.

This is structurally the same as `aead-wrapped-keyed` but with a
different key-derivation chain. The plugin code is the same; only
how the host supplies `host_secret` differs.

### TM-5 — live debugger / memory access

Out of scope. If the attacker can pause your process and read
memory, they can read the user's password from RAM as it is
typed. They can read AES-GCM session keys mid-decrypt. They can
edit the running code.

No cryptographic plugin design defends against this. The defense is
at a different layer: OS-level memory protection, anti-debug, code
signing, attestation, secure enclaves. BaseFWX does best-effort key
wiping via `SecureClear` / `SecretBuffer` but explicitly does not
claim defense against live memory access.

---

## The three plugin profiles

Given the threat models above, plugins fall into three usable
shapes. **Pick one before you start writing code.**

### Profile A — Traffic-shaping (AEAD-wrapped)

| | |
| - | - |
| Pipeline position | `BASEFWX_PLUGIN_POS_PRE_AEAD` and/or `BASEFWX_PLUGIN_POS_POST_AEAD` |
| API used | `forward` / `inverse` (the deterministic v1 path) |
| Capabilities() | `0` is fine (or just `BASEFWX_PLUGIN_POS_*` flags) |
| Defends against | TM-1 |
| Does NOT defend against | TM-2, TM-3 (but AEAD does, so the deployment as a whole is fine) |
| Example | `passthrough/`, `xor-rotate/` |

Use when: you want DPI evasion, header mimicry, byte distribution
shaping, or any other traffic-analysis defense applied to a payload
that AES-GCM already encrypts and authenticates. The AEAD layer
provides confidentiality and integrity around the plugin; the
plugin only shapes the appearance of the wire bytes.

### Profile B — Authenticated keyed (raw-mode safe)

| | |
| - | - |
| Pipeline position | `BASEFWX_PLUGIN_POS_RAW` (the host refuses POS_RAW without `CAP_SAFE_RAW_MODE`) |
| API used | `forward_keyed` / `inverse_keyed` |
| Capabilities() | at minimum `KEYED \| SAFE_RAW_MODE \| REQUIRES_HOST_KEY`; commonly also `REQUIRES_TWEAK` or `NONDETERMINISTIC` |
| Defends against | TM-1, TM-2, TM-3, TM-4 (with appropriate key chain) |
| Does NOT defend against | TM-5 |
| Example | `aead-wrapped-keyed/`, `time-tweak/` |

Use when: there is no AES-GCM wrapping the plugin's output, OR you
want the plugin's transform to be cryptographically meaningful
even when the AEAD layer is also present. Mandatory if you want a
malicious client to be unable to forge server-bound blobs.

### Profile C — Statically embedded

| | |
| - | - |
| Distribution | Plugin source compiled into the host binary; no `.so`/`.dll` on disk |
| Registration | `BASEFWX_PLUGIN_REGISTER_STATIC(basefwx_plugin_entry())` in [plugin_static.hpp](../../cpp/include/basefwx/plugin_static.hpp) |
| License | Static linking or embedding BaseFWX itself follows LGPL-3.0-or-later requirements for the BaseFWX library files involved; the example plugin template remains MIT OR Apache-2.0 |
| Security properties | Identical to whichever of Profile A or Profile B the plugin actually implements. Static embedding is a deployment choice, not a security primitive. |
| Example | `static-embed/` |

Use when: your deployment cannot ship a separate plugin artifact —
single-file distribution, kiosk app, signed-bundle constraint.
**Pair with Profile B if you need raw-mode safety; static embedding
alone does not provide it.**

---

## The rules in one screen

1. **Open-source crypto, keyed plugins.** The crypto core is public;
   the plugin code is also public from the attacker's perspective
   (extractable). What is keyed is what's secret. Build the plugin
   so the secret is the host-derived key, not the plugin code.

2. **AEAD-wrapped use is the default.** Profile A plugins do not
   need to defend against TM-2/TM-3 because the AEAD layer does.
   If you do not have a specific raw-mode requirement, ship
   Profile A.

3. **Raw-mode requires keyed.** `BASEFWX_PLUGIN_POS_RAW` is only
   accepted by the host when the plugin returns
   `BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE` from `capabilities()`. The
   host's refusal is a fail-closed behavior. Do not work around it.

4. **`host_secret` defends against extracted-plugin attackers.**
   Mix it into your keystream / MAC. Do not use it as a static
   constant or compare against it directly.

5. **`tweak` defends against oracle attackers.** Use it. If you
   can't get one from the host, generate one yourself
   (e.g. unix time, embedded in your output) and set
   `BASEFWX_PLUGIN_CAP_NONDETERMINISTIC`.

6. **Self-derived tweak is fine.** It is not weaker than a
   host-supplied tweak as long as you embed it into your output so
   `inverse_keyed` can recover it. The decoder must not need any
   information the wire bytes do not carry.

7. **Wipe key material before returning.** Use
   `basefwx::plugin::SecretBuffer` for any derived keys, salts, or
   intermediates. Local stack arrays leak through reused stack
   frames; heap allocations leak through reused malloc arenas.

8. **Never compare MACs with `memcmp`.** Use a constant-time
   comparison (`CRYPTO_memcmp` from OpenSSL, or roll a portable
   one). Timing leaks on MAC comparison reveal forgeries.

9. **Versioning is not optional.** Bake a 16-byte UUID into the
   plugin and into the wire output (the host writes the plugin's
   `plugin_id` into the blob's plugin tag at encrypt time). If
   you change the transform, mint a NEW UUID — do not re-use an
   old ID with new semantics.

10. **There is no defense against TM-5.** If your threat model
    includes a debugger or memory-read attacker, BaseFWX is not
    the layer that solves it. Use OS isolation, secure enclaves,
    or hardware-backed key storage as appropriate.

---

## A short worked example

You're shipping a client→server protocol. The client is closed
source; the server is yours. You want:

- Bytes on the wire that don't look like AES-GCM ciphertext (DPI
  evasion).
- A malicious client cannot forge blobs that the server accepts.
- An attacker who decompiles the client and extracts the .so
  cannot bulk-decrypt captured traffic offline.
- An attacker who has the running client cannot run it as a
  keystream oracle.

This is TM-1 + TM-2 + TM-3 + TM-4. You need Profile B with both
`host_secret` AND `tweak`:

1. Server provisions a 32-byte shared-with-clients key `K_pair`
   per (client, server) session. It travels to the client through
   whatever bootstrap channel already authenticates the client.
2. Client host derives `host_secret = HKDF(K_pair, "myco.plugin.v1", 32)`
   and passes it to `forward_keyed`.
3. Client host generates a 16-byte random `tweak` per blob and
   passes it.
4. The plugin's `forward_keyed`:
   - Splits `HKDF(host_secret, "ks" || tweak, 64)` into a 32-byte
     AES-CTR key and a 32-byte HMAC-SHA256 key.
   - XORs the AES-CTR keystream over the input.
   - Computes HMAC-SHA256(mac_key, tweak || ciphertext) and
     appends 16 bytes of the tag.
   - Writes `tweak || ciphertext || tag` to the output.
5. The plugin's `inverse_keyed`:
   - Reads the tweak off the head, re-derives the two keys.
   - Recomputes the MAC and compares constant-time. Reject on
     mismatch.
   - XORs the keystream off the ciphertext.
6. Capabilities: `KEYED | SAFE_RAW_MODE | REQUIRES_HOST_KEY |
   NONDETERMINISTIC`. (`NONDETERMINISTIC` because the tweak is
   self-embedded; you could alternately set `REQUIRES_TWEAK` if
   the host carries the tweak out-of-band.)

That plugin is safe against TM-1, TM-2, TM-3, TM-4 simultaneously.
It is NOT safe against TM-5; nothing here is.

The `aead-wrapped-keyed/` example in this directory is exactly
this shape, simplified.

---

## What "rock hard" means in practice

This contract is meant to be small enough to read, narrow enough
to audit, and unambiguous enough that the failure modes are
visible at code-review time. Specifically:

- The host **refuses** `BASEFWX_PLUGIN_POS_RAW` for plugins that
  do not set `CAP_SAFE_RAW_MODE`. No warning, no override, no
  config flag. The dangerous default is impossible.
- The host **refuses** `forward_keyed` calls where the plugin set
  `CAP_REQUIRES_TWEAK` but the host passed `tweak_len == 0`.
  Likewise for `CAP_REQUIRES_HOST_KEY`.
- The plugin **must** wipe key material via `SecretBuffer`.
- The plugin **must** sign its transform with a stable 16-byte ID;
  the host carries that ID in the wire blob's plugin tag so the
  decoder loads the right plugin and refuses a substituted one.
- The plugin's `selftest` runs at load when
  `BASEFWX_PLUGIN_SELFTEST=1`, so a CI pipeline that loads the
  plugin and forgets to round-trip it fails closed.

Anything we cannot enforce mechanically lives in this document.
Anything we can, we do.
