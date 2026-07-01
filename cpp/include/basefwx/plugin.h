/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#ifndef BASEFWX_PLUGIN_H
#define BASEFWX_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version of this ABI. Bump only on incompatible changes. */
#define BASEFWX_PLUGIN_API_VERSION 1u

/* Length of the stable plugin identifier in bytes (UUID-shaped). */
#define BASEFWX_PLUGIN_ID_LEN 16u

/* Return codes. Functions return 0 on success and a small negative
 * integer on failure. The host treats any non-zero return as a hard
 * failure and does not retry. */
#define BASEFWX_PLUGIN_OK                 0
#define BASEFWX_PLUGIN_ERR_GENERIC       -1
#define BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL -2
#define BASEFWX_PLUGIN_ERR_BAD_INPUT     -3
#define BASEFWX_PLUGIN_ERR_BAD_STATE     -4
#define BASEFWX_PLUGIN_ERR_NOT_SUPPORTED -5
/* Returned by capabilities-gated calls when the host invokes a
 * function the plugin did not declare it supports. Distinct from
 * NOT_SUPPORTED so authors can tell "I don't implement this" from
 * "I never claimed I implemented this." */
#define BASEFWX_PLUGIN_ERR_CAP_MISMATCH  -6

/* Opaque per-instance state. The plugin owns the layout; the host
 * only ever holds a pointer-to-opaque. */
typedef struct basefwx_plugin_ctx basefwx_plugin_ctx;

/* Pipeline position flags. Combine with bitwise OR if your plugin
 * supports both. The host writes the selected position(s) into the
 * blob's plugin tag at encrypt time. */
#define BASEFWX_PLUGIN_POS_PRE_AEAD   (1u << 0)  /* transforms plaintext */
#define BASEFWX_PLUGIN_POS_POST_AEAD  (1u << 1)  /* transforms ciphertext */
#define BASEFWX_PLUGIN_POS_RAW        (1u << 2)  /* transforms raw bytes,
                                                  * no AEAD layer above
                                                  * or below. Only valid
                                                  * if capabilities()
                                                  * returns
                                                  * BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE
                                                  * — the host MUST
                                                  * refuse otherwise. */

/* Capability bits returned by capabilities(). See THREAT_MODEL.md
 * for what each bit means in terms of which attacks it raises the
 * cost of. The host reads this once after init() and stores it; the
 * plugin must return the same value for the lifetime of the
 * instance. */

/* The plugin implements forward_keyed / inverse_keyed in addition
 * to (or instead of) forward / inverse. Without this bit, the host
 * will only call the deterministic v1 forward / inverse. */
#define BASEFWX_PLUGIN_CAP_KEYED              (1u << 0)

/* The plugin self-certifies that it is safe to use in BASEFWX_PLUGIN_POS_RAW,
 * i.e. without an AEAD layer wrapping its output. This is a strong
 * claim: it asserts the plugin provides its own integrity protection
 * (e.g. an embedded MAC over the host_secret) AND its own per-call
 * randomization (so identical plaintexts do not produce identical
 * ciphertexts). The host MUST refuse POS_RAW for any plugin that
 * does not set this bit. */
#define BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE      (1u << 1)

/* The plugin requires the host to supply a non-empty `tweak` to
 * forward_keyed / inverse_keyed. The host fails the call closed if
 * the bit is set and tweak_len == 0. */
#define BASEFWX_PLUGIN_CAP_REQUIRES_TWEAK     (1u << 2)

/* The plugin requires the host to supply non-empty `host_secret` to
 * forward_keyed / inverse_keyed. The host fails the call closed if
 * the bit is set and host_secret_len == 0. */
#define BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY  (1u << 3)

/* The plugin's output for the same (input, tweak, host_secret) tuple
 * may vary call-to-call — it draws on entropy outside its arguments
 * (e.g. current unix time embedded in the output, or a counter held
 * in plugin state). Hosts that need byte-deterministic output
 * (snapshot-test mode, cross-runtime parity test) MUST refuse plugins
 * with this bit set. The inverse path MUST still recover the original
 * input from the plugin's own output, regardless of when it was
 * produced. */
#define BASEFWX_PLUGIN_CAP_NONDETERMINISTIC   (1u << 4)

/*
 * Single-instance vtable.
 *
 * The host expects a single function `basefwx_plugin_entry()` to
 * return a pointer to this struct. The struct is read-only after the
 * plugin reports it; do not mutate any field after returning.
 */
typedef struct {
    /* ABI gate. Must equal BASEFWX_PLUGIN_API_VERSION. */
    uint32_t api_version;

    /* Stable 16-byte identifier for this plugin's transform.
     * Generate once (e.g. uuidgen) and never change it. The host
     * uses this to refuse a blob produced under a different plugin. */
    uint8_t plugin_id[BASEFWX_PLUGIN_ID_LEN];

    /* Human-readable. Null-terminated. */
    const char* name;

    /* Plugin's own semver string. Free-form; the host doesn't parse it. */
    const char* version;

    /* Bitmask of BASEFWX_PLUGIN_POS_* values the plugin supports.
     * The host will refuse to use this plugin in a position not
     * listed here. */
    uint32_t supported_positions;

    /*
     * Initialize an instance.
     *
     * `config` is opaque to the host — a deployment-specific byte
     * blob passed through from the caller's config (e.g. a JSON
     * snippet, a key file). The plugin may ignore it. `config_len`
     * may be 0.
     *
     * On success, write the instance pointer to *ctx and return
     * BASEFWX_PLUGIN_OK. On failure, leave *ctx unchanged and
     * return a negative error code.
     */
    int (*init)(basefwx_plugin_ctx** ctx,
                const uint8_t* config, size_t config_len);

    /*
     * Tear down an instance. Called exactly once per successful
     * init(). The plugin must zero any sensitive material it holds
     * before returning. Idempotent on NULL.
     */
    void (*destroy)(basefwx_plugin_ctx* ctx);

    /*
     * Forward transform — used at encrypt time.
     *
     * Reads `in_len` bytes from `in`. Writes the transformed result
     * to `out` (capacity `out_cap`). On success, sets *out_len to
     * the number of bytes written and returns BASEFWX_PLUGIN_OK.
     *
     * Length change is permitted; the host will allocate a worst-case
     * buffer using max_output_for_input() (below) before calling.
     *
     * Must be deterministic: identical input produces identical output
     * within a given instance.
     *
     * THREAT MODEL: this function is suitable for use inside
     * BASEFWX_PLUGIN_POS_PRE_AEAD or BASEFWX_PLUGIN_POS_POST_AEAD,
     * where AES-GCM provides confidentiality and integrity around the
     * plugin transform. It is NOT suitable for BASEFWX_PLUGIN_POS_RAW:
     * a deterministic, keyless function from bytes to bytes is a
     * substitution cipher under chosen-plaintext oracle attack. For
     * raw-mode use, implement forward_keyed / inverse_keyed and set
     * BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE in capabilities(). See
     * examples/plugins/THREAT_MODEL.md.
     */
    int (*forward)(basefwx_plugin_ctx* ctx,
                   const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t out_cap, size_t* out_len);

    /*
     * Inverse transform — used at decrypt time. Must be the exact
     * inverse of forward(): for any in, out == forward(in) implies
     * inverse(out) == in.
     *
     * If the input doesn't appear to be valid forward()-output (e.g.
     * a truncated payload), return BASEFWX_PLUGIN_ERR_BAD_INPUT —
     * the host will surface this as a normal "plugin rejected
     * payload" error.
     */
    int (*inverse)(basefwx_plugin_ctx* ctx,
                   const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t out_cap, size_t* out_len);

    /*
     * Maximum output length the plugin can produce for an input of
     * `in_len` bytes. Used by the host to size the output buffer
     * before calling forward(). For length-preserving plugins this
     * is just `in_len`. For length-changing plugins, return the
     * worst case. The host considers a transform "expensive" if
     * the ratio exceeds 4× and may warn.
     */
    size_t (*max_output_for_input)(basefwx_plugin_ctx* ctx, size_t in_len);

    /*
     * Optional self-test. Called by `basefwx-plugin-verify` and at
     * plugin load when `BASEFWX_PLUGIN_SELFTEST=1` is set. The plugin
     * should round-trip a handful of fixed test vectors through
     * forward/inverse and return OK if they match.
     *
     * NULL is permitted — the plugin signals "no self-test available."
     * The host will then run its own black-box round-trip with a
     * 16-byte random buffer.
     */
    int (*selftest)(basefwx_plugin_ctx* ctx);

    /*
     * Capability bitmask. Returns a bitwise OR of
     * BASEFWX_PLUGIN_CAP_* values. The host calls this exactly once
     * after a successful init() and stores the result; the plugin
     * must return the same value for the lifetime of the instance.
     *
     * NULL is permitted for backwards compatibility with v1 plugins
     * compiled before this slot was defined; the host treats NULL
     * as capabilities() == 0 (no keyed support, no raw-mode safety
     * claim, no requirements).
     */
    uint32_t (*capabilities)(const basefwx_plugin_ctx* ctx);

    /*
     * Keyed forward transform — used at encrypt time when the host
     * has per-blob tweak material and/or a host-derived secret to
     * bind into the plugin's output.
     *
     *   tweak        — per-blob entropy supplied by the host. The
     *                  host generates this (typical: 16 random bytes
     *                  per blob), and either prepends it to the
     *                  blob's wire format or threads it via an
     *                  out-of-band channel. May be NULL (tweak_len 0)
     *                  if the plugin's capabilities() did not set
     *                  CAP_REQUIRES_TWEAK; the host fails the call
     *                  closed if the bit is set and tweak_len is 0.
     *
     *   host_secret  — key material derived by the host from the
     *                  caller's password (typical: 32 bytes of
     *                  HKDF-SHA256 output under a versioned info
     *                  string). The plugin uses this to bind its
     *                  output to the user's secret, so extracting
     *                  the plugin and its config does not let an
     *                  attacker reproduce the transform offline.
     *                  May be NULL (host_secret_len 0) if the
     *                  plugin did not set CAP_REQUIRES_HOST_KEY; the
     *                  host fails the call closed if the bit is set
     *                  and host_secret_len is 0.
     *
     * The plugin MUST treat both buffers as read-only and MUST NOT
     * retain pointers to them after the call returns. Wipe any
     * derived intermediate key material before returning.
     *
     * NULL is permitted at the vtable slot for v1 plugins that only
     * support the deterministic forward(); the host will use that
     * path and refuse POS_RAW for the plugin. To advertise keyed
     * support, set BASEFWX_PLUGIN_CAP_KEYED in capabilities().
     */
    int (*forward_keyed)(basefwx_plugin_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         const uint8_t* tweak, size_t tweak_len,
                         const uint8_t* host_secret, size_t host_secret_len,
                         uint8_t* out, size_t out_cap, size_t* out_len);

    /*
     * Keyed inverse transform — used at decrypt time. Must be the
     * exact inverse of forward_keyed() under the same (tweak,
     * host_secret) pair.
     *
     * Self-derived-tweak plugins (e.g. the time-tweak example) may
     * accept tweak_len == 0 at this slot and recover the per-blob
     * entropy from the input itself (typical pattern: the plugin's
     * forward_keyed prepended the tweak bytes to its output, and
     * inverse_keyed reads them off the head). Set
     * CAP_NONDETERMINISTIC in capabilities() for that pattern;
     * authors who do NOT do this still set CAP_REQUIRES_TWEAK.
     */
    int (*inverse_keyed)(basefwx_plugin_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         const uint8_t* tweak, size_t tweak_len,
                         const uint8_t* host_secret, size_t host_secret_len,
                         uint8_t* out, size_t out_cap, size_t* out_len);

    /*
     * Reserved tail. Future ABI revisions can add function pointers
     * here without bumping api_version, provided the host treats
     * a NULL pointer as "feature not supported."
     */
    void (*reserved_1)(void);
} basefwx_plugin_vtable;

/*
 * Exported by the plugin. The host dlsym()s this symbol and calls it
 * exactly once per .so load. The returned pointer must remain valid
 * for the lifetime of the loaded library.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#  define BASEFWX_PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define BASEFWX_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#  define BASEFWX_PLUGIN_EXPORT
#endif

/*
 * Plugin entry point. Declared here so static analyzers can find it;
 * the plugin itself defines the symbol with BASEFWX_PLUGIN_EXPORT.
 *
 *   const basefwx_plugin_vtable* basefwx_plugin_entry(void);
 */

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* BASEFWX_PLUGIN_H */
