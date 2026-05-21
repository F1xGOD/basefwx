/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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

/* Opaque per-instance state. The plugin owns the layout; the host
 * only ever holds a pointer-to-opaque. */
typedef struct basefwx_plugin_ctx basefwx_plugin_ctx;

/* Pipeline position flags. Combine with bitwise OR if your plugin
 * supports both. The host writes the selected position(s) into the
 * blob's plugin tag at encrypt time. */
#define BASEFWX_PLUGIN_POS_PRE_AEAD   (1u << 0)  /* transforms plaintext */
#define BASEFWX_PLUGIN_POS_POST_AEAD  (1u << 1)  /* transforms ciphertext */

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
     * Reserved tail. Future ABI revisions can add function pointers
     * here without bumping api_version, provided the host treats
     * a NULL pointer as "feature not supported."
     */
    void (*reserved_1)(void);
    void (*reserved_2)(void);
    void (*reserved_3)(void);
    void (*reserved_4)(void);
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
