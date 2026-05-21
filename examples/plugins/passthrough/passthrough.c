/*
 * BaseFWX example plugin
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0, with the
 * BaseFWX Plugin-Template Exception (see LICENCE clause 5).
 * You may use this file as a starting template for your own
 * Plugin under any license your Plugin chooses.
 */


#include <stdlib.h>
#include <string.h>

#include "basefwx/plugin.h"

/* Unique 16-byte identifier for THIS plugin. Generated once with
 * `uuidgen` and frozen for the life of the plugin — never change
 * after release. If you fork passthrough into your own plugin,
 * regenerate this and update the matching field in `kVtable`.
 * UUID: 4e3a09b1-3c8c-4f1e-9c3d-4a8b3f0c1d7e */

/* The example plugin holds no per-instance state, but the type still
 * has to exist so the host can pass *something* through. A struct
 * with one dummy field keeps the type non-opaque from the plugin's
 * point of view and zero-overhead. */
struct basefwx_plugin_ctx {
    int initialized;
};

static int pt_init(basefwx_plugin_ctx** out,
                   const uint8_t* config,
                   size_t config_len)
{
    (void)config;
    (void)config_len;
    if (!out) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    basefwx_plugin_ctx* ctx = (basefwx_plugin_ctx*)calloc(1, sizeof(*ctx));
    if (!ctx) return BASEFWX_PLUGIN_ERR_GENERIC;
    ctx->initialized = 1;
    *out = ctx;
    return BASEFWX_PLUGIN_OK;
}

static void pt_destroy(basefwx_plugin_ctx* ctx)
{
    if (!ctx) return;
    /* Real plugins should zero any secret material here. The
     * passthrough has nothing sensitive to wipe, but we model the
     * pattern anyway. */
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

static int pt_forward(basefwx_plugin_ctx* ctx,
                      const uint8_t* in, size_t in_len,
                      uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (!ctx || !ctx->initialized) return BASEFWX_PLUGIN_ERR_BAD_STATE;
    if (!out_len) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (in_len > out_cap) return BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL;
    if (in_len > 0) {
        if (!in || !out) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
        memcpy(out, in, in_len);
    }
    *out_len = in_len;
    return BASEFWX_PLUGIN_OK;
}

static int pt_inverse(basefwx_plugin_ctx* ctx,
                      const uint8_t* in, size_t in_len,
                      uint8_t* out, size_t out_cap, size_t* out_len)
{
    /* For passthrough the inverse is identical to the forward. Real
     * plugins implement the actual inverse transform here. */
    return pt_forward(ctx, in, in_len, out, out_cap, out_len);
}

static size_t pt_max_output(basefwx_plugin_ctx* ctx, size_t in_len)
{
    (void)ctx;
    return in_len;  /* length-preserving */
}

static int pt_selftest(basefwx_plugin_ctx* ctx)
{
    /* Round-trip a small fixed buffer to catch obvious regressions.
     * `basefwx-plugin-verify` runs this and treats a non-zero return
     * as a fail. */
    static const uint8_t kVec[] = {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x10, 0x20,
        0xa5, 0xa5, 0x5a, 0x5a, 0x11, 0x22, 0x33, 0x44,
    };
    uint8_t buf1[sizeof(kVec)];
    uint8_t buf2[sizeof(kVec)];
    size_t n1 = 0, n2 = 0;
    if (pt_forward(ctx, kVec, sizeof(kVec), buf1, sizeof(buf1), &n1) != BASEFWX_PLUGIN_OK)
        return BASEFWX_PLUGIN_ERR_GENERIC;
    if (n1 != sizeof(kVec)) return BASEFWX_PLUGIN_ERR_GENERIC;
    if (pt_inverse(ctx, buf1, n1, buf2, sizeof(buf2), &n2) != BASEFWX_PLUGIN_OK)
        return BASEFWX_PLUGIN_ERR_GENERIC;
    if (n2 != sizeof(kVec)) return BASEFWX_PLUGIN_ERR_GENERIC;
    if (memcmp(kVec, buf2, sizeof(kVec)) != 0)
        return BASEFWX_PLUGIN_ERR_GENERIC;
    return BASEFWX_PLUGIN_OK;
}

static const basefwx_plugin_vtable kVtable = {
    .api_version = BASEFWX_PLUGIN_API_VERSION,
    .plugin_id = {
        0x4e, 0x3a, 0x09, 0xb1, 0x3c, 0x8c, 0x4f, 0x1e,
        0x9c, 0x3d, 0x4a, 0x8b, 0x3f, 0x0c, 0x1d, 0x7e,
    },
    .name = "passthrough",
    .version = "1.0.0",
    .supported_positions = BASEFWX_PLUGIN_POS_PRE_AEAD | BASEFWX_PLUGIN_POS_POST_AEAD,
    .init = pt_init,
    .destroy = pt_destroy,
    .forward = pt_forward,
    .inverse = pt_inverse,
    .max_output_for_input = pt_max_output,
    .selftest = pt_selftest,
    .reserved_1 = NULL,
    .reserved_2 = NULL,
    .reserved_3 = NULL,
    .reserved_4 = NULL,
};

BASEFWX_PLUGIN_EXPORT
const basefwx_plugin_vtable* basefwx_plugin_entry(void)
{
    return &kVtable;
}
