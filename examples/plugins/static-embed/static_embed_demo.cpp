/*
 * BaseFWX example — static-embedded plugin
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0, with the
 * BaseFWX Plugin-Template Exception (see LICENCE clause 5).
 *
 * ----------------------------------------------------------------
 * Demonstrates the plugin_static.hpp Registry API. The plugin
 * source is compiled directly into this host binary instead of
 * being shipped as a separate .so. The host loader resolves the
 * plugin by its 16-byte ID from the in-process Registry, NOT via
 * dlopen.
 *
 * License note: statically linking BaseFWX itself into a closed-
 * source binary requires a commercial license (see LICENSING.md).
 * The example here statically embeds ONLY the plugin source against
 * a header-only public ABI; it does not link the BaseFWX
 * implementation at all, so it stays inside the free track. Real
 * commercial deployments that want both the plugin AND the
 * BaseFWX library embedded need the commercial license.
 *
 * Build:
 *     cmake -S examples/plugins/static-embed -B examples/plugins/static-embed/build
 *     cmake --build examples/plugins/static-embed/build
 *
 * Produces an executable that:
 *   1. Defines an in-process plugin (here: a trivial XOR-with-host-secret
 *      transform, similar in shape to xor-rotate but bound to host_secret).
 *   2. Registers it at startup via BASEFWX_PLUGIN_REGISTER_STATIC.
 *   3. Looks it up by plugin_id and runs a forward / inverse round-trip.
 *   4. Prints PASS / FAIL.
 * ---------------------------------------------------------------- */

#include <basefwx/plugin.hpp>
#include <basefwx/plugin_static.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace {

class StaticEmbedExamplePlugin {
public:
    explicit StaticEmbedExamplePlugin(basefwx::plugin::ConfigView /*config*/) {}

    std::size_t MaxOutput(std::size_t in_len) const noexcept {
        return in_len;
    }

    std::uint32_t Capabilities() const noexcept {
        // Keyed (uses host_secret) but NOT raw-mode-safe — no integrity.
        // For raw-mode safety, copy aead-wrapped-keyed/.
        return BASEFWX_PLUGIN_CAP_KEYED
             | BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY;
    }

    std::size_t Forward(basefwx::plugin::BytesView /*in*/,
                        basefwx::plugin::BytesSpan /*out*/) {
        throw std::logic_error("static-embed-demo: use forward_keyed");
    }

    std::size_t Inverse(basefwx::plugin::BytesView /*in*/,
                        basefwx::plugin::BytesSpan /*out*/) {
        throw std::logic_error("static-embed-demo: use inverse_keyed");
    }

    std::size_t ForwardKeyed(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView /*tweak*/,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        return XorTransform(in, host_secret, out);
    }

    std::size_t InverseKeyed(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView /*tweak*/,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        return XorTransform(in, host_secret, out);  // XOR is self-inverse
    }

private:
    std::size_t XorTransform(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        if (host_secret.empty()) {
            throw std::invalid_argument("static-embed-demo: host_secret required");
        }
        if (out.capacity() < in.size()) {
            throw std::out_of_range("static-embed-demo: out too small");
        }
        for (std::size_t i = 0; i < in.size(); ++i) {
            out.data()[i] = static_cast<std::uint8_t>(
                in.data()[i] ^ host_secret.data()[i % host_secret.size()]);
        }
        return in.size();
    }
};

// Plugin ID: 18b3e72c-4905-4a3a-b6d8-c1f29f574e8a
BASEFWX_PLUGIN_DEFINE_KEYED(
    StaticEmbedExamplePlugin,
    0x18, 0xb3, 0xe7, 0x2c, 0x49, 0x05, 0x4a, 0x3a,
    0xb6, 0xd8, 0xc1, 0xf2, 0x9f, 0x57, 0x4e, 0x8a,
    "static-embed-demo",
    "1.0.0",
    BASEFWX_PLUGIN_POS_PRE_AEAD | BASEFWX_PLUGIN_POS_POST_AEAD);

}  // namespace

// Register the plugin at program startup. After this runs, the
// Registry can resolve the plugin by its 16-byte ID, without
// dlopen / dlsym.
BASEFWX_PLUGIN_REGISTER_STATIC(basefwx_plugin_entry());

namespace {

constexpr std::array<std::uint8_t, 16> kExpectedPluginId = {
    0x18, 0xb3, 0xe7, 0x2c, 0x49, 0x05, 0x4a, 0x3a,
    0xb6, 0xd8, 0xc1, 0xf2, 0x9f, 0x57, 0x4e, 0x8a,
};

int RunRoundTrip() {
    auto* vtbl = basefwx::plugin::Registry::Instance().Find(kExpectedPluginId);
    if (vtbl == nullptr) {
        std::fprintf(stderr, "FAIL: plugin not found in registry\n");
        return 1;
    }
    std::printf("OK: resolved plugin %s v%s from registry (no dlopen)\n",
                vtbl->name, vtbl->version);

    if (vtbl->capabilities == nullptr || vtbl->forward_keyed == nullptr) {
        std::fprintf(stderr, "FAIL: vtable missing keyed slots\n");
        return 1;
    }

    basefwx_plugin_ctx* ctx = nullptr;
    if (vtbl->init(&ctx, nullptr, 0) != BASEFWX_PLUGIN_OK || ctx == nullptr) {
        std::fprintf(stderr, "FAIL: init() failed\n");
        return 1;
    }

    const std::uint32_t caps = vtbl->capabilities(ctx);
    std::printf("OK: capabilities=0x%08x (KEYED=%d REQUIRES_HOST_KEY=%d)\n",
                caps,
                (caps & BASEFWX_PLUGIN_CAP_KEYED) ? 1 : 0,
                (caps & BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY) ? 1 : 0);

    const char* plaintext = "static-embed-demo round-trip payload";
    const std::size_t pt_len = std::strlen(plaintext);
    const std::uint8_t host_secret[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
        0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
    };

    const std::size_t cap = vtbl->max_output_for_input(ctx, pt_len);
    std::vector<std::uint8_t> mid(cap);
    std::vector<std::uint8_t> back(cap);
    std::size_t mid_len = 0;
    if (vtbl->forward_keyed(ctx,
                            reinterpret_cast<const std::uint8_t*>(plaintext), pt_len,
                            nullptr, 0,
                            host_secret, sizeof(host_secret),
                            mid.data(), mid.size(), &mid_len) != BASEFWX_PLUGIN_OK) {
        std::fprintf(stderr, "FAIL: forward_keyed failed\n");
        vtbl->destroy(ctx);
        return 1;
    }
    std::size_t back_len = 0;
    if (vtbl->inverse_keyed(ctx,
                            mid.data(), mid_len,
                            nullptr, 0,
                            host_secret, sizeof(host_secret),
                            back.data(), back.size(), &back_len) != BASEFWX_PLUGIN_OK) {
        std::fprintf(stderr, "FAIL: inverse_keyed failed\n");
        vtbl->destroy(ctx);
        return 1;
    }
    if (back_len != pt_len ||
        std::memcmp(back.data(), plaintext, pt_len) != 0) {
        std::fprintf(stderr, "FAIL: round-trip mismatch\n");
        vtbl->destroy(ctx);
        return 1;
    }

    vtbl->destroy(ctx);
    std::printf("PASS: static-embed plugin round-trip OK (%zu bytes)\n", pt_len);
    return 0;
}

}  // namespace

int main() {
    std::printf("BaseFWX static-embed plugin demo\n");
    std::printf("Registry holds %zu plugin(s).\n",
                basefwx::plugin::Registry::Instance().Count());
    return RunRoundTrip();
}
