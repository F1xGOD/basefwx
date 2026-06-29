/*
 * BaseFWX example plugin
 * Copyright (C) 2020-2026  FixCraft Inc.
 * SPDX-License-Identifier: MIT OR Apache-2.0
 * This file is intentionally permissive so plugin authors can use it as a starting template.
 */


#include <basefwx/plugin.hpp>

#include <array>
#include <stdexcept>

class XorRotatePlugin {
public:
    explicit XorRotatePlugin(basefwx::plugin::ConfigView config) {
        if (config.size() != kKeyLen) {
            throw std::invalid_argument(
                "xor-rotate requires exactly 32 bytes of config (the XOR key)");
        }
        key_.assign(config);
    }

    std::size_t MaxOutput(std::size_t in_len) const noexcept {
        return in_len;  // length-preserving
    }

    std::size_t Forward(basefwx::plugin::BytesView in,
                        basefwx::plugin::BytesSpan out) {
        return Transform(in, out);
    }

    // XOR is self-inverse, so Inverse() is the same operation.
    std::size_t Inverse(basefwx::plugin::BytesView in,
                        basefwx::plugin::BytesSpan out) {
        return Transform(in, out);
    }

private:
    std::size_t Transform(basefwx::plugin::BytesView in,
                          basefwx::plugin::BytesSpan out) {
        if (in.size() > out.capacity()) {
            // Will be translated to BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL
            // by the wrapper.
            throw std::out_of_range("xor-rotate: output buffer too small");
        }
        std::uint8_t* o = out.data();
        for (std::size_t i = 0; i < in.size(); ++i) {
            // Rotate through the key with the position-dependent twist.
            const std::uint8_t k = key_.data()[i % kKeyLen];
            const std::uint8_t roll = static_cast<std::uint8_t>(i * 31u);
            o[i] = static_cast<std::uint8_t>(in.data()[i] ^ k ^ roll);
        }
        return in.size();
    }

    static constexpr std::size_t kKeyLen = 32;
    basefwx::plugin::SecretBuffer key_;
};

// Plugin ID: 8d4c2a01-1f70-4d3a-91ab-2c5e8f917b04
//            (uuidgen output; never reused outside this example).
BASEFWX_PLUGIN_DEFINE(
    XorRotatePlugin,
    0x8d, 0x4c, 0x2a, 0x01, 0x1f, 0x70, 0x4d, 0x3a,
    0x91, 0xab, 0x2c, 0x5e, 0x8f, 0x91, 0x7b, 0x04,
    "xor-rotate",
    "1.0.0",
    BASEFWX_PLUGIN_POS_PRE_AEAD | BASEFWX_PLUGIN_POS_POST_AEAD);
