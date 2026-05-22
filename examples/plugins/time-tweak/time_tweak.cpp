/*
 * BaseFWX example plugin
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0, with the
 * BaseFWX Plugin-Template Exception (see LICENCE clause 5).
 * You may use this file as a starting template for your own
 * Plugin under any license your Plugin chooses.
 *
 * ----------------------------------------------------------------
 * Self-derived-tweak reference. Demonstrates how a plugin can use
 * external entropy (here: a unix timestamp; could equally be a
 * counter, a process-startup random, etc.) to produce different
 * output for the same input on every call, while still being
 * fully decodable from the wire bytes alone.
 *
 * Wire format (after the plugin's transform):
 *
 *   [ tweak (8 bytes, BE unix-ms) ][ keystream-XOR of plaintext ]
 *
 * The plugin embeds the tweak at the head of its output. The
 * decoder reads it back and re-derives the keystream. The host
 * supplies host_secret; the host does NOT supply a tweak (the
 * plugin sets CAP_NONDETERMINISTIC, telling the host that the
 * tweak is self-derived).
 *
 * Construction:
 *
 *   tweak       = current unix time in milliseconds, 8 bytes big-endian
 *   keystream   = HKDF-SHA256(ikm=host_secret, salt=tweak,
 *                             info="example.time-tweak.v1", L=len(plaintext))
 *   output      = tweak || (plaintext XOR keystream)
 *
 * The HKDF expansion bound (HKDF-SHA256 caps at 255 * 32 = 8160
 * bytes) means this example can only handle short messages
 * directly. Production code that needs streaming should derive a
 * single AES key from HKDF and use a stream cipher (AES-CTR /
 * ChaCha20). The aead-wrapped-keyed example shows that pattern.
 *
 * Security note: this plugin provides confidentiality (per-call
 * fresh keystream bound to host_secret) but NO integrity. An
 * attacker can flip bits in the ciphertext and the decoder will
 * not detect it. Combine with an AEAD layer above (POS_POST_AEAD)
 * or add an HMAC tag (see aead-wrapped-keyed for the canonical
 * shape) before using in a threat model that includes active
 * tampering.
 * ---------------------------------------------------------------- */

#include <basefwx/plugin.hpp>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace {

constexpr std::size_t kTweakLen   = 8;
constexpr std::size_t kHkdfMax    = 255u * 32u;  // HKDF-SHA256 RFC-5869 bound

constexpr const char kHkdfInfo[]  = "example.time-tweak.v1";

void HkdfSha256(const std::uint8_t* ikm, std::size_t ikm_len,
                const std::uint8_t* salt, std::size_t salt_len,
                const std::uint8_t* info, std::size_t info_len,
                std::uint8_t* out, std::size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (ctx == nullptr) throw std::runtime_error("HKDF ctx alloc failed");
    auto fail = [&](const char* what) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error(what);
    };
    if (EVP_PKEY_derive_init(ctx) != 1) fail("HKDF derive_init failed");
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) fail("HKDF set_md failed");
    if (salt_len > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(salt_len)) != 1) {
        fail("HKDF set_salt failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, static_cast<int>(ikm_len)) != 1) {
        fail("HKDF set_key failed");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, static_cast<int>(info_len)) != 1) {
        fail("HKDF set_info failed");
    }
    std::size_t want = out_len;
    if (EVP_PKEY_derive(ctx, out, &want) != 1 || want != out_len) {
        fail("HKDF derive failed");
    }
    EVP_PKEY_CTX_free(ctx);
}

void WriteBe64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<std::uint8_t>(v & 0xff);
        v >>= 8;
    }
}

}  // namespace

class TimeTweakPlugin {
public:
    explicit TimeTweakPlugin(basefwx::plugin::ConfigView /*config*/) {
        // No static keying. All entropy comes from host_secret +
        // per-call self-derived tweak.
    }

    std::size_t MaxOutput(std::size_t in_len) const noexcept {
        return in_len + kTweakLen;
    }

    std::uint32_t Capabilities() const noexcept {
        return BASEFWX_PLUGIN_CAP_KEYED
             | BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY
             | BASEFWX_PLUGIN_CAP_NONDETERMINISTIC;
        // Deliberately NOT CAP_SAFE_RAW_MODE — this example provides
        // confidentiality but not integrity, so it must run wrapped
        // in an AEAD layer to be safe. See header comment.
    }

    std::size_t Forward(basefwx::plugin::BytesView /*in*/,
                        basefwx::plugin::BytesSpan /*out*/) {
        throw std::logic_error("time-tweak: use forward_keyed");
    }

    std::size_t Inverse(basefwx::plugin::BytesView /*in*/,
                        basefwx::plugin::BytesSpan /*out*/) {
        throw std::logic_error("time-tweak: use inverse_keyed");
    }

    std::size_t ForwardKeyed(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView /*tweak*/,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        if (host_secret.empty()) {
            throw std::invalid_argument("time-tweak: host_secret required");
        }
        if (in.size() > kHkdfMax) {
            // For short messages only — see header comment for the
            // streaming-friendly variant.
            throw std::invalid_argument("time-tweak: input too long for example");
        }
        if (out.capacity() < in.size() + kTweakLen) {
            throw std::out_of_range("time-tweak: out too small");
        }
        std::uint8_t tweak[kTweakLen];
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        WriteBe64(tweak, static_cast<std::uint64_t>(now_ms));

        basefwx::plugin::SecretBuffer ks(in.size());
        HkdfSha256(host_secret.data(), host_secret.size(),
                   tweak, kTweakLen,
                   reinterpret_cast<const std::uint8_t*>(kHkdfInfo),
                   sizeof(kHkdfInfo) - 1,
                   ks.data(), in.size());

        // Lay out: tweak || (in XOR keystream).
        std::memcpy(out.data(), tweak, kTweakLen);
        for (std::size_t i = 0; i < in.size(); ++i) {
            out.data()[kTweakLen + i] =
                static_cast<std::uint8_t>(in.data()[i] ^ ks.data()[i]);
        }
        return kTweakLen + in.size();
    }

    std::size_t InverseKeyed(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView /*tweak*/,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        if (host_secret.empty()) {
            throw std::invalid_argument("time-tweak: host_secret required");
        }
        if (in.size() < kTweakLen) {
            throw std::invalid_argument("time-tweak: input shorter than tweak");
        }
        const std::size_t pt_len = in.size() - kTweakLen;
        if (pt_len > kHkdfMax) {
            throw std::invalid_argument("time-tweak: ciphertext too long for example");
        }
        if (out.capacity() < pt_len) {
            throw std::out_of_range("time-tweak: out too small");
        }
        const std::uint8_t* embedded_tweak = in.data();
        basefwx::plugin::SecretBuffer ks(pt_len);
        HkdfSha256(host_secret.data(), host_secret.size(),
                   embedded_tweak, kTweakLen,
                   reinterpret_cast<const std::uint8_t*>(kHkdfInfo),
                   sizeof(kHkdfInfo) - 1,
                   ks.data(), pt_len);
        for (std::size_t i = 0; i < pt_len; ++i) {
            out.data()[i] = static_cast<std::uint8_t>(
                in.data()[kTweakLen + i] ^ ks.data()[i]);
        }
        return pt_len;
    }
};

// Plugin ID: 4f3a8c12-7d65-49b8-bc02-91e4a6087d31
//            (uuidgen output; never reused outside this example).
BASEFWX_PLUGIN_DEFINE_KEYED(
    TimeTweakPlugin,
    0x4f, 0x3a, 0x8c, 0x12, 0x7d, 0x65, 0x49, 0xb8,
    0xbc, 0x02, 0x91, 0xe4, 0xa6, 0x08, 0x7d, 0x31,
    "time-tweak",
    "1.0.0",
    BASEFWX_PLUGIN_POS_PRE_AEAD | BASEFWX_PLUGIN_POS_POST_AEAD);
