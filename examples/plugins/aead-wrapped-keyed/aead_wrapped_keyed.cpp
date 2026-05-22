/*
 * BaseFWX example plugin
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0, with the
 * BaseFWX Plugin-Template Exception (see LICENCE clause 5).
 * You may use this file as a starting template for your own
 * Plugin under any license your Plugin chooses.
 *
 * ----------------------------------------------------------------
 * Profile B reference: AEAD-wrapped, keyed, raw-mode safe.
 * Defends against THREAT_MODEL.md TM-1, TM-2, TM-3, and TM-4.
 *
 * Wire format (after the plugin's transform):
 *
 *   [ ciphertext (= len(plaintext)) ][ tag (16 bytes) ]
 *
 * The host owns the tweak: it generates 16 random bytes per blob and
 * supplies them via forward_keyed. The host either prepends `tweak`
 * to the blob it stores/transmits, or threads it out-of-band. The
 * decoder calls inverse_keyed with the same tweak.
 *
 * Construction:
 *
 *   derived  = HKDF-SHA256(ikm=host_secret, salt=tweak,
 *                          info="example.aead-wrapped-keyed.v1", L=80)
 *   aes_key  = derived[0..32]
 *   aes_iv   = derived[32..48]
 *   mac_key  = derived[48..80]
 *
 *   ciphertext = AES-256-CTR(aes_key, aes_iv, plaintext)
 *   tag        = HMAC-SHA256(mac_key, tweak || ciphertext)[0..16]
 *
 *   forward output = ciphertext || tag
 *
 * Why these choices:
 *
 *   - HKDF binds the keys to BOTH host_secret AND tweak. An attacker
 *     who extracts the plugin .so AND its config (which this plugin
 *     does not even consult for crypto) still cannot reproduce the
 *     transform without the host's host_secret.
 *
 *   - AES-IV is freshly derived per call from HKDF output instead of
 *     the conventional "use tweak as IV". This means the IV uniqueness
 *     argument doesn't rely on careful tweak handling at the host
 *     side; the IV is unique whenever (host_secret, tweak) is unique.
 *
 *   - HMAC tag is over `tweak || ciphertext` so a tweak swap is also
 *     detected.
 *
 *   - Constant-time tag comparison (CRYPTO_memcmp).
 *
 *   - All derived key material is wiped via SecretBuffer before the
 *     transform returns.
 * ---------------------------------------------------------------- */

#include <basefwx/plugin.hpp>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstring>
#include <stdexcept>

namespace {

constexpr std::size_t kAesKeyLen = 32;
constexpr std::size_t kAesIvLen  = 16;
constexpr std::size_t kMacKeyLen = 32;
constexpr std::size_t kTagLen    = 16;
constexpr std::size_t kHkdfLen   = kAesKeyLen + kAesIvLen + kMacKeyLen;
constexpr std::size_t kTweakLen  = 16;

constexpr const char kHkdfInfo[] = "example.aead-wrapped-keyed.v1";

// HKDF-SHA256 via OpenSSL EVP. Plugin authors who need a portable
// implementation can copy this or use libsodium / libhydrogen
// equivalents.
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

// AES-256-CTR keystream XOR. Length-preserving.
void AesCtrCrypt(const std::uint8_t key[kAesKeyLen],
                 const std::uint8_t iv[kAesIvLen],
                 const std::uint8_t* in, std::size_t len,
                 std::uint8_t* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw std::runtime_error("CTR ctx alloc failed");
    auto fail = [&](const char* what) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(what);
    };
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
        fail("CTR init failed");
    }
    int outl = 0;
    if (EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(len)) != 1) {
        fail("CTR update failed");
    }
    int finl = 0;
    if (EVP_EncryptFinal_ex(ctx, out + outl, &finl) != 1) {
        fail("CTR final failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}

// HMAC-SHA256 via OpenSSL 3.x EVP_MAC. The legacy HMAC_* API is
// deprecated in 3.0; this matches the pattern in basefwx core.
void HmacSha256(const std::uint8_t key[kMacKeyLen],
                const std::uint8_t* data1, std::size_t len1,
                const std::uint8_t* data2, std::size_t len2,
                std::uint8_t out[32]) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac == nullptr) throw std::runtime_error("MAC fetch failed");
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == nullptr) {
        EVP_MAC_free(mac);
        throw std::runtime_error("MAC ctx alloc failed");
    }
    auto fail = [&](const char* what) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw std::runtime_error(what);
    };
    char digest_name[] = "SHA256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                  digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, key, kMacKeyLen, params) != 1) fail("MAC init failed");
    if (len1 > 0 && EVP_MAC_update(ctx, data1, len1) != 1) fail("MAC update1 failed");
    if (len2 > 0 && EVP_MAC_update(ctx, data2, len2) != 1) fail("MAC update2 failed");
    std::size_t out_len = 32;
    if (EVP_MAC_final(ctx, out, &out_len, 32) != 1 || out_len != 32) {
        fail("MAC final failed");
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

}  // namespace

class AeadWrappedKeyedPlugin {
public:
    explicit AeadWrappedKeyedPlugin(basefwx::plugin::ConfigView /*config*/) {
        // This plugin deliberately does not consult the static config
        // blob for any crypto-relevant material. All keying comes from
        // the per-call host_secret. See THREAT_MODEL.md TM-2: making
        // the secret static is exactly the footgun the keyed path
        // exists to close.
    }

    std::size_t MaxOutput(std::size_t in_len) const noexcept {
        return in_len + kTagLen;
    }

    std::uint32_t Capabilities() const noexcept {
        return BASEFWX_PLUGIN_CAP_KEYED
             | BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE
             | BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY
             | BASEFWX_PLUGIN_CAP_REQUIRES_TWEAK;
    }

    // The v1 deterministic path is not implemented — this plugin is
    // strict raw-mode-safe and refuses use without keying.
    std::size_t Forward(basefwx::plugin::BytesView /*in*/,
                        basefwx::plugin::BytesSpan /*out*/) {
        throw std::logic_error("aead-wrapped-keyed: use forward_keyed; "
                               "the deterministic v1 path is unsafe for this plugin");
    }

    std::size_t Inverse(basefwx::plugin::BytesView /*in*/,
                        basefwx::plugin::BytesSpan /*out*/) {
        throw std::logic_error("aead-wrapped-keyed: use inverse_keyed");
    }

    std::size_t ForwardKeyed(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView tweak,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        if (tweak.size() != kTweakLen) {
            throw std::invalid_argument(
                "aead-wrapped-keyed: tweak must be exactly 16 bytes");
        }
        if (host_secret.empty()) {
            throw std::invalid_argument(
                "aead-wrapped-keyed: host_secret required");
        }
        const std::size_t need = in.size() + kTagLen;
        if (out.capacity() < need) {
            throw std::out_of_range("aead-wrapped-keyed: out too small");
        }
        basefwx::plugin::SecretBuffer derived(kHkdfLen);
        HkdfSha256(host_secret.data(), host_secret.size(),
                   tweak.data(), tweak.size(),
                   reinterpret_cast<const std::uint8_t*>(kHkdfInfo),
                   sizeof(kHkdfInfo) - 1,
                   derived.data(), kHkdfLen);
        const std::uint8_t* aes_key = derived.data();
        const std::uint8_t* aes_iv  = derived.data() + kAesKeyLen;
        const std::uint8_t* mac_key = derived.data() + kAesKeyLen + kAesIvLen;

        std::uint8_t* ct = out.data();
        AesCtrCrypt(aes_key, aes_iv, in.data(), in.size(), ct);

        std::uint8_t tag_full[32];
        HmacSha256(mac_key, tweak.data(), tweak.size(),
                   ct, in.size(), tag_full);
        std::memcpy(out.data() + in.size(), tag_full, kTagLen);
        // tag_full holds the full 32-byte digest; only first 16 are
        // exposed. Wipe the unused tail explicitly.
        OPENSSL_cleanse(tag_full, sizeof(tag_full));

        return need;
    }

    std::size_t InverseKeyed(basefwx::plugin::BytesView in,
                             basefwx::plugin::BytesView tweak,
                             basefwx::plugin::BytesView host_secret,
                             basefwx::plugin::BytesSpan out) {
        if (tweak.size() != kTweakLen) {
            throw std::invalid_argument(
                "aead-wrapped-keyed: tweak must be exactly 16 bytes");
        }
        if (host_secret.empty()) {
            throw std::invalid_argument(
                "aead-wrapped-keyed: host_secret required");
        }
        if (in.size() < kTagLen) {
            throw std::invalid_argument(
                "aead-wrapped-keyed: input shorter than tag");
        }
        const std::size_t ct_len = in.size() - kTagLen;
        if (out.capacity() < ct_len) {
            throw std::out_of_range("aead-wrapped-keyed: out too small");
        }
        basefwx::plugin::SecretBuffer derived(kHkdfLen);
        HkdfSha256(host_secret.data(), host_secret.size(),
                   tweak.data(), tweak.size(),
                   reinterpret_cast<const std::uint8_t*>(kHkdfInfo),
                   sizeof(kHkdfInfo) - 1,
                   derived.data(), kHkdfLen);
        const std::uint8_t* aes_key = derived.data();
        const std::uint8_t* aes_iv  = derived.data() + kAesKeyLen;
        const std::uint8_t* mac_key = derived.data() + kAesKeyLen + kAesIvLen;

        std::uint8_t tag_expected[32];
        HmacSha256(mac_key, tweak.data(), tweak.size(),
                   in.data(), ct_len, tag_expected);
        // CRYPTO_memcmp is constant-time on the inputs.
        const int diff = CRYPTO_memcmp(tag_expected,
                                       in.data() + ct_len,
                                       kTagLen);
        OPENSSL_cleanse(tag_expected, sizeof(tag_expected));
        if (diff != 0) {
            throw std::invalid_argument(
                "aead-wrapped-keyed: tag mismatch (wrong key, tweak, or tampered)");
        }
        AesCtrCrypt(aes_key, aes_iv, in.data(), ct_len, out.data());
        return ct_len;
    }
};

// Plugin ID: 7e2b5d9f-08c4-4f12-9a1e-5b3c8d6f4127
//            (uuidgen output; never reused outside this example).
BASEFWX_PLUGIN_DEFINE_KEYED(
    AeadWrappedKeyedPlugin,
    0x7e, 0x2b, 0x5d, 0x9f, 0x08, 0xc4, 0x4f, 0x12,
    0x9a, 0x1e, 0x5b, 0x3c, 0x8d, 0x6f, 0x41, 0x27,
    "aead-wrapped-keyed",
    "1.0.0",
    BASEFWX_PLUGIN_POS_PRE_AEAD | BASEFWX_PLUGIN_POS_POST_AEAD | BASEFWX_PLUGIN_POS_RAW);
