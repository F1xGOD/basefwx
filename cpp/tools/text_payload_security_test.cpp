/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/base64.hpp"
#include "basefwx/codec.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/filecodec.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/pb512.hpp"

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t kAuthenticatedPayloadVersion = 3;
constexpr std::uint8_t kLegacyMaskedPayloadVersion = 2;
constexpr std::size_t kPayloadHeaderSize = 5;
constexpr std::string_view kPassword =
    "basefwx-text-payload-test-password";

class ScopedEnvironment {
  public:
    ScopedEnvironment(const char* name, const std::string& value)
        : name_(name) {
        if (const char* existing = std::getenv(name)) {
            previous_ = existing;
        }
#if defined(_WIN32)
        _putenv_s(name, value.c_str());
#else
        setenv(name, value.c_str(), 1);
#endif
    }

    ~ScopedEnvironment() {
#if defined(_WIN32)
        _putenv_s(name_.c_str(), previous_.value_or("").c_str());
#else
        if (previous_.has_value()) {
            setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            unsetenv(name_.c_str());
        }
#endif
    }

    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

  private:
    std::string name_;
    std::optional<std::string> previous_;
};

void ExpectReject(const std::function<void()>& action,
                  std::string_view label,
                  std::string_view message_part = {}) {
    try {
        action();
    } catch (const std::exception& exc) {
        if (message_part.empty()
            || std::string_view(exc.what()).find(message_part)
                != std::string_view::npos) {
            return;
        }
        throw std::runtime_error(
            std::string(label) + " produced unexpected rejection: "
            + exc.what());
    }
    throw std::runtime_error(std::string(label) + " was accepted");
}

basefwx::pb512::KdfOptions TestKdf() {
    basefwx::pb512::KdfOptions kdf;
    kdf.label = "pbkdf2";
    kdf.pbkdf2_iterations = 1;
    return kdf;
}

Bytes DecodeOuter(const std::string& encoded) {
    bool ok = false;
    Bytes raw = basefwx::base64::Decode(encoded, &ok);
    if (!ok) {
        throw std::runtime_error("new text payload was not canonical base64");
    }
    return raw;
}

std::string Repack(const std::vector<Bytes>& parts) {
    return basefwx::base64::Encode(
        basefwx::format::PackLengthPrefixed(parts));
}

struct CodecCase {
    std::string_view name;
    std::string_view mask_info;
    std::string_view mask_aad;
    std::string_view stream_info;
    bool require_password;
    std::function<std::string(const std::string&)> encode;
    std::function<std::string(const std::string&)> decode;
};

std::string MakeLegacyV2(const CodecCase& codec,
                         const std::string& plaintext,
                         const basefwx::pb512::KdfOptions& kdf) {
    basefwx::keywrap::MaskKeyResult mask =
        basefwx::keywrap::PrepareMaskKey(
            std::string(kPassword),
            false,
            codec.mask_info,
            codec.require_password,
            codec.mask_aad,
            kdf);
    const Bytes clear(plaintext.begin(), plaintext.end());
    const Bytes masked = basefwx::keywrap::MaskPayload(
        mask.mask_key, clear, codec.stream_info);
    Bytes payload;
    payload.reserve(kPayloadHeaderSize + masked.size());
    payload.push_back(kLegacyMaskedPayloadVersion);
    const std::uint32_t length = static_cast<std::uint32_t>(clear.size());
    payload.push_back(static_cast<std::uint8_t>((length >> 24) & 0xff));
    payload.push_back(static_cast<std::uint8_t>((length >> 16) & 0xff));
    payload.push_back(static_cast<std::uint8_t>((length >> 8) & 0xff));
    payload.push_back(static_cast<std::uint8_t>(length & 0xff));
    payload.insert(payload.end(), masked.begin(), masked.end());
    return Repack({mask.user_blob, mask.master_blob, payload});
}

void TestCodec(const CodecCase& codec) {
    const std::string plaintext =
        std::string(codec.name) + " authenticated text payload";
    const std::string encoded = codec.encode(plaintext);
    const Bytes raw = DecodeOuter(encoded);
    std::vector<Bytes> parts =
        basefwx::format::UnpackLengthPrefixed(raw, 3);
    if (parts[2].size() < kPayloadHeaderSize
        || parts[2][0] != kAuthenticatedPayloadVersion) {
        throw std::runtime_error(
            std::string(codec.name) + " did not emit payload version 3");
    }
    if (codec.decode(encoded) != plaintext) {
        throw std::runtime_error(
            std::string(codec.name) + " v3 round trip failed");
    }

    const std::string obfuscated = basefwx::codec::Code(encoded);
    if (obfuscated == encoded || codec.decode(obfuscated) != plaintext) {
        throw std::runtime_error(
            std::string(codec.name)
            + " did not accept historical token-map expansion");
    }

    std::vector<Bytes> tag_tampered = parts;
    tag_tampered[2].back() ^= 1u;
    ExpectReject(
        [&]() { (void)codec.decode(Repack(tag_tampered)); },
        std::string(codec.name) + " ciphertext/tag tamper",
        "auth");

    std::vector<Bytes> header_tampered = parts;
    header_tampered[2][4] ^= 1u;
    ExpectReject(
        [&]() { (void)codec.decode(Repack(header_tampered)); },
        std::string(codec.name) + " header-length tamper",
        "length mismatch");

    const std::string legacy = MakeLegacyV2(codec, plaintext, TestKdf());
    {
        ScopedEnvironment disabled("BASEFWX_ALLOW_LEGACY_TEXT_V2", "0");
        ExpectReject(
            [&]() { (void)codec.decode(legacy); },
            std::string(codec.name) + " legacy v2 default policy",
            "disabled");
    }
    {
        ScopedEnvironment recovery("BASEFWX_ALLOW_LEGACY_TEXT_V2", "1");
        if (codec.decode(legacy) != plaintext) {
            throw std::runtime_error(
                std::string(codec.name) + " legacy v2 recovery failed");
        }
    }
}

void TestRawB512FileRecovery(const basefwx::pb512::KdfOptions& kdf) {
    basefwx::filecodec::FileOptions unauthenticated;
    unauthenticated.enable_aead = false;
    ExpectReject(
        [&]() {
            (void)basefwx::filecodec::B512EncodeBytes(
                Bytes{'p', 'a', 'y', 'l', 'o', 'a', 'd'},
                ".txt",
                std::string(kPassword),
                unauthenticated,
                kdf);
        },
        "unauthenticated b512file writer",
        "retired");

    const std::string extension = basefwx::pb512::B512Encode(
        ".txt", std::string(kPassword), false, kdf);
    const std::string data = basefwx::pb512::B512Encode(
        "cGF5bG9hZA==", std::string(kPassword), false, kdf);
    const std::string raw_text = extension
        + std::string(basefwx::constants::kFwxDelim)
        + data;
    const Bytes raw(raw_text.begin(), raw_text.end());

    {
        ScopedEnvironment disabled(
            "BASEFWX_ALLOW_LEGACY_B512FILE_RAW", "0");
        ExpectReject(
            [&]() {
                (void)basefwx::filecodec::B512DecodeBytes(
                    raw, std::string(kPassword), {}, kdf);
            },
            "unauthenticated raw b512file default policy",
            "disabled");
    }
    {
        ScopedEnvironment recovery(
            "BASEFWX_ALLOW_LEGACY_B512FILE_RAW", "1");
        const basefwx::filecodec::DecodedBytes decoded =
            basefwx::filecodec::B512DecodeBytes(
                raw, std::string(kPassword), {}, kdf);
        if (decoded.data != Bytes{'p', 'a', 'y', 'l', 'o', 'a', 'd'}
            || decoded.extension != ".txt") {
            throw std::runtime_error(
                "unauthenticated raw b512file recovery failed");
        }
    }
}

}  // namespace

int main() {
    try {
        ScopedEnvironment test_iters("BASEFWX_TEST_KDF_ITERS", "1");
        ScopedEnvironment canonical_output("BASEFWX_OBFUSCATE_CODECS", "0");
        const basefwx::pb512::KdfOptions kdf = TestKdf();

        const CodecCase b512{
            "b512",
            basefwx::constants::kB512MaskInfo,
            basefwx::constants::kMaskAadB512,
            basefwx::constants::kB512StreamInfo,
            false,
            [&](const std::string& value) {
                return basefwx::pb512::B512Encode(
                    value, std::string(kPassword), false, kdf);
            },
            [&](const std::string& value) {
                return basefwx::pb512::B512Decode(
                    value, std::string(kPassword), false, kdf);
            }};
        const CodecCase pb512{
            "pb512",
            basefwx::constants::kPb512MaskInfo,
            basefwx::constants::kMaskAadPb512,
            basefwx::constants::kPb512StreamInfo,
            true,
            [&](const std::string& value) {
                return basefwx::pb512::Pb512Encode(
                    value, std::string(kPassword), false, kdf);
            },
            [&](const std::string& value) {
                return basefwx::pb512::Pb512Decode(
                    value, std::string(kPassword), false, kdf);
            }};

        TestCodec(b512);
        TestCodec(pb512);
        TestRawB512FileRecovery(kdf);
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "text payload security test failed: "
                  << exc.what() << '\n';
        return 1;
    }
}
