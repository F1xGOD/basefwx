/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/pb512.hpp"

#include "basefwx/base64.hpp"
#include "basefwx/codec.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"

#include <limits>
#include <stdexcept>
#include <string_view>

namespace basefwx::pb512 {

namespace {

using basefwx::keywrap::MaskKeyResult;
using basefwx::keywrap::MaskPayload;
using basefwx::keywrap::PrepareMaskKey;
using basefwx::keywrap::RecoverMaskKey;

constexpr std::uint8_t kAuthenticatedPayloadVersion = 0x03;
constexpr std::uint8_t kLegacyMaskedPayloadVersion = 0x02;
constexpr std::size_t kPayloadHeaderSize = 5;

std::string BytesToString(const std::vector<std::uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

void AppendU32(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    output.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

std::uint32_t ReadU32(const Bytes& input, std::size_t offset) {
    if (offset > input.size() || input.size() - offset < 4) {
        throw std::runtime_error("Malformed payload");
    }
    return (static_cast<std::uint32_t>(input[offset]) << 24)
         | (static_cast<std::uint32_t>(input[offset + 1]) << 16)
         | (static_cast<std::uint32_t>(input[offset + 2]) << 8)
         | static_cast<std::uint32_t>(input[offset + 3]);
}

Bytes PayloadAad(std::string_view domain, const Bytes& payload) {
    if (payload.size() < kPayloadHeaderSize) {
        throw std::runtime_error("Malformed payload");
    }
    Bytes aad(domain.begin(), domain.end());
    aad.insert(aad.end(), payload.begin(), payload.begin() + kPayloadHeaderSize);
    return aad;
}

std::uint32_t ValidateAuthenticatedPayload(const Bytes& payload) {
    const std::size_t overhead = kPayloadHeaderSize
        + basefwx::constants::kAeadNonceLen
        + basefwx::constants::kAeadTagLen;
    if (payload.size() < overhead) {
        throw std::runtime_error("Authenticated payload is truncated");
    }
    const std::uint32_t expected_len = ReadU32(payload, 1);
    if (static_cast<std::size_t>(expected_len) != payload.size() - overhead) {
        throw std::runtime_error("Payload length mismatch");
    }
    return expected_len;
}

std::uint32_t ValidateLegacyMaskedPayload(const Bytes& payload) {
    if (!basefwx::env::IsEnabled("BASEFWX_ALLOW_LEGACY_TEXT_V2", false)) {
        throw std::runtime_error(
            "Unauthenticated text payload v2 is disabled; set "
            "BASEFWX_ALLOW_LEGACY_TEXT_V2=1 only to recover trusted legacy data");
    }
    if (payload.size() < kPayloadHeaderSize) {
        throw std::runtime_error("Malformed payload");
    }
    const std::uint32_t expected_len = ReadU32(payload, 1);
    if (static_cast<std::size_t>(expected_len)
        != payload.size() - kPayloadHeaderSize) {
        throw std::runtime_error("Payload length mismatch");
    }
    return expected_len;
}

std::string EncodeMaskedPayload(const std::vector<std::uint8_t>& mask_key,
                                const std::vector<std::uint8_t>& user_blob,
                                const std::vector<std::uint8_t>& master_blob,
                                const std::string& input,
                                std::string_view payload_aead_info,
                                std::string_view payload_aad) {
    if (input.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("Text payload is too large");
    }

    basefwx::crypto::SecureBytes plain_bytes{
        Bytes(input.begin(), input.end())};
    basefwx::crypto::SecureBytes payload_key{
        basefwx::crypto::HkdfSha256(mask_key, payload_aead_info, 32)};
    Bytes payload;
    payload.reserve(kPayloadHeaderSize
        + basefwx::constants::kAeadNonceLen
        + plain_bytes.size()
        + basefwx::constants::kAeadTagLen);
    payload.push_back(kAuthenticatedPayloadVersion);
    AppendU32(payload, static_cast<std::uint32_t>(plain_bytes.size()));
    const Bytes aad = PayloadAad(payload_aad, payload);
    const Bytes encrypted = basefwx::crypto::AesGcmEncrypt(
        payload_key.bytes(), plain_bytes.bytes(), aad);
    payload.insert(payload.end(), encrypted.begin(), encrypted.end());

    std::vector<basefwx::format::Bytes> parts = {user_blob, master_blob, payload};
    std::vector<std::uint8_t> blob = basefwx::format::PackLengthPrefixed(parts);
    std::string encoded = basefwx::base64::Encode(blob);
    if (basefwx::env::IsEnabled("BASEFWX_OBFUSCATE_CODECS", false)) {
        return basefwx::codec::Code(encoded);
    }
    return encoded;
}

std::string DecodeMaskedPayload(const std::string& input,
                                const std::string& password,
                                bool use_master,
                                std::string_view mask_info,
                                std::string_view aad,
                                std::string_view stream_info,
                                std::string_view payload_aead_info,
                                std::string_view payload_aad,
                                const KdfOptions& kdf) {
    std::string prepared = input;
    std::string fallback;
    if (!basefwx::base64::IsLikelyBase64(prepared)) {
        prepared = basefwx::codec::Decode(input);
        fallback = input;
    }
    bool ok = false;
    std::vector<std::uint8_t> raw = basefwx::base64::Decode(prepared, &ok);
    if (!ok) {
        if (fallback.empty()) {
            std::string decoded = basefwx::codec::Decode(input);
            if (decoded != prepared) {
                raw = basefwx::base64::Decode(decoded, &ok);
            }
        } else if (fallback != prepared) {
            raw = basefwx::base64::Decode(fallback, &ok);
        }
    }
    if (!ok) {
        throw std::runtime_error("Invalid payload encoding");
    }
    std::vector<basefwx::format::Bytes> parts = basefwx::format::UnpackLengthPrefixed(raw, 3);
    const std::vector<std::uint8_t>& payload = parts[2];
    if (payload.empty()) {
        throw std::runtime_error("Unsupported payload format");
    }

    if (payload[0] == kAuthenticatedPayloadVersion) {
        const std::uint32_t expected_len = ValidateAuthenticatedPayload(payload);
        basefwx::crypto::SecureBytes mask_key{RecoverMaskKey(
            parts[0], parts[1], password, use_master, mask_info, aad, kdf)};
        basefwx::crypto::SecureBytes payload_key{basefwx::crypto::HkdfSha256(
            mask_key.bytes(), payload_aead_info, 32)};
        const Bytes payload_blob(payload.begin() + kPayloadHeaderSize, payload.end());
        basefwx::crypto::SecureBytes clear{basefwx::crypto::AesGcmDecrypt(
            payload_key.bytes(), payload_blob, PayloadAad(payload_aad, payload))};
        if (clear.size() != expected_len) {
            throw std::runtime_error("Payload length mismatch");
        }
        return BytesToString(clear.bytes());
    }

    if (payload[0] == kLegacyMaskedPayloadVersion) {
        const std::uint32_t expected_len = ValidateLegacyMaskedPayload(payload);
        basefwx::crypto::SecureBytes mask_key{RecoverMaskKey(
            parts[0], parts[1], password, use_master, mask_info, aad, kdf)};
        const Bytes masked(payload.begin() + kPayloadHeaderSize, payload.end());
        basefwx::crypto::SecureBytes clear{
            MaskPayload(mask_key.bytes(), masked, stream_info)};
        if (clear.size() != expected_len) {
            throw std::runtime_error("Payload length mismatch");
        }
        return BytesToString(clear.bytes());
    }

    throw std::runtime_error("Unsupported payload format");
}

}  // namespace

std::string B512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    MaskKeyResult mask = PrepareMaskKey(password, use_master, constants::kB512MaskInfo, false, constants::kMaskAadB512, kdf);
    return EncodeMaskedPayload(
        mask.mask_key,
        mask.user_blob,
        mask.master_blob,
        input,
        constants::kB512PayloadAeadInfo,
        constants::kB512PayloadAad);
}

std::string B512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    return DecodeMaskedPayload(input, password, use_master, constants::kB512MaskInfo, constants::kMaskAadB512,
                               constants::kB512StreamInfo,
                               constants::kB512PayloadAeadInfo,
                               constants::kB512PayloadAad,
                               kdf);
}

std::string Pb512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    MaskKeyResult mask = PrepareMaskKey(password, use_master, constants::kPb512MaskInfo, true, constants::kMaskAadPb512, kdf);
    return EncodeMaskedPayload(
        mask.mask_key,
        mask.user_blob,
        mask.master_blob,
        input,
        constants::kPb512PayloadAeadInfo,
        constants::kPb512PayloadAad);
}

std::string Pb512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    return DecodeMaskedPayload(input, password, use_master, constants::kPb512MaskInfo, constants::kMaskAadPb512,
                               constants::kPb512StreamInfo,
                               constants::kPb512PayloadAeadInfo,
                               constants::kPb512PayloadAad,
                               kdf);
}

}  // namespace basefwx::pb512
