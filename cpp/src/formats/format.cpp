/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/format.hpp"

#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"

#include <limits>
#include <stdexcept>

namespace basefwx::format {

namespace {

std::uint32_t ReadU32BE(const Bytes& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Malformed length-prefixed blob (missing length)");
    }
    return (static_cast<std::uint32_t>(data[offset]) << 24)
           | (static_cast<std::uint32_t>(data[offset + 1]) << 16)
           | (static_cast<std::uint32_t>(data[offset + 2]) << 8)
           | static_cast<std::uint32_t>(data[offset + 3]);
}

}  // namespace

Bytes PackLengthPrefixed(const std::vector<Bytes>& parts) {
    constexpr std::size_t max =
        static_cast<std::size_t>(basefwx::constants::kLengthPrefixedMax);
    if (parts.size() > max / 4u) {
        throw std::runtime_error(
            "Length-prefixed blob exceeds 64 MiB total cap");
    }
    std::size_t total = 4u * parts.size();
    for (const auto& part : parts) {
        if (part.size() > max
            || part.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error(
                "Length-prefixed part exceeds 64 MiB cap");
        }
        if (part.size() > max - total) {
            throw std::runtime_error(
                "Length-prefixed blob exceeds 64 MiB total cap");
        }
        total += part.size();
    }
    Bytes out(total);
    std::size_t offset = 0;
    for (const auto& part : parts) {
        std::uint32_t len = static_cast<std::uint32_t>(part.size());
        out[offset] = static_cast<std::uint8_t>((len >> 24) & 0xFF);
        out[offset + 1] = static_cast<std::uint8_t>((len >> 16) & 0xFF);
        out[offset + 2] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
        out[offset + 3] = static_cast<std::uint8_t>(len & 0xFF);
        offset += 4;
        if (!part.empty()) {
            std::copy(part.begin(), part.end(), out.begin() + offset);
            offset += part.size();
        }
    }
    return out;
}

std::vector<Bytes> UnpackLengthPrefixed(const Bytes& data, std::size_t count) {
    // Match the 64 MiB total cap that Format.java has had since 3.4.x.
    // Without this, a malicious blob declaring a single 4 GiB part survives
    // until the data.size() bounds check fires — long enough for any
    // upstream code that pre-sizes a buffer from the length field to OOM.
    constexpr std::size_t kMaxPartLen =
        static_cast<std::size_t>(basefwx::constants::kLengthPrefixedMax);
    constexpr std::size_t kMaxTotalLen =
        static_cast<std::size_t>(basefwx::constants::kLengthPrefixedMax);
    if (data.size() > kMaxTotalLen) {
        throw std::runtime_error(
            "Length-prefixed blob exceeds 64 MiB total cap");
    }
    std::vector<Bytes> parts;
    parts.reserve(count);
    std::size_t offset = 0;
    std::size_t total_consumed = 0;
    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t len = ReadU32BE(data, offset);
        offset += 4;
        if (len > kMaxPartLen) {
            throw std::runtime_error("Length-prefixed part exceeds 64 MiB cap");
        }
        total_consumed += len;
        if (total_consumed > kMaxTotalLen) {
            throw std::runtime_error("Length-prefixed blob exceeds 64 MiB total cap");
        }
        if (offset + len > data.size()) {
            throw std::runtime_error("Malformed length-prefixed blob (truncated part)");
        }
        Bytes part;
        if (len > 0) {
            part.insert(part.end(), data.begin() + offset, data.begin() + offset + len);
        }
        parts.push_back(std::move(part));
        offset += len;
    }
    if (offset != data.size()) {
        throw std::runtime_error("Malformed length-prefixed blob (extra bytes)");
    }
    return parts;
}

PayloadParts SplitPayload(const Bytes& payload) {
    if (payload.size() < 4) {
        throw std::runtime_error("Payload too short");
    }
    std::uint32_t meta_len = ReadU32BE(payload, 0);
    if (meta_len > basefwx::constants::kMetadataMax) {
        throw std::runtime_error("Payload metadata exceeds 1 MiB cap");
    }
    std::size_t meta_end = 4 + meta_len;
    if (meta_end > payload.size()) {
        throw std::runtime_error("Malformed payload metadata header");
    }
    PayloadParts parts;
    if (meta_len > 0) {
        parts.metadata_blob.assign(payload.begin() + 4, payload.begin() + meta_end);
    }
    parts.ciphertext.insert(parts.ciphertext.end(), payload.begin() + meta_end, payload.end());
    return parts;
}

std::optional<MetadataPreview> TryDecodeMetadata(const Bytes& payload) {
    if (payload.size() < 4) {
        return std::nullopt;
    }
    std::uint32_t meta_len = ReadU32BE(payload, 0);
    if (meta_len > basefwx::constants::kMetadataMax) {
        return std::nullopt;
    }
    std::size_t meta_end = 4 + meta_len;
    if (meta_end > payload.size()) {
        return std::nullopt;
    }
    MetadataPreview preview;
    preview.metadata_len = meta_len;
    if (meta_len == 0) {
        return preview;
    }
    std::string blob(payload.begin() + 4, payload.begin() + meta_end);
    if (!basefwx::base64::IsLikelyBase64(blob)) {
        return std::nullopt;
    }
    bool ok = false;
    std::vector<std::uint8_t> decoded = basefwx::base64::Decode(blob, &ok);
    if (!ok) {
        return std::nullopt;
    }
    preview.metadata_base64 = blob;
    preview.metadata_json.assign(decoded.begin(), decoded.end());
    return preview;
}

}  // namespace basefwx::format
