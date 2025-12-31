#include "basefwx/format.hpp"

#include "basefwx/base64.hpp"

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
    std::size_t total = 4 * parts.size();
    for (const auto& part : parts) {
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
    std::vector<Bytes> parts;
    parts.reserve(count);
    std::size_t offset = 0;
    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t len = ReadU32BE(data, offset);
        offset += 4;
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
