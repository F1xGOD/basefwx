#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace basefwx::format {

using Bytes = std::vector<std::uint8_t>;

struct PayloadParts {
    std::string metadata_blob;
    Bytes ciphertext;
};

struct MetadataPreview {
    std::uint32_t metadata_len = 0;
    std::string metadata_base64;
    std::string metadata_json;
};

Bytes PackLengthPrefixed(const std::vector<Bytes>& parts);
std::vector<Bytes> UnpackLengthPrefixed(const Bytes& data, std::size_t count);

PayloadParts SplitPayload(const Bytes& payload);
std::optional<MetadataPreview> TryDecodeMetadata(const Bytes& payload);

}  // namespace basefwx::format
