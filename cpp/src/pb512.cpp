#include "basefwx/pb512.hpp"

#include "basefwx/base64.hpp"
#include "basefwx/codec.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"

#include <stdexcept>
#include <string_view>

namespace basefwx::pb512 {

namespace {

using basefwx::keywrap::MaskKeyResult;
using basefwx::keywrap::MaskPayload;
using basefwx::keywrap::PrepareMaskKey;
using basefwx::keywrap::RecoverMaskKey;

std::string BytesToString(const std::vector<std::uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::string EncodeMaskedPayload(const std::vector<std::uint8_t>& mask_key,
                                const std::vector<std::uint8_t>& user_blob,
                                const std::vector<std::uint8_t>& master_blob,
                                const std::string& input,
                                std::string_view stream_info) {
    std::vector<std::uint8_t> plain_bytes(input.begin(), input.end());
    std::vector<std::uint8_t> masked = MaskPayload(mask_key, plain_bytes, stream_info);
    std::vector<std::uint8_t> payload;
    payload.reserve(1 + 4 + masked.size());
    payload.push_back(0x02);
    std::uint32_t len = static_cast<std::uint32_t>(plain_bytes.size());
    payload.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>(len & 0xFF));
    payload.insert(payload.end(), masked.begin(), masked.end());

    std::vector<basefwx::format::Bytes> parts = {user_blob, master_blob, payload};
    std::vector<std::uint8_t> blob = basefwx::format::PackLengthPrefixed(parts);
    std::string encoded = basefwx::base64::Encode(blob);
    if (basefwx::env::IsEnabled("BASEFWX_OBFUSCATE_CODECS", true)) {
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
                                const KdfOptions& kdf) {
    std::string prepared = input;
    bool ok = false;
    std::vector<std::uint8_t> raw = basefwx::base64::Decode(prepared, &ok);
    if (!ok) {
        prepared = basefwx::codec::Decode(input);
        raw = basefwx::base64::Decode(prepared, &ok);
    }
    if (!ok) {
        throw std::runtime_error("Invalid payload encoding");
    }
    std::vector<basefwx::format::Bytes> parts = basefwx::format::UnpackLengthPrefixed(raw, 3);
    std::vector<std::uint8_t> mask_key = RecoverMaskKey(parts[0], parts[1], password, use_master, mask_info, aad, kdf);
    const std::vector<std::uint8_t>& payload = parts[2];
    if (payload.empty() || payload[0] != 0x02) {
        throw std::runtime_error("Unsupported payload format");
    }
    if (payload.size() < 5) {
        throw std::runtime_error("Malformed payload");
    }
    std::uint32_t expected_len = (static_cast<std::uint32_t>(payload[1]) << 24)
                                 | (static_cast<std::uint32_t>(payload[2]) << 16)
                                 | (static_cast<std::uint32_t>(payload[3]) << 8)
                                 | static_cast<std::uint32_t>(payload[4]);
    std::vector<std::uint8_t> masked(payload.begin() + 5, payload.end());
    if (expected_len != masked.size()) {
        throw std::runtime_error("Payload length mismatch");
    }
    std::vector<std::uint8_t> clear = MaskPayload(mask_key, masked, stream_info);
    return BytesToString(clear);
}

}  // namespace

std::string B512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    MaskKeyResult mask = PrepareMaskKey(password, use_master, constants::kB512MaskInfo, false, constants::kMaskAadB512, kdf);
    return EncodeMaskedPayload(mask.mask_key, mask.user_blob, mask.master_blob, input, constants::kB512StreamInfo);
}

std::string B512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    return DecodeMaskedPayload(input, password, use_master, constants::kB512MaskInfo, constants::kMaskAadB512,
                               constants::kB512StreamInfo, kdf);
}

std::string Pb512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    MaskKeyResult mask = PrepareMaskKey(password, use_master, constants::kPb512MaskInfo, true, constants::kMaskAadPb512, kdf);
    return EncodeMaskedPayload(mask.mask_key, mask.user_blob, mask.master_blob, input, constants::kPb512StreamInfo);
}

std::string Pb512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    return DecodeMaskedPayload(input, password, use_master, constants::kPb512MaskInfo, constants::kMaskAadPb512,
                               constants::kPb512StreamInfo, kdf);
}

}  // namespace basefwx::pb512
