#pragma once

#include "basefwx/pb512.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace basefwx::keywrap {

using Bytes = std::vector<std::uint8_t>;

struct MaskKeyResult {
    Bytes mask_key;
    Bytes user_blob;
    Bytes master_blob;
    bool used_master = false;
};

std::string ResolveKdfLabel(const std::string& label);
Bytes DeriveUserKeyWithLabel(const std::string& password,
                             const Bytes& salt,
                             const std::string& label,
                             const basefwx::pb512::KdfOptions& kdf);

Bytes MaskPayload(const Bytes& mask_key, const Bytes& payload, std::string_view info);

MaskKeyResult PrepareMaskKey(const std::string& password,
                             bool use_master,
                             std::string_view mask_info,
                             bool require_password,
                             std::string_view aad,
                             const basefwx::pb512::KdfOptions& kdf);

Bytes RecoverMaskKey(const Bytes& user_blob,
                     const Bytes& master_blob,
                     const std::string& password,
                     bool use_master,
                     std::string_view mask_info,
                     std::string_view aad,
                     const basefwx::pb512::KdfOptions& kdf);

}  // namespace basefwx::keywrap
