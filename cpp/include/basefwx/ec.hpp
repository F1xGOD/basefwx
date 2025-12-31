#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace basefwx::ec {

using Bytes = std::vector<std::uint8_t>;

struct KemResult {
    Bytes blob;
    Bytes shared;
};

std::optional<Bytes> LoadMasterPublicKey(bool create_if_missing);
Bytes LoadMasterPrivateKey();
bool IsEcMasterBlob(const Bytes& blob);
KemResult KemEncrypt(const Bytes& public_key);
Bytes KemDecrypt(const Bytes& private_key, const Bytes& blob);

}  // namespace basefwx::ec
