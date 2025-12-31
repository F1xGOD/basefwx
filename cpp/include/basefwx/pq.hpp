#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace basefwx::pq {

using Bytes = std::vector<std::uint8_t>;

struct KemResult {
    Bytes ciphertext;
    Bytes shared;
};

std::optional<Bytes> LoadMasterPublicKey();
Bytes LoadMasterPrivateKey();
KemResult KemEncrypt(const Bytes& public_key);
Bytes KemDecrypt(const Bytes& private_key, const Bytes& ciphertext);

Bytes DecodeKeyBytes(const Bytes& raw);

}  // namespace basefwx::pq
