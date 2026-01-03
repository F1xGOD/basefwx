#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace basefwx::crypto {

using Bytes = std::vector<std::uint8_t>;

Bytes RandomBytes(std::size_t size);
Bytes HkdfSha256(const Bytes& key_material, std::string_view info, std::size_t length);
Bytes HkdfSha256Stream(const Bytes& key_material, std::string_view info, std::size_t length);
Bytes Pbkdf2HmacSha256(const std::string& password, const Bytes& salt, std::size_t iterations, std::size_t length);
Bytes HmacSha256(const Bytes& key, const Bytes& data);
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
Bytes Argon2idHashRaw(const std::string& password,
                      const Bytes& salt,
                      std::uint32_t time_cost,
                      std::uint32_t memory_cost,
                      std::uint32_t parallelism,
                      std::size_t length);
#endif
Bytes AeadEncrypt(const Bytes& key, const Bytes& plaintext, const Bytes& aad);
Bytes AeadDecrypt(const Bytes& key, const Bytes& blob, const Bytes& aad);
Bytes AesGcmEncrypt(const Bytes& key, const Bytes& plaintext, const Bytes& aad);
Bytes AesGcmDecrypt(const Bytes& key, const Bytes& blob, const Bytes& aad);
Bytes AesGcmEncryptWithIv(const Bytes& key, const Bytes& iv, const Bytes& plaintext, const Bytes& aad);
Bytes AesGcmDecryptWithIv(const Bytes& key, const Bytes& iv, const Bytes& blob, const Bytes& aad);
Bytes AesCtrTransform(const Bytes& key, const Bytes& iv, const Bytes& data);
Bytes Sha3_512(const Bytes& data);

}  // namespace basefwx::crypto
