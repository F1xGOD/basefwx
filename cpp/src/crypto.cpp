#include "basefwx/crypto.hpp"

#include "basefwx/constants.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
#include <argon2.h>
#endif

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace basefwx::crypto {

namespace {

void Ensure(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

}  // namespace

Bytes RandomBytes(std::size_t size) {
    Bytes out(size);
    if (size == 0) {
        return out;
    }
    Ensure(RAND_bytes(out.data(), static_cast<int>(out.size())) == 1, "RAND_bytes failed");
    return out;
}

Bytes HkdfSha256(const Bytes& key_material, std::string_view info, std::size_t length) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        throw std::runtime_error("HKDF context allocation failed");
    }
    Bytes out(length);
    std::size_t out_len = out.size();

    try {
        Ensure(EVP_PKEY_derive_init(pctx) == 1, "HKDF init failed");
        Ensure(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1, "HKDF set md failed");
        Ensure(EVP_PKEY_CTX_set1_hkdf_key(pctx, key_material.data(), static_cast<int>(key_material.size())) == 1,
               "HKDF set key failed");
        if (!info.empty()) {
            Ensure(EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info.data()),
                                               static_cast<int>(info.size())) == 1,
                   "HKDF set info failed");
        }
        Ensure(EVP_PKEY_derive(pctx, out.data(), &out_len) == 1, "HKDF derive failed");
        out.resize(out_len);
    } catch (...) {
        EVP_PKEY_CTX_free(pctx);
        throw;
    }
    EVP_PKEY_CTX_free(pctx);
    return out;
}

Bytes HkdfSha256Stream(const Bytes& key_material, std::string_view info, std::size_t length) {
    if (length == 0) {
        return {};
    }
    static const Bytes zero_salt(32, 0);
    Bytes prk = HmacSha256(zero_salt, key_material);
    Bytes out(length);
    Bytes prev;
    std::size_t offset = 0;
    std::uint32_t counter = 1;
    unsigned char counter_bytes[4];
    std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)> ctx(HMAC_CTX_new(), &HMAC_CTX_free);
    if (!ctx) {
        throw std::runtime_error("HKDF stream context allocation failed");
    }
    while (offset < length) {
        Ensure(HMAC_Init_ex(ctx.get(), prk.data(), static_cast<int>(prk.size()), EVP_sha256(), nullptr) == 1,
               "HKDF stream init failed");
        if (!prev.empty()) {
            Ensure(HMAC_Update(ctx.get(), prev.data(), prev.size()) == 1, "HKDF stream update failed");
        }
        if (!info.empty()) {
            Ensure(HMAC_Update(ctx.get(),
                               reinterpret_cast<const unsigned char*>(info.data()),
                               info.size()) == 1,
                   "HKDF stream update failed");
        }
        counter_bytes[0] = static_cast<unsigned char>((counter >> 24) & 0xFF);
        counter_bytes[1] = static_cast<unsigned char>((counter >> 16) & 0xFF);
        counter_bytes[2] = static_cast<unsigned char>((counter >> 8) & 0xFF);
        counter_bytes[3] = static_cast<unsigned char>(counter & 0xFF);
        Ensure(HMAC_Update(ctx.get(), counter_bytes, sizeof(counter_bytes)) == 1, "HKDF stream update failed");
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        Ensure(HMAC_Final(ctx.get(), digest, &digest_len) == 1, "HKDF stream final failed");
        prev.assign(digest, digest + digest_len);
        std::size_t take = std::min<std::size_t>(digest_len, length - offset);
        std::memcpy(out.data() + offset, prev.data(), take);
        offset += take;
        counter++;
    }
    return out;
}

Bytes Pbkdf2HmacSha256(const std::string& password, const Bytes& salt, std::size_t iterations, std::size_t length) {
    Bytes out(length);
    Ensure(PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt.data(),
                             static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(),
                             static_cast<int>(out.size()), out.data()) == 1,
           "PBKDF2 failed");
    return out;
}

Bytes HmacSha256(const Bytes& key, const Bytes& data) {
    unsigned int out_len = EVP_MAX_MD_SIZE;
    Bytes out(out_len);
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
              static_cast<int>(data.size()), out.data(), &out_len)) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    out.resize(out_len);
    return out;
}

#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
Bytes Argon2idHashRaw(const std::string& password,
                      const Bytes& salt,
                      std::uint32_t time_cost,
                      std::uint32_t memory_cost,
                      std::uint32_t parallelism,
                      std::size_t length) {
    Bytes out(length);
    int rc = argon2id_hash_raw(time_cost,
                               memory_cost,
                               parallelism,
                               password.data(),
                               password.size(),
                               salt.data(),
                               salt.size(),
                               out.data(),
                               out.size());
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("Argon2id failed: ") + argon2_error_message(rc));
    }
    return out;
}
#endif

Bytes AesGcmEncrypt(const Bytes& key, const Bytes& plaintext, const Bytes& aad) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-GCM expects 32-byte key");
    }
    Bytes nonce = RandomBytes(constants::kAeadNonceLen);
    Bytes ciphertext(plaintext.size());
    Bytes tag(constants::kAeadTagLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-GCM context allocation failed");
    }
    int out_len = 0;
    int total_len = 0;

    try {
        Ensure(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
               "AES-GCM init failed");
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1,
               "AES-GCM set iv length failed");
        Ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1,
               "AES-GCM set key failed");
        if (!aad.empty()) {
            Ensure(EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) == 1,
                   "AES-GCM aad failed");
        }
        if (!plaintext.empty()) {
            Ensure(EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(),
                                     static_cast<int>(plaintext.size())) == 1,
                   "AES-GCM encrypt failed");
            total_len += out_len;
        }
        Ensure(EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &out_len) == 1,
               "AES-GCM final failed");
        total_len += out_len;
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1,
               "AES-GCM get tag failed");
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(static_cast<std::size_t>(total_len));
    Bytes out;
    out.reserve(nonce.size() + ciphertext.size() + tag.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

Bytes AesGcmEncryptWithIv(const Bytes& key, const Bytes& iv, const Bytes& plaintext, const Bytes& aad) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-GCM expects 32-byte key");
    }
    if (iv.empty()) {
        throw std::runtime_error("AES-GCM IV is required");
    }
    Bytes ciphertext(plaintext.size());
    Bytes tag(constants::kAeadTagLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-GCM context allocation failed");
    }
    int out_len = 0;
    int total_len = 0;

    try {
        Ensure(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
               "AES-GCM init failed");
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1,
               "AES-GCM set iv length failed");
        Ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1,
               "AES-GCM set key failed");
        if (!aad.empty()) {
            Ensure(EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) == 1,
                   "AES-GCM aad failed");
        }
        if (!plaintext.empty()) {
            Ensure(EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(),
                                     static_cast<int>(plaintext.size())) == 1,
                   "AES-GCM encrypt failed");
            total_len += out_len;
        }
        Ensure(EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &out_len) == 1,
               "AES-GCM final failed");
        total_len += out_len;
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1,
               "AES-GCM get tag failed");
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(static_cast<std::size_t>(total_len));
    Bytes out;
    out.reserve(ciphertext.size() + tag.size());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

Bytes AesGcmDecrypt(const Bytes& key, const Bytes& blob, const Bytes& aad) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-GCM expects 32-byte key");
    }
    if (blob.size() < constants::kAeadNonceLen + constants::kAeadTagLen) {
        throw std::runtime_error("AES-GCM blob too short");
    }
    Bytes nonce(blob.begin(), blob.begin() + constants::kAeadNonceLen);
    Bytes tag(blob.end() - constants::kAeadTagLen, blob.end());
    Bytes ciphertext(blob.begin() + constants::kAeadNonceLen, blob.end() - constants::kAeadTagLen);

    Bytes plaintext(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-GCM context allocation failed");
    }
    int out_len = 0;
    int total_len = 0;

    try {
        Ensure(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
               "AES-GCM init failed");
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1,
               "AES-GCM set iv length failed");
        Ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1,
               "AES-GCM set key failed");
        if (!aad.empty()) {
            Ensure(EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) == 1,
                   "AES-GCM aad failed");
        }
        if (!ciphertext.empty()) {
            Ensure(EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(),
                                     static_cast<int>(ciphertext.size())) == 1,
                   "AES-GCM decrypt failed");
            total_len += out_len;
        }
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1,
               "AES-GCM set tag failed");
        Ensure(EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &out_len) == 1,
               "AES-GCM auth failed");
        total_len += out_len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<std::size_t>(total_len));
    return plaintext;
}

Bytes AesGcmDecryptWithIv(const Bytes& key, const Bytes& iv, const Bytes& blob, const Bytes& aad) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-GCM expects 32-byte key");
    }
    if (iv.empty()) {
        throw std::runtime_error("AES-GCM IV is required");
    }
    if (blob.size() < constants::kAeadTagLen) {
        throw std::runtime_error("AES-GCM blob too short");
    }
    Bytes ciphertext(blob.begin(), blob.end() - constants::kAeadTagLen);
    Bytes tag(blob.end() - constants::kAeadTagLen, blob.end());

    Bytes plaintext(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-GCM context allocation failed");
    }
    int out_len = 0;
    int total_len = 0;

    try {
        Ensure(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
               "AES-GCM init failed");
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1,
               "AES-GCM set iv length failed");
        Ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1,
               "AES-GCM set key failed");
        if (!aad.empty()) {
            Ensure(EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) == 1,
                   "AES-GCM aad failed");
        }
        if (!ciphertext.empty()) {
            Ensure(EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(),
                                     static_cast<int>(ciphertext.size())) == 1,
                   "AES-GCM decrypt failed");
            total_len += out_len;
        }
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                   const_cast<unsigned char*>(tag.data())) == 1,
               "AES-GCM set tag failed");
        Ensure(EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &out_len) == 1,
               "AES-GCM auth failed");
        total_len += out_len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<std::size_t>(total_len));
    return plaintext;
}

Bytes AeadEncrypt(const Bytes& key, const Bytes& plaintext, const Bytes& aad) {
    return AesGcmEncrypt(key, plaintext, aad);
}

Bytes AeadDecrypt(const Bytes& key, const Bytes& blob, const Bytes& aad) {
    return AesGcmDecrypt(key, blob, aad);
}

Bytes AesCtrTransform(const Bytes& key, const Bytes& iv, const Bytes& data) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-CTR expects 32-byte key");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("AES-CTR expects 16-byte IV");
    }
    Bytes out(data.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-CTR context allocation failed");
    }
    int out_len = 0;
    int total_len = 0;

    try {
        Ensure(EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) == 1,
               "AES-CTR init failed");
        if (!data.empty()) {
            Ensure(EVP_EncryptUpdate(ctx, out.data(), &out_len, data.data(), static_cast<int>(data.size())) == 1,
                   "AES-CTR update failed");
            total_len += out_len;
        }
        Ensure(EVP_EncryptFinal_ex(ctx, out.data() + total_len, &out_len) == 1,
               "AES-CTR final failed");
        total_len += out_len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    out.resize(static_cast<std::size_t>(total_len));
    return out;
}

Bytes Sha3_512(const Bytes& data) {
    const EVP_MD* md = EVP_sha3_512();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("SHA3-512 context allocation failed");
    }
    unsigned int out_len = 0;
    Bytes out(EVP_MD_size(md));
    try {
        Ensure(EVP_DigestInit_ex(ctx, md, nullptr) == 1, "SHA3-512 init failed");
        if (!data.empty()) {
            Ensure(EVP_DigestUpdate(ctx, data.data(), data.size()) == 1, "SHA3-512 update failed");
        }
        Ensure(EVP_DigestFinal_ex(ctx, out.data(), &out_len) == 1, "SHA3-512 final failed");
    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
    EVP_MD_CTX_free(ctx);
    out.resize(out_len);
    return out;
}

}  // namespace basefwx::crypto
