/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

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
std::size_t AesGcmEncryptWithIvInto(const Bytes& key,
                                    const Bytes& iv,
                                    const std::uint8_t* plaintext,
                                    std::size_t plaintext_len,
                                    const Bytes& aad,
                                    std::uint8_t* out,
                                    std::size_t out_len);
std::size_t AesGcmDecryptWithIvInto(const Bytes& key,
                                    const Bytes& iv,
                                    const std::uint8_t* blob,
                                    std::size_t blob_len,
                                    const Bytes& aad,
                                    std::uint8_t* out,
                                    std::size_t out_len);
Bytes AesCtrTransform(const Bytes& key, const Bytes& iv, const Bytes& data);
// In-place CTR transform that avoids the std::vector zero-fill in the
// out-of-place form (which was ~0.5 GB/s of pure memset on the an7 hot
// loop). `data` is mutated to ciphertext / plaintext.
void AesCtrTransformInPlace(const Bytes& key, const Bytes& iv, Bytes& data);
Bytes Sha3_512(const Bytes& data);
void SecureClear(std::uint8_t* data, std::size_t length);
void SecureClear(Bytes& bytes);
void SecureClear(std::string& text);

// SecretGuard tracks pointers to externally-owned buffers and SecureClears
// each one in its destructor. It does NOT own the buffers — they must
// outlive the guard.
//
// LIFETIME RULE: declare SecretGuard AFTER every local it tracks. C++
// destroys stack locals in reverse construction order, so a guard
// declared AFTER its tracked locals is destroyed BEFORE them and
// SecureClears while the buffers are still alive. A guard declared
// BEFORE its tracked locals dereferences freed vector storage on
// destruction — heap corruption follows.
//
// For NEW code, prefer SecureBytes (defined below). SecureBytes owns its
// Bytes and wipes them on destruction — no lifetime rule to remember.
// SecretGuard stays here for cases where the secret is a `std::string`
// password, or where existing code already follows the lifetime rule.
class SecretGuard {
public:
    SecretGuard() = default;
    SecretGuard(const SecretGuard&) = delete;
    SecretGuard& operator=(const SecretGuard&) = delete;
    SecretGuard(SecretGuard&&) = delete;
    SecretGuard& operator=(SecretGuard&&) = delete;
    ~SecretGuard();

    void Add(Bytes& bytes);
    void Add(std::string& text);

private:
    std::vector<Bytes*> byte_buffers_;
    std::vector<std::string*> string_buffers_;
};

// SecureBytes is an RAII owner for key material: it wraps a Bytes,
// SecureClears the contents on destruction, and is move-only so the
// secret has exactly one owner at any moment. Prefer this over
// SecretGuard for any new local holding key material — there is no
// "declare it after the tracked variable" footgun because the wrap
// IS the variable.
//
// Pattern:
//
//   basefwx::crypto::SecureBytes priv{load_pq_private_key(...)};
//   basefwx::crypto::SecureBytes shared{
//       basefwx::pq::KemDecrypt(priv.bytes(), pq_ciphertext)};
//   // ... use priv.bytes() and shared.bytes() ...
//   // On scope exit: shared wiped first, then priv. Throws between
//   // bindings still wipe everything bound so far.
//
// Pass-through to APIs taking `const Bytes&` is direct via `.bytes()`.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(Bytes bytes) noexcept : bytes_(std::move(bytes)) {}

    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    SecureBytes(SecureBytes&& other) noexcept : bytes_(std::move(other.bytes_)) {}
    SecureBytes& operator=(SecureBytes&& other) noexcept;

    ~SecureBytes() noexcept;

    // Direct access to the wrapped buffer. The reference is valid for
    // the lifetime of *this; do not store it past that.
    Bytes&       bytes() noexcept             { return bytes_; }
    const Bytes& bytes() const noexcept       { return bytes_; }

    std::uint8_t*       data() noexcept       { return bytes_.data(); }
    const std::uint8_t* data() const noexcept { return bytes_.data(); }
    std::size_t  size()  const noexcept       { return bytes_.size(); }
    bool         empty() const noexcept       { return bytes_.empty(); }

    // Replace contents, wiping the previous buffer first. Use for
    // patterns that lazily fill the secret after the SecureBytes is
    // declared.
    void Reset(Bytes bytes) noexcept;

    // Yield ownership of the bytes WITHOUT wiping. The returned Bytes
    // is the caller's problem to wipe — use sparingly, normally only
    // when handing the secret to another wrapper that will wipe it.
    Bytes Release() noexcept;

private:
    Bytes bytes_;
};

}  // namespace basefwx::crypto
