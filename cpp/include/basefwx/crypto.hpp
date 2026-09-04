/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace basefwx::crypto {

// One-shot AEAD / KDF / MAC / RNG helpers. Prefer these over opening a
// parallel EVP_* path. Chunked file codecs and obfuscation may call OpenSSL
// EVP directly for throughput — see SECURITY.md "Crypto helper boundaries".

using Bytes = std::vector<std::uint8_t>;

class AuthenticationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

Bytes RandomBytes(std::size_t size);
Bytes HkdfSha256(const Bytes& key_material, std::string_view info, std::size_t length);
// RFC 5869 extract+expand with an explicit salt. New protocol designs should
// use this overload so the transcript salt is part of the key schedule rather
// than concatenated into the input key material by the caller.
Bytes HkdfSha256(const Bytes& key_material,
                 const Bytes& salt,
                 std::string_view info,
                 std::size_t length);
// Released large-payload compatibility PRF. This is NOT RFC 5869 HKDF:
// after a zero-salt HMAC-SHA256 extract, each block is
// HMAC(PRK, previous || info || uint32_be(counter)). The four-byte counter is
// intentionally preserved because mask payloads larger than 8160 bytes are
// stored using this stream in existing BaseFWX formats.
Bytes CompatPrfStreamSha256(const Bytes& key_material,
                            std::string_view info,
                            std::size_t length);
[[deprecated("use CompatPrfStreamSha256; this compatibility stream is not RFC 5869 HKDF")]]
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
// Returns owned plaintext from a ciphertext slice. The private result buffer
// is wiped if authentication fails and is released to the caller on success.
Bytes AesGcmDecryptWithIvOwned(const Bytes& key,
                               const Bytes& iv,
                               const std::uint8_t* blob,
                               std::size_t blob_len,
                               const Bytes& aad);
std::size_t AesGcmEncryptWithIvInto(const Bytes& key,
                                    const Bytes& iv,
                                    const std::uint8_t* plaintext,
                                    std::size_t plaintext_len,
                                    const Bytes& aad,
                                    std::uint8_t* out,
                                    std::size_t out_len);
// Decrypts into private staging storage and copies to `out` only after the
// GCM tag verifies. Authentication failure therefore leaves `out` unchanged.
std::size_t AesGcmDecryptWithIvInto(const Bytes& key,
                                    const Bytes& iv,
                                    const std::uint8_t* blob,
                                    std::size_t blob_len,
                                    const Bytes& aad,
                                    std::uint8_t* out,
                                    std::size_t out_len);

// Reusable AES-256-GCM context.
//
// Every one-shot helper above builds a fresh EVP_CIPHER_CTX and redoes the
// full AES-256 key schedule per call. That is the right shape for a file
// codec that seals one payload. It is the wrong shape for a per-frame
// protocol, where the same process seals thousands of small records a second
// and pays the allocation and the schedule every time.
//
// AeadContext keeps the cipher contexts and the key schedule alive across
// calls and takes the nonce and AAD per record. Both entry points write into
// caller-provided storage, so a caller that already owns an output buffer
// does not pay for a second std::vector zero-fill.
//
// Nonce discipline is the caller's: GCM fails catastrophically if a nonce
// repeats under one key, and a long-lived context is exactly where that
// mistake becomes possible. Seal rejects an immediate repeat of the previous
// nonce as a misuse guard. That is a backstop against the obvious bug, NOT a
// uniqueness proof -- the caller still owns a counter or a random nonce.
//
// Not thread-safe. One context per direction per connection, the way a
// directional ratchet already holds one key schedule per direction.
class AeadContext {
public:
    static constexpr std::size_t kKeyLength = 32;
    static constexpr std::size_t kTagLength = 16;
    static constexpr std::size_t kDefaultNonceLength = 12;

    // Builds both cipher contexts and installs the key schedule. `key` must
    // be exactly 32 bytes. `nonce_length` is fixed for the life of the
    // context because GCM's IV length is part of the cipher setup rather
    // than per-message state.
    explicit AeadContext(const Bytes& key,
                         std::size_t nonce_length = kDefaultNonceLength);
    ~AeadContext();

    AeadContext(const AeadContext&) = delete;
    AeadContext& operator=(const AeadContext&) = delete;
    AeadContext(AeadContext&&) noexcept;
    AeadContext& operator=(AeadContext&&) noexcept;

    std::size_t nonce_length() const noexcept;

    // Bytes Seal adds on top of the plaintext length.
    static constexpr std::size_t OverheadBytes() noexcept { return kTagLength; }

    // Installs a new key schedule into the existing contexts, reusing the
    // OpenSSL allocations. A ratchet that derives a fresh message key per
    // record calls this instead of constructing a new context, which is what
    // turns "one allocation per frame" into "one allocation per direction".
    // The nonce-repeat guard resets, since a repeated nonce under a new key
    // is not a reuse.
    void Rekey(const Bytes& key);

    // Writes `ciphertext || tag` into `out` and returns the byte count,
    // which is always plaintext_len + kTagLength. `out_len` must be at least
    // that. Ciphertext is public, so it is produced directly into `out`.
    std::size_t Seal(const Bytes& nonce,
                     const std::uint8_t* plaintext,
                     std::size_t plaintext_len,
                     const Bytes& aad,
                     std::uint8_t* out,
                     std::size_t out_len);

    // Reads `ciphertext || tag` from `blob` and writes the plaintext into
    // `out`, returning blob_len - kTagLength.
    //
    // OpenSSL emits GCM plaintext from EVP_DecryptUpdate before
    // EVP_DecryptFinal_ex authenticates the tag, so Open decrypts into
    // private staging owned by this context and copies to `out` only after
    // the tag verifies -- the same property AesGcmDecryptWithIvInto has.
    // Authentication failure leaves `out` untouched and throws
    // AuthenticationError. The staging buffer is reused across calls and
    // wiped when the context is destroyed, so the property costs a copy but
    // no per-record allocation.
    std::size_t Open(const Bytes& nonce,
                     const std::uint8_t* blob,
                     std::size_t blob_len,
                     const Bytes& aad,
                     std::uint8_t* out,
                     std::size_t out_len);

private:
    struct State;
    std::unique_ptr<State> state_;
};

// IETF ChaCha20-Poly1305 (RFC 8439) one-shot AEAD with a caller-supplied
// nonce. The key must be 32 bytes and the IV exactly 12; unlike AES-GCM this
// construction has no other legal nonce size, so a short or long IV is
// rejected rather than passed to OpenSSL.
//
// The encrypted form is `ciphertext || 16-byte tag` with no framing: the
// caller owns nonce storage and association. AAD is explicit and may be
// empty, which RFC 8439 defines as absorbing zero AAD bytes -- byte-identical
// to a caller that never supplies AAD at all.
Bytes ChaCha20Poly1305EncryptWithIv(const Bytes& key,
                                    const Bytes& iv,
                                    const Bytes& plaintext,
                                    const Bytes& aad);
// Returns owned plaintext from a `ciphertext || tag` slice. The result is
// staged in private wiping storage and released to the caller only after the
// Poly1305 tag verifies; authentication failure publishes nothing and throws
// AuthenticationError.
Bytes ChaCha20Poly1305DecryptWithIvOwned(const Bytes& key,
                                         const Bytes& iv,
                                         const std::uint8_t* blob,
                                         std::size_t blob_len,
                                         const Bytes& aad);

Bytes AesCtrTransform(const Bytes& key, const Bytes& iv, const Bytes& data);
// In-place CTR transform that avoids the std::vector zero-fill in the
// out-of-place form (which was ~0.5 GB/s of pure memset on the an7 hot
// loop). `data` is mutated to ciphertext / plaintext.
void AesCtrTransformInPlace(const Bytes& key, const Bytes& iv, Bytes& data);
Bytes Sha3_512(const Bytes& data);
void SecureClear(std::uint8_t* data, std::size_t length) noexcept;
void SecureClear(Bytes& bytes) noexcept;
void SecureClear(std::string& text) noexcept;

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
    ~SecretGuard() noexcept;

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
