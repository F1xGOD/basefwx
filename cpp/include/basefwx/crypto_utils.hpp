/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace basefwx::crypto::detail {

// RAII wrappers for OpenSSL resources to prevent memory leaks
struct EVPCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};

struct EVPMDCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept {
        if (ctx) EVP_MD_CTX_free(ctx);
    }
};

struct EVPPKEYCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const noexcept {
        if (ctx) EVP_PKEY_CTX_free(ctx);
    }
};

// BaseFWX requires OpenSSL 3.0 or newer. src/crypto/crypto.cpp includes
// <openssl/core_names.h> and <openssl/params.h> unconditionally and both
// arrived with the 3.0 provider API, so no build of this library against
// 1.1.1, LibreSSL or BoringSSL has ever been possible. The pre-3.0
// HMAC_CTX wrappers that used to sit behind an #else here were therefore
// unreachable in every build rather than merely every configured one.
// Stating the requirement fails a wrong toolchain here instead of inside
// a preprocessor error deep in a source file.
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "BaseFWX requires OpenSSL 3.0 or newer"
#endif

struct EVPMACDeleter {
    void operator()(EVP_MAC* mac) const noexcept {
        if (mac) EVP_MAC_free(mac);
    }
};

struct EVPMACCtxDeleter {
    void operator()(EVP_MAC_CTX* ctx) const noexcept {
        if (ctx) EVP_MAC_CTX_free(ctx);
    }
};

using UniqueMac = std::unique_ptr<EVP_MAC, EVPMACDeleter>;
using UniqueMacCtx = std::unique_ptr<EVP_MAC_CTX, EVPMACCtxDeleter>;

using UniqueCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EVPCipherCtxDeleter>;
using UniqueMDCtx = std::unique_ptr<EVP_MD_CTX, EVPMDCtxDeleter>;
using UniquePKEYCtx = std::unique_ptr<EVP_PKEY_CTX, EVPPKEYCtxDeleter>;

// Stack buffer for small operations - avoids heap allocation
template<std::size_t N>
class StackBuffer {
public:
    StackBuffer() = default;
    
    std::uint8_t* data() noexcept { return buffer_; }
    const std::uint8_t* data() const noexcept { return buffer_; }
    constexpr std::size_t size() const noexcept { return N; }
    constexpr std::size_t capacity() const noexcept { return N; }
    
    std::uint8_t& operator[](std::size_t idx) noexcept { return buffer_[idx]; }
    const std::uint8_t& operator[](std::size_t idx) const noexcept { return buffer_[idx]; }
    
private:
    std::uint8_t buffer_[N];
};

// Fast append without reallocation checks
inline void AppendBytes(std::vector<std::uint8_t>& dest, const std::uint8_t* src, std::size_t len) {
    if (len == 0) return;
    const std::size_t old_size = dest.size();
    dest.resize(old_size + len);
    memcpy(dest.data() + old_size, src, len);
}

inline void AppendBytes(std::vector<std::uint8_t>& dest, const std::vector<std::uint8_t>& src) {
    if (src.empty()) return;
    AppendBytes(dest, src.data(), src.size());
}

// Reserve with size hint to avoid multiple reallocations
inline void ReserveForAppend(std::vector<std::uint8_t>& vec, std::size_t additional) {
    const std::size_t new_size = vec.size() + additional;
    if (new_size > vec.capacity()) {
        vec.reserve(new_size);
    }
}

}  // namespace basefwx::crypto::detail
