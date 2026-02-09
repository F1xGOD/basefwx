#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
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
#else
struct HMACCtxDeleter {
    void operator()(HMAC_CTX* ctx) const noexcept {
        if (ctx) HMAC_CTX_free(ctx);
    }
};

using UniqueHmacCtx = std::unique_ptr<HMAC_CTX, HMACCtxDeleter>;
#endif

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
