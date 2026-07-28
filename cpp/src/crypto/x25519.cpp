/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/x25519.hpp"

#include "basefwx/crypto.hpp"

#include <algorithm>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>

namespace basefwx::x25519 {
namespace {

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

constexpr std::size_t kX25519KeyBytes = 32;

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}  // namespace

KeyPair& KeyPair::operator=(KeyPair&& other) noexcept {
    if (this != &other) {
        wipe_private();
        public_key = std::move(other.public_key);
        private_key = std::move(other.private_key);
    }
    return *this;
}

KeyPair::~KeyPair() {
    wipe_private();
}

void KeyPair::wipe_private() noexcept {
    basefwx::crypto::SecureClear(private_key);
}

KeyPair GenerateKeyPair() {
    PkeyCtxPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr),
                       EVP_PKEY_CTX_free);
    Require(context != nullptr, "X25519 key generation context allocation failed");
    Require(EVP_PKEY_keygen_init(context.get()) == 1,
            "X25519 key generation initialization failed");

    EVP_PKEY* generated = nullptr;
    Require(EVP_PKEY_keygen(context.get(), &generated) == 1 && generated != nullptr,
            "X25519 key generation failed");
    PkeyPtr key(generated, EVP_PKEY_free);

    KeyPair result;
    result.public_key.resize(kX25519KeyBytes);
    result.private_key.resize(kX25519KeyBytes);
    std::size_t public_len = result.public_key.size();
    std::size_t private_len = result.private_key.size();
    Require(EVP_PKEY_get_raw_public_key(key.get(), result.public_key.data(),
                                        &public_len) == 1 &&
                public_len == kX25519KeyBytes,
            "X25519 public key export failed");
    Require(EVP_PKEY_get_raw_private_key(key.get(), result.private_key.data(),
                                         &private_len) == 1 &&
                private_len == kX25519KeyBytes,
            "X25519 private key export failed");
    return result;
}

Bytes DeriveSharedSecret(const Bytes& private_key, const Bytes& peer_public_key) {
    Require(private_key.size() == kX25519KeyBytes,
            "X25519 private key must be 32 bytes");
    Require(peer_public_key.size() == kX25519KeyBytes,
            "X25519 public key must be 32 bytes");

    PkeyPtr local(EVP_PKEY_new_raw_private_key(
                      EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size()),
                  EVP_PKEY_free);
    PkeyPtr peer(EVP_PKEY_new_raw_public_key(
                     EVP_PKEY_X25519, nullptr, peer_public_key.data(),
                     peer_public_key.size()),
                 EVP_PKEY_free);
    Require(local != nullptr && peer != nullptr, "X25519 raw key import failed");

    PkeyCtxPtr context(EVP_PKEY_CTX_new(local.get(), nullptr), EVP_PKEY_CTX_free);
    Require(context != nullptr, "X25519 derive context allocation failed");
    Require(EVP_PKEY_derive_init(context.get()) == 1,
            "X25519 derive initialization failed");
    Require(EVP_PKEY_derive_set_peer(context.get(), peer.get()) == 1,
            "X25519 peer key rejected");

    std::size_t shared_len = 0;
    Require(EVP_PKEY_derive(context.get(), nullptr, &shared_len) == 1 &&
                shared_len == kX25519KeyBytes,
            "X25519 shared-secret size query failed");
    basefwx::crypto::SecureBytes shared{Bytes(shared_len)};
    Require(EVP_PKEY_derive(context.get(), shared.data(), &shared_len) == 1 &&
                shared_len == kX25519KeyBytes,
            "X25519 shared-secret derivation failed");
    Require(std::any_of(shared.bytes().begin(), shared.bytes().end(),
                        [](std::uint8_t byte) { return byte != 0; }),
            "X25519 peer produced the forbidden all-zero shared secret");
    return shared.Release();
}

}  // namespace basefwx::x25519
