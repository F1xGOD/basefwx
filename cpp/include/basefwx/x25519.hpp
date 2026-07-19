/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <utility>
#include <vector>

namespace basefwx::x25519 {

using Bytes = std::vector<std::uint8_t>;

struct KeyPair {
    Bytes public_key;
    Bytes private_key;

    KeyPair() = default;
    KeyPair(Bytes pub, Bytes priv) noexcept
        : public_key(std::move(pub)), private_key(std::move(priv)) {}

    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair(KeyPair&& other) noexcept = default;
    KeyPair& operator=(KeyPair&& other) noexcept;
    ~KeyPair();

private:
    void wipe_private() noexcept;
};

KeyPair GenerateKeyPair();
Bytes DeriveSharedSecret(const Bytes& private_key, const Bytes& peer_public_key);

}  // namespace basefwx::x25519
