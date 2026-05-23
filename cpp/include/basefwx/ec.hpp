/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace basefwx::ec {

using Bytes = std::vector<std::uint8_t>;

// Move-only, self-wiping result of EC KemEncrypt(). `blob` is the
// public ECIES-style wrapped output that goes on the wire; `shared`
// is the secret material that must not persist in heap pages. Same
// pattern as basefwx::pq::KemResult — see that struct's header
// comment for the move-only + destructor-wipe rationale.
struct KemResult {
    Bytes blob;
    Bytes shared;

    KemResult() = default;
    KemResult(Bytes b, Bytes sh) noexcept
        : blob(std::move(b)), shared(std::move(sh)) {}

    KemResult(const KemResult&) = delete;
    KemResult& operator=(const KemResult&) = delete;
    KemResult(KemResult&&) noexcept = default;
    KemResult& operator=(KemResult&& other) noexcept;
    ~KemResult();

private:
    void wipe_shared() noexcept;
};

std::optional<Bytes> LoadMasterPublicKey(bool create_if_missing);
Bytes LoadMasterPrivateKey();
bool IsEcMasterBlob(const Bytes& blob);
KemResult KemEncrypt(const Bytes& public_key);
Bytes KemDecrypt(const Bytes& private_key, const Bytes& blob);

}  // namespace basefwx::ec
