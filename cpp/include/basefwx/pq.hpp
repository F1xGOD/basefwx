/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace basefwx::pq {

using Bytes = std::vector<std::uint8_t>;

// Move-only, self-wiping result of KemEncrypt(). `ciphertext` is
// public-by-design — it's what gets sent on the wire and the receiver
// uses it to recover the shared secret via KemDecrypt(). `shared` is
// the symmetric KEM output: secret material that must never persist
// in heap pages once the caller is done deriving keys from it.
//
// Why move-only: copying the result would duplicate the secret, and
// both copies would have to be wiped. Move-only forces callers to be
// explicit about who owns the secret at any moment and guarantees
// exactly one wipe via the destructor. Standard pattern for any RAII
// container that holds key material.
struct KemResult {
    Bytes ciphertext;
    Bytes shared;

    KemResult() = default;
    KemResult(Bytes ct, Bytes sh) noexcept
        : ciphertext(std::move(ct)), shared(std::move(sh)) {}

    KemResult(const KemResult&) = delete;
    KemResult& operator=(const KemResult&) = delete;
    KemResult(KemResult&& other) noexcept = default;
    KemResult& operator=(KemResult&& other) noexcept {
        if (this != &other) {
            // Wipe the outgoing secret before letting the new content
            // take over — without this an assignment chain like
            //   a = std::move(b); a = std::move(c);
            // would leak `b`'s shared secret into freed heap pages.
            wipe_shared();
            ciphertext = std::move(other.ciphertext);
            shared = std::move(other.shared);
        }
        return *this;
    }
    ~KemResult() { wipe_shared(); }

private:
    void wipe_shared() noexcept {
        if (shared.empty()) return;
        // `volatile` keeps the compiler from eliding the store. This
        // is the same pattern basefwx::crypto::SecureClear uses; we
        // open-code it here to avoid pulling crypto.hpp into this
        // public header (and to stay header-only).
        volatile std::uint8_t* p = shared.data();
        for (std::size_t i = 0; i < shared.size(); ++i) p[i] = 0;
    }
};

std::optional<Bytes> LoadMasterPublicKey();
Bytes LoadMasterPrivateKey();
KemResult KemEncrypt(const Bytes& public_key);
Bytes KemDecrypt(const Bytes& private_key, const Bytes& ciphertext);
std::string CurrentKemAlgorithm();
bool IsSupportedKemAlgorithm(std::string_view algorithm);

Bytes DecodeKeyBytes(const Bytes& raw);

}  // namespace basefwx::pq
