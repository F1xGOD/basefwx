/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include "basefwx/pb512.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace basefwx::keywrap {

using Bytes = std::vector<std::uint8_t>;

struct MasterPublicKeys {
    std::optional<Bytes> pq;
    std::optional<Bytes> ec;
};

struct MaskKeyResult {
    Bytes mask_key;
    Bytes user_blob;
    Bytes master_blob;
    bool used_master = false;
    std::string master_kem = "none";

    MaskKeyResult() = default;
    MaskKeyResult(const MaskKeyResult&) = delete;
    MaskKeyResult& operator=(const MaskKeyResult&) = delete;
    MaskKeyResult(MaskKeyResult&&) noexcept = default;
    MaskKeyResult& operator=(MaskKeyResult&& other) noexcept;
    ~MaskKeyResult();

private:
    void wipe_mask_key() noexcept;
};

std::string ResolveKdfLabel(const std::string& label);
// Resolve an untrusted wire label. Unlike ResolveKdfLabel(), this never
// accepts caller-only defaults such as an empty string or "auto".
std::string ResolvePeerKdfLabel(const std::string& label);
Bytes DeriveUserKeyWithLabel(const std::string& password,
                             const Bytes& salt,
                             const std::string& label,
                             const basefwx::pb512::KdfOptions& kdf);

// Fail closed when peer-supplied ENC-ARGON2-* costs exceed shared maxima.
void RequirePeerArgon2WithinLimits(std::uint32_t time_cost,
                                   std::uint32_t memory_kib,
                                   std::uint32_t parallelism);
void RequirePeerPbkdf2WithinLimits(std::size_t iterations);

Bytes MaskPayload(const Bytes& mask_key, const Bytes& payload, std::string_view info);

MaskKeyResult PrepareMaskKey(const std::string& password,
                             bool use_master,
                             std::string_view mask_info,
                             bool require_password,
                             std::string_view aad,
                             const basefwx::pb512::KdfOptions& kdf,
                             const MasterPublicKeys* selected_master = nullptr);

Bytes RecoverMaskKey(const Bytes& user_blob,
                     const Bytes& master_blob,
                     const std::string& password,
                     bool use_master,
                     std::string_view mask_info,
                     std::string_view aad,
                     const basefwx::pb512::KdfOptions& kdf,
                     std::string_view legacy_user_aad = {});

}  // namespace basefwx::keywrap
