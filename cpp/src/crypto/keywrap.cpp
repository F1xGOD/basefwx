/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/keywrap.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/ec.hpp"
#include "basefwx/env.hpp"
#include "basefwx/pq.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <optional>
#include <stdexcept>

namespace basefwx::keywrap {

MaskKeyResult& MaskKeyResult::operator=(MaskKeyResult&& other) noexcept {
    if (this != &other) {
        wipe_mask_key();
        mask_key = std::move(other.mask_key);
        user_blob = std::move(other.user_blob);
        master_blob = std::move(other.master_blob);
        used_master = other.used_master;
        master_kem = std::move(other.master_kem);
        other.used_master = false;
        other.master_kem = "none";
    }
    return *this;
}

MaskKeyResult::~MaskKeyResult() {
    wipe_mask_key();
}

void MaskKeyResult::wipe_mask_key() noexcept {
    basefwx::crypto::SecureClear(mask_key);
}

namespace {

using basefwx::constants::kUserKdfSaltSize;

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool IsArgon2Label(const std::string& label) {
    return label == "argon2" || label == "argon2id";
}

std::vector<std::uint8_t> ToBytes(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

bool StrictPqOnly() {
    return basefwx::env::IsEnabled("BASEFWX_PQ_STRICT", false)
        || basefwx::env::IsEnabled("BASEFWX_PQ_ONLY", false);
}

std::string DefaultKdfLabel() {
    std::string env_label = basefwx::env::Get("BASEFWX_USER_KDF");
    if (!env_label.empty()) {
        const std::string normalized = ToLower(env_label);
        if (normalized != "auto") {
            return normalized;
        }
    }
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    return "argon2id";
#else
    return "pbkdf2";
#endif
}

bool SkipShortHardening() {
#if defined(BASEFWX_TESTING) && BASEFWX_TESTING
    return !basefwx::env::TestKdfIters().empty();
#else
    return false;
#endif
}

}  // namespace

basefwx::pb512::KdfOptions HardenKdfOptionsForPassword(
    const std::string& password,
    const basefwx::pb512::KdfOptions& kdf) {
    if (password.empty() || SkipShortHardening()) {
        return kdf;
    }
    if (password.size() >= basefwx::constants::kShortPasswordMin) {
        return kdf;
    }
    basefwx::pb512::KdfOptions hardened = kdf;
    hardened.pbkdf2_iterations = std::max(
        hardened.pbkdf2_iterations,
        static_cast<std::size_t>(basefwx::constants::kShortPbkdf2Iterations)
    );
    hardened.argon2_time_cost = std::max(hardened.argon2_time_cost,
                                         basefwx::constants::kShortArgon2TimeCost);
    hardened.argon2_memory_cost = std::max(hardened.argon2_memory_cost,
                                           basefwx::constants::kShortArgon2MemoryCost);
    hardened.argon2_parallelism = std::max(hardened.argon2_parallelism,
                                           basefwx::constants::kShortArgon2Parallelism);
    return hardened;
}

std::string ResolveKdfLabel(const std::string& label) {
    std::string normalized = ToLower(label);
    if (normalized.empty() || normalized == "auto") {
        normalized = ToLower(DefaultKdfLabel());
    }
    if (normalized == "pbkdf2" || IsArgon2Label(normalized)) {
        return normalized;
    }
    throw std::runtime_error("Unsupported KDF label: " + normalized);
}

std::string ResolvePeerKdfLabel(const std::string& label) {
    if (label == "pbkdf2" || IsArgon2Label(label)) {
        return label;
    }
    throw std::runtime_error("Unsupported peer KDF label: " + label);
}

Bytes DeriveUserKeyWithLabel(const std::string& password,
                             const Bytes& salt,
                             const std::string& label,
                             const basefwx::pb512::KdfOptions& kdf) {
    if (salt.size() < kUserKdfSaltSize) {
        throw std::runtime_error("User key salt must be at least 16 bytes");
    }
    std::string normalized = ResolveKdfLabel(label);
    if (IsArgon2Label(normalized)) {
        RequirePeerArgon2WithinLimits(
            kdf.argon2_time_cost, kdf.argon2_memory_cost, kdf.argon2_parallelism);
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
        return basefwx::crypto::Argon2idHashRaw(
            password,
            salt,
            kdf.argon2_time_cost,
            kdf.argon2_memory_cost,
            kdf.argon2_parallelism,
            32
        );
#else
        throw std::runtime_error("Argon2 KDF requested but argon2 backend is unavailable");
#endif
    }
    if (normalized == "pbkdf2") {
        RequirePeerPbkdf2WithinLimits(kdf.pbkdf2_iterations);
        return basefwx::crypto::Pbkdf2HmacSha256(password, salt, kdf.pbkdf2_iterations, 32);
    }
    throw std::runtime_error("Unsupported KDF label: " + normalized);
}

void RequirePeerArgon2WithinLimits(std::uint32_t time_cost,
                                   std::uint32_t memory_kib,
                                   std::uint32_t parallelism) {
    if (time_cost == 0 || memory_kib == 0 || parallelism == 0) {
        throw std::runtime_error("Peer Argon2 parameters must be positive");
    }
    if (time_cost > constants::kArgon2TimeCostMax) {
        throw std::runtime_error("Peer ENC-ARGON2-TC exceeds maximum");
    }
    if (memory_kib > constants::kArgon2MemoryCostMax) {
        throw std::runtime_error("Peer ENC-ARGON2-MEM exceeds maximum");
    }
    if (parallelism > constants::kArgon2ParallelismMax) {
        throw std::runtime_error("Peer ENC-ARGON2-PAR exceeds maximum");
    }
}

void RequirePeerPbkdf2WithinLimits(std::size_t iterations) {
    if (iterations == 0) {
        throw std::runtime_error("Peer PBKDF2 iteration count must be positive");
    }
    if (iterations > constants::kPeerPbkdf2IterationsMax) {
        throw std::runtime_error("Peer PBKDF2 iteration count exceeds maximum");
    }
}

Bytes MaskPayload(const Bytes& mask_key, const Bytes& payload, std::string_view info) {
    if (payload.empty()) {
        return {};
    }
    basefwx::crypto::SecureBytes stream;
    if (payload.size() > basefwx::constants::kHkdfMaxLen) {
        stream.Reset(
            basefwx::crypto::CompatPrfStreamSha256(
                mask_key, info, payload.size()));
    } else {
        stream.Reset(
            basefwx::crypto::HkdfSha256(
                mask_key, info, payload.size()));
    }
    Bytes out(payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(
            payload[i] ^ stream.bytes()[i]);
    }
    return out;
}

MaskKeyResult PrepareMaskKey(const std::string& password,
                             bool use_master,
                             std::string_view mask_info,
                             bool require_password,
                             std::string_view aad,
                             const basefwx::pb512::KdfOptions& kdf,
                             const MasterPublicKeys* selected_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    basefwx::crypto::SecretGuard secrets;
    secrets.Add(resolved);
    basefwx::RequireStrongPasswordForEncryption(resolved, "key wrap");
    if (require_password && resolved.empty()) {
        throw std::runtime_error("Password required for this mode");
    }
    basefwx::pb512::KdfOptions kdf_opts =
        HardenKdfOptionsForPassword(resolved, kdf);
    const std::string kdf_label = ResolveKdfLabel(kdf_opts.label);
    if (!resolved.empty()) {
        if (IsArgon2Label(kdf_label)) {
            RequirePeerArgon2WithinLimits(
                kdf_opts.argon2_time_cost,
                kdf_opts.argon2_memory_cost,
                kdf_opts.argon2_parallelism);
        } else if (kdf_label == "pbkdf2") {
            RequirePeerPbkdf2WithinLimits(
                kdf_opts.pbkdf2_iterations);
        } else {
            throw std::runtime_error(
                "Unsupported KDF label: " + kdf_label);
        }
    }
    const bool pq_only = StrictPqOnly();
    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (use_master) {
        if (selected_master != nullptr) {
            pq_pub = selected_master->pq;
            ec_pub = selected_master->ec;
        } else {
            pq_pub = basefwx::pq::LoadMasterPublicKey();
        }
        if (selected_master == nullptr
            && !pq_pub.has_value()
            && !ec_pub.has_value()
            && !pq_only) {
            // 3.7.0: the BASEFWX_MASTER_EC_CREATE_IF_MISSING env-driven
            // auto-generation is removed. Silently minting a fresh EC
            // master keypair when the configured one is absent produced
            // ciphertext that looked recoverable on the encrypt host and
            // hard-failed everywhere else. Callers needing an EC master
            // must provision the key explicitly out-of-band.
            ec_pub = basefwx::ec::LoadMasterPublicKey(
                /*allow_autogen=*/false);
        }
    }
    if (use_master && pq_only && !pq_pub.has_value()) {
        throw std::runtime_error(
            "PQ strict mode requires a configured ML-KEM master public key");
    }
    bool use_master_effective = use_master && (pq_pub.has_value() || ec_pub.has_value());
    if (use_master && !use_master_effective) {
        // Degrading to password-only would write a file that looks escrowed
        // on this host and is unrecoverable once the password is lost. The
        // caller asked for a master key; refusing is the only honest answer.
        throw std::runtime_error(
            "master key requested but no master public key is configured");
    }
    if (resolved.empty() && !use_master_effective) {
        throw std::runtime_error("Password required when master key is unavailable");
    }

    MaskKeyResult result;
    result.used_master = use_master_effective;
    basefwx::crypto::SecureBytes mask_key;
    if (use_master_effective) {
        if (pq_pub.has_value()) {
            result.master_kem = std::string(basefwx::pq::KemAlgorithmName(
                basefwx::pq::InferKemAlgorithmFromPublicKey(*pq_pub)));
            basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(*pq_pub);
            result.master_blob = kem.ciphertext;
            basefwx::crypto::SecureBytes shared{std::move(kem.shared)};
            mask_key.Reset(basefwx::crypto::HkdfSha256(
                shared.bytes(), mask_info, 32));
        } else if (ec_pub.has_value()) {
            result.master_kem = "EC";
            basefwx::ec::KemResult kem = basefwx::ec::KemEncrypt(*ec_pub);
            result.master_blob = kem.blob;
            basefwx::crypto::SecureBytes shared{std::move(kem.shared)};
            mask_key.Reset(basefwx::crypto::HkdfSha256(
                shared.bytes(), mask_info, 32));
        } else {
            mask_key.Reset(basefwx::crypto::RandomBytes(32));
        }
    } else {
        mask_key.Reset(basefwx::crypto::RandomBytes(32));
    }
    Bytes salt = basefwx::crypto::RandomBytes(kUserKdfSaltSize);
    if (!resolved.empty()) {
        basefwx::crypto::SecureBytes user_key{
            DeriveUserKeyWithLabel(
                resolved, salt, kdf_label, kdf_opts)};
        Bytes aad_bytes = ToBytes(aad);
        Bytes wrapped = basefwx::crypto::AeadEncrypt(
            user_key.bytes(), mask_key.bytes(), aad_bytes);

        if (kdf_label.size() > 255) {
            throw std::runtime_error("KDF label too long");
        }
        result.user_blob.reserve(
            1 + kdf_label.size() + salt.size() + wrapped.size());
        result.user_blob.push_back(
            static_cast<std::uint8_t>(kdf_label.size()));
        result.user_blob.insert(
            result.user_blob.end(), kdf_label.begin(), kdf_label.end());
        result.user_blob.insert(result.user_blob.end(), salt.begin(), salt.end());
        result.user_blob.insert(result.user_blob.end(), wrapped.begin(), wrapped.end());
    }

    result.mask_key = mask_key.Release();
    return result;
}

Bytes RecoverMaskKey(const Bytes& user_blob,
                     const Bytes& master_blob,
                     const std::string& password,
                     bool use_master,
                     std::string_view mask_info,
                     std::string_view aad,
                     const basefwx::pb512::KdfOptions& kdf,
                     std::string_view legacy_user_aad) {
    std::string resolved = basefwx::ResolvePassword(password);
    basefwx::crypto::SecretGuard secrets;
    secrets.Add(resolved);
    std::exception_ptr master_failure;
    if (!master_blob.empty() && use_master) {
        try {
            if (basefwx::ec::IsEcMasterBlob(master_blob)) {
                if (StrictPqOnly()) {
                    throw std::runtime_error(
                        "EC master blobs are disabled in PQ strict mode");
                }
                basefwx::crypto::SecureBytes private_key{
                    basefwx::ec::LoadMasterPrivateKey()};
                basefwx::crypto::SecureBytes shared{
                    basefwx::ec::KemDecrypt(private_key.bytes(), master_blob)};
                return basefwx::crypto::HkdfSha256(
                    shared.bytes(), mask_info, 32);
            }
            basefwx::crypto::SecureBytes private_key{
                basefwx::pq::LoadMasterPrivateKey()};
            basefwx::crypto::SecureBytes shared{
                basefwx::pq::KemDecrypt(private_key.bytes(), master_blob)};
            return basefwx::crypto::HkdfSha256(shared.bytes(), mask_info, 32);
        } catch (...) {
            // A dual-wrapped payload has an independent password recovery
            // path. Missing, wrong, corrupt, disabled, or policy-rejected
            // master material must not make that valid wrap unreachable.
            master_failure = std::current_exception();
        }
    }
    if (user_blob.empty()) {
        if (master_failure) {
            std::rethrow_exception(master_failure);
        }
        if (!master_blob.empty() && !use_master) {
            throw std::runtime_error("Master key required to decode this payload");
        }
        throw std::runtime_error("Ciphertext missing key transport data");
    }
    if (resolved.empty()) {
        if (master_failure) {
            std::rethrow_exception(master_failure);
        }
        throw std::runtime_error("Password required to decode this payload");
    }
    if (user_blob.size() < 1) {
        throw std::runtime_error("Corrupted user key blob: missing KDF metadata");
    }

    std::size_t kdf_len = user_blob[0];
    std::size_t header_len = 1 + kdf_len + kUserKdfSaltSize;
    if (user_blob.size() < header_len) {
        throw std::runtime_error("Corrupted user key blob: truncated data");
    }
    std::string label;
    if (kdf_len > 0) {
        label.assign(reinterpret_cast<const char*>(user_blob.data() + 1), kdf_len);
    } else {
        label = kdf.label;
    }
    label = kdf_len > 0
        ? ResolvePeerKdfLabel(label)
        : ResolveKdfLabel(kdf.label);
    Bytes salt(user_blob.begin() + 1 + kdf_len, user_blob.begin() + header_len);
    Bytes wrapped(user_blob.begin() + header_len, user_blob.end());
    Bytes aad_bytes = ToBytes(aad);

    // 3.7.0: auth failure is terminal. The pre-3.6.3 PBKDF2-32k second-chance
    // path was removed — it silently downgraded the KDF cost 20x on any
    // exception (not just AEAD tag mismatch), which could mask non-auth
    // errors and produce a successful decrypt under a much weaker derivation.
    // Blobs from 2.x / pre-3.x are out of the supported window
    // (see SECURITY.md "≤ 2.7: Treat as incompatible").
    basefwx::pb512::KdfOptions kdf_opts = HardenKdfOptionsForPassword(resolved, kdf);
    basefwx::crypto::SecureBytes user_key{
        DeriveUserKeyWithLabel(resolved, salt, label, kdf_opts)};
    try {
        return basefwx::crypto::AeadDecrypt(
            user_key.bytes(), wrapped, aad_bytes);
    } catch (const basefwx::crypto::AuthenticationError&) {
        if (legacy_user_aad.empty() || legacy_user_aad == aad) {
            throw;
        }
        return basefwx::crypto::AeadDecrypt(
            user_key.bytes(), wrapped, ToBytes(legacy_user_aad));
    }
}

}  // namespace basefwx::keywrap
