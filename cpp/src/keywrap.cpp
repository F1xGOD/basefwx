#include "basefwx/keywrap.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/ec.hpp"
#include "basefwx/env.hpp"
#include "basefwx/pq.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <stdexcept>

namespace basefwx::keywrap {

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

std::string DefaultKdfLabel() {
    std::string env_label = basefwx::env::Get("BASEFWX_USER_KDF");
    if (!env_label.empty()) {
        return ToLower(env_label);
    }
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    return "argon2id";
#else
    return "pbkdf2";
#endif
}

bool SkipShortHardening() {
    return !basefwx::env::Get("BASEFWX_TEST_KDF_ITERS").empty();
}

basefwx::pb512::KdfOptions HardenKdfOptions(const std::string& password,
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
                                           basefwx::constants::DefaultArgon2Parallelism());
    return hardened;
}

}  // namespace

std::string ResolveKdfLabel(const std::string& label) {
    if (label.empty()) {
        return DefaultKdfLabel();
    }
    std::string normalized = ToLower(label);
    if (normalized == "auto") {
        return DefaultKdfLabel();
    }
    return normalized;
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
        return basefwx::crypto::Pbkdf2HmacSha256(password, salt, kdf.pbkdf2_iterations, 32);
    }
    throw std::runtime_error("Unsupported KDF label: " + normalized);
}

Bytes MaskPayload(const Bytes& mask_key, const Bytes& payload, std::string_view info) {
    if (payload.empty()) {
        return {};
    }
    Bytes stream;
    if (payload.size() > basefwx::constants::kHkdfMaxLen) {
        stream = basefwx::crypto::HkdfSha256Stream(info, mask_key, payload.size());
    } else {
        stream = basefwx::crypto::HkdfSha256(info, mask_key, payload.size());
    }
    Bytes out(payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(payload[i] ^ stream[i]);
    }
    return out;
}

MaskKeyResult PrepareMaskKey(const std::string& password,
                             bool use_master,
                             std::string_view mask_info,
                             bool require_password,
                             std::string_view aad,
                             const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (require_password && resolved.empty()) {
        throw std::runtime_error("Password required for this mode");
    }
    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            try {
                ec_pub = basefwx::ec::LoadMasterPublicKey(true);
            } catch (const std::exception&) {
                ec_pub = std::nullopt;
            }
        }
    }
    bool use_master_effective = use_master && (pq_pub.has_value() || ec_pub.has_value());
    if (resolved.empty() && !use_master_effective) {
        throw std::runtime_error("Password required when master key is unavailable");
    }

    MaskKeyResult result;
    result.used_master = use_master_effective;
    if (use_master_effective) {
        if (pq_pub.has_value()) {
            basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(*pq_pub);
            result.master_blob = kem.ciphertext;
            result.mask_key = basefwx::crypto::HkdfSha256(mask_info, kem.shared, 32);
        } else if (ec_pub.has_value()) {
            basefwx::ec::KemResult kem = basefwx::ec::KemEncrypt(*ec_pub);
            result.master_blob = kem.blob;
            result.mask_key = basefwx::crypto::HkdfSha256(mask_info, kem.shared, 32);
        } else {
            result.mask_key = basefwx::crypto::RandomBytes(32);
        }
    } else {
        result.mask_key = basefwx::crypto::RandomBytes(32);
    }
    Bytes salt = basefwx::crypto::RandomBytes(kUserKdfSaltSize);
    if (!resolved.empty()) {
        basefwx::pb512::KdfOptions kdf_opts = HardenKdfOptions(resolved, kdf);
        std::string label = ResolveKdfLabel(kdf_opts.label);
        Bytes user_key = DeriveUserKeyWithLabel(resolved, salt, label, kdf_opts);
        Bytes aad_bytes = ToBytes(aad);
        Bytes wrapped = basefwx::crypto::AeadEncrypt(user_key, result.mask_key, aad_bytes);

        if (label.size() > 255) {
            throw std::runtime_error("KDF label too long");
        }
        result.user_blob.reserve(1 + label.size() + salt.size() + wrapped.size());
        result.user_blob.push_back(static_cast<std::uint8_t>(label.size()));
        result.user_blob.insert(result.user_blob.end(), label.begin(), label.end());
        result.user_blob.insert(result.user_blob.end(), salt.begin(), salt.end());
        result.user_blob.insert(result.user_blob.end(), wrapped.begin(), wrapped.end());
    }

    return result;
}

Bytes RecoverMaskKey(const Bytes& user_blob,
                     const Bytes& master_blob,
                     const std::string& password,
                     bool use_master,
                     std::string_view mask_info,
                     std::string_view aad,
                     const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (!master_blob.empty()) {
        if (!use_master) {
            throw std::runtime_error("Master key required to decode this payload");
        }
        if (basefwx::ec::IsEcMasterBlob(master_blob)) {
            Bytes private_key = basefwx::ec::LoadMasterPrivateKey();
            Bytes shared = basefwx::ec::KemDecrypt(private_key, master_blob);
            return basefwx::crypto::HkdfSha256(mask_info, shared, 32);
        }
        Bytes private_key = basefwx::pq::LoadMasterPrivateKey();
        Bytes shared = basefwx::pq::KemDecrypt(private_key, master_blob);
        return basefwx::crypto::HkdfSha256(mask_info, shared, 32);
    }
    if (user_blob.empty()) {
        throw std::runtime_error("Ciphertext missing key transport data");
    }
    if (resolved.empty()) {
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
    label = ResolveKdfLabel(label.empty() ? kdf.label : label);
    Bytes salt(user_blob.begin() + 1 + kdf_len, user_blob.begin() + header_len);
    Bytes wrapped(user_blob.begin() + header_len, user_blob.end());
    Bytes aad_bytes = ToBytes(aad);

    try {
        basefwx::pb512::KdfOptions kdf_opts = HardenKdfOptions(resolved, kdf);
        Bytes user_key = DeriveUserKeyWithLabel(resolved, salt, label, kdf_opts);
        return basefwx::crypto::AeadDecrypt(user_key, wrapped, aad_bytes);
    } catch (const std::exception&) {
        if (label != "pbkdf2" || !kdf.allow_pbkdf2_fallback) {
            throw;
        }
    }

    basefwx::pb512::KdfOptions fallback = kdf;
    fallback.pbkdf2_iterations = basefwx::constants::kUserKdfIterationsFallback;
    Bytes user_key = DeriveUserKeyWithLabel(resolved, salt, label, fallback);
    return basefwx::crypto::AeadDecrypt(user_key, wrapped, aad_bytes);
}

}  // namespace basefwx::keywrap
