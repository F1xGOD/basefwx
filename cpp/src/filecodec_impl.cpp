/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "filecodec_internal.hpp"

#include "basefwx/archive.hpp"
#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/crypto_utils.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/basefwx.hpp"
#include "basefwx/ec.hpp"
#include "basefwx/metadata.hpp"
#include "basefwx/obfuscation.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/pq.hpp"
#include "basefwx/runtime.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace basefwx::filecodec::internal {

basefwx::pb512::KdfOptions HardenKdfOptionsForPassword(const std::string& password,
                                                       const basefwx::pb512::KdfOptions& kdf) {
    if (password.empty()) {
        return kdf;
    }
    if (!basefwx::env::TestKdfIters().empty()) {
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

bool StrictPqOnly() {
    return basefwx::env::IsEnabled("BASEFWX_PQ_STRICT", false)
        || basefwx::env::IsEnabled("BASEFWX_PQ_ONLY", false);
}

std::optional<Bytes> TryLoadEcPublic(bool create_if_missing) {
    if (StrictPqOnly()) {
        return std::nullopt;
    }
    try {
        const bool allow_create = create_if_missing
            && basefwx::env::IsEnabled("BASEFWX_MASTER_EC_CREATE_IF_MISSING", false);
        return basefwx::ec::LoadMasterPublicKey(allow_create);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

PayloadKeys DerivePayloadKeys(const Bytes& root_key) {
    PayloadKeys keys;
    keys.aead = basefwx::crypto::HkdfSha256(root_key, constants::kFwxAesPayloadAeadInfo, 32);
    keys.obf = basefwx::crypto::HkdfSha256(root_key, constants::kFwxAesPayloadObfInfo, 32);
    return keys;
}

Bytes ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read file size: " + path.string());
    }
    input.seekg(0, std::ios::beg);
    
    Bytes data;
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!input) {
            throw std::runtime_error("Failed to read file: " + path.string());
        }
    }
    return data;
}

void WriteFileBytes(const std::filesystem::path& path, const Bytes& data) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + path.string());
    }
    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!output) {
            throw std::runtime_error("Failed to write file: " + path.string());
        }
    }
}

std::uint64_t FileSize(const std::filesystem::path& path) {
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        throw std::runtime_error("Failed to stat file: " + path.string());
    }
    return static_cast<std::uint64_t>(size);
}

Bytes ToBytes(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

std::string ToString(const Bytes& data) {
    return std::string(data.begin(), data.end());
}

std::string ResolveKdfLabel(const basefwx::pb512::KdfOptions& kdf) {
    return basefwx::keywrap::ResolveKdfLabel(kdf.label);
}

std::optional<std::uint32_t> ParseUint32(const std::string& value) {
    if (value.empty()) {
        return std::nullopt;
    }
    try {
        return static_cast<std::uint32_t>(std::stoul(value));
    } catch (...) {
        return std::nullopt;
    }
}

std::pair<std::string, std::string> SplitMetadata(const std::string& payload) {
    std::string delim(constants::kMetaDelim);
    auto pos = payload.find(delim);
    if (pos == std::string::npos) {
        return {"", payload};
    }
    return {payload.substr(0, pos), payload.substr(pos + delim.size())};
}

std::pair<std::string, std::string> SplitWithDelims(const std::string& payload,
                                                    std::string_view label) {
    std::string delim(constants::kFwxDelim);
    auto pos = payload.find(delim);
    if (pos != std::string::npos) {
        return {payload.substr(0, pos), payload.substr(pos + delim.size())};
    }
    std::string legacy(constants::kLegacyFwxDelim);
    pos = payload.find(legacy);
    if (pos != std::string::npos) {
        return {payload.substr(0, pos), payload.substr(pos + legacy.size())};
    }
    throw std::runtime_error(std::string("Malformed ") + std::string(label) + " payload");
}

std::pair<std::string, std::string> SplitWithHeavyDelims(const std::string& payload,
                                                         std::string_view label) {
    std::string delim(constants::kFwxHeavyDelim);
    auto pos = payload.find(delim);
    if (pos != std::string::npos) {
        return {payload.substr(0, pos), payload.substr(pos + delim.size())};
    }
    std::string legacy(constants::kLegacyFwxHeavyDelim);
    pos = payload.find(legacy);
    if (pos != std::string::npos) {
        return {payload.substr(0, pos), payload.substr(pos + legacy.size())};
    }
    throw std::runtime_error(std::string("Malformed ") + std::string(label) + " payload");
}

basefwx::archive::PackMode ResolvePackMode(const basefwx::metadata::MetadataMap& meta,
                                           const std::string& ext) {
    std::string flag = basefwx::metadata::GetValue(meta, constants::kPackMetaKey);
    auto mode = basefwx::archive::PackModeFromFlag(flag);
    if (mode == basefwx::archive::PackMode::None && !ext.empty()) {
        mode = basefwx::archive::PackModeFromExtension(std::filesystem::path(ext));
    }
    return mode;
}

Bytes Uint32Be(std::uint32_t value) {
    return Bytes{
        static_cast<std::uint8_t>((value >> 24) & 0xFF),
        static_cast<std::uint8_t>((value >> 16) & 0xFF),
        static_cast<std::uint8_t>((value >> 8) & 0xFF),
        static_cast<std::uint8_t>(value & 0xFF)
    };
}

Bytes Uint64Be(std::uint64_t value) {
    Bytes out(8);
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<std::uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

Bytes Uint16Be(std::uint16_t value) {
    return Bytes{
        static_cast<std::uint8_t>((value >> 8) & 0xFF),
        static_cast<std::uint8_t>(value & 0xFF)
    };
}

void ThrowIfInterrupted() {
    if (basefwx::runtime::StopRequested()) {
        throw std::runtime_error("Interrupted");
    }
}

std::uint64_t TellPosOrThrow(std::istream& stream) {
    std::streampos pos = stream.tellg();
    if (pos < 0) {
        throw std::runtime_error("Failed to determine stream position");
    }
    return static_cast<std::uint64_t>(pos);
}

StreamCipherLayout ResolveStreamCipherLayout(const std::filesystem::path& input,
                                             std::istream& stream,
                                             std::uint32_t encoded_payload_len,
                                             std::uint32_t metadata_len) {
    StreamCipherLayout layout;
    layout.body_start = TellPosOrThrow(stream);

    std::uint64_t file_size = FileSize(input);
    constexpr std::uint64_t tag_len = static_cast<std::uint64_t>(constants::kAeadTagLen);
    if (file_size < layout.body_start + tag_len) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    layout.body_len = file_size - layout.body_start - tag_len;

    std::uint64_t payload_len_64 = 4ull
        + static_cast<std::uint64_t>(metadata_len)
        + static_cast<std::uint64_t>(constants::kAeadNonceLen)
        + layout.body_len
        + static_cast<std::uint64_t>(constants::kAeadTagLen);
    if (static_cast<std::uint32_t>(payload_len_64) != encoded_payload_len) {
        throw std::runtime_error("Malformed length-prefixed blob (payload length mismatch)");
    }
    return layout;
}

Bytes EncryptAesPayload(const std::string& plaintext,
                        const std::string& password,
                        bool use_master,
                        const std::string& metadata_blob,
                        const basefwx::pb512::KdfOptions& kdf,
                        std::uint32_t kdf_iterations,
                        std::optional<std::uint32_t> argon2_time,
                        std::optional<std::uint32_t> argon2_mem,
                        std::optional<std::uint32_t> argon2_par,
                        bool obfuscate,
                        bool fast_obf) {
    std::string resolved = basefwx::ResolvePassword(password);
    Bytes metadata_bytes = ToBytes(metadata_blob);
    Bytes aad = metadata_bytes;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = use_master && (pq_pub.has_value() || ec_pub.has_value());
    if (resolved.empty() && !use_master_effective) {
        throw std::runtime_error("Password required when no usable master key is available");
    }

    Bytes master_payload;
    Bytes ephemeral_key;
    PayloadKeys payload_keys;
    basefwx::crypto::SecretGuard secrets;
    secrets.Add(resolved);
    secrets.Add(ephemeral_key);
    secrets.Add(payload_keys.aead);
    secrets.Add(payload_keys.obf);
    if (use_master_effective) {
        if (pq_pub.has_value()) {
            basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(*pq_pub);
            master_payload = kem.ciphertext;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
            basefwx::crypto::SecureClear(kem.shared);
        } else if (ec_pub.has_value()) {
            basefwx::ec::KemResult kem = basefwx::ec::KemEncrypt(*ec_pub);
            master_payload = kem.blob;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
            basefwx::crypto::SecureClear(kem.shared);
        } else {
            ephemeral_key = basefwx::crypto::RandomBytes(constants::kEphemeralKeyLen);
        }
    } else {
        ephemeral_key = basefwx::crypto::RandomBytes(constants::kEphemeralKeyLen);
    }

    Bytes user_blob;
    if (!resolved.empty()) {
        basefwx::pb512::KdfOptions kdf_opts = kdf;
        kdf_opts.pbkdf2_iterations = kdf_iterations;
        if (argon2_time.has_value()) {
            kdf_opts.argon2_time_cost = argon2_time.value();
        }
        if (argon2_mem.has_value()) {
            kdf_opts.argon2_memory_cost = argon2_mem.value();
        }
        if (argon2_par.has_value()) {
            kdf_opts.argon2_parallelism = argon2_par.value();
        }
        kdf_opts = HardenKdfOptionsForPassword(resolved, kdf_opts);
        std::string label = basefwx::keywrap::ResolveKdfLabel(kdf_opts.label);
        Bytes salt = basefwx::crypto::RandomBytes(constants::kUserKdfSaltSize);
        Bytes user_key = basefwx::keywrap::DeriveUserKeyWithLabel(resolved, salt, label, kdf_opts);
        Bytes wrapped = basefwx::crypto::AeadEncrypt(user_key, ephemeral_key, aad);
        basefwx::crypto::SecureClear(user_key);
        user_blob.reserve(salt.size() + wrapped.size());
        user_blob.insert(user_blob.end(), salt.begin(), salt.end());
        user_blob.insert(user_blob.end(), wrapped.begin(), wrapped.end());
    }

    payload_keys = DerivePayloadKeys(ephemeral_key);
    Bytes payload_bytes = ToBytes(plaintext);
    if (obfuscate) {
        payload_bytes = basefwx::obf::ObfuscateBytes(payload_bytes, payload_keys.obf, fast_obf);
    }

    Bytes nonce = basefwx::crypto::RandomBytes(constants::kAeadNonceLen);
    Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(payload_keys.aead, nonce, payload_bytes, aad);
    Bytes ciphertext;
    ciphertext.reserve(nonce.size() + ct.size());
    ciphertext.insert(ciphertext.end(), nonce.begin(), nonce.end());
    ciphertext.insert(ciphertext.end(), ct.begin(), ct.end());

    Bytes payload;
    Bytes meta_len = Uint32Be(static_cast<std::uint32_t>(metadata_bytes.size()));
    payload.reserve(meta_len.size() + metadata_bytes.size() + ciphertext.size());
    payload.insert(payload.end(), meta_len.begin(), meta_len.end());
    payload.insert(payload.end(), metadata_bytes.begin(), metadata_bytes.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

    std::vector<basefwx::format::Bytes> parts = {user_blob, master_payload, payload};
    return basefwx::format::PackLengthPrefixed(parts);
}

std::string DecryptAesPayload(const Bytes& blob,
                              const std::string& password,
                              bool use_master,
                              const basefwx::pb512::KdfOptions& kdf,
                              bool obfuscate,
                              std::string* metadata_out) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::vector<basefwx::format::Bytes> parts = basefwx::format::UnpackLengthPrefixed(blob, 3);
    const Bytes& user_blob = parts[0];
    const Bytes& master_blob = parts[1];
    const Bytes& payload_blob = parts[2];

    if (payload_blob.size() < 4) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    std::uint32_t meta_len = (static_cast<std::uint32_t>(payload_blob[0]) << 24)
                             | (static_cast<std::uint32_t>(payload_blob[1]) << 16)
                             | (static_cast<std::uint32_t>(payload_blob[2]) << 8)
                             | static_cast<std::uint32_t>(payload_blob[3]);
    std::size_t meta_end = 4 + meta_len;
    if (meta_end > payload_blob.size()) {
        throw std::runtime_error("Malformed payload metadata header");
    }
    Bytes metadata_bytes(payload_blob.begin() + 4, payload_blob.begin() + static_cast<std::ptrdiff_t>(meta_end));
    std::string metadata_blob = ToString(metadata_bytes);
    if (metadata_out) {
        *metadata_out = metadata_blob;
    }
    auto meta = basefwx::metadata::Decode(metadata_blob);
    std::string obf_hint = basefwx::metadata::GetValue(meta, "ENC-OBF");
    if (obf_hint.empty()) {
        obf_hint = "yes";
    }
    bool should_deobfuscate = obfuscate && obf_hint != "no";
    bool fast_obf = should_deobfuscate && obf_hint == "fast";
    bool use_derived_keys = basefwx::metadata::GetValue(meta, "ENC-KSEP") == "v1";

    std::string kdf_label = basefwx::metadata::GetValue(meta, "ENC-KDF");
    kdf_label = basefwx::keywrap::ResolveKdfLabel(kdf_label.empty() ? kdf.label : kdf_label);
    auto kdf_iter = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-KDF-ITER"));
    auto argon2_time = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-TC"));
    auto argon2_mem = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-MEM"));
    auto argon2_par = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-PAR"));

    Bytes ciphertext(payload_blob.begin() + static_cast<std::ptrdiff_t>(meta_end), payload_blob.end());
    if (ciphertext.size() < constants::kAeadNonceLen + constants::kAeadTagLen) {
        throw std::runtime_error("Ciphertext truncated");
    }

    Bytes ephemeral_key;
    PayloadKeys payload_keys;
    basefwx::crypto::SecretGuard secrets;
    secrets.Add(resolved);
    secrets.Add(ephemeral_key);
    secrets.Add(payload_keys.aead);
    secrets.Add(payload_keys.obf);
    if (!master_blob.empty()) {
        if (!use_master) {
            throw std::runtime_error("Master key required to decrypt this payload");
        }
        if (basefwx::ec::IsEcMasterBlob(master_blob)) {
            if (StrictPqOnly()) {
                throw std::runtime_error("EC master blobs are disabled in PQ strict mode");
            }
            basefwx::crypto::SecureBytes private_key{basefwx::ec::LoadMasterPrivateKey()};
            basefwx::crypto::SecureBytes shared{
                basefwx::ec::KemDecrypt(private_key.bytes(), master_blob)};
            ephemeral_key = basefwx::crypto::HkdfSha256(shared.bytes(), constants::kKemInfo, 32);
        } else {
            basefwx::crypto::SecureBytes private_key{basefwx::pq::LoadMasterPrivateKey()};
            basefwx::crypto::SecureBytes shared{
                basefwx::pq::KemDecrypt(private_key.bytes(), master_blob)};
            ephemeral_key = basefwx::crypto::HkdfSha256(shared.bytes(), constants::kKemInfo, 32);
        }
    } else if (!user_blob.empty()) {
        if (resolved.empty()) {
            throw std::runtime_error("User password required to decrypt this payload");
        }
        if (user_blob.size() < constants::kUserKdfSaltSize + constants::kAeadNonceLen + constants::kAeadTagLen) {
            throw std::runtime_error("Corrupted user key blob: missing salt or AEAD data");
        }
        Bytes salt(user_blob.begin(), user_blob.begin() + static_cast<std::ptrdiff_t>(constants::kUserKdfSaltSize));
        Bytes wrapped(user_blob.begin() + static_cast<std::ptrdiff_t>(constants::kUserKdfSaltSize), user_blob.end());
        basefwx::pb512::KdfOptions kdf_opts = kdf;
        kdf_opts.label = kdf_label;
        if (kdf_iter.has_value()) {
            kdf_opts.pbkdf2_iterations = kdf_iter.value();
        } else {
            kdf_opts.pbkdf2_iterations = basefwx::constants::kUserKdfIterations;
        }
        if (argon2_time.has_value()) {
            kdf_opts.argon2_time_cost = argon2_time.value();
        }
        if (argon2_mem.has_value()) {
            kdf_opts.argon2_memory_cost = argon2_mem.value();
        }
        if (argon2_par.has_value()) {
            kdf_opts.argon2_parallelism = argon2_par.value();
        }
        kdf_opts = HardenKdfOptionsForPassword(resolved, kdf_opts);
        Bytes user_key = basefwx::keywrap::DeriveUserKeyWithLabel(resolved, salt, kdf_label, kdf_opts);
        ephemeral_key = basefwx::crypto::AeadDecrypt(user_key, wrapped, metadata_bytes);
        basefwx::crypto::SecureClear(user_key);
    } else {
        throw std::runtime_error("Ciphertext missing key transport data");
    }

    Bytes* aead_key = &ephemeral_key;
    Bytes* obf_key = &ephemeral_key;
    if (use_derived_keys) {
        payload_keys = DerivePayloadKeys(ephemeral_key);
        aead_key = &payload_keys.aead;
        obf_key = &payload_keys.obf;
    }

    Bytes nonce(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(constants::kAeadNonceLen));
    Bytes tag(ciphertext.end() - static_cast<std::ptrdiff_t>(constants::kAeadTagLen), ciphertext.end());
    Bytes body(ciphertext.begin() + static_cast<std::ptrdiff_t>(constants::kAeadNonceLen),
               ciphertext.end() - static_cast<std::ptrdiff_t>(constants::kAeadTagLen));
    Bytes body_with_tag = body;
    body_with_tag.insert(body_with_tag.end(), tag.begin(), tag.end());

    Bytes plain = basefwx::crypto::AesGcmDecryptWithIv(*aead_key, nonce, body_with_tag, metadata_bytes);
    if (should_deobfuscate) {
        plain = basefwx::obf::DeobfuscateBytes(plain, *obf_key, fast_obf);
    }
    return ToString(plain);
}

bool EnableAead(const FileOptions& options) {
    return options.enable_aead && basefwx::env::IsEnabled("BASEFWX_B512_AEAD", true);
}

bool EnableObfuscation(const FileOptions& options) {
    return options.enable_obfuscation && basefwx::env::IsEnabled("BASEFWX_OBFUSCATE", true);
}

bool PerfModeEnabled() {
    return basefwx::env::IsEnabled("BASEFWX_PERF", false);
}

bool UseFastObfuscation(std::uint64_t length) {
    return PerfModeEnabled() && length >= basefwx::constants::kPerfObfuscationThreshold;
}

std::string ObfMode(bool obfuscate, bool fast) {
    if (!obfuscate) {
        return "no";
    }
    return fast ? "fast" : "yes";
}

std::optional<std::string> PeekMetadataBlob(const std::filesystem::path& input) {
    std::ifstream preview(input, std::ios::binary);
    if (!preview) {
        return std::nullopt;
    }
    auto read_u32 = [&](std::uint32_t& out) -> bool {
        std::array<std::uint8_t, 4> buf{};
        preview.read(reinterpret_cast<char*>(buf.data()), buf.size());
        if (preview.gcount() != static_cast<std::streamsize>(buf.size())) {
            return false;
        }
        out = (static_cast<std::uint32_t>(buf[0]) << 24)
              | (static_cast<std::uint32_t>(buf[1]) << 16)
              | (static_cast<std::uint32_t>(buf[2]) << 8)
              | static_cast<std::uint32_t>(buf[3]);
        return true;
    };

    std::uint32_t len_user = 0;
    if (!read_u32(len_user)) {
        return std::nullopt;
    }
    preview.seekg(len_user, std::ios::cur);
    std::uint32_t len_master = 0;
    if (!read_u32(len_master)) {
        return std::nullopt;
    }
    preview.seekg(len_master, std::ios::cur);
    std::uint32_t len_payload = 0;
    if (!read_u32(len_payload)) {
        return std::nullopt;
    }
    if (len_payload < 4) {
        return std::nullopt;
    }
    std::uint32_t metadata_len = 0;
    if (!read_u32(metadata_len)) {
        return std::nullopt;
    }
    Bytes metadata_bytes(metadata_len);
    if (metadata_len > 0) {
        preview.read(reinterpret_cast<char*>(metadata_bytes.data()), metadata_len);
        if (preview.gcount() != static_cast<std::streamsize>(metadata_len)) {
            return std::nullopt;
        }
    }
    return ToString(metadata_bytes);
}

}  // namespace basefwx::filecodec::internal
