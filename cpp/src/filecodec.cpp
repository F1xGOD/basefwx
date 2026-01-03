#include "basefwx/filecodec.hpp"

#include "basefwx/archive.hpp"
#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/basefwx.hpp"
#include "basefwx/ec.hpp"
#include "basefwx/metadata.hpp"
#include "basefwx/obfuscation.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/pq.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace basefwx::filecodec {

namespace {

using Bytes = std::vector<std::uint8_t>;

basefwx::pb512::KdfOptions HardenKdfOptionsForPassword(const std::string& password,
                                                       const basefwx::pb512::KdfOptions& kdf) {
    if (password.empty()) {
        return kdf;
    }
    if (!basefwx::env::Get("BASEFWX_TEST_KDF_ITERS").empty()) {
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

std::optional<Bytes> TryLoadEcPublic(bool create_if_missing) {
    try {
        return basefwx::ec::LoadMasterPublicKey(create_if_missing);
    } catch (const std::exception&) {
        return std::nullopt;
    }
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
    Bytes data(static_cast<std::size_t>(size));
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

class AesGcmEncryptor {
public:
    AesGcmEncryptor(const Bytes& key, const Bytes& nonce, const Bytes& aad) {
        if (key.size() != 32) {
            throw std::runtime_error("AES-GCM expects 32-byte key");
        }
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_) {
            throw std::runtime_error("AES-GCM context allocation failed");
        }
        if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("AES-GCM init failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
            throw std::runtime_error("AES-GCM set iv length failed");
        }
        if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            throw std::runtime_error("AES-GCM set key failed");
        }
        if (!aad.empty()) {
            int out_len = 0;
            if (EVP_EncryptUpdate(ctx_, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
                throw std::runtime_error("AES-GCM aad failed");
            }
        }
    }

    ~AesGcmEncryptor() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
    }

    Bytes Update(const Bytes& input) {
        if (input.empty()) {
            return {};
        }
        Bytes out(input.size());
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx_, out.data(), &out_len, input.data(), static_cast<int>(input.size())) != 1) {
            throw std::runtime_error("AES-GCM encrypt failed");
        }
        out.resize(static_cast<std::size_t>(out_len));
        return out;
    }

    Bytes Final() {
        Bytes out(16);
        int out_len = 0;
        if (EVP_EncryptFinal_ex(ctx_, out.data(), &out_len) != 1) {
            throw std::runtime_error("AES-GCM final failed");
        }
        out.resize(static_cast<std::size_t>(out_len));
        return out;
    }

    Bytes Tag() {
        Bytes tag(constants::kAeadTagLen);
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
            throw std::runtime_error("AES-GCM get tag failed");
        }
        return tag;
    }

private:
    EVP_CIPHER_CTX* ctx_{nullptr};
};

class AesGcmDecryptor {
public:
    AesGcmDecryptor(const Bytes& key, const Bytes& nonce, const Bytes& aad) {
        if (key.size() != 32) {
            throw std::runtime_error("AES-GCM expects 32-byte key");
        }
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_) {
            throw std::runtime_error("AES-GCM context allocation failed");
        }
        if (EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("AES-GCM init failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
            throw std::runtime_error("AES-GCM set iv length failed");
        }
        if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            throw std::runtime_error("AES-GCM set key failed");
        }
        if (!aad.empty()) {
            int out_len = 0;
            if (EVP_DecryptUpdate(ctx_, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
                throw std::runtime_error("AES-GCM aad failed");
            }
        }
    }

    ~AesGcmDecryptor() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
    }

    Bytes Update(const Bytes& input) {
        if (input.empty()) {
            return {};
        }
        Bytes out(input.size());
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx_, out.data(), &out_len, input.data(), static_cast<int>(input.size())) != 1) {
            throw std::runtime_error("AES-GCM decrypt failed");
        }
        out.resize(static_cast<std::size_t>(out_len));
        return out;
    }

    void Final(const Bytes& tag) {
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                const_cast<std::uint8_t*>(tag.data())) != 1) {
            throw std::runtime_error("AES-GCM set tag failed");
        }
        std::array<std::uint8_t, 16> buffer{};
        int out_len = 0;
        if (EVP_DecryptFinal_ex(ctx_, buffer.data(), &out_len) != 1) {
            throw std::runtime_error("AES-GCM auth failed");
        }
    }

private:
    EVP_CIPHER_CTX* ctx_{nullptr};
};

Bytes EncryptAesPayload(const std::string& plaintext,
                        const std::string& password,
                        bool use_master,
                        const std::string& metadata_blob,
                        const basefwx::pb512::KdfOptions& kdf,
                        std::uint32_t kdf_iterations,
                        std::optional<std::uint32_t> argon2_time,
                        std::optional<std::uint32_t> argon2_mem,
                        std::optional<std::uint32_t> argon2_par,
                        bool obfuscate) {
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

    Bytes master_payload;
    Bytes ephemeral_key;
    if (use_master_effective) {
        if (pq_pub.has_value()) {
            basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(*pq_pub);
            master_payload = kem.ciphertext;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
        } else if (ec_pub.has_value()) {
            basefwx::ec::KemResult kem = basefwx::ec::KemEncrypt(*ec_pub);
            master_payload = kem.blob;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
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
        user_blob.reserve(salt.size() + wrapped.size());
        user_blob.insert(user_blob.end(), salt.begin(), salt.end());
        user_blob.insert(user_blob.end(), wrapped.begin(), wrapped.end());
    }

    Bytes payload_bytes = ToBytes(plaintext);
    if (obfuscate) {
        payload_bytes = basefwx::obf::ObfuscateBytes(payload_bytes, ephemeral_key);
    }

    Bytes nonce = basefwx::crypto::RandomBytes(constants::kAeadNonceLen);
    Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(ephemeral_key, nonce, payload_bytes, aad);
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
    bool should_deobfuscate = obfuscate && basefwx::metadata::GetValue(meta, "ENC-OBF") != "no";

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
    if (!master_blob.empty()) {
        if (!use_master) {
            throw std::runtime_error("Master key required to decrypt this payload");
        }
        if (basefwx::ec::IsEcMasterBlob(master_blob)) {
            Bytes private_key = basefwx::ec::LoadMasterPrivateKey();
            Bytes shared = basefwx::ec::KemDecrypt(private_key, master_blob);
            ephemeral_key = basefwx::crypto::HkdfSha256(shared, constants::kKemInfo, 32);
        } else {
            Bytes private_key = basefwx::pq::LoadMasterPrivateKey();
            Bytes shared = basefwx::pq::KemDecrypt(private_key, master_blob);
            ephemeral_key = basefwx::crypto::HkdfSha256(shared, constants::kKemInfo, 32);
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
    } else {
        throw std::runtime_error("Ciphertext missing key transport data");
    }

    Bytes nonce(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(constants::kAeadNonceLen));
    Bytes tag(ciphertext.end() - static_cast<std::ptrdiff_t>(constants::kAeadTagLen), ciphertext.end());
    Bytes body(ciphertext.begin() + static_cast<std::ptrdiff_t>(constants::kAeadNonceLen),
               ciphertext.end() - static_cast<std::ptrdiff_t>(constants::kAeadTagLen));
    Bytes body_with_tag = body;
    body_with_tag.insert(body_with_tag.end(), tag.begin(), tag.end());

    Bytes plain = basefwx::crypto::AesGcmDecryptWithIv(ephemeral_key, nonce, body_with_tag, metadata_bytes);
    if (should_deobfuscate) {
        plain = basefwx::obf::DeobfuscateBytes(plain, ephemeral_key);
    }
    return ToString(plain);
}

bool EnableAead(const FileOptions& options) {
    return options.enable_aead && basefwx::env::IsEnabled("BASEFWX_B512_AEAD", true);
}

bool EnableObfuscation(const FileOptions& options) {
    return options.enable_obfuscation && basefwx::env::IsEnabled("BASEFWX_OBFUSCATE", true);
}

std::string B512EncodeFileSimple(const std::filesystem::path& input,
                                 const std::string& password,
                                 const FileOptions& options,
                                 const basefwx::pb512::KdfOptions& kdf,
                                 std::string_view pack_flag) {
    std::string resolved = basefwx::ResolvePassword(password);
    Bytes data = ReadFileBytes(input);
    std::string b64_payload = basefwx::base64::Encode(data);
    std::string ext = input.extension().string();

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);

    std::string ext_token = basefwx::pb512::B512Encode(ext, resolved, use_master_effective, kdf_opts);
    std::string data_token = basefwx::pb512::B512Encode(b64_payload, resolved, use_master_effective, kdf_opts);

    bool use_aead = EnableAead(options);
    std::string metadata_blob = basefwx::metadata::Build(
        "FWX512R",
        options.strip_metadata,
        use_master_effective,
        use_aead ? "AESGCM" : "NONE",
        kdf_label,
        {},
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::string(pack_flag)
    );

    std::string body = ext_token + std::string(constants::kFwxDelim) + data_token;
    std::string payload = metadata_blob.empty()
        ? body
        : metadata_blob + std::string(constants::kMetaDelim) + body;
    Bytes payload_bytes = ToBytes(payload);

    Bytes output_bytes;
    if (use_aead) {
        auto mask = basefwx::keywrap::PrepareMaskKey(
            resolved,
            use_master_effective,
            constants::kB512FileMaskInfo,
            !use_master_effective,
            constants::kMaskAadB512File,
            kdf_opts
        );
        Bytes aead_key = basefwx::crypto::HkdfSha256(mask.mask_key, constants::kB512AeadInfo, 32);
        Bytes ct = basefwx::crypto::AeadEncrypt(aead_key, payload_bytes, Bytes(constants::kB512AeadInfo.begin(),
                                                                              constants::kB512AeadInfo.end()));
        std::vector<basefwx::format::Bytes> parts = {mask.user_blob, mask.master_blob, ct};
        output_bytes = basefwx::format::PackLengthPrefixed(parts);
    } else {
        output_bytes = payload_bytes;
    }

    std::filesystem::path out_path = input;
    out_path.replace_extension(".fwx");
    WriteFileBytes(out_path, output_bytes);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    return out_path.string();
}

std::string B512EncodeFileStream(const std::filesystem::path& input,
                                 const std::string& password,
                                 const FileOptions& options,
                                 const basefwx::pb512::KdfOptions& kdf,
                                 std::string_view pack_flag) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password required for streaming b512 encode");
    }
    if (!EnableAead(options)) {
        throw std::runtime_error("Streaming b512 encode requires AEAD mode");
    }
    std::uint64_t input_size = FileSize(input);
    std::size_t chunk_size = options.stream_chunk_size;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);

    Bytes stream_salt = basefwx::obf::StreamObfuscator::GenerateSalt();
    std::string ext = input.extension().string();
    Bytes ext_bytes = ToBytes(ext);

    std::string metadata_blob = basefwx::metadata::Build(
        "FWX512R",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "STREAM",
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::string(pack_flag)
    );
    Bytes metadata_bytes = ToBytes(metadata_blob);
    Bytes prefix_bytes;
    if (!metadata_blob.empty()) {
        prefix_bytes = metadata_bytes;
        std::string delim(constants::kMetaDelim);
        prefix_bytes.insert(prefix_bytes.end(), delim.begin(), delim.end());
    }

    Bytes stream_header;
    stream_header.insert(stream_header.end(), constants::kStreamMagic.begin(), constants::kStreamMagic.end());
    Bytes chunk_bytes = Uint32Be(static_cast<std::uint32_t>(chunk_size));
    stream_header.insert(stream_header.end(), chunk_bytes.begin(), chunk_bytes.end());
    Bytes size_bytes = Uint64Be(input_size);
    stream_header.insert(stream_header.end(), size_bytes.begin(), size_bytes.end());
    stream_header.insert(stream_header.end(), stream_salt.begin(), stream_salt.end());
    Bytes ext_len = Uint16Be(static_cast<std::uint16_t>(ext_bytes.size()));
    stream_header.insert(stream_header.end(), ext_len.begin(), ext_len.end());
    stream_header.insert(stream_header.end(), ext_bytes.begin(), ext_bytes.end());

    std::uint64_t plaintext_len = static_cast<std::uint64_t>(prefix_bytes.size() + stream_header.size() + input_size);

    auto mask = basefwx::keywrap::PrepareMaskKey(
        resolved,
        use_master_effective,
        constants::kB512FileMaskInfo,
        !use_master_effective,
        constants::kMaskAadB512File,
        kdf_opts
    );
    Bytes aead_key = basefwx::crypto::HkdfSha256(mask.mask_key, constants::kB512AeadInfo, 32);
    Bytes nonce = basefwx::crypto::RandomBytes(constants::kAeadNonceLen);

    std::uint64_t payload_len = 4 + metadata_bytes.size() + nonce.size() + plaintext_len + constants::kAeadTagLen;

    std::filesystem::path out_path = input;
    out_path.replace_extension(".fwx");
    std::ofstream output(out_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + out_path.string());
    }

    Bytes len_user = Uint32Be(static_cast<std::uint32_t>(mask.user_blob.size()));
    Bytes len_master = Uint32Be(static_cast<std::uint32_t>(mask.master_blob.size()));
    Bytes len_payload = Uint32Be(static_cast<std::uint32_t>(payload_len));
    output.write(reinterpret_cast<const char*>(len_user.data()), len_user.size());
    output.write(reinterpret_cast<const char*>(mask.user_blob.data()), static_cast<std::streamsize>(mask.user_blob.size()));
    output.write(reinterpret_cast<const char*>(len_master.data()), len_master.size());
    output.write(reinterpret_cast<const char*>(mask.master_blob.data()), static_cast<std::streamsize>(mask.master_blob.size()));
    output.write(reinterpret_cast<const char*>(len_payload.data()), len_payload.size());

    Bytes metadata_len = Uint32Be(static_cast<std::uint32_t>(metadata_bytes.size()));
    output.write(reinterpret_cast<const char*>(metadata_len.data()), metadata_len.size());
    if (!metadata_bytes.empty()) {
        output.write(reinterpret_cast<const char*>(metadata_bytes.data()),
                     static_cast<std::streamsize>(metadata_bytes.size()));
    }
    output.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));

    AesGcmEncryptor encryptor(aead_key, nonce, metadata_bytes);
    if (!prefix_bytes.empty()) {
        Bytes ct = encryptor.Update(prefix_bytes);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }
    if (!stream_header.empty()) {
        Bytes ct = encryptor.Update(stream_header);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }

    basefwx::obf::StreamObfuscator obfuscator = basefwx::obf::StreamObfuscator::ForPassword(resolved, stream_salt);
    std::ifstream input_stream(input, std::ios::binary);
    if (!input_stream) {
        throw std::runtime_error("Failed to open input file: " + input.string());
    }
    Bytes buffer(chunk_size);
    while (input_stream) {
        buffer.resize(chunk_size);
        input_stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = input_stream.gcount();
        if (got <= 0) {
            break;
        }
        buffer.resize(static_cast<std::size_t>(got));
        obfuscator.EncodeChunkInPlace(buffer);
        Bytes ct = encryptor.Update(buffer);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }

    Bytes final_chunk = encryptor.Final();
    if (!final_chunk.empty()) {
        output.write(reinterpret_cast<const char*>(final_chunk.data()), static_cast<std::streamsize>(final_chunk.size()));
    }
    Bytes tag = encryptor.Tag();
    output.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));

    output.flush();
    if (!output) {
        throw std::runtime_error("Failed to write output file: " + out_path.string());
    }
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    return out_path.string();
}

std::string B512DecodeFileStream(const std::filesystem::path& input,
                                 const std::string& password,
                                 const FileOptions& options,
                                 const basefwx::pb512::KdfOptions& kdf) {
    if (!EnableAead(options)) {
        throw std::runtime_error("Streaming b512 decode requires AEAD mode");
    }
    std::string resolved = basefwx::ResolvePassword(password);
    std::ifstream handle(input, std::ios::binary);
    if (!handle) {
        throw std::runtime_error("Failed to open file: " + input.string());
    }
    auto read_u32 = [&](std::uint32_t& out) {
        std::array<std::uint8_t, 4> buf{};
        handle.read(reinterpret_cast<char*>(buf.data()), buf.size());
        if (handle.gcount() != static_cast<std::streamsize>(buf.size())) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
        out = (static_cast<std::uint32_t>(buf[0]) << 24)
              | (static_cast<std::uint32_t>(buf[1]) << 16)
              | (static_cast<std::uint32_t>(buf[2]) << 8)
              | static_cast<std::uint32_t>(buf[3]);
    };

    std::uint32_t len_user = 0;
    read_u32(len_user);
    Bytes user_blob(len_user);
    if (len_user > 0) {
        handle.read(reinterpret_cast<char*>(user_blob.data()), len_user);
        if (handle.gcount() != static_cast<std::streamsize>(len_user)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    std::uint32_t len_master = 0;
    read_u32(len_master);
    Bytes master_blob(len_master);
    if (len_master > 0) {
        handle.read(reinterpret_cast<char*>(master_blob.data()), len_master);
        if (handle.gcount() != static_cast<std::streamsize>(len_master)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    std::uint32_t len_payload = 0;
    read_u32(len_payload);
    if (len_payload < 4 + constants::kAeadNonceLen + constants::kAeadTagLen) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    std::uint32_t metadata_len = 0;
    read_u32(metadata_len);
    Bytes metadata_bytes(metadata_len);
    if (metadata_len > 0) {
        handle.read(reinterpret_cast<char*>(metadata_bytes.data()), metadata_len);
        if (handle.gcount() != static_cast<std::streamsize>(metadata_len)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    auto meta = basefwx::metadata::Decode(ToString(metadata_bytes));
    Bytes nonce(constants::kAeadNonceLen);
    handle.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
    if (handle.gcount() != static_cast<std::streamsize>(nonce.size())) {
        throw std::runtime_error("Ciphertext payload truncated");
    }

    std::uint64_t cipher_body_len = len_payload - 4 - metadata_len - constants::kAeadNonceLen - constants::kAeadTagLen;
    std::uint64_t cipher_body_start = static_cast<std::uint64_t>(handle.tellg());
    handle.seekg(static_cast<std::streamoff>(cipher_body_len), std::ios::cur);
    Bytes tag(constants::kAeadTagLen);
    handle.read(reinterpret_cast<char*>(tag.data()), tag.size());
    if (handle.gcount() != static_cast<std::streamsize>(tag.size())) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    handle.seekg(static_cast<std::streamoff>(cipher_body_start), std::ios::beg);

    bool use_master_effective = options.use_master && !options.strip_metadata;
    auto meta_preview = basefwx::metadata::Decode(ToString(metadata_bytes));
    if (basefwx::metadata::GetValue(meta_preview, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }
    Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
        user_blob,
        master_blob,
        resolved,
        use_master_effective,
        constants::kB512FileMaskInfo,
        constants::kMaskAadB512File,
        kdf
    );
    Bytes aead_key = basefwx::crypto::HkdfSha256(mask_key, constants::kB512AeadInfo, 32);

    AesGcmDecryptor decryptor(aead_key, nonce, metadata_bytes);
    std::filesystem::path temp_plain = input;
    temp_plain += ".plain.tmp";
    std::ofstream plain_out(temp_plain, std::ios::binary);
    if (!plain_out) {
        throw std::runtime_error("Failed to create temp file");
    }

    std::uint64_t remaining = cipher_body_len;
    Bytes buffer(options.stream_chunk_size);
    while (remaining > 0) {
        std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
        buffer.resize(take);
        handle.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(take));
        if (handle.gcount() != static_cast<std::streamsize>(take)) {
            throw std::runtime_error("Ciphertext truncated");
        }
        Bytes plain = decryptor.Update(buffer);
        if (!plain.empty()) {
            plain_out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
        }
        remaining -= take;
    }
    decryptor.Final(tag);
    plain_out.flush();

    if (resolved.empty()) {
        throw std::runtime_error("Password required for streaming b512 decode");
    }

    std::ifstream plain_in(temp_plain, std::ios::binary);
    if (!plain_in) {
        throw std::runtime_error("Failed to open plaintext temp file");
    }
    if (!metadata_bytes.empty()) {
        Bytes prefix(metadata_bytes.size());
        plain_in.read(reinterpret_cast<char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
        if (plain_in.gcount() != static_cast<std::streamsize>(prefix.size()) || prefix != metadata_bytes) {
            throw std::runtime_error("Metadata integrity mismatch detected");
        }
        Bytes delim(constants::kMetaDelim.begin(), constants::kMetaDelim.end());
        Bytes delim_buf(delim.size());
        plain_in.read(reinterpret_cast<char*>(delim_buf.data()), static_cast<std::streamsize>(delim_buf.size()));
        if (plain_in.gcount() != static_cast<std::streamsize>(delim_buf.size()) || delim_buf != delim) {
            throw std::runtime_error("Malformed streaming payload: missing metadata delimiter");
        }
    }

    Bytes magic(constants::kStreamMagic.begin(), constants::kStreamMagic.end());
    Bytes magic_buf(magic.size());
    plain_in.read(reinterpret_cast<char*>(magic_buf.data()), static_cast<std::streamsize>(magic_buf.size()));
    if (plain_in.gcount() != static_cast<std::streamsize>(magic_buf.size()) || magic_buf != magic) {
        throw std::runtime_error("Malformed streaming payload: magic mismatch");
    }
    std::array<std::uint8_t, 4> chunk_buf{};
    plain_in.read(reinterpret_cast<char*>(chunk_buf.data()), chunk_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(chunk_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing chunk size");
    }
    std::uint32_t chunk_size = (static_cast<std::uint32_t>(chunk_buf[0]) << 24)
                               | (static_cast<std::uint32_t>(chunk_buf[1]) << 16)
                               | (static_cast<std::uint32_t>(chunk_buf[2]) << 8)
                               | static_cast<std::uint32_t>(chunk_buf[3]);
    if (chunk_size == 0 || chunk_size > (16u << 20)) {
        chunk_size = static_cast<std::uint32_t>(options.stream_chunk_size);
    }
    std::array<std::uint8_t, 8> size_buf{};
    plain_in.read(reinterpret_cast<char*>(size_buf.data()), size_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(size_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing original size");
    }
    std::uint64_t original_size = 0;
    for (std::uint8_t b : size_buf) {
        original_size = (original_size << 8) | b;
    }
    Bytes salt(basefwx::obf::StreamObfuscator::kSaltLen);
    plain_in.read(reinterpret_cast<char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
    if (plain_in.gcount() != static_cast<std::streamsize>(salt.size())) {
        throw std::runtime_error("Malformed streaming payload: missing salt");
    }
    std::array<std::uint8_t, 2> ext_len_buf{};
    plain_in.read(reinterpret_cast<char*>(ext_len_buf.data()), ext_len_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(ext_len_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing extension length");
    }
    std::uint16_t ext_len = static_cast<std::uint16_t>((ext_len_buf[0] << 8) | ext_len_buf[1]);
    Bytes ext_bytes(ext_len);
    if (ext_len > 0) {
        plain_in.read(reinterpret_cast<char*>(ext_bytes.data()), static_cast<std::streamsize>(ext_len));
        if (plain_in.gcount() != static_cast<std::streamsize>(ext_len)) {
            throw std::runtime_error("Malformed streaming payload: truncated extension");
        }
    }

    basefwx::obf::StreamObfuscator decoder = basefwx::obf::StreamObfuscator::ForPassword(resolved, salt);
    std::filesystem::path target = input;
    target.replace_extension("");
    std::string ext;
    if (!ext_bytes.empty()) {
        ext = ToString(ext_bytes);
        target.replace_extension(ext);
    }
    auto pack_mode = ResolvePackMode(meta, ext);
    std::ofstream out(target, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file");
    }
    Bytes chunk_buf_bytes(chunk_size);
    std::uint64_t processed = 0;
    while (processed < original_size) {
        std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(chunk_size, original_size - processed));
        chunk_buf_bytes.resize(take);
        plain_in.read(reinterpret_cast<char*>(chunk_buf_bytes.data()), static_cast<std::streamsize>(take));
        if (plain_in.gcount() != static_cast<std::streamsize>(take)) {
            throw std::runtime_error("Streaming payload truncated");
        }
        decoder.DecodeChunkInPlace(chunk_buf_bytes);
        out.write(reinterpret_cast<const char*>(chunk_buf_bytes.data()),
                  static_cast<std::streamsize>(chunk_buf_bytes.size()));
        processed += static_cast<std::uint64_t>(chunk_buf_bytes.size());
    }
    out.flush();
    plain_in.close();
    std::filesystem::remove(temp_plain);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    if (pack_mode != basefwx::archive::PackMode::None) {
        return basefwx::archive::UnpackArchive(target, pack_mode).string();
    }
    return target.string();
}

std::string B512DecodeFileSimple(const std::filesystem::path& input,
                                 const std::string& password,
                                 const FileOptions& options,
                                 const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    Bytes raw = ReadFileBytes(input);
    bool use_master_effective = options.use_master && !options.strip_metadata;
    std::string content;
    bool binary_mode = false;
    std::vector<basefwx::format::Bytes> parts;
    try {
        parts = basefwx::format::UnpackLengthPrefixed(raw, 3);
        binary_mode = true;
    } catch (const std::exception&) {
        binary_mode = false;
    }
    if (binary_mode) {
        Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
            parts[0], parts[1], resolved, use_master_effective,
            constants::kB512FileMaskInfo, constants::kMaskAadB512File, kdf);
        Bytes aead_key = basefwx::crypto::HkdfSha256(mask_key, constants::kB512AeadInfo, 32);
        Bytes payload = basefwx::crypto::AeadDecrypt(
            aead_key, parts[2], Bytes(constants::kB512AeadInfo.begin(), constants::kB512AeadInfo.end()));
        content = ToString(payload);
    } else {
        content = ToString(raw);
    }

    auto [metadata_blob, body] = SplitMetadata(content);
    auto meta = basefwx::metadata::Decode(metadata_blob);
    std::string master_hint = basefwx::metadata::GetValue(meta, "ENC-MASTER");
    if (master_hint == "no") {
        use_master_effective = false;
    }

    auto [header, payload] = SplitWithDelims(body, "FWX container");
    std::string ext = basefwx::pb512::B512Decode(header, resolved, use_master_effective, kdf);
    std::string data_b64 = basefwx::pb512::B512Decode(payload, resolved, use_master_effective, kdf);
    auto pack_mode = ResolvePackMode(meta, ext);

    bool ok = false;
    Bytes decoded = basefwx::base64::Decode(data_b64, &ok);
    if (!ok) {
        throw std::runtime_error("Failed to decode base64 payload");
    }
    std::filesystem::path target = input;
    target.replace_extension("");
    if (!ext.empty()) {
        target.replace_extension(ext);
    }
    WriteFileBytes(target, decoded);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    if (pack_mode != basefwx::archive::PackMode::None) {
        return basefwx::archive::UnpackArchive(target, pack_mode).string();
    }
    return target.string();
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

std::string Pb512EncodeFileSimple(const std::filesystem::path& input,
                                  const std::string& password,
                                  const FileOptions& options,
                                  const basefwx::pb512::KdfOptions& kdf,
                                  std::string_view pack_flag) {
    std::string resolved = basefwx::ResolvePassword(password);
    Bytes data = ReadFileBytes(input);
    std::string b64_payload = basefwx::base64::Encode(data);
    std::string ext = input.extension().string();

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);
    bool obf_enabled = EnableObfuscation(options);

    std::string ext_token = basefwx::pb512::Pb512Encode(ext, resolved, use_master_effective, kdf_opts);
    std::string data_token = basefwx::pb512::Pb512Encode(b64_payload, resolved, use_master_effective, kdf_opts);

    std::optional<std::uint32_t> argon_time;
    std::optional<std::uint32_t> argon_mem;
    std::optional<std::uint32_t> argon_par;
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    argon_time = basefwx::constants::kHeavyArgon2TimeCost;
    argon_mem = basefwx::constants::kHeavyArgon2MemoryCost;
    argon_par = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif

    std::string metadata_blob = basefwx::metadata::Build(
        "AES-HEAVY",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "",
        obf_enabled,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        std::string(pack_flag)
    );

    std::string body = ext_token + std::string(constants::kFwxHeavyDelim) + data_token;
    std::string plaintext = metadata_blob.empty()
        ? body
        : metadata_blob + std::string(constants::kMetaDelim) + body;

    Bytes blob = EncryptAesPayload(
        plaintext,
        resolved,
        use_master_effective,
        metadata_blob,
        kdf_opts,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        obf_enabled
    );

    std::filesystem::path out_path = input;
    out_path.replace_extension(".fwx");
    WriteFileBytes(out_path, blob);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    return out_path.string();
}

std::string Pb512EncodeFileStream(const std::filesystem::path& input,
                                  const std::string& password,
                                  const FileOptions& options,
                                  const basefwx::pb512::KdfOptions& kdf,
                                  std::string_view pack_flag) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password required for AES-heavy streaming mode");
    }
    std::uint64_t input_size = FileSize(input);
    std::size_t chunk_size = options.stream_chunk_size;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);
    bool obf_enabled = EnableObfuscation(options);

    std::optional<std::uint32_t> argon_time;
    std::optional<std::uint32_t> argon_mem;
    std::optional<std::uint32_t> argon_par;
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    argon_time = basefwx::constants::kHeavyArgon2TimeCost;
    argon_mem = basefwx::constants::kHeavyArgon2MemoryCost;
    argon_par = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif

    Bytes stream_salt = basefwx::obf::StreamObfuscator::GenerateSalt();
    std::string ext = input.extension().string();
    Bytes ext_bytes = ToBytes(ext);

    std::string metadata_blob = basefwx::metadata::Build(
        "AES-HEAVY",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "STREAM",
        obf_enabled,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        std::string(pack_flag)
    );
    Bytes metadata_bytes = ToBytes(metadata_blob);
    Bytes prefix_bytes;
    if (!metadata_blob.empty()) {
        prefix_bytes = metadata_bytes;
        std::string delim(constants::kMetaDelim);
        prefix_bytes.insert(prefix_bytes.end(), delim.begin(), delim.end());
    }

    Bytes stream_header;
    stream_header.insert(stream_header.end(), constants::kStreamMagic.begin(), constants::kStreamMagic.end());
    Bytes chunk_bytes = Uint32Be(static_cast<std::uint32_t>(chunk_size));
    stream_header.insert(stream_header.end(), chunk_bytes.begin(), chunk_bytes.end());
    Bytes size_bytes = Uint64Be(input_size);
    stream_header.insert(stream_header.end(), size_bytes.begin(), size_bytes.end());
    stream_header.insert(stream_header.end(), stream_salt.begin(), stream_salt.end());
    Bytes ext_len = Uint16Be(static_cast<std::uint16_t>(ext_bytes.size()));
    stream_header.insert(stream_header.end(), ext_len.begin(), ext_len.end());
    stream_header.insert(stream_header.end(), ext_bytes.begin(), ext_bytes.end());

    std::uint64_t plaintext_len = static_cast<std::uint64_t>(prefix_bytes.size() + stream_header.size() + input_size);

    Bytes master_payload;
    Bytes ephemeral_key;
    if (use_master_effective) {
        if (pq_pub.has_value()) {
            basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(*pq_pub);
            master_payload = kem.ciphertext;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
        } else if (ec_pub.has_value()) {
            basefwx::ec::KemResult kem = basefwx::ec::KemEncrypt(*ec_pub);
            master_payload = kem.blob;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
        } else {
            ephemeral_key = basefwx::crypto::RandomBytes(constants::kEphemeralKeyLen);
        }
    } else {
        ephemeral_key = basefwx::crypto::RandomBytes(constants::kEphemeralKeyLen);
    }

    Bytes user_blob;
    if (!resolved.empty()) {
        basefwx::pb512::KdfOptions kdf_wrap = kdf_opts;
        kdf_wrap.pbkdf2_iterations = basefwx::constants::HeavyPbkdf2Iterations();
        if (argon_time.has_value()) {
            kdf_wrap.argon2_time_cost = argon_time.value();
        }
        if (argon_mem.has_value()) {
            kdf_wrap.argon2_memory_cost = argon_mem.value();
        }
        if (argon_par.has_value()) {
            kdf_wrap.argon2_parallelism = argon_par.value();
        }
        kdf_wrap = HardenKdfOptionsForPassword(resolved, kdf_wrap);
        Bytes salt = basefwx::crypto::RandomBytes(constants::kUserKdfSaltSize);
        Bytes user_key = basefwx::keywrap::DeriveUserKeyWithLabel(resolved, salt, kdf_label, kdf_wrap);
        Bytes wrapped = basefwx::crypto::AeadEncrypt(user_key, ephemeral_key, metadata_bytes);
        user_blob.reserve(salt.size() + wrapped.size());
        user_blob.insert(user_blob.end(), salt.begin(), salt.end());
        user_blob.insert(user_blob.end(), wrapped.begin(), wrapped.end());
    }

    Bytes nonce = basefwx::crypto::RandomBytes(constants::kAeadNonceLen);
    std::uint64_t payload_len = 4 + metadata_bytes.size() + nonce.size() + plaintext_len + constants::kAeadTagLen;

    std::filesystem::path out_path = input;
    out_path.replace_extension(".fwx");
    std::ofstream output(out_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + out_path.string());
    }

    Bytes len_user = Uint32Be(static_cast<std::uint32_t>(user_blob.size()));
    Bytes len_master = Uint32Be(static_cast<std::uint32_t>(master_payload.size()));
    Bytes len_payload = Uint32Be(static_cast<std::uint32_t>(payload_len));
    output.write(reinterpret_cast<const char*>(len_user.data()), len_user.size());
    output.write(reinterpret_cast<const char*>(user_blob.data()), static_cast<std::streamsize>(user_blob.size()));
    output.write(reinterpret_cast<const char*>(len_master.data()), len_master.size());
    output.write(reinterpret_cast<const char*>(master_payload.data()), static_cast<std::streamsize>(master_payload.size()));
    output.write(reinterpret_cast<const char*>(len_payload.data()), len_payload.size());

    Bytes metadata_len = Uint32Be(static_cast<std::uint32_t>(metadata_bytes.size()));
    output.write(reinterpret_cast<const char*>(metadata_len.data()), metadata_len.size());
    if (!metadata_bytes.empty()) {
        output.write(reinterpret_cast<const char*>(metadata_bytes.data()),
                     static_cast<std::streamsize>(metadata_bytes.size()));
    }
    output.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));

    AesGcmEncryptor encryptor(ephemeral_key, nonce, metadata_bytes);
    if (!prefix_bytes.empty()) {
        Bytes ct = encryptor.Update(prefix_bytes);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }
    if (!stream_header.empty()) {
        Bytes ct = encryptor.Update(stream_header);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }

    basefwx::obf::StreamObfuscator obfuscator = basefwx::obf::StreamObfuscator::ForPassword(resolved, stream_salt);
    std::ifstream input_stream(input, std::ios::binary);
    if (!input_stream) {
        throw std::runtime_error("Failed to open input file: " + input.string());
    }
    Bytes buffer(chunk_size);
    while (input_stream) {
        buffer.resize(chunk_size);
        input_stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = input_stream.gcount();
        if (got <= 0) {
            break;
        }
        buffer.resize(static_cast<std::size_t>(got));
        obfuscator.EncodeChunkInPlace(buffer);
        Bytes ct = encryptor.Update(buffer);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }

    Bytes final_chunk = encryptor.Final();
    if (!final_chunk.empty()) {
        output.write(reinterpret_cast<const char*>(final_chunk.data()), static_cast<std::streamsize>(final_chunk.size()));
    }
    Bytes tag = encryptor.Tag();
    output.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));

    output.flush();
    if (!output) {
        throw std::runtime_error("Failed to write output file: " + out_path.string());
    }
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    return out_path.string();
}

std::string Pb512DecodeFileStream(const std::filesystem::path& input,
                                  const std::string& password,
                                  const FileOptions& options,
                                  const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::ifstream handle(input, std::ios::binary);
    if (!handle) {
        throw std::runtime_error("Failed to open file: " + input.string());
    }
    auto read_u32 = [&](std::uint32_t& out) {
        std::array<std::uint8_t, 4> buf{};
        handle.read(reinterpret_cast<char*>(buf.data()), buf.size());
        if (handle.gcount() != static_cast<std::streamsize>(buf.size())) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
        out = (static_cast<std::uint32_t>(buf[0]) << 24)
              | (static_cast<std::uint32_t>(buf[1]) << 16)
              | (static_cast<std::uint32_t>(buf[2]) << 8)
              | static_cast<std::uint32_t>(buf[3]);
    };

    std::uint32_t len_user = 0;
    read_u32(len_user);
    Bytes user_blob(len_user);
    if (len_user > 0) {
        handle.read(reinterpret_cast<char*>(user_blob.data()), len_user);
        if (handle.gcount() != static_cast<std::streamsize>(len_user)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    std::uint32_t len_master = 0;
    read_u32(len_master);
    Bytes master_blob(len_master);
    if (len_master > 0) {
        handle.read(reinterpret_cast<char*>(master_blob.data()), len_master);
        if (handle.gcount() != static_cast<std::streamsize>(len_master)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    std::uint32_t len_payload = 0;
    read_u32(len_payload);
    if (len_payload < 4 + constants::kAeadNonceLen + constants::kAeadTagLen) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    std::uint32_t metadata_len = 0;
    read_u32(metadata_len);
    Bytes metadata_bytes(metadata_len);
    if (metadata_len > 0) {
        handle.read(reinterpret_cast<char*>(metadata_bytes.data()), metadata_len);
        if (handle.gcount() != static_cast<std::streamsize>(metadata_len)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    Bytes nonce(constants::kAeadNonceLen);
    handle.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
    if (handle.gcount() != static_cast<std::streamsize>(nonce.size())) {
        throw std::runtime_error("Ciphertext payload truncated");
    }

    std::uint64_t cipher_body_len = len_payload - 4 - metadata_len - constants::kAeadNonceLen - constants::kAeadTagLen;
    std::uint64_t cipher_body_start = static_cast<std::uint64_t>(handle.tellg());
    handle.seekg(static_cast<std::streamoff>(cipher_body_len), std::ios::cur);
    Bytes tag(constants::kAeadTagLen);
    handle.read(reinterpret_cast<char*>(tag.data()), tag.size());
    if (handle.gcount() != static_cast<std::streamsize>(tag.size())) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    handle.seekg(static_cast<std::streamoff>(cipher_body_start), std::ios::beg);

    bool use_master_effective = options.use_master && !options.strip_metadata;
    std::string metadata_blob = ToString(metadata_bytes);
    auto meta = basefwx::metadata::Decode(metadata_blob);
    if (basefwx::metadata::GetValue(meta, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }

    std::string kdf_label = basefwx::metadata::GetValue(meta, "ENC-KDF");
    kdf_label = basefwx::keywrap::ResolveKdfLabel(kdf_label.empty() ? kdf.label : kdf_label);
    auto kdf_iter = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-KDF-ITER"));
    auto argon2_time = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-TC"));
    auto argon2_mem = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-MEM"));
    auto argon2_par = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-PAR"));

    Bytes ephemeral_key;
    if (!master_blob.empty()) {
        if (!use_master_effective) {
            throw std::runtime_error("Master key required to decrypt this payload");
        }
        if (basefwx::ec::IsEcMasterBlob(master_blob)) {
            Bytes private_key = basefwx::ec::LoadMasterPrivateKey();
            Bytes shared = basefwx::ec::KemDecrypt(private_key, master_blob);
            ephemeral_key = basefwx::crypto::HkdfSha256(shared, constants::kKemInfo, 32);
        } else {
            Bytes private_key = basefwx::pq::LoadMasterPrivateKey();
            Bytes shared = basefwx::pq::KemDecrypt(private_key, master_blob);
            ephemeral_key = basefwx::crypto::HkdfSha256(shared, constants::kKemInfo, 32);
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
    } else {
        throw std::runtime_error("Ciphertext missing key transport data");
    }

    AesGcmDecryptor decryptor(ephemeral_key, nonce, metadata_bytes);
    std::filesystem::path temp_plain = input;
    temp_plain += ".plain.tmp";
    std::ofstream plain_out(temp_plain, std::ios::binary);
    if (!plain_out) {
        throw std::runtime_error("Failed to create temp file");
    }

    std::uint64_t remaining = cipher_body_len;
    Bytes buffer(options.stream_chunk_size);
    while (remaining > 0) {
        std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
        buffer.resize(take);
        handle.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(take));
        if (handle.gcount() != static_cast<std::streamsize>(take)) {
            throw std::runtime_error("Ciphertext truncated");
        }
        Bytes plain = decryptor.Update(buffer);
        if (!plain.empty()) {
            plain_out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
        }
        remaining -= take;
    }
    decryptor.Final(tag);
    plain_out.flush();

    if (resolved.empty()) {
        throw std::runtime_error("Password required for AES-heavy streaming decode");
    }

    std::ifstream plain_in(temp_plain, std::ios::binary);
    if (!plain_in) {
        throw std::runtime_error("Failed to open plaintext temp file");
    }
    if (!metadata_bytes.empty()) {
        Bytes prefix(metadata_bytes.size());
        plain_in.read(reinterpret_cast<char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
        if (plain_in.gcount() != static_cast<std::streamsize>(prefix.size()) || prefix != metadata_bytes) {
            throw std::runtime_error("Metadata integrity mismatch detected");
        }
        Bytes delim(constants::kMetaDelim.begin(), constants::kMetaDelim.end());
        Bytes delim_buf(delim.size());
        plain_in.read(reinterpret_cast<char*>(delim_buf.data()), static_cast<std::streamsize>(delim_buf.size()));
        if (plain_in.gcount() != static_cast<std::streamsize>(delim_buf.size()) || delim_buf != delim) {
            throw std::runtime_error("Malformed streaming payload: missing metadata delimiter");
        }
    }

    Bytes magic(constants::kStreamMagic.begin(), constants::kStreamMagic.end());
    Bytes magic_buf(magic.size());
    plain_in.read(reinterpret_cast<char*>(magic_buf.data()), static_cast<std::streamsize>(magic_buf.size()));
    if (plain_in.gcount() != static_cast<std::streamsize>(magic_buf.size()) || magic_buf != magic) {
        throw std::runtime_error("Malformed streaming payload: magic mismatch");
    }
    std::array<std::uint8_t, 4> chunk_buf{};
    plain_in.read(reinterpret_cast<char*>(chunk_buf.data()), chunk_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(chunk_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing chunk size");
    }
    std::uint32_t chunk_size = (static_cast<std::uint32_t>(chunk_buf[0]) << 24)
                               | (static_cast<std::uint32_t>(chunk_buf[1]) << 16)
                               | (static_cast<std::uint32_t>(chunk_buf[2]) << 8)
                               | static_cast<std::uint32_t>(chunk_buf[3]);
    if (chunk_size == 0 || chunk_size > (16u << 20)) {
        chunk_size = static_cast<std::uint32_t>(options.stream_chunk_size);
    }
    std::array<std::uint8_t, 8> size_buf{};
    plain_in.read(reinterpret_cast<char*>(size_buf.data()), size_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(size_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing original size");
    }
    std::uint64_t original_size = 0;
    for (std::uint8_t b : size_buf) {
        original_size = (original_size << 8) | b;
    }
    Bytes salt(basefwx::obf::StreamObfuscator::kSaltLen);
    plain_in.read(reinterpret_cast<char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
    if (plain_in.gcount() != static_cast<std::streamsize>(salt.size())) {
        throw std::runtime_error("Malformed streaming payload: missing salt");
    }
    std::array<std::uint8_t, 2> ext_len_buf{};
    plain_in.read(reinterpret_cast<char*>(ext_len_buf.data()), ext_len_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(ext_len_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing extension length");
    }
    std::uint16_t ext_len = static_cast<std::uint16_t>((ext_len_buf[0] << 8) | ext_len_buf[1]);
    Bytes ext_bytes(ext_len);
    if (ext_len > 0) {
        plain_in.read(reinterpret_cast<char*>(ext_bytes.data()), static_cast<std::streamsize>(ext_len));
        if (plain_in.gcount() != static_cast<std::streamsize>(ext_len)) {
            throw std::runtime_error("Malformed streaming payload: truncated extension");
        }
    }

    basefwx::obf::StreamObfuscator decoder = basefwx::obf::StreamObfuscator::ForPassword(resolved, salt);
    std::filesystem::path target = input;
    target.replace_extension("");
    std::string ext;
    if (!ext_bytes.empty()) {
        ext = ToString(ext_bytes);
        target.replace_extension(ext);
    }
    auto pack_mode = ResolvePackMode(meta, ext);
    std::ofstream out(target, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file");
    }
    Bytes chunk_buf_bytes(chunk_size);
    std::uint64_t processed = 0;
    while (processed < original_size) {
        std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(chunk_size, original_size - processed));
        chunk_buf_bytes.resize(take);
        plain_in.read(reinterpret_cast<char*>(chunk_buf_bytes.data()), static_cast<std::streamsize>(take));
        if (plain_in.gcount() != static_cast<std::streamsize>(take)) {
            throw std::runtime_error("Streaming payload truncated");
        }
        decoder.DecodeChunkInPlace(chunk_buf_bytes);
        out.write(reinterpret_cast<const char*>(chunk_buf_bytes.data()),
                  static_cast<std::streamsize>(chunk_buf_bytes.size()));
        processed += static_cast<std::uint64_t>(chunk_buf_bytes.size());
    }
    out.flush();
    plain_in.close();
    std::filesystem::remove(temp_plain);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    if (pack_mode != basefwx::archive::PackMode::None) {
        return basefwx::archive::UnpackArchive(target, pack_mode).string();
    }
    return target.string();
}

}  // namespace

std::string B512EncodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf) {
    std::filesystem::path input(path);
    if (!std::filesystem::exists(input)) {
        throw std::runtime_error("Input file not found: " + input.string());
    }
    auto pack = basefwx::archive::PackInput(input, options.compress);
    std::filesystem::path source = pack.used ? pack.source : input;
    std::string pack_flag = basefwx::archive::PackFlag(pack.mode);
    std::string output;
    try {
        std::uint64_t size = FileSize(source);
        std::uint64_t b64_len = ((size + 2u) / 3u) * 4u;
        bool force_stream = b64_len > basefwx::constants::kHkdfMaxLen;
        if (EnableAead(options) && (size >= options.stream_threshold || force_stream)) {
            output = B512EncodeFileStream(source, password, options, kdf, pack_flag);
        } else if (force_stream) {
            throw std::runtime_error("b512file payload too large for non-AEAD mode; enable AEAD or use streaming");
        } else {
            output = B512EncodeFileSimple(source, password, options, kdf, pack_flag);
        }
        if (pack.used) {
            std::filesystem::path final_out = input;
            final_out.replace_extension(".fwx");
            std::error_code ec;
            std::filesystem::remove(final_out, ec);
            std::filesystem::rename(output, final_out, ec);
            if (ec) {
                throw std::runtime_error("Failed to move output file: " + ec.message());
            }
            output = final_out.string();
            if (!options.keep_input) {
                if (std::filesystem::is_directory(input)) {
                    std::filesystem::remove_all(input, ec);
                } else {
                    std::filesystem::remove(input, ec);
                }
            }
        }
    } catch (...) {
        basefwx::archive::CleanupPack(pack);
        throw;
    }
    basefwx::archive::CleanupPack(pack);
    return output;
}

std::string B512DecodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf) {
    std::filesystem::path input(path);
    if (!std::filesystem::exists(input)) {
        throw std::runtime_error("Input file not found: " + input.string());
    }
    auto meta_preview = PeekMetadataBlob(input);
    if (meta_preview.has_value()) {
        auto meta = basefwx::metadata::Decode(meta_preview.value());
        std::string mode = basefwx::metadata::GetValue(meta, "ENC-MODE");
        if (!mode.empty() && mode == "STREAM") {
            return B512DecodeFileStream(input, password, options, kdf);
        }
    }
    return B512DecodeFileSimple(input, password, options, kdf);
}

std::vector<std::uint8_t> B512EncodeBytes(const std::vector<std::uint8_t>& data,
                                          const std::string& extension,
                                          const std::string& password,
                                          const FileOptions& options,
                                          const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::uint64_t b64_len = ((data.size() + 2u) / 3u) * 4u;
    if (b64_len > basefwx::constants::kHkdfMaxLen) {
        throw std::runtime_error("b512file bytes payload too large; use file-based streaming APIs");
    }
    std::string b64_payload = basefwx::base64::Encode(data);
    std::string ext = extension;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);

    std::string ext_token = basefwx::pb512::B512Encode(ext, resolved, use_master_effective, kdf_opts);
    std::string data_token = basefwx::pb512::B512Encode(b64_payload, resolved, use_master_effective, kdf_opts);

    bool use_aead = EnableAead(options);
    std::string metadata_blob = basefwx::metadata::Build(
        "FWX512R",
        options.strip_metadata,
        use_master_effective,
        use_aead ? "AESGCM" : "NONE",
        kdf_label,
        {},
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::string()
    );

    std::string body = ext_token + std::string(constants::kFwxDelim) + data_token;
    std::string payload = metadata_blob.empty()
        ? body
        : metadata_blob + std::string(constants::kMetaDelim) + body;
    Bytes payload_bytes = ToBytes(payload);

    if (!use_aead) {
        return payload_bytes;
    }
    auto mask = basefwx::keywrap::PrepareMaskKey(
        resolved,
        use_master_effective,
        constants::kB512FileMaskInfo,
        !use_master_effective,
        constants::kMaskAadB512File,
        kdf_opts
    );
    Bytes aead_key = basefwx::crypto::HkdfSha256(mask.mask_key, constants::kB512AeadInfo, 32);
    Bytes ct = basefwx::crypto::AeadEncrypt(
        aead_key, payload_bytes,
        Bytes(constants::kB512AeadInfo.begin(), constants::kB512AeadInfo.end()));
    std::vector<basefwx::format::Bytes> parts = {mask.user_blob, mask.master_blob, ct};
    return basefwx::format::PackLengthPrefixed(parts);
}

DecodedBytes B512DecodeBytes(const std::vector<std::uint8_t>& blob,
                             const std::string& password,
                             const FileOptions& options,
                             const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    bool use_master_effective = options.use_master && !options.strip_metadata;
    std::string content;
    bool binary_mode = false;
    std::vector<basefwx::format::Bytes> parts;
    try {
        parts = basefwx::format::UnpackLengthPrefixed(blob, 3);
        binary_mode = true;
    } catch (const std::exception&) {
        binary_mode = false;
    }
    if (binary_mode) {
        Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
            parts[0], parts[1], resolved, use_master_effective,
            constants::kB512FileMaskInfo, constants::kMaskAadB512File, kdf);
        Bytes aead_key = basefwx::crypto::HkdfSha256(mask_key, constants::kB512AeadInfo, 32);
        Bytes payload = basefwx::crypto::AeadDecrypt(
            aead_key, parts[2],
            Bytes(constants::kB512AeadInfo.begin(), constants::kB512AeadInfo.end()));
        content = ToString(payload);
    } else {
        content = ToString(blob);
    }

    auto [metadata_blob, body] = SplitMetadata(content);
    auto meta = basefwx::metadata::Decode(metadata_blob);
    std::string master_hint = basefwx::metadata::GetValue(meta, "ENC-MASTER");
    if (master_hint == "no") {
        use_master_effective = false;
    }

    auto [header, payload] = SplitWithDelims(body, "FWX container");
    std::string ext = basefwx::pb512::B512Decode(header, resolved, use_master_effective, kdf);
    std::string data_b64 = basefwx::pb512::B512Decode(payload, resolved, use_master_effective, kdf);
    bool ok = false;
    Bytes decoded = basefwx::base64::Decode(data_b64, &ok);
    if (!ok) {
        throw std::runtime_error("Failed to decode base64 payload");
    }
    return DecodedBytes{decoded, ext};
}

std::vector<std::uint8_t> Pb512EncodeBytes(const std::vector<std::uint8_t>& data,
                                           const std::string& extension,
                                           const std::string& password,
                                           const FileOptions& options,
                                           const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::uint64_t b64_len = ((data.size() + 2u) / 3u) * 4u;
    if (b64_len > basefwx::constants::kHkdfMaxLen) {
        throw std::runtime_error("pb512file bytes payload too large; use file-based streaming APIs");
    }
    std::string b64_payload = basefwx::base64::Encode(data);
    std::string ext = extension;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);
    bool obf_enabled = EnableObfuscation(options);

    std::string ext_token = basefwx::pb512::Pb512Encode(ext, resolved, use_master_effective, kdf_opts);
    std::string data_token = basefwx::pb512::Pb512Encode(b64_payload, resolved, use_master_effective, kdf_opts);

    std::optional<std::uint32_t> argon_time;
    std::optional<std::uint32_t> argon_mem;
    std::optional<std::uint32_t> argon_par;
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    argon_time = basefwx::constants::kHeavyArgon2TimeCost;
    argon_mem = basefwx::constants::kHeavyArgon2MemoryCost;
    argon_par = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif

    std::string metadata_blob = basefwx::metadata::Build(
        "AES-HEAVY",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "",
        obf_enabled,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        std::string()
    );

    std::string body = ext_token + std::string(constants::kFwxHeavyDelim) + data_token;
    std::string plaintext = metadata_blob.empty()
        ? body
        : metadata_blob + std::string(constants::kMetaDelim) + body;

    Bytes blob = EncryptAesPayload(
        plaintext,
        resolved,
        use_master_effective,
        metadata_blob,
        kdf_opts,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        obf_enabled
    );
    return blob;
}

DecodedBytes Pb512DecodeBytes(const std::vector<std::uint8_t>& blob,
                              const std::string& password,
                              const FileOptions& options,
                              const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    bool use_master_effective = options.use_master && !options.strip_metadata;
    bool obf_enabled = EnableObfuscation(options);
    std::string metadata_blob;
    std::string plaintext = DecryptAesPayload(blob, resolved, use_master_effective, kdf, obf_enabled, &metadata_blob);

    auto [meta_blob, payload] = SplitMetadata(plaintext);
    auto meta = basefwx::metadata::Decode(meta_blob);
    if (basefwx::metadata::GetValue(meta, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }
    auto split = SplitWithHeavyDelims(payload, "FWX heavy");
    std::string ext = basefwx::pb512::Pb512Decode(split.first, resolved, use_master_effective, kdf);
    std::string data_b64 = basefwx::pb512::Pb512Decode(split.second, resolved, use_master_effective, kdf);

    bool ok = false;
    Bytes decoded = basefwx::base64::Decode(data_b64, &ok);
    if (!ok) {
        throw std::runtime_error("Failed to decode base64 payload");
    }
    return DecodedBytes{decoded, ext};
}

std::string Pb512EncodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf) {
    std::filesystem::path input(path);
    if (!std::filesystem::exists(input)) {
        throw std::runtime_error("Input file not found: " + input.string());
    }
    auto pack = basefwx::archive::PackInput(input, options.compress);
    std::filesystem::path source = pack.used ? pack.source : input;
    std::string pack_flag = basefwx::archive::PackFlag(pack.mode);
    std::string output;
    try {
        std::uint64_t size = FileSize(source);
        std::uint64_t b64_len = ((size + 2u) / 3u) * 4u;
        bool force_stream = b64_len > basefwx::constants::kHkdfMaxLen;
        if (size >= options.stream_threshold || force_stream) {
            output = Pb512EncodeFileStream(source, password, options, kdf, pack_flag);
        } else {
            output = Pb512EncodeFileSimple(source, password, options, kdf, pack_flag);
        }
        if (pack.used) {
            std::filesystem::path final_out = input;
            final_out.replace_extension(".fwx");
            std::error_code ec;
            std::filesystem::remove(final_out, ec);
            std::filesystem::rename(output, final_out, ec);
            if (ec) {
                throw std::runtime_error("Failed to move output file: " + ec.message());
            }
            output = final_out.string();
            if (!options.keep_input) {
                if (std::filesystem::is_directory(input)) {
                    std::filesystem::remove_all(input, ec);
                } else {
                    std::filesystem::remove(input, ec);
                }
            }
        }
    } catch (...) {
        basefwx::archive::CleanupPack(pack);
        throw;
    }
    basefwx::archive::CleanupPack(pack);
    return output;
}

std::string Pb512DecodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::filesystem::path input(path);
    if (!std::filesystem::exists(input)) {
        throw std::runtime_error("Input file not found: " + input.string());
    }
    auto meta_preview = PeekMetadataBlob(input);
    if (meta_preview.has_value()) {
        auto meta = basefwx::metadata::Decode(meta_preview.value());
        std::string mode = basefwx::metadata::GetValue(meta, "ENC-MODE");
        if (!mode.empty() && mode == "STREAM") {
            return Pb512DecodeFileStream(input, password, options, kdf);
        }
    }

    Bytes blob = ReadFileBytes(input);
    bool use_master_effective = options.use_master && !options.strip_metadata;
    std::string metadata_blob;
    bool obf_enabled = EnableObfuscation(options);
    std::string plaintext = DecryptAesPayload(blob, resolved, use_master_effective, kdf, obf_enabled, &metadata_blob);

    auto [meta_blob, payload] = SplitMetadata(plaintext);
    auto meta = basefwx::metadata::Decode(meta_blob);
    if (basefwx::metadata::GetValue(meta, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }
    auto split = SplitWithHeavyDelims(payload, "FWX heavy");
    std::string ext = basefwx::pb512::Pb512Decode(split.first, resolved, use_master_effective, kdf);
    std::string data_b64 = basefwx::pb512::Pb512Decode(split.second, resolved, use_master_effective, kdf);
    auto pack_mode = ResolvePackMode(meta, ext);

    bool ok = false;
    Bytes decoded = basefwx::base64::Decode(data_b64, &ok);
    if (!ok) {
        throw std::runtime_error("Failed to decode base64 payload");
    }
    std::filesystem::path target = input;
    target.replace_extension("");
    if (!ext.empty()) {
        target.replace_extension(ext);
    }
    WriteFileBytes(target, decoded);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    if (pack_mode != basefwx::archive::PackMode::None) {
        return basefwx::archive::UnpackArchive(target, pack_mode).string();
    }
    return target.string();
}


}  // namespace basefwx::filecodec
