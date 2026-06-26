/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include "basefwx/archive.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto_utils.hpp"
#include "basefwx/filecodec.hpp"
#include "basefwx/metadata.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/evp.h>

namespace basefwx::filecodec::internal {

using Bytes = std::vector<std::uint8_t>;

struct PayloadKeys {
    Bytes aead;
    Bytes obf;
};

struct StreamCipherLayout {
    std::uint64_t body_start = 0;
    std::uint64_t body_len = 0;
};

class TempFileCleanup {
public:
    explicit TempFileCleanup(std::filesystem::path path)
        : path_(std::move(path)) {}

    TempFileCleanup(const TempFileCleanup&) = delete;
    TempFileCleanup& operator=(const TempFileCleanup&) = delete;

    ~TempFileCleanup() {
        if (!active_) {
            return;
        }
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    void Dismiss() noexcept {
        active_ = false;
    }

private:
    std::filesystem::path path_;
    bool active_ = true;
};

class AesGcmEncryptor {
public:
    AesGcmEncryptor(const Bytes& key, const Bytes& nonce, const Bytes& aad) {
        if (key.size() != 32) {
            throw std::runtime_error("AES-GCM expects 32-byte key");
        }
        ctx_ = basefwx::crypto::detail::UniqueCipherCtx(EVP_CIPHER_CTX_new());
        if (!ctx_) {
            throw std::runtime_error("AES-GCM context allocation failed");
        }
        if (EVP_EncryptInit_ex(ctx_.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("AES-GCM init failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
            throw std::runtime_error("AES-GCM set iv length failed");
        }
        if (EVP_EncryptInit_ex(ctx_.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
            throw std::runtime_error("AES-GCM set key failed");
        }
        if (!aad.empty()) {
            int out_len = 0;
            if (EVP_EncryptUpdate(ctx_.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
                throw std::runtime_error("AES-GCM aad failed");
            }
        }
    }

    // Disable copy
    AesGcmEncryptor(const AesGcmEncryptor&) = delete;
    AesGcmEncryptor& operator=(const AesGcmEncryptor&) = delete;

    Bytes Update(const Bytes& input) {
        if (input.empty()) {
            return {};
        }
        Bytes out(input.size());
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx_.get(), out.data(), &out_len, input.data(), static_cast<int>(input.size())) != 1) {
            throw std::runtime_error("AES-GCM encrypt failed");
        }
        out.resize(static_cast<std::size_t>(out_len));
        return out;
    }

    Bytes Final() {
        std::array<std::uint8_t, 16> out{};
        int out_len = 0;
        if (EVP_EncryptFinal_ex(ctx_.get(), out.data(), &out_len) != 1) {
            throw std::runtime_error("AES-GCM final failed");
        }
        return Bytes(out.data(), out.data() + out_len);
    }

    Bytes Tag() {
        std::array<std::uint8_t, constants::kAeadTagLen> tag{};
        if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
            throw std::runtime_error("AES-GCM get tag failed");
        }
        return Bytes(tag.data(), tag.data() + tag.size());
    }

private:
    basefwx::crypto::detail::UniqueCipherCtx ctx_;
};

class AesGcmDecryptor {
public:
    AesGcmDecryptor(const Bytes& key, const Bytes& nonce, const Bytes& aad) {
        if (key.size() != 32) {
            throw std::runtime_error("AES-GCM expects 32-byte key");
        }
        ctx_ = basefwx::crypto::detail::UniqueCipherCtx(EVP_CIPHER_CTX_new());
        if (!ctx_) {
            throw std::runtime_error("AES-GCM context allocation failed");
        }
        if (EVP_DecryptInit_ex(ctx_.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("AES-GCM init failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
            throw std::runtime_error("AES-GCM set iv length failed");
        }
        if (EVP_DecryptInit_ex(ctx_.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
            throw std::runtime_error("AES-GCM set key failed");
        }
        if (!aad.empty()) {
            int out_len = 0;
            if (EVP_DecryptUpdate(ctx_.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
                throw std::runtime_error("AES-GCM aad failed");
            }
        }
    }

    // Disable copy
    AesGcmDecryptor(const AesGcmDecryptor&) = delete;
    AesGcmDecryptor& operator=(const AesGcmDecryptor&) = delete;

    Bytes Update(const Bytes& input) {
        if (input.empty()) {
            return {};
        }
        Bytes out(input.size());
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx_.get(), out.data(), &out_len, input.data(), static_cast<int>(input.size())) != 1) {
            throw std::runtime_error("AES-GCM decrypt failed");
        }
        out.resize(static_cast<std::size_t>(out_len));
        return out;
    }

    void Final(const Bytes& tag) {
        if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                const_cast<std::uint8_t*>(tag.data())) != 1) {
            throw std::runtime_error("AES-GCM set tag failed");
        }
        std::array<std::uint8_t, 16> buffer{};
        int out_len = 0;
        if (EVP_DecryptFinal_ex(ctx_.get(), buffer.data(), &out_len) != 1) {
            throw std::runtime_error("AES-GCM auth failed");
        }
    }

private:
    basefwx::crypto::detail::UniqueCipherCtx ctx_;
};

basefwx::pb512::KdfOptions HardenKdfOptionsForPassword(const std::string& password,
                                                       const basefwx::pb512::KdfOptions& kdf);

bool StrictPqOnly();

std::optional<Bytes> TryLoadEcPublic(bool create_if_missing);

PayloadKeys DerivePayloadKeys(const Bytes& root_key);

Bytes ReadFileBytes(const std::filesystem::path& path);

void WriteFileBytes(const std::filesystem::path& path, const Bytes& data);

std::uint64_t FileSize(const std::filesystem::path& path);

Bytes ToBytes(const std::string& text);

std::string ToString(const Bytes& data);

std::string ResolveKdfLabel(const basefwx::pb512::KdfOptions& kdf);

std::optional<std::uint32_t> ParseUint32(const std::string& value);

std::pair<std::string, std::string> SplitMetadata(const std::string& payload);

std::pair<std::string, std::string> SplitWithDelims(const std::string& payload,
                                                    std::string_view label);

std::pair<std::string, std::string> SplitWithHeavyDelims(const std::string& payload,
                                                         std::string_view label);

basefwx::archive::PackMode ResolvePackMode(const basefwx::metadata::MetadataMap& meta,
                                           const std::string& ext);

Bytes Uint32Be(std::uint32_t value);

Bytes Uint64Be(std::uint64_t value);

Bytes Uint16Be(std::uint16_t value);

void ThrowIfInterrupted();

std::uint64_t TellPosOrThrow(std::istream& stream);

StreamCipherLayout ResolveStreamCipherLayout(const std::filesystem::path& input,
                                             std::istream& stream,
                                             std::uint32_t encoded_payload_len,
                                             std::uint32_t metadata_len);

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
                        bool fast_obf);

std::string DecryptAesPayload(const Bytes& blob,
                              const std::string& password,
                              bool use_master,
                              const basefwx::pb512::KdfOptions& kdf,
                              bool obfuscate,
                              std::string* metadata_out);

bool EnableAead(const FileOptions& options);

bool EnableObfuscation(const FileOptions& options);

bool PerfModeEnabled();

bool UseFastObfuscation(std::uint64_t length);

std::string ObfMode(bool obfuscate, bool fast);

std::optional<std::string> PeekMetadataBlob(const std::filesystem::path& input);

std::string B512EncodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf);

std::string B512DecodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf);

std::vector<std::uint8_t> B512EncodeBytes(const std::vector<std::uint8_t>& data,
                                          const std::string& extension,
                                          const std::string& password,
                                          const FileOptions& options,
                                          const basefwx::pb512::KdfOptions& kdf);

DecodedBytes B512DecodeBytes(const std::vector<std::uint8_t>& blob,
                             const std::string& password,
                             const FileOptions& options,
                             const basefwx::pb512::KdfOptions& kdf);

std::vector<std::uint8_t> Pb512EncodeBytes(const std::vector<std::uint8_t>& data,
                                           const std::string& extension,
                                           const std::string& password,
                                           const FileOptions& options,
                                           const basefwx::pb512::KdfOptions& kdf);

DecodedBytes Pb512DecodeBytes(const std::vector<std::uint8_t>& blob,
                              const std::string& password,
                              const FileOptions& options,
                              const basefwx::pb512::KdfOptions& kdf);

std::string Pb512EncodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf);

std::string Pb512DecodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf);

}  // namespace basefwx::filecodec::internal
