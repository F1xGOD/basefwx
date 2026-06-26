/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "imagecipher_internal.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/system_info.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <new>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <chrono>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include <openssl/evp.h>

#if defined(_WIN32)
#include <windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif
#else
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace basefwx::imagecipher::internal {

void AppendBalancedTrailer(const std::filesystem::path& path,
                          std::string_view magic,
                          const Bytes& blob) {
    if (blob.empty()) {
        return;
    }
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) {
        throw std::runtime_error("Failed to append trailer: " + path.string());
    }
    out.write(magic.data(), static_cast<std::streamsize>(magic.size()));
    std::array<std::uint8_t, 4> len_bytes{};
    std::uint32_t len = static_cast<std::uint32_t>(blob.size());
    len_bytes[0] = static_cast<std::uint8_t>((len >> 24) & 0xFF);
    len_bytes[1] = static_cast<std::uint8_t>((len >> 16) & 0xFF);
    len_bytes[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    len_bytes[3] = static_cast<std::uint8_t>(len & 0xFF);
    out.write(reinterpret_cast<const char*>(len_bytes.data()),
              static_cast<std::streamsize>(len_bytes.size()));
    if (!blob.empty()) {
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }
    out.write(magic.data(), static_cast<std::streamsize>(magic.size()));
    out.write(reinterpret_cast<const char*>(len_bytes.data()),
              static_cast<std::streamsize>(len_bytes.size()));
    if (!out) {
        throw std::runtime_error("Failed to append trailer: " + path.string());
    }
}

void AppendTrailerStream(const std::filesystem::path& output_path,
                         const std::filesystem::path& original_path,
                         const std::string& password,
                         const std::function<void(double)>& progress_cb = {},
                         const Bytes& archive_key_override = Bytes{},
                         const Bytes& key_header = Bytes{},
                         std::string_view archive_info = basefwx::constants::kImageCipherArchiveInfo) {
    auto magic = basefwx::constants::kImageCipherTrailerMagic;
    std::error_code ec;
    auto size = std::filesystem::file_size(original_path, ec);
    if (ec) {
        throw std::runtime_error("Failed to stat input for trailer");
    }
    std::uint64_t blob_len = static_cast<std::uint64_t>(key_header.size())
                             + basefwx::constants::kAeadNonceLen
                             + size
                             + basefwx::constants::kAeadTagLen;
    if (blob_len > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("Trailer too large");
    }
    std::uint32_t len = static_cast<std::uint32_t>(blob_len);
    std::array<std::uint8_t, 4> len_bytes{};
    len_bytes[0] = static_cast<std::uint8_t>((len >> 24) & 0xFF);
    len_bytes[1] = static_cast<std::uint8_t>((len >> 16) & 0xFF);
    len_bytes[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    len_bytes[3] = static_cast<std::uint8_t>(len & 0xFF);

    Bytes archive_key = archive_key_override;
    if (archive_key.empty()) {
        Bytes material = DeriveMaterial(password);
        archive_key = basefwx::crypto::HkdfSha256(material, archive_info, 32);
    }
    Bytes aad(archive_info.begin(), archive_info.end());
    Bytes nonce = basefwx::crypto::RandomBytes(basefwx::constants::kAeadNonceLen);

    std::ifstream input(original_path, std::ios::binary);
    std::ofstream out(output_path, std::ios::binary | std::ios::app);
    if (!input || !out) {
        throw std::runtime_error("Failed to open trailer streams");
    }
    out.write(magic.data(), static_cast<std::streamsize>(magic.size()));
    out.write(reinterpret_cast<const char*>(len_bytes.data()),
              static_cast<std::streamsize>(len_bytes.size()));
    if (!key_header.empty()) {
        out.write(reinterpret_cast<const char*>(key_header.data()),
                  static_cast<std::streamsize>(key_header.size()));
    }
    out.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-GCM context allocation failed");
    }
    std::vector<std::uint8_t> buffer(1024 * 1024);
    std::vector<std::uint8_t> outbuf(buffer.size() + 16);
    int out_len = 0;

    try {
        Ensure(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
               "AES-GCM init failed");
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                   static_cast<int>(nonce.size()), nullptr) == 1,
               "AES-GCM ivlen failed");
        Ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, archive_key.data(), nonce.data()) == 1,
               "AES-GCM key init failed");
        if (!aad.empty()) {
            Ensure(EVP_EncryptUpdate(ctx, nullptr, &out_len,
                                     aad.data(), static_cast<int>(aad.size())) == 1,
                   "AES-GCM aad failed");
        }
    std::uint64_t processed = 0;
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = input.gcount();
        if (got <= 0) {
            break;
        }
        Ensure(EVP_EncryptUpdate(ctx, outbuf.data(), &out_len,
                                 buffer.data(), static_cast<int>(got)) == 1,
               "AES-GCM update failed");
        if (out_len > 0) {
            out.write(reinterpret_cast<const char*>(outbuf.data()), out_len);
        }
        processed += static_cast<std::uint64_t>(got);
        if (progress_cb && size > 0) {
            double frac = static_cast<double>(processed) / static_cast<double>(size);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
    }
        Ensure(EVP_EncryptFinal_ex(ctx, outbuf.data(), &out_len) == 1,
               "AES-GCM final failed");
        if (out_len > 0) {
            out.write(reinterpret_cast<const char*>(outbuf.data()), out_len);
        }
        std::array<std::uint8_t, basefwx::constants::kAeadTagLen> tag{};
        Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                   static_cast<int>(tag.size()), tag.data()) == 1,
               "AES-GCM tag failed");
        out.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
        out.write(magic.data(), static_cast<std::streamsize>(magic.size()));
        out.write(reinterpret_cast<const char*>(len_bytes.data()),
                  static_cast<std::streamsize>(len_bytes.size()));
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
}

bool TryDecryptTrailerStream(const std::filesystem::path& input_path,
                             const std::string& password,
                             const std::filesystem::path& output_path,
                             bool use_master,
                             const std::function<void(double)>& progress_cb = {}) {
    auto magic = basefwx::constants::kImageCipherTrailerMagic;
    const std::size_t footer_len = magic.size() + 4;
    std::error_code ec;
    auto size = std::filesystem::file_size(input_path, ec);
    if (ec || size < footer_len) {
        return false;
    }
    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        return false;
    }
    bool header_seen = false;
    try {
        input.seekg(static_cast<std::streamoff>(size - footer_len), std::ios::beg);
        std::vector<std::uint8_t> footer(footer_len);
        input.read(reinterpret_cast<char*>(footer.data()), static_cast<std::streamsize>(footer.size()));
        if (input.gcount() != static_cast<std::streamsize>(footer.size())) {
            return false;
        }
        if (std::memcmp(footer.data(), magic.data(), magic.size()) != 0) {
            return false;
        }
        std::uint32_t blob_len = (static_cast<std::uint32_t>(footer[magic.size()]) << 24)
                                 | (static_cast<std::uint32_t>(footer[magic.size() + 1]) << 16)
                                 | (static_cast<std::uint32_t>(footer[magic.size() + 2]) << 8)
                                 | static_cast<std::uint32_t>(footer[magic.size() + 3]);
        if (blob_len == 0) {
            return false;
        }
        std::uint64_t trailer_start = size - footer_len - blob_len - footer_len;
        if (static_cast<std::int64_t>(trailer_start) < 0) {
            return false;
        }
        input.seekg(static_cast<std::streamoff>(trailer_start), std::ios::beg);
        std::vector<std::uint8_t> header(footer_len);
        input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
        if (input.gcount() != static_cast<std::streamsize>(header.size())) {
            return false;
        }
        if (std::memcmp(header.data(), magic.data(), magic.size()) != 0) {
            return false;
        }
        std::uint32_t header_len = (static_cast<std::uint32_t>(header[magic.size()]) << 24)
                                   | (static_cast<std::uint32_t>(header[magic.size() + 1]) << 16)
                                   | (static_cast<std::uint32_t>(header[magic.size() + 2]) << 8)
                                   | static_cast<std::uint32_t>(header[magic.size() + 3]);
        if (header_len != blob_len) {
            return false;
        }
        std::uint64_t blob_start = trailer_start + footer_len;
        input.seekg(static_cast<std::streamoff>(blob_start), std::ios::beg);

        Bytes archive_key;
        std::string archive_info = std::string(basefwx::constants::kImageCipherArchiveInfo);
        Bytes nonce(basefwx::constants::kAeadNonceLen);
        std::uint64_t cipher_len = 0;

        Bytes prefix(basefwx::constants::kJmgKeyMagic.size());
        input.read(reinterpret_cast<char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
        if (input.gcount() != static_cast<std::streamsize>(prefix.size())) {
            return false;
        }
        if (std::memcmp(prefix.data(),
                        basefwx::constants::kJmgKeyMagic.data(),
                        basefwx::constants::kJmgKeyMagic.size()) == 0) {
            header_seen = true;
            std::array<std::uint8_t, 5> meta{};
            input.read(reinterpret_cast<char*>(meta.data()), static_cast<std::streamsize>(meta.size()));
            if (input.gcount() != static_cast<std::streamsize>(meta.size())) {
                throw std::runtime_error("Truncated JMG key header");
            }
            std::uint32_t payload_len = (static_cast<std::uint32_t>(meta[1]) << 24)
                                        | (static_cast<std::uint32_t>(meta[2]) << 16)
                                        | (static_cast<std::uint32_t>(meta[3]) << 8)
                                        | static_cast<std::uint32_t>(meta[4]);
            if (payload_len > blob_len) {
                throw std::runtime_error("Invalid JMG key header length");
            }
            Bytes header_bytes;
            header_bytes.insert(header_bytes.end(), prefix.begin(), prefix.end());
            header_bytes.insert(header_bytes.end(), meta.begin(), meta.end());
            Bytes payload(payload_len);
            if (payload_len > 0) {
                input.read(reinterpret_cast<char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
                if (input.gcount() != static_cast<std::streamsize>(payload.size())) {
                    throw std::runtime_error("Truncated JMG key header");
                }
                header_bytes.insert(header_bytes.end(), payload.begin(), payload.end());
            }
            std::size_t parsed_len = 0;
            Bytes user_blob;
            Bytes master_blob;
            std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy;
            if (!ParseJmgHeader(header_bytes, parsed_len, user_blob, master_blob, &profile_id)) {
                throw std::runtime_error("Invalid JMG key header");
            }
            basefwx::pb512::KdfOptions kdf;
            Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
                user_blob,
                master_blob,
                password,
                use_master,
                basefwx::constants::kJmgMaskInfo,
                basefwx::constants::kMaskAadJmg,
                kdf
            );
            archive_key = ArchiveKeyFromMask(mask_key, profile_id);
            archive_info = JmgArchiveInfoForProfile(profile_id);
            input.read(reinterpret_cast<char*>(nonce.data()),
                       static_cast<std::streamsize>(nonce.size()));
            if (input.gcount() != static_cast<std::streamsize>(nonce.size())) {
                throw std::runtime_error("Truncated JMG trailer nonce");
            }
            if (blob_len < parsed_len + basefwx::constants::kAeadNonceLen + basefwx::constants::kAeadTagLen) {
                throw std::runtime_error("Invalid JMG trailer length");
            }
            cipher_len = blob_len - parsed_len - basefwx::constants::kAeadNonceLen - basefwx::constants::kAeadTagLen;
        } else {
            Bytes material = DeriveMaterial(password);
            archive_key = basefwx::crypto::HkdfSha256(material, basefwx::constants::kImageCipherArchiveInfo, 32);
            std::memcpy(nonce.data(), prefix.data(), prefix.size());
            std::size_t remaining = nonce.size() - prefix.size();
            input.read(reinterpret_cast<char*>(nonce.data() + prefix.size()),
                       static_cast<std::streamsize>(remaining));
            if (input.gcount() != static_cast<std::streamsize>(remaining)) {
                return false;
            }
            if (blob_len < basefwx::constants::kAeadNonceLen + basefwx::constants::kAeadTagLen) {
                return false;
            }
            cipher_len = blob_len - basefwx::constants::kAeadNonceLen - basefwx::constants::kAeadTagLen;
        }

        Bytes aad(archive_info.begin(), archive_info.end());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return false;
        }
        std::vector<std::uint8_t> buffer(1024 * 1024);
        std::vector<std::uint8_t> outbuf(buffer.size() + 16);
        int out_len = 0;
        std::ofstream output(output_path, std::ios::binary);
        if (!output) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        try {
            Ensure(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
                   "AES-GCM init failed");
            Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                       static_cast<int>(nonce.size()), nullptr) == 1,
                   "AES-GCM ivlen failed");
            Ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, archive_key.data(), nonce.data()) == 1,
                   "AES-GCM key init failed");
            if (!aad.empty()) {
                Ensure(EVP_DecryptUpdate(ctx, nullptr, &out_len,
                                         aad.data(), static_cast<int>(aad.size())) == 1,
                       "AES-GCM aad failed");
            }
            std::uint64_t remaining = cipher_len;
            std::uint64_t processed = 0;
            while (remaining > 0) {
                std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
                input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(take));
                std::streamsize got = input.gcount();
                if (got <= 0) {
                    EVP_CIPHER_CTX_free(ctx);
                    return false;
                }
                Ensure(EVP_DecryptUpdate(ctx, outbuf.data(), &out_len,
                                         buffer.data(), static_cast<int>(got)) == 1,
                       "AES-GCM update failed");
                if (out_len > 0) {
                    output.write(reinterpret_cast<const char*>(outbuf.data()), out_len);
                }
                remaining -= static_cast<std::uint64_t>(got);
                processed += static_cast<std::uint64_t>(got);
                if (progress_cb && cipher_len > 0) {
                    double frac = static_cast<double>(processed) / static_cast<double>(cipher_len);
                    if (frac > 1.0) {
                        frac = 1.0;
                    }
                    progress_cb(frac);
                }
            }
            std::array<std::uint8_t, basefwx::constants::kAeadTagLen> tag{};
            input.read(reinterpret_cast<char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
            if (input.gcount() != static_cast<std::streamsize>(tag.size())) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            Ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                       static_cast<int>(tag.size()), tag.data()) == 1,
                   "AES-GCM tag failed");
            Ensure(EVP_DecryptFinal_ex(ctx, outbuf.data(), &out_len) == 1,
                   "AES-GCM auth failed");
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }

        EVP_CIPHER_CTX_free(ctx);
        return true;
    } catch (...) {
        if (header_seen) {
            throw;
        }
        return false;
    }
}

bool ExtractTrailerWithMagic(const Bytes& data,
                             std::string_view magic,
                             Bytes& payload,
                             Bytes& trailer) {
    const std::size_t magic_len = magic.size();
    const std::size_t footer_len = magic_len + 4;
    payload = data;
    trailer.clear();
    if (magic_len == 0 || data.size() < footer_len) {
        return false;
    }

    auto read_u32 = [](const std::uint8_t* ptr) {
        return (static_cast<std::uint32_t>(ptr[0]) << 24)
               | (static_cast<std::uint32_t>(ptr[1]) << 16)
               | (static_cast<std::uint32_t>(ptr[2]) << 8)
               | static_cast<std::uint32_t>(ptr[3]);
    };

    std::size_t footer_pos = data.size() - footer_len;
    if (std::memcmp(data.data() + footer_pos, magic.data(), magic_len) == 0) {
        std::uint32_t len = read_u32(data.data() + footer_pos + magic_len);
        std::uint64_t total = static_cast<std::uint64_t>(data.size());
        std::uint64_t needed = static_cast<std::uint64_t>(footer_len)
                               + static_cast<std::uint64_t>(len)
                               + static_cast<std::uint64_t>(footer_len);
        if (needed <= total) {
            std::uint64_t header_pos = total - needed;
            if (std::memcmp(data.data() + header_pos, magic.data(), magic_len) == 0) {
                std::uint32_t header_len = read_u32(data.data() + header_pos + magic_len);
                if (header_len == len) {
                    std::size_t blob_start = static_cast<std::size_t>(header_pos + footer_len);
                    std::size_t blob_end = blob_start + len;
                    payload.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(header_pos));
                    trailer.assign(data.begin() + static_cast<std::ptrdiff_t>(blob_start),
                                   data.begin() + static_cast<std::ptrdiff_t>(blob_end));
                    return true;
                }
            }
        }
    }

    for (std::size_t i = data.size(); i-- > 0;) {
        if (i + footer_len > data.size()) {
            continue;
        }
        if (std::memcmp(data.data() + i, magic.data(), magic_len) != 0) {
            continue;
        }
        std::uint32_t len = read_u32(data.data() + i + magic_len);
        std::size_t blob_start = i + footer_len;
        std::size_t blob_end = blob_start + len;
        if (blob_end != data.size()) {
            continue;
        }
        payload.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(i));
        trailer.assign(data.begin() + static_cast<std::ptrdiff_t>(blob_start),
                       data.begin() + static_cast<std::ptrdiff_t>(blob_end));
        return true;
    }
    return false;
}

struct TrailerInfo {
    std::uint64_t blob_start = 0;
    std::uint64_t blob_len = 0;
    std::uint64_t trailer_start = 0;
};

std::optional<TrailerInfo> ExtractBalancedTrailerInfo(const std::filesystem::path& path,
                                                      std::string_view magic) {
    const std::size_t footer_len = magic.size() + 4;
    std::error_code ec;
    std::uint64_t size = std::filesystem::file_size(path, ec);
    if (ec || size < footer_len) {
        return std::nullopt;
    }
    auto read_u32 = [](const std::uint8_t* ptr) -> std::uint32_t {
        return (static_cast<std::uint32_t>(ptr[0]) << 24)
            | (static_cast<std::uint32_t>(ptr[1]) << 16)
            | (static_cast<std::uint32_t>(ptr[2]) << 8)
            | static_cast<std::uint32_t>(ptr[3]);
    };
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    input.seekg(static_cast<std::streamoff>(size - footer_len), std::ios::beg);
    std::vector<std::uint8_t> footer(footer_len);
    input.read(reinterpret_cast<char*>(footer.data()), static_cast<std::streamsize>(footer.size()));
    if (input.gcount() != static_cast<std::streamsize>(footer.size())) {
        return std::nullopt;
    }
    if (std::memcmp(footer.data(), magic.data(), magic.size()) != 0) {
        return std::nullopt;
    }
    std::uint64_t blob_len = read_u32(footer.data() + magic.size());
    std::uint64_t trailer_start = size - footer_len - blob_len - footer_len;
    if (trailer_start > size) {
        return std::nullopt;
    }
    input.seekg(static_cast<std::streamoff>(trailer_start), std::ios::beg);
    std::vector<std::uint8_t> header(footer_len);
    input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (input.gcount() != static_cast<std::streamsize>(header.size())) {
        return std::nullopt;
    }
    if (std::memcmp(header.data(), magic.data(), magic.size()) != 0) {
        return std::nullopt;
    }
    if (read_u32(header.data() + magic.size()) != blob_len) {
        return std::nullopt;
    }
    TrailerInfo info;
    info.blob_start = trailer_start + footer_len;
    info.blob_len = blob_len;
    info.trailer_start = trailer_start;
    return info;
}

std::optional<JmgResolvedKeys> ResolveJmgHeaderKeys(const Bytes& blob,
                                                    const std::string& password,
                                                    bool use_master) {
    std::size_t header_len = 0;
    Bytes user_blob;
    Bytes master_blob;
    std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy;
    if (!ParseJmgHeader(blob, header_len, user_blob, master_blob, &profile_id)) {
        return std::nullopt;
    }
    basefwx::pb512::KdfOptions kdf;
    Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
        user_blob,
        master_blob,
        password,
        use_master,
        basefwx::constants::kJmgMaskInfo,
        basefwx::constants::kMaskAadJmg,
        kdf
    );
    JmgResolvedKeys keys;
    keys.header_len = header_len;
    keys.profile_id = profile_id;
    keys.material = DeriveMaterialFromMask(mask_key, profile_id);
    keys.base_key = BaseKeyFromMask(mask_key, profile_id);
    keys.archive_key = ArchiveKeyFromMask(mask_key, profile_id);
    return keys;
}

Bytes LoadBaseKeyFromKeyTrailerFile(const std::filesystem::path& input_path,
                                    const std::string& password,
                                    bool use_master,
                                    std::uint8_t* profile_id_out = nullptr) {
    auto trailer_info = ExtractBalancedTrailerInfo(input_path, basefwx::constants::kImageCipherKeyTrailerMagic);
    if (!trailer_info.has_value() || trailer_info->blob_len == 0) {
        return {};
    }
    if (trailer_info->blob_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("JMG key trailer too large");
    }
    Bytes blob(static_cast<std::size_t>(trailer_info->blob_len));
    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open key trailer stream");
    }
    input.seekg(static_cast<std::streamoff>(trailer_info->blob_start), std::ios::beg);
    input.read(reinterpret_cast<char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    if (input.gcount() != static_cast<std::streamsize>(blob.size())) {
        throw std::runtime_error("Failed to read JMG key trailer");
    }
    auto keys = ResolveJmgHeaderKeys(blob, password, use_master);
    if (!keys.has_value()) {
        throw std::runtime_error("Invalid JMG key trailer");
    }
    if (keys->header_len != blob.size()) {
        throw std::runtime_error("Invalid JMG key trailer payload");
    }
    if (profile_id_out) {
        *profile_id_out = keys->profile_id;
    }
    return keys->base_key;
}

Bytes LoadBaseKeyFromKeyTrailerBytes(const Bytes& file_bytes,
                                     const std::string& password,
                                     bool use_master,
                                     std::uint8_t* profile_id_out = nullptr) {
    Bytes payload;
    Bytes trailer;
    if (!ExtractTrailerWithMagic(file_bytes, basefwx::constants::kImageCipherKeyTrailerMagic, payload, trailer)
        || trailer.empty()) {
        return {};
    }
    auto keys = ResolveJmgHeaderKeys(trailer, password, use_master);
    if (!keys.has_value()) {
        throw std::runtime_error("Invalid JMG key trailer");
    }
    if (keys->header_len != trailer.size()) {
        throw std::runtime_error("Invalid JMG key trailer payload");
    }
    if (profile_id_out) {
        *profile_id_out = keys->profile_id;
    }
    return keys->base_key;
}

void WarnNoArchivePayload() {
    if (basefwx::env::IsEnabled("BASEFWX_NO_LOG", false)) {
        return;
    }
    std::cerr
        << "WARNING: jMG no-archive payload detected; restored media may not be byte-identical to the original input."
        << std::endl;
}

}  // namespace basefwx::imagecipher::internal
