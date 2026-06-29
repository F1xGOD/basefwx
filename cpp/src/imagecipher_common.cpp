/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
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

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::filesystem::path NormalizePath(const std::string& path) {
    std::filesystem::path p(path);
    p = p.lexically_normal();
    if (p.is_relative()) {
        return std::filesystem::absolute(p);
    }
    return p;
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
            throw std::runtime_error("Failed to write output file: " + path.string());
        }
    }
}

std::string ExtensionLower(const std::filesystem::path& path) {
    std::string ext = path.extension().string();
    if (!ext.empty() && ext[0] == '.') {
        ext.erase(0, 1);
    }
    return ToLower(ext);
}

std::uint32_t ParseIterations(const std::string& raw, std::uint32_t fallback) {
    if (raw.empty()) {
        return fallback;
    }
    try {
        std::uint64_t parsed = static_cast<std::uint64_t>(std::stoul(raw));
        if (parsed == 0) {
            return fallback;
        }
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            return std::numeric_limits<std::uint32_t>::max();
        }
        return static_cast<std::uint32_t>(parsed);
    } catch (const std::exception&) {
        return fallback;
    }
}

std::uint32_t ResolveImageKdfIterations() {
    std::string raw = basefwx::env::Get("BASEFWX_USER_KDF_ITERS");
    if (raw.empty()) {
        raw = basefwx::env::TestKdfIters();
    }
    std::uint32_t parsed = ParseIterations(raw, basefwx::constants::kUserKdfIterations);
    return std::max<std::uint32_t>(static_cast<std::uint32_t>(basefwx::constants::kUserKdfIterations), parsed);
}

std::uint32_t HardenImageIterations(const std::string& password, std::uint32_t iters) {
    if (password.empty()) {
        return iters;
    }
    if (!basefwx::env::TestKdfIters().empty()) {
        return iters;
    }
    if (password.size() < basefwx::constants::kShortPasswordMin) {
        if (iters < basefwx::constants::kShortPbkdf2Iterations) {
            iters = static_cast<std::uint32_t>(basefwx::constants::kShortPbkdf2Iterations);
        }
    }
    return iters;
}

Bytes DeriveMaterial(const std::string& password) {
    Bytes salt(basefwx::constants::kImageCipherStreamInfo.begin(),
               basefwx::constants::kImageCipherStreamInfo.end());
    std::uint32_t iters = ResolveImageKdfIterations();
    iters = HardenImageIterations(password, iters);
    return basefwx::crypto::Pbkdf2HmacSha256(password, salt, iters, 64);
}

std::uint8_t NormalizeJmgProfile(std::uint8_t profile_id) {
    if (profile_id != basefwx::constants::kJmgSecurityProfileLegacy
        && profile_id != basefwx::constants::kJmgSecurityProfileMax) {
        throw std::runtime_error("Unsupported JMG security profile");
    }
    return profile_id;
}

std::string JmgProfileLabel(std::string_view label, std::uint8_t profile_id) {
    NormalizeJmgProfile(profile_id);
    if (profile_id == basefwx::constants::kJmgSecurityProfileMax) {
        return std::string(label) + ".max";
    }
    return std::string(label);
}

std::string JmgStreamInfoForProfile(std::uint8_t profile_id) {
    return JmgProfileLabel(basefwx::constants::kImageCipherStreamInfo, profile_id);
}

std::string JmgArchiveInfoForProfile(std::uint8_t profile_id) {
    return JmgProfileLabel(basefwx::constants::kImageCipherArchiveInfo, profile_id);
}

std::uint8_t JmgVideoMaskBitsForProfile(std::uint8_t profile_id) {
    NormalizeJmgProfile(profile_id);
    if (profile_id == basefwx::constants::kJmgSecurityProfileMax) {
        return 8;
    }
    return 6;
}

std::uint16_t JmgAudioMaskBitsForProfile(std::uint8_t profile_id) {
    NormalizeJmgProfile(profile_id);
    if (profile_id == basefwx::constants::kJmgSecurityProfileMax) {
        return 16;
    }
    return 13;
}

Bytes DeriveMaterialFromMask(const Bytes& mask_key,
                             std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy) {
    return basefwx::crypto::HkdfSha256(mask_key, JmgStreamInfoForProfile(profile_id), 64);
}

Bytes BaseKeyFromMask(const Bytes& mask_key,
                      std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy) {
    return basefwx::crypto::HkdfSha256(mask_key, JmgStreamInfoForProfile(profile_id), 32);
}

Bytes ArchiveKeyFromMask(const Bytes& mask_key,
                         std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy) {
    return basefwx::crypto::HkdfSha256(mask_key, JmgArchiveInfoForProfile(profile_id), 32);
}

Bytes BuildJmgHeader(const Bytes& user_blob,
                     const Bytes& master_blob,
                     std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileDefault) {
    profile_id = NormalizeJmgProfile(profile_id);
    std::vector<basefwx::format::Bytes> parts = {user_blob, master_blob};
    Bytes payload = basefwx::format::PackLengthPrefixed(parts);
    payload.insert(payload.begin(), profile_id);
    Bytes header;
    header.reserve(basefwx::constants::kJmgKeyMagic.size() + 1 + 4 + payload.size());
    header.insert(header.end(),
                  basefwx::constants::kJmgKeyMagic.begin(),
                  basefwx::constants::kJmgKeyMagic.end());
    header.push_back(basefwx::constants::kJmgKeyVersion);
    std::uint32_t len = static_cast<std::uint32_t>(payload.size());
    header.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFF));
    header.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFF));
    header.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
    header.push_back(static_cast<std::uint8_t>(len & 0xFF));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

bool ParseJmgHeader(const Bytes& blob,
                    std::size_t& header_len,
                    Bytes& user_blob,
                    Bytes& master_blob,
                    std::uint8_t* profile_id_out = nullptr) {
    const std::size_t header_min = basefwx::constants::kJmgKeyMagic.size() + 1 + 4;
    if (blob.size() < header_min) {
        return false;
    }
    if (std::memcmp(blob.data(),
                    basefwx::constants::kJmgKeyMagic.data(),
                    basefwx::constants::kJmgKeyMagic.size()) != 0) {
        return false;
    }
    std::uint8_t version = blob[basefwx::constants::kJmgKeyMagic.size()];
    if (version != basefwx::constants::kJmgKeyVersionLegacy
        && version != basefwx::constants::kJmgKeyVersion) {
        throw std::runtime_error("Unsupported JMG key header version");
    }
    std::uint32_t payload_len = (static_cast<std::uint32_t>(blob[basefwx::constants::kJmgKeyMagic.size() + 1]) << 24)
                                | (static_cast<std::uint32_t>(blob[basefwx::constants::kJmgKeyMagic.size() + 2]) << 16)
                                | (static_cast<std::uint32_t>(blob[basefwx::constants::kJmgKeyMagic.size() + 3]) << 8)
                                | static_cast<std::uint32_t>(blob[basefwx::constants::kJmgKeyMagic.size() + 4]);
    header_len = header_min + payload_len;
    if (blob.size() < header_len) {
        throw std::runtime_error("Truncated JMG key header");
    }
    Bytes payload(blob.begin() + static_cast<std::ptrdiff_t>(header_min),
                  blob.begin() + static_cast<std::ptrdiff_t>(header_len));
    std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy;
    Bytes key_payload = payload;
    if (version == basefwx::constants::kJmgKeyVersion) {
        if (payload.empty()) {
            throw std::runtime_error("Truncated JMG key header profile");
        }
        profile_id = NormalizeJmgProfile(payload[0]);
        key_payload.assign(payload.begin() + 1, payload.end());
    }
    auto parts = basefwx::format::UnpackLengthPrefixed(key_payload, 2);
    user_blob = parts[0];
    master_blob = parts[1];
    if (profile_id_out) {
        *profile_id_out = profile_id;
    }
    return true;
}

std::uint64_t ReadU64Be(const std::uint8_t* data) {
    return (static_cast<std::uint64_t>(data[0]) << 56)
           | (static_cast<std::uint64_t>(data[1]) << 48)
           | (static_cast<std::uint64_t>(data[2]) << 40)
           | (static_cast<std::uint64_t>(data[3]) << 32)
           | (static_cast<std::uint64_t>(data[4]) << 24)
           | (static_cast<std::uint64_t>(data[5]) << 16)
           | (static_cast<std::uint64_t>(data[6]) << 8)
           | (static_cast<std::uint64_t>(data[7]));
}

void Ensure(bool ok, const char* msg) {
    if (!ok) {
        throw std::runtime_error(msg);
    }
}

}  // namespace basefwx::imagecipher::internal
