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

namespace {
struct StbAllocHeader {
    size_t size;
};

void* stb_malloc(size_t size) {
    if (size == 0) {
        return nullptr;
    }
    size_t total = size + sizeof(StbAllocHeader);
    auto* base = new (std::nothrow) std::uint8_t[total];
    if (!base) {
        return nullptr;
    }
    auto* header = reinterpret_cast<StbAllocHeader*>(base);
    header->size = size;
    return base + sizeof(StbAllocHeader);
}

void* stb_realloc(void* ptr, size_t new_size) {
    if (!ptr) {
        return stb_malloc(new_size);
    }
    if (new_size == 0) {
        return nullptr;
    }
    auto* base = static_cast<std::uint8_t*>(ptr) - sizeof(StbAllocHeader);
    auto* header = reinterpret_cast<StbAllocHeader*>(base);
    size_t old_size = header->size;
    size_t total = new_size + sizeof(StbAllocHeader);
    auto* fresh = new (std::nothrow) std::uint8_t[total];
    if (!fresh) {
        return nullptr;
    }
    auto* fresh_header = reinterpret_cast<StbAllocHeader*>(fresh);
    fresh_header->size = new_size;
    std::memcpy(fresh + sizeof(StbAllocHeader), base + sizeof(StbAllocHeader),
                std::min(old_size, new_size));
    delete[] base;
    return fresh + sizeof(StbAllocHeader);
}

void stb_free(void* ptr) {
    if (!ptr) {
        return;
    }
    auto* base = static_cast<std::uint8_t*>(ptr) - sizeof(StbAllocHeader);
    delete[] base;
}
}  // namespace

#define STBI_MALLOC(sz) stb_malloc(sz)
#define STBI_REALLOC(p, newsz) stb_realloc(p, newsz)
#define STBI_FREE(p) stb_free(p)
#define STBIW_MALLOC(sz) stb_malloc(sz)
#define STBIW_REALLOC(p, newsz) stb_realloc(p, newsz)
#define STBIW_FREE(p) stb_free(p)
#define STB_IMAGE_IMPLEMENTATION
#define STBI_FAILURE_USERMSG
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
#include <vector>

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

struct Xoroshiro128Plus {
    std::uint64_t s0 = 0;
    std::uint64_t s1 = 0;

    static std::uint64_t Rotl(std::uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }

    std::uint64_t Next() {
        std::uint64_t result = s0 + s1;
        std::uint64_t t = s1 ^ s0;
        s0 = Rotl(s0, 55) ^ t ^ (t << 14);
        s1 = Rotl(t, 36);
        return result;
    }

    std::uint64_t NextBounded(std::uint64_t bound) {
        if (bound == 0) {
            return 0;
        }
        std::uint64_t threshold = (~bound + 1) % bound;
        while (true) {
            std::uint64_t value = Next();
            if (value >= threshold) {
                return value % bound;
            }
        }
    }
};

struct ImageBuffer {
    int width = 0;
    int height = 0;
    int channels = 0;
    Bytes pixels;
};

ImageBuffer DecodeImage(const Bytes& blob, const std::filesystem::path& path_hint) {
    int width = 0;
    int height = 0;
    int channels_in_file = 0;
    if (!stbi_info_from_memory(blob.data(), static_cast<int>(blob.size()),
                               &width, &height, &channels_in_file)) {
        throw std::runtime_error("Unsupported image input: " + path_hint.string());
    }
    int target_channels = 0;
    if (channels_in_file == 1) {
        target_channels = 1;
    } else if (channels_in_file >= 4) {
        target_channels = 4;
    } else {
        target_channels = 3;
    }

    int loaded_channels = 0;
    unsigned char* data = stbi_load_from_memory(blob.data(), static_cast<int>(blob.size()),
                                                &width, &height, &loaded_channels,
                                                target_channels);
    if (!data) {
        const char* reason = stbi_failure_reason();
        std::string msg = reason ? reason : "unknown error";
        throw std::runtime_error("Failed to decode image: " + msg);
    }
    std::size_t total = static_cast<std::size_t>(width) * static_cast<std::size_t>(height)
                        * static_cast<std::size_t>(target_channels);
    Bytes pixels(data, data + total);
    stbi_image_free(data);

    ImageBuffer buffer;
    buffer.width = width;
    buffer.height = height;
    buffer.channels = target_channels;
    buffer.pixels = std::move(pixels);
    return buffer;
}

void WriteImage(const std::filesystem::path& path,
                const ImageBuffer& image,
                const std::string& format) {
    std::filesystem::create_directories(path.parent_path());
    std::string fmt = ToLower(format);

    const int width = image.width;
    const int height = image.height;
    int channels = image.channels;
    Bytes pixels = image.pixels;

    if ((fmt == "jpg" || fmt == "jpeg") && channels == 4) {
        Bytes rgb;
        rgb.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 3);
        for (int i = 0; i < width * height; ++i) {
            rgb[i * 3] = pixels[i * 4];
            rgb[i * 3 + 1] = pixels[i * 4 + 1];
            rgb[i * 3 + 2] = pixels[i * 4 + 2];
        }
        pixels.swap(rgb);
        channels = 3;
    }

    std::filesystem::path temp = path;
    temp += "._tmp";

    int ok = 0;
    if (fmt == "png") {
        ok = stbi_write_png(temp.string().c_str(), width, height, channels,
                            pixels.data(), width * channels);
    } else if (fmt == "jpg" || fmt == "jpeg") {
        ok = stbi_write_jpg(temp.string().c_str(), width, height, channels,
                            pixels.data(), 90);
    } else if (fmt == "bmp") {
        ok = stbi_write_bmp(temp.string().c_str(), width, height, channels,
                            pixels.data());
    } else if (fmt == "tga") {
        ok = stbi_write_tga(temp.string().c_str(), width, height, channels,
                            pixels.data());
    } else {
        throw std::runtime_error("Unsupported image format: " + format);
    }

    if (ok == 0) {
        throw std::runtime_error("Failed to write image: " + path.string());
    }

    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        throw std::runtime_error("Failed to finalize image output: " + path.string());
    }
}

void BuildMaskAndShuffle(const std::string& password,
                         std::size_t num_pixels,
                         int channels,
                         std::vector<std::uint8_t>& mask,
                         std::vector<std::uint8_t>& rotations,
                         std::vector<std::size_t>& perm,
                         Bytes& material,
                         const Bytes* material_override = nullptr) {
    if (material_override) {
        material = *material_override;
    } else {
        material = DeriveMaterial(password);
    }
    Bytes key(material.begin(), material.begin() + 32);
    Bytes nonce(material.begin() + 32, material.begin() + 48);
    std::array<std::uint8_t, 16> seed_bytes{};
    std::copy(material.begin() + 48, material.begin() + 64, seed_bytes.begin());

    std::uint64_t s0 = ReadU64Be(seed_bytes.data());
    std::uint64_t s1 = ReadU64Be(seed_bytes.data() + 8);
    if (s0 == 0 && s1 == 0) {
        s1 = 1;
    }
    Xoroshiro128Plus rng{ s0, s1 };

    std::size_t total = num_pixels * static_cast<std::size_t>(channels);
    Bytes zeros(total, 0);
    Bytes mask_bytes = basefwx::crypto::AesCtrTransform(key, nonce, zeros);
    mask.assign(mask_bytes.begin(), mask_bytes.end());

    rotations.clear();
    if (channels > 1) {
        rotations.resize(num_pixels);
        for (std::size_t i = 0; i < num_pixels; ++i) {
            rotations[i] = static_cast<std::uint8_t>(rng.NextBounded(static_cast<std::uint64_t>(channels)));
        }
    }

    perm.resize(num_pixels);
    for (std::size_t i = 0; i < num_pixels; ++i) {
        perm[i] = i;
    }
    if (num_pixels > 1) {
        for (std::size_t i = num_pixels - 1; i > 0; --i) {
            std::size_t j = static_cast<std::size_t>(rng.NextBounded(static_cast<std::uint64_t>(i + 1)));
            std::swap(perm[i], perm[j]);
        }
    }
}

void ApplyRotation(std::vector<std::uint8_t>& data,
                   std::size_t num_pixels,
                   int channels,
                   const std::vector<std::uint8_t>& rotations,
                   bool invert) {
    if (channels <= 1) {
        return;
    }
    std::array<std::uint8_t, 4> tmp{};
    for (std::size_t i = 0; i < num_pixels; ++i) {
        std::uint8_t r = rotations[i];
        if (r == 0) {
            continue;
        }
        std::uint8_t* row = data.data() + i * static_cast<std::size_t>(channels);
        for (int c = 0; c < channels; ++c) {
            int idx = invert ? (c + channels - r) % channels : (c + r) % channels;
            tmp[c] = row[idx];
        }
        for (int c = 0; c < channels; ++c) {
            row[c] = tmp[c];
        }
    }
}

void ApplyPermutation(std::vector<std::uint8_t>& data,
                      std::size_t num_pixels,
                      int channels,
                      const std::vector<std::size_t>& perm,
                      bool invert) {
    std::vector<std::uint8_t> out(data.size());
    if (!invert) {
        for (std::size_t i = 0; i < num_pixels; ++i) {
            std::size_t src = perm[i];
            std::memcpy(out.data() + i * static_cast<std::size_t>(channels),
                        data.data() + src * static_cast<std::size_t>(channels),
                        static_cast<std::size_t>(channels));
        }
    } else {
        std::vector<std::size_t> inv_perm(num_pixels);
        for (std::size_t i = 0; i < num_pixels; ++i) {
            inv_perm[perm[i]] = i;
        }
        for (std::size_t i = 0; i < num_pixels; ++i) {
            std::size_t src = inv_perm[i];
            std::memcpy(out.data() + i * static_cast<std::size_t>(channels),
                        data.data() + src * static_cast<std::size_t>(channels),
                        static_cast<std::size_t>(channels));
        }
    }
    data.swap(out);
}

void ApplyMask(std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& mask) {
    if (data.size() != mask.size()) {
        throw std::runtime_error("Image mask length mismatch");
    }
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(data[i] ^ mask[i]);
    }
}

std::string EncryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool include_trailer,
                            bool archive_original,
                            bool use_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    basefwx::RequireStrongPasswordForEncryption(resolved, "jMG");
    if (!include_trailer) {
        if (basefwx::env::Get("BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION") != "1") {
            throw std::runtime_error(
                "Image encryption without trailer is deterministic and insecure; "
                "set BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION=1 to allow or enable trailer");
        }
        if (resolved.empty()) {
            throw std::runtime_error("Password is required for image encryption without trailer");
        }
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }

    Bytes original_bytes = ReadFileBytes(input_path);
    ImageBuffer image = DecodeImage(original_bytes, input_path);

    std::size_t num_pixels = static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height);
    std::vector<std::uint8_t> mask;
    std::vector<std::uint8_t> rotations;
    std::vector<std::size_t> perm;
    Bytes material;
    Bytes material_override;
    Bytes archive_key;
    Bytes trailer_header;
    const std::uint8_t security_profile = basefwx::constants::kJmgSecurityProfileDefault;

    if (include_trailer) {
        basefwx::pb512::KdfOptions kdf;
        auto mask_key = basefwx::keywrap::PrepareMaskKey(
            resolved,
            use_master,
            basefwx::constants::kJmgMaskInfo,
            false,
            basefwx::constants::kMaskAadJmg,
            kdf
        );
        material_override = DeriveMaterialFromMask(mask_key.mask_key, security_profile);
        archive_key = ArchiveKeyFromMask(mask_key.mask_key, security_profile);
        trailer_header = BuildJmgHeader(mask_key.user_blob, mask_key.master_blob, security_profile);
    }

    BuildMaskAndShuffle(resolved, num_pixels, image.channels, mask, rotations, perm, material,
                        include_trailer ? &material_override : nullptr);

    ApplyMask(image.pixels, mask);
    ApplyRotation(image.pixels, num_pixels, image.channels, rotations, false);
    ApplyPermutation(image.pixels, num_pixels, image.channels, perm, false);

    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    if (output_path.extension().empty()) {
        output_path.replace_extension(input_path.extension());
    }
    std::string fmt = ExtensionLower(output_path);
    if (fmt.empty()) {
        fmt = ExtensionLower(input_path);
    }

    WriteImage(output_path, image, fmt);

    if (include_trailer) {
        if (archive_original) {
            std::string archive_info = JmgArchiveInfoForProfile(security_profile);
            Bytes aad(archive_info.begin(), archive_info.end());
            Bytes archive_blob = basefwx::crypto::AeadEncrypt(archive_key, original_bytes, aad);
            Bytes trailer = trailer_header;
            trailer.insert(trailer.end(), archive_blob.begin(), archive_blob.end());
            AppendBalancedTrailer(output_path, basefwx::constants::kImageCipherTrailerMagic, trailer);
        } else {
            AppendBalancedTrailer(output_path, basefwx::constants::kImageCipherKeyTrailerMagic, trailer_header);
        }
    }

    return output_path.string();
}

std::string DecryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool use_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }

    Bytes file_bytes = ReadFileBytes(input_path);
    Bytes payload;
    Bytes trailer;
    Bytes key_trailer;
    bool has_archive_trailer = ExtractTrailerWithMagic(
        file_bytes,
        basefwx::constants::kImageCipherTrailerMagic,
        payload,
        trailer
    );
    bool has_key_trailer = false;
    if (!has_archive_trailer) {
        has_key_trailer = ExtractTrailerWithMagic(
            file_bytes,
            basefwx::constants::kImageCipherKeyTrailerMagic,
            payload,
            key_trailer
        );
    }

    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    Bytes material_override;
    bool have_material_override = false;
    if (has_archive_trailer && !trailer.empty()) {
        bool header_detected = false;
        try {
            std::size_t magic_len = basefwx::constants::kJmgKeyMagic.size();
            if (trailer.size() >= magic_len
                && std::memcmp(trailer.data(), basefwx::constants::kJmgKeyMagic.data(), magic_len) == 0) {
                header_detected = true;
            }
            std::optional<JmgResolvedKeys> header_keys = ResolveJmgHeaderKeys(trailer, resolved, use_master);
            if (header_detected && !header_keys.has_value()) {
                throw std::runtime_error("Invalid JMG key header");
            }
            Bytes archive_key;
            Bytes archive_blob;
            std::string archive_info = std::string(basefwx::constants::kImageCipherArchiveInfo);
            if (header_keys.has_value()) {
                archive_key = header_keys->archive_key;
                material_override = header_keys->material;
                have_material_override = true;
                archive_info = JmgArchiveInfoForProfile(header_keys->profile_id);
                archive_blob.assign(
                    trailer.begin() + static_cast<std::ptrdiff_t>(header_keys->header_len),
                    trailer.end()
                );
            } else {
                Bytes material = DeriveMaterial(resolved);
                archive_key = basefwx::crypto::HkdfSha256(material, basefwx::constants::kImageCipherArchiveInfo, 32);
                archive_blob = trailer;
            }
            Bytes aad(archive_info.begin(), archive_info.end());
            Bytes original_bytes = basefwx::crypto::AeadDecrypt(archive_key, archive_blob, aad);
            WriteFileBytes(output_path, original_bytes);
            return output_path.string();
        } catch (const std::exception&) {
            if (header_detected) {
                throw;
            }
        }
    }

    if (has_key_trailer && !key_trailer.empty()) {
        auto header_keys = ResolveJmgHeaderKeys(key_trailer, resolved, use_master);
        if (!header_keys.has_value()) {
            throw std::runtime_error("Invalid JMG key trailer");
        }
        if (header_keys->header_len != key_trailer.size()) {
            throw std::runtime_error("Invalid JMG key trailer payload");
        }
        material_override = header_keys->material;
        have_material_override = true;
        WarnNoArchivePayload();
    }

    ImageBuffer image = DecodeImage(payload.empty() ? file_bytes : payload, input_path);
    std::size_t num_pixels = static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height);
    std::vector<std::uint8_t> mask;
    std::vector<std::uint8_t> rotations;
    std::vector<std::size_t> perm;
    Bytes material_unused;
    BuildMaskAndShuffle(
        resolved,
        num_pixels,
        image.channels,
        mask,
        rotations,
        perm,
        material_unused,
        have_material_override ? &material_override : nullptr
    );

    ApplyPermutation(image.pixels, num_pixels, image.channels, perm, true);
    ApplyRotation(image.pixels, num_pixels, image.channels, rotations, true);
    ApplyMask(image.pixels, mask);

    if (output_path.extension().empty()) {
        output_path.replace_extension(input_path.extension());
    }
    std::string fmt = ExtensionLower(output_path);
    if (fmt.empty()) {
        fmt = ExtensionLower(input_path);
    }

    WriteImage(output_path, image, fmt);
    return output_path.string();
}

}  // namespace basefwx::imagecipher::internal
