#include "basefwx/imagecipher.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/pb512.hpp"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_FAILURE_USERMSG
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <functional>
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
#include <vector>

#include <openssl/evp.h>

namespace basefwx::imagecipher {

namespace {

using basefwx::crypto::Bytes;

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
        raw = basefwx::env::Get("BASEFWX_TEST_KDF_ITERS");
    }
    std::uint32_t parsed = ParseIterations(raw, basefwx::constants::kUserKdfIterations);
    return std::max<std::uint32_t>(200000, parsed);
}

std::uint32_t HardenImageIterations(const std::string& password, std::uint32_t iters) {
    if (password.empty()) {
        return iters;
    }
    if (!basefwx::env::Get("BASEFWX_TEST_KDF_ITERS").empty()) {
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

void AppendTrailer(const std::filesystem::path& path, const Bytes& blob) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) {
        throw std::runtime_error("Failed to append trailer: " + path.string());
    }
    const auto magic = basefwx::constants::kImageCipherTrailerMagic;
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
    if (!out) {
        throw std::runtime_error("Failed to append trailer: " + path.string());
    }
}

void AppendTrailerStream(const std::filesystem::path& output_path,
                         const std::filesystem::path& original_path,
                         const std::string& password,
                         const std::function<void(double)>& progress_cb = {}) {
    auto magic = basefwx::constants::kImageCipherTrailerMagic;
    std::error_code ec;
    auto size = std::filesystem::file_size(original_path, ec);
    if (ec) {
        throw std::runtime_error("Failed to stat input for trailer");
    }
    std::uint64_t blob_len = basefwx::constants::kAeadNonceLen + size + basefwx::constants::kAeadTagLen;
    if (blob_len > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("Trailer too large");
    }
    std::uint32_t len = static_cast<std::uint32_t>(blob_len);
    std::array<std::uint8_t, 4> len_bytes{};
    len_bytes[0] = static_cast<std::uint8_t>((len >> 24) & 0xFF);
    len_bytes[1] = static_cast<std::uint8_t>((len >> 16) & 0xFF);
    len_bytes[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    len_bytes[3] = static_cast<std::uint8_t>(len & 0xFF);

    Bytes material = DeriveMaterial(password);
    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo, material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());
    Bytes nonce = basefwx::crypto::RandomBytes(basefwx::constants::kAeadNonceLen);

    std::ifstream input(original_path, std::ios::binary);
    std::ofstream out(output_path, std::ios::binary | std::ios::app);
    if (!input || !out) {
        throw std::runtime_error("Failed to open trailer streams");
    }
    out.write(magic.data(), static_cast<std::streamsize>(magic.size()));
    out.write(reinterpret_cast<const char*>(len_bytes.data()),
              static_cast<std::streamsize>(len_bytes.size()));
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

    Bytes material = DeriveMaterial(password);
    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo, material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());

    Bytes nonce(basefwx::constants::kAeadNonceLen);
    input.read(reinterpret_cast<char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
    if (input.gcount() != static_cast<std::streamsize>(nonce.size())) {
        return false;
    }
    std::uint64_t cipher_len = blob_len - basefwx::constants::kAeadNonceLen - basefwx::constants::kAeadTagLen;

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
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool ExtractTrailer(const Bytes& data, Bytes& payload, Bytes& trailer) {
    std::string magic(basefwx::constants::kImageCipherTrailerMagic.begin(),
                      basefwx::constants::kImageCipherTrailerMagic.end());
    if (magic.size() != 4) {
        return false;
    }
    std::size_t idx = data.size();
    bool found = false;
    for (std::size_t i = data.size(); i-- > 0;) {
        if (i + magic.size() > data.size()) {
            continue;
        }
        if (std::memcmp(data.data() + i, magic.data(), magic.size()) == 0) {
            idx = i;
            found = true;
            break;
        }
    }
    if (!found) {
        payload = data;
        return false;
    }
    if (idx + magic.size() + 4 > data.size()) {
        payload = data;
        return false;
    }
    std::uint32_t len = (static_cast<std::uint32_t>(data[idx + 4]) << 24)
                        | (static_cast<std::uint32_t>(data[idx + 5]) << 16)
                        | (static_cast<std::uint32_t>(data[idx + 6]) << 8)
                        | static_cast<std::uint32_t>(data[idx + 7]);
    std::size_t blob_start = idx + magic.size() + 4;
    std::size_t blob_end = blob_start + len;
    if (blob_end > data.size()) {
        payload = data;
        return false;
    }
    payload.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(idx));
    trailer.assign(data.begin() + static_cast<std::ptrdiff_t>(blob_start),
                   data.begin() + static_cast<std::ptrdiff_t>(blob_end));
    return true;
}

void BuildMaskAndShuffle(const std::string& password,
                         std::size_t num_pixels,
                         int channels,
                         std::vector<std::uint8_t>& mask,
                         std::vector<std::uint8_t>& rotations,
                         std::vector<std::size_t>& perm,
                         Bytes& material) {
    material = DeriveMaterial(password);
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

}  // namespace

std::string EncryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool include_trailer) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password is required for image encryption");
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

    BuildMaskAndShuffle(resolved, num_pixels, image.channels, mask, rotations, perm, material);

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
        Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo,
                                                       material, 32);
        Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
                  basefwx::constants::kImageCipherArchiveInfo.end());
        Bytes archive_blob = basefwx::crypto::AeadEncrypt(archive_key, original_bytes, aad);
        AppendTrailer(output_path, archive_blob);
    }

    return output_path.string();
}

std::string DecryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password is required for image decryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }

    Bytes file_bytes = ReadFileBytes(input_path);
    Bytes payload;
    Bytes trailer;
    bool has_trailer = ExtractTrailer(file_bytes, payload, trailer);

    Bytes material = DeriveMaterial(resolved);
    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo,
                                                   material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());

    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    if (has_trailer && !trailer.empty()) {
        try {
            Bytes original_bytes = basefwx::crypto::AeadDecrypt(archive_key, trailer, aad);
            WriteFileBytes(output_path, original_bytes);
            return output_path.string();
        } catch (const std::exception&) {
        }
    }

    ImageBuffer image = DecodeImage(payload.empty() ? file_bytes : payload, input_path);
    std::size_t num_pixels = static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height);
    std::vector<std::uint8_t> mask;
    std::vector<std::uint8_t> rotations;
    std::vector<std::size_t> perm;
    Bytes material_unused;
    BuildMaskAndShuffle(resolved, num_pixels, image.channels, mask, rotations, perm, material_unused);

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

namespace {

struct VideoInfo {
    int width = 0;
    int height = 0;
    double fps = 0.0;
    std::uint64_t bit_rate = 0;
    bool valid = false;
};

struct AudioInfo {
    int sample_rate = 0;
    int channels = 0;
    std::uint64_t bit_rate = 0;
    bool valid = false;
};

struct FormatInfo {
    double duration = 0.0;
    std::uint64_t bit_rate = 0;
    bool valid = false;
};

constexpr double kJmgTargetGrowth = 1.1;
constexpr double kJmgMaxGrowth = 2.0;
constexpr std::uint64_t kJmgMinAudioBps = 64000;
constexpr std::uint64_t kJmgMinVideoBps = 200000;

std::string QuoteArg(const std::string& arg) {
    std::string out;
    out.reserve(arg.size() + 2);
    out.push_back('"');
    for (char ch : arg) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

std::string JoinArgs(const std::vector<std::string>& args) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& arg : args) {
        if (!first) {
            oss << ' ';
        }
        first = false;
        oss << QuoteArg(arg);
    }
    return oss.str();
}

std::string RunCommandCapture(const std::vector<std::string>& args) {
    std::string cmd = JoinArgs(args);
    std::array<char, 4096> buffer{};
    std::string output;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to run command: " + cmd);
    }
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }
    int rc = pclose(pipe);
    if (rc != 0) {
        throw std::runtime_error("Command failed: " + cmd);
    }
    return output;
}

void RunCommand(const std::vector<std::string>& args) {
    std::string cmd = JoinArgs(args);
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        throw std::runtime_error("Command failed: " + cmd);
    }
}

double ParseRate(const std::string& rate) {
    if (rate.empty()) {
        return 0.0;
    }
    auto pos = rate.find('/');
    try {
        if (pos == std::string::npos) {
            return std::stod(rate);
        }
        double num = std::stod(rate.substr(0, pos));
        double den = std::stod(rate.substr(pos + 1));
        return den == 0.0 ? 0.0 : num / den;
    } catch (const std::exception&) {
        return 0.0;
    }
}

std::vector<std::string> SplitLines(const std::string& input) {
    std::vector<std::string> lines;
    std::istringstream iss(input);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

VideoInfo ProbeVideo(const std::filesystem::path& path) {
    VideoInfo info;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,avg_frame_rate,r_frame_rate,bit_rate",
        "-of", "default=nw=1:nk=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return info;
    }
    auto lines = SplitLines(out);
    if (lines.size() < 2) {
        return info;
    }
    try {
        info.width = std::stoi(lines[0]);
        info.height = std::stoi(lines[1]);
    } catch (const std::exception&) {
        return info;
    }
    double fps = 0.0;
    if (lines.size() >= 3) {
        fps = ParseRate(lines[2]);
    }
    if (fps <= 0.0 && lines.size() >= 4) {
        fps = ParseRate(lines[3]);
    }
    if (lines.size() >= 5) {
        try {
            info.bit_rate = static_cast<std::uint64_t>(std::stoull(lines[4]));
        } catch (const std::exception&) {
            info.bit_rate = 0;
        }
    }
    info.fps = fps;
    info.valid = info.width > 0 && info.height > 0;
    return info;
}

AudioInfo ProbeAudio(const std::filesystem::path& path) {
    AudioInfo info;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-select_streams", "a:0",
        "-show_entries", "stream=sample_rate,channels,bit_rate",
        "-of", "default=nw=1:nk=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return info;
    }
    auto lines = SplitLines(out);
    if (lines.size() < 2) {
        return info;
    }
    try {
        info.sample_rate = std::stoi(lines[0]);
        info.channels = std::stoi(lines[1]);
    } catch (const std::exception&) {
        return info;
    }
    if (lines.size() >= 3) {
        try {
            info.bit_rate = static_cast<std::uint64_t>(std::stoull(lines[2]));
        } catch (const std::exception&) {
            info.bit_rate = 0;
        }
    }
    info.valid = info.sample_rate > 0 && info.channels > 0;
    return info;
}

std::map<std::string, std::string> ProbeMetadata(const std::filesystem::path& path) {
    std::map<std::string, std::string> tags;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-show_entries", "format_tags",
        "-of", "default=nw=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return tags;
    }
    auto lines = SplitLines(out);
    for (const auto& line : lines) {
        constexpr std::string_view prefix = "TAG:";
        if (line.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        auto pos = line.find('=');
        if (pos == std::string::npos || pos <= prefix.size()) {
            continue;
        }
        std::string key = line.substr(prefix.size(), pos - prefix.size());
        std::string value = line.substr(pos + 1);
        if (!key.empty() && !value.empty()) {
            tags.emplace(std::move(key), std::move(value));
        }
    }
    return tags;
}

FormatInfo ProbeFormat(const std::filesystem::path& path) {
    FormatInfo info;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-show_entries", "format=duration,bit_rate",
        "-of", "default=nw=1:nk=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return info;
    }
    auto lines = SplitLines(out);
    if (lines.empty()) {
        return info;
    }
    if (!lines.empty()) {
        try {
            info.duration = std::stod(lines[0]);
        } catch (const std::exception&) {
            info.duration = 0.0;
        }
    }
    if (lines.size() >= 2) {
        try {
            info.bit_rate = static_cast<std::uint64_t>(std::stoull(lines[1]));
        } catch (const std::exception&) {
            info.bit_rate = 0;
        }
    }
    info.valid = info.duration > 0.0 || info.bit_rate > 0;
    return info;
}

struct BitrateTargets {
    std::optional<std::uint64_t> video;
    std::optional<std::uint64_t> audio;
};

BitrateTargets EstimateBitrates(const std::filesystem::path& path,
                                const VideoInfo& video,
                                const AudioInfo& audio) {
    FormatInfo fmt = ProbeFormat(path);
    std::uint64_t total_bps = fmt.bit_rate;
    if (total_bps == 0 && fmt.duration > 0.0) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(path, ec);
        if (!ec && fmt.duration > 0.0) {
            total_bps = static_cast<std::uint64_t>((bytes * 8.0) / fmt.duration);
        }
    }
    std::uint64_t video_bps = video.bit_rate;
    std::uint64_t audio_bps = audio.bit_rate;
    if (total_bps > 0) {
        std::uint64_t target_total = static_cast<std::uint64_t>(total_bps * kJmgTargetGrowth);
        std::uint64_t max_total = static_cast<std::uint64_t>(total_bps * kJmgMaxGrowth);
        if (target_total == 0) {
            target_total = total_bps;
        }
        if (target_total > max_total) {
            target_total = max_total;
        }
        if (video.valid && video_bps == 0) {
            if (audio_bps > 0) {
                video_bps = target_total > audio_bps ? (target_total - audio_bps) : target_total;
            } else {
                video_bps = std::max<std::uint64_t>(kJmgMinVideoBps, static_cast<std::uint64_t>(target_total * 0.85));
            }
        }
        if (audio.valid && audio_bps == 0) {
            audio_bps = std::max<std::uint64_t>(kJmgMinAudioBps, static_cast<std::uint64_t>(target_total * 0.15));
        }
        if (video_bps > 0) {
            video_bps = std::min(video_bps, max_total);
        }
        if (audio_bps > 0) {
            audio_bps = std::min(audio_bps, max_total);
        }
    }
    BitrateTargets targets;
    if (video.valid && video_bps > 0) {
        targets.video = video_bps;
    }
    if (audio.valid && audio_bps > 0) {
        targets.audio = audio_bps;
    }
    return targets;
}

std::filesystem::path CreateTempDir(const std::string& prefix) {
    auto base = std::filesystem::temp_directory_path();
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 64; ++i) {
        auto token = std::to_string(gen());
        auto candidate = base / (prefix + "-" + token);
        std::error_code ec;
        if (std::filesystem::create_directory(candidate, ec)) {
            return candidate;
        }
    }
    throw std::runtime_error("Failed to create temporary directory");
}

struct ProgressReporter {
    bool enabled = true;
    bool printed = false;
    bool use_ansi = false;
    std::chrono::steady_clock::time_point last_tick{};
    double last_fraction = -1.0;

    ProgressReporter() {
        const char* term = std::getenv("TERM");
        const char* no_color = std::getenv("NO_COLOR");
        use_ansi = !no_color && term && std::string(term) != "dumb";
        last_tick = std::chrono::steady_clock::now();
    }

    static std::string RenderBar(double fraction, int width = 30) {
        if (fraction < 0.0) {
            fraction = 0.0;
        } else if (fraction > 1.0) {
            fraction = 1.0;
        }
        int filled = static_cast<int>(std::round(fraction * width));
        if (filled > width) {
            filled = width;
        }
        std::string bar;
        bar.reserve(static_cast<std::size_t>(width + 2));
        bar.push_back('(');
        bar.append(static_cast<std::size_t>(filled), '#');
        bar.append(static_cast<std::size_t>(width - filled), ' ');
        bar.push_back(')');
        return bar;
    }

    void Update(double fraction, const std::string& phase, const std::filesystem::path& path) {
        if (!enabled) {
            return;
        }
        auto now = std::chrono::steady_clock::now();
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_tick);
        if (printed && delta.count() < 120 && fraction < 1.0 && std::abs(fraction - last_fraction) < 0.005) {
            return;
        }
        last_tick = now;
        last_fraction = fraction;
        int pct = static_cast<int>(std::round(fraction * 100.0));
        std::string bar = RenderBar(fraction);
        std::string name = path.filename().string();
        std::string line1 = "Overall " + bar + " " + std::to_string(pct) + "% " + phase;
        std::string line2 = "File    " + bar + " " + std::to_string(pct) + "% " + name;
        if (use_ansi) {
            if (printed) {
                std::cout << "\033[2A";
            }
            std::cout << "\r\033[2K" << line1 << "\n"
                      << "\r\033[2K" << line2 << std::flush;
        } else {
            std::cout << line1 << "\n" << line2 << std::endl;
        }
        printed = true;
    }

    void Finish() {
        if (printed) {
            std::cout << std::endl;
            printed = false;
        }
    }
};

Bytes BaseKeyFromPassword(const std::string& password) {
    Bytes material = DeriveMaterial(password);
    return Bytes(material.begin(), material.begin() + 32);
}

Bytes UnitMaterial(const Bytes& base_key, const std::string& label, std::uint64_t index, std::size_t length) {
    Bytes info(label.begin(), label.end());
    info.push_back(static_cast<std::uint8_t>((index >> 56) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 48) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 40) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 32) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 24) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 16) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 8) & 0xFF));
    info.push_back(static_cast<std::uint8_t>(index & 0xFF));
    std::string info_str(reinterpret_cast<const char*>(info.data()), info.size());
    return basefwx::crypto::HkdfSha256(info_str, base_key, length);
}

std::uint64_t SplitMix64(std::uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t x = state;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

std::vector<std::size_t> PermuteIndices(std::size_t count, std::uint64_t seed) {
    std::vector<std::size_t> order(count);
    for (std::size_t i = 0; i < count; ++i) {
        order[i] = i;
    }
    std::uint64_t state = seed;
    if (count <= 1) {
        return order;
    }
    for (std::size_t i = count - 1; i > 0; --i) {
        std::uint64_t rnd = SplitMix64(state);
        std::size_t j = static_cast<std::size_t>(rnd % (i + 1));
        if (j != i) {
            std::swap(order[i], order[j]);
        }
    }
    return order;
}

std::size_t ResolveMediaWorkers(std::size_t max_tasks) {
    const char* raw = std::getenv("BASEFWX_MEDIA_WORKERS");
    if (raw && *raw) {
        try {
            std::size_t parsed = static_cast<std::size_t>(std::stoul(raw));
            if (parsed > 0) {
                return std::min(parsed, std::max<std::size_t>(1, max_tasks));
            }
        } catch (const std::exception&) {
        }
    }
    unsigned int hw = std::thread::hardware_concurrency();
    std::size_t workers = hw > 0 ? static_cast<std::size_t>(hw) : 1;
    return std::min(workers, std::max<std::size_t>(1, max_tasks));
}

template <typename Fn>
void ParallelFor(std::size_t count, std::size_t max_workers, Fn&& fn) {
    std::size_t workers = ResolveMediaWorkers(std::min(count, max_workers));
    if (count == 0 || workers <= 1) {
        for (std::size_t i = 0; i < count; ++i) {
            fn(i);
        }
        return;
    }
    std::atomic<std::size_t> next{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (std::size_t w = 0; w < workers; ++w) {
        threads.emplace_back([&]() {
            while (true) {
                std::size_t idx = next.fetch_add(1);
                if (idx >= count) {
                    break;
                }
                fn(idx);
            }
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}

Bytes ShuffleFrameBlocks(const Bytes& frame,
                         int width,
                         int height,
                         int channels,
                         std::uint64_t seed,
                         int block_size) {
    int blocks_x = (width + block_size - 1) / block_size;
    int blocks_y = (height + block_size - 1) / block_size;
    std::size_t total_blocks = static_cast<std::size_t>(blocks_x) * static_cast<std::size_t>(blocks_y);
    auto perm = PermuteIndices(total_blocks, seed);
    Bytes out(frame.size());
    for (std::size_t dest_idx = 0; dest_idx < total_blocks; ++dest_idx) {
        std::size_t src_idx = perm[dest_idx];
        int dx = static_cast<int>(dest_idx % blocks_x) * block_size;
        int dy = static_cast<int>(dest_idx / blocks_x) * block_size;
        int sx = static_cast<int>(src_idx % blocks_x) * block_size;
        int sy = static_cast<int>(src_idx / blocks_x) * block_size;
        int copy_w = std::min(block_size, width - dx);
        copy_w = std::min(copy_w, width - sx);
        int copy_h = std::min(block_size, height - dy);
        copy_h = std::min(copy_h, height - sy);
        for (int row = 0; row < copy_h; ++row) {
            std::size_t src_off = static_cast<std::size_t>(((sy + row) * width + sx) * channels);
            std::size_t dst_off = static_cast<std::size_t>(((dy + row) * width + dx) * channels);
            std::size_t span = static_cast<std::size_t>(copy_w * channels);
            std::memcpy(out.data() + dst_off, frame.data() + src_off, span);
        }
    }
    return out;
}

Bytes UnshuffleFrameBlocks(const Bytes& frame,
                           int width,
                           int height,
                           int channels,
                           std::uint64_t seed,
                           int block_size) {
    int blocks_x = (width + block_size - 1) / block_size;
    int blocks_y = (height + block_size - 1) / block_size;
    std::size_t total_blocks = static_cast<std::size_t>(blocks_x) * static_cast<std::size_t>(blocks_y);
    auto perm = PermuteIndices(total_blocks, seed);
    Bytes out(frame.size());
    for (std::size_t dest_idx = 0; dest_idx < total_blocks; ++dest_idx) {
        std::size_t src_idx = perm[dest_idx];
        int dx = static_cast<int>(dest_idx % blocks_x) * block_size;
        int dy = static_cast<int>(dest_idx / blocks_x) * block_size;
        int sx = static_cast<int>(src_idx % blocks_x) * block_size;
        int sy = static_cast<int>(src_idx / blocks_x) * block_size;
        int copy_w = std::min(block_size, width - dx);
        copy_w = std::min(copy_w, width - sx);
        int copy_h = std::min(block_size, height - dy);
        copy_h = std::min(copy_h, height - sy);
        for (int row = 0; row < copy_h; ++row) {
            std::size_t src_off = static_cast<std::size_t>(((dy + row) * width + dx) * channels);
            std::size_t dst_off = static_cast<std::size_t>(((sy + row) * width + sx) * channels);
            std::size_t span = static_cast<std::size_t>(copy_w * channels);
            std::memcpy(out.data() + dst_off, frame.data() + src_off, span);
        }
    }
    return out;
}

Bytes AudioMaskTransform(const Bytes& data, const Bytes& key, const Bytes& iv) {
    if (data.empty()) {
        return {};
    }
    Bytes zeros(data.size(), 0);
    Bytes stream = basefwx::crypto::AesCtrTransform(key, iv, zeros);
    Bytes out = data;
    constexpr std::uint16_t kAudioMaskBits = 13;
    constexpr std::uint16_t mask = static_cast<std::uint16_t>((1u << kAudioMaskBits) - 1u);
    std::size_t samples = out.size() / 2;
    for (std::size_t i = 0; i < samples; ++i) {
        std::size_t off = i * 2;
        std::uint16_t sample = static_cast<std::uint16_t>(out[off])
                               | static_cast<std::uint16_t>(out[off + 1] << 8);
        std::uint16_t ks = static_cast<std::uint16_t>(stream[off])
                           | static_cast<std::uint16_t>(stream[off + 1] << 8);
        std::uint16_t mixed = static_cast<std::uint16_t>(sample ^ (ks & mask));
        out[off] = static_cast<std::uint8_t>(mixed & 0xFFu);
        out[off + 1] = static_cast<std::uint8_t>((mixed >> 8) & 0xFFu);
    }
    return out;
}

Bytes VideoMaskTransform(const Bytes& data, const Bytes& key, const Bytes& iv) {
    if (data.empty()) {
        return {};
    }
    Bytes zeros(data.size(), 0);
    Bytes stream = basefwx::crypto::AesCtrTransform(key, iv, zeros);
    Bytes out = data;
    constexpr std::uint8_t kVideoMaskBits = 6;
    constexpr std::uint8_t mask = static_cast<std::uint8_t>((1u << kVideoMaskBits) - 1u);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(out[i] ^ (stream[i] & mask));
    }
    return out;
}

Bytes ShuffleAudioSamples(const Bytes& block, std::uint64_t seed, bool inverse) {
    if (block.empty()) {
        return block;
    }
    std::size_t samples = block.size() / 2;
    if (samples <= 1) {
        return block;
    }
    auto perm = PermuteIndices(samples, seed);
    Bytes out(block.size());
    if (!inverse) {
        for (std::size_t dest_idx = 0; dest_idx < samples; ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            std::size_t src_off = src_idx * 2;
            std::size_t dst_off = dest_idx * 2;
            out[dst_off] = block[src_off];
            out[dst_off + 1] = block[src_off + 1];
        }
    } else {
        for (std::size_t dest_idx = 0; dest_idx < samples; ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            std::size_t src_off = src_idx * 2;
            std::size_t dst_off = dest_idx * 2;
            out[src_off] = block[dst_off];
            out[src_off + 1] = block[dst_off + 1];
        }
    }
    if (block.size() % 2) {
        out.back() = block.back();
    }
    return out;
}

void ScrambleVideoRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const VideoInfo& video,
                      const Bytes& base_key,
                      const std::function<void(double)>& progress_cb = {}) {
    std::size_t frame_size = static_cast<std::size_t>(video.width) * static_cast<std::size_t>(video.height) * 3u;
    if (frame_size == 0) {
        throw std::runtime_error("Invalid video dimensions");
    }
    int group_frames = static_cast<int>(std::max(2.0, std::round((video.fps > 0.0 ? video.fps : 30.0) * 1.0)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw video buffers");
    }
    std::uint64_t frame_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_frames = 0;
    std::uint64_t total_frames = 0;
    if (progress_cb) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec && frame_size > 0) {
            total_frames = static_cast<std::uint64_t>(bytes / frame_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = frame_index;
        std::vector<Bytes> frames;
        frames.reserve(static_cast<std::size_t>(group_frames));
        for (int i = 0; i < group_frames; ++i) {
            Bytes frame(frame_size);
            input.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
            if (input.gcount() != static_cast<std::streamsize>(frame.size())) {
                break;
            }
            frames.push_back(std::move(frame));
            ++frame_index;
        }
        if (frames.empty()) {
            break;
        }
        std::vector<Bytes> processed(frames.size());
        ParallelFor(frames.size(), static_cast<std::size_t>(group_frames), [&](std::size_t idx) {
            std::uint64_t frame_id = group_start_index + idx;
            Bytes material = UnitMaterial(base_key, "jmg-frame", frame_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            Bytes masked = VideoMaskTransform(frames[idx], key, iv);
            Bytes seed_bytes = UnitMaterial(base_key, "jmg-fblk", frame_id, 16);
            std::uint64_t seed = 0;
            for (std::uint8_t b : seed_bytes) {
                seed = (seed << 8) | b;
            }
            processed[idx] = ShuffleFrameBlocks(masked, video.width, video.height, 3, seed, 2);
        });
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, "jmg-fgrp", seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(processed.size(), seed);
        for (auto idx : perm) {
            output.write(reinterpret_cast<const char*>(processed[idx].data()),
                         static_cast<std::streamsize>(processed[idx].size()));
        }
        processed_frames += processed.size();
        if (progress_cb && total_frames > 0) {
            double frac = static_cast<double>(processed_frames) / static_cast<double>(total_frames);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        ++group_index;
    }
}

void ScrambleAudioRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const AudioInfo& audio,
                      const Bytes& base_key,
                      const std::function<void(double)>& progress_cb = {}) {
    constexpr double kAudioBlockSeconds = 0.15;
    constexpr double kAudioGroupSeconds = 1.0;
    int samples_per_block = std::max(1, static_cast<int>(std::round(audio.sample_rate * kAudioBlockSeconds)));
    std::size_t block_size = static_cast<std::size_t>(samples_per_block * audio.channels * 2);
    int group_blocks = std::max(2, static_cast<int>(std::round(kAudioGroupSeconds / kAudioBlockSeconds)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw audio buffers");
    }
    std::uint64_t block_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_blocks = 0;
    std::uint64_t total_blocks = 0;
    if (progress_cb && block_size > 0) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec) {
            total_blocks = static_cast<std::uint64_t>((bytes + block_size - 1) / block_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = block_index;
        std::vector<Bytes> blocks;
        blocks.reserve(static_cast<std::size_t>(group_blocks));
        for (int i = 0; i < group_blocks; ++i) {
            Bytes block(block_size);
            input.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(block.size()));
            if (input.gcount() == 0) {
                break;
            }
            block.resize(static_cast<std::size_t>(input.gcount()));
            blocks.push_back(std::move(block));
            ++block_index;
        }
        if (blocks.empty()) {
            break;
        }
        std::vector<Bytes> processed(blocks.size());
        ParallelFor(blocks.size(), static_cast<std::size_t>(group_blocks), [&](std::size_t idx) {
            std::uint64_t block_id = group_start_index + idx;
            Bytes material = UnitMaterial(base_key, "jmg-ablock", block_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            Bytes masked = AudioMaskTransform(blocks[idx], key, iv);
            Bytes seed_bytes = UnitMaterial(base_key, "jmg-asamp", block_id, 16);
            std::uint64_t seed = 0;
            for (std::uint8_t b : seed_bytes) {
                seed = (seed << 8) | b;
            }
            processed[idx] = ShuffleAudioSamples(masked, seed, false);
        });
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, "jmg-agrp", seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(processed.size(), seed);
        for (auto idx : perm) {
            output.write(reinterpret_cast<const char*>(processed[idx].data()),
                         static_cast<std::streamsize>(processed[idx].size()));
        }
        processed_blocks += processed.size();
        if (progress_cb && total_blocks > 0) {
            double frac = static_cast<double>(processed_blocks) / static_cast<double>(total_blocks);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        ++group_index;
    }
}

void UnscrambleVideoRaw(const std::filesystem::path& raw_in,
                        const std::filesystem::path& raw_out,
                        const VideoInfo& video,
                        const Bytes& base_key,
                        const std::function<void(double)>& progress_cb = {}) {
    std::size_t frame_size = static_cast<std::size_t>(video.width) * static_cast<std::size_t>(video.height) * 3u;
    if (frame_size == 0) {
        throw std::runtime_error("Invalid video dimensions");
    }
    int group_frames = static_cast<int>(std::max(2.0, std::round((video.fps > 0.0 ? video.fps : 30.0) * 1.0)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw video buffers");
    }
    std::uint64_t frame_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_frames = 0;
    std::uint64_t total_frames = 0;
    if (progress_cb) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec && frame_size > 0) {
            total_frames = static_cast<std::uint64_t>(bytes / frame_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = frame_index;
        std::vector<Bytes> frames;
        frames.reserve(static_cast<std::size_t>(group_frames));
        for (int i = 0; i < group_frames; ++i) {
            Bytes frame(frame_size);
            input.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
            if (input.gcount() != static_cast<std::streamsize>(frame.size())) {
                break;
            }
            frames.push_back(std::move(frame));
        }
        if (frames.empty()) {
            break;
        }
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, "jmg-fgrp", seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(frames.size(), seed);
        std::vector<Bytes> ordered(frames.size());
        for (std::size_t dest_idx = 0; dest_idx < perm.size(); ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            ordered[src_idx] = std::move(frames[dest_idx]);
        }
        std::vector<Bytes> restored(ordered.size());
        ParallelFor(ordered.size(), static_cast<std::size_t>(group_frames), [&](std::size_t idx) {
            std::uint64_t frame_id = group_start_index + idx;
            Bytes seed_bytes_local = UnitMaterial(base_key, "jmg-fblk", frame_id, 16);
            std::uint64_t seed_local = 0;
            for (std::uint8_t b : seed_bytes_local) {
                seed_local = (seed_local << 8) | b;
            }
            Bytes unshuffled = UnshuffleFrameBlocks(ordered[idx], video.width, video.height, 3, seed_local, 2);
            Bytes material = UnitMaterial(base_key, "jmg-frame", frame_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            restored[idx] = VideoMaskTransform(unshuffled, key, iv);
        });
        for (const auto& frame : restored) {
            output.write(reinterpret_cast<const char*>(frame.data()),
                         static_cast<std::streamsize>(frame.size()));
        }
        processed_frames += restored.size();
        if (progress_cb && total_frames > 0) {
            double frac = static_cast<double>(processed_frames) / static_cast<double>(total_frames);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        frame_index += restored.size();
        ++group_index;
    }
}

void UnscrambleAudioRaw(const std::filesystem::path& raw_in,
                        const std::filesystem::path& raw_out,
                        const AudioInfo& audio,
                        const Bytes& base_key,
                        const std::function<void(double)>& progress_cb = {}) {
    constexpr double kAudioBlockSeconds = 0.15;
    constexpr double kAudioGroupSeconds = 1.0;
    int samples_per_block = std::max(1, static_cast<int>(std::round(audio.sample_rate * kAudioBlockSeconds)));
    std::size_t block_size = static_cast<std::size_t>(samples_per_block * audio.channels * 2);
    int group_blocks = std::max(2, static_cast<int>(std::round(kAudioGroupSeconds / kAudioBlockSeconds)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw audio buffers");
    }
    std::uint64_t block_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_blocks = 0;
    std::uint64_t total_blocks = 0;
    if (progress_cb && block_size > 0) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec) {
            total_blocks = static_cast<std::uint64_t>((bytes + block_size - 1) / block_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = block_index;
        std::vector<Bytes> blocks;
        blocks.reserve(static_cast<std::size_t>(group_blocks));
        for (int i = 0; i < group_blocks; ++i) {
            Bytes block(block_size);
            input.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(block.size()));
            if (input.gcount() == 0) {
                break;
            }
            block.resize(static_cast<std::size_t>(input.gcount()));
            blocks.push_back(std::move(block));
        }
        if (blocks.empty()) {
            break;
        }
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, "jmg-agrp", seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(blocks.size(), seed);
        std::vector<Bytes> ordered(blocks.size());
        for (std::size_t dest_idx = 0; dest_idx < perm.size(); ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            ordered[src_idx] = std::move(blocks[dest_idx]);
        }
        std::vector<Bytes> restored(ordered.size());
        ParallelFor(ordered.size(), static_cast<std::size_t>(group_blocks), [&](std::size_t idx) {
            std::uint64_t block_id = group_start_index + idx;
            Bytes seed_bytes_local = UnitMaterial(base_key, "jmg-asamp", block_id, 16);
            std::uint64_t seed_local = 0;
            for (std::uint8_t b : seed_bytes_local) {
                seed_local = (seed_local << 8) | b;
            }
            Bytes unshuffled = ShuffleAudioSamples(ordered[idx], seed_local, true);
            Bytes material = UnitMaterial(base_key, "jmg-ablock", block_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            restored[idx] = AudioMaskTransform(unshuffled, key, iv);
        });
        for (const auto& block : restored) {
            output.write(reinterpret_cast<const char*>(block.data()),
                         static_cast<std::streamsize>(block.size()));
        }
        processed_blocks += restored.size();
        if (progress_cb && total_blocks > 0) {
            double frac = static_cast<double>(processed_blocks) / static_cast<double>(total_blocks);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        block_index += restored.size();
        ++group_index;
    }
}

std::vector<std::string> EncryptMetadataArgs(const std::map<std::string, std::string>& tags,
                                             const std::string& password) {
    std::vector<std::string> args;
    for (const auto& kv : tags) {
        try {
            std::string enc = basefwx::pb512::B512Encode(kv.second, password, false, {});
            args.push_back(kv.first + "=" + enc);
        } catch (const std::exception&) {
        }
    }
    return args;
}

std::vector<std::string> DecryptMetadataArgs(const std::map<std::string, std::string>& tags,
                                             const std::string& password) {
    std::vector<std::string> args;
    for (const auto& kv : tags) {
        try {
            std::string dec = basefwx::pb512::B512Decode(kv.second, password, false, {});
            args.push_back(kv.first + "=" + dec);
        } catch (const std::exception&) {
        }
    }
    return args;
}

bool IsImageExt(const std::filesystem::path& path) {
    static const std::set<std::string> exts = {
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp", ".tif", ".tiff", ".heic", ".heif", ".avif", ".ico"
    };
    std::string ext = ToLower(path.extension().string());
    return exts.count(ext) > 0;
}

std::vector<std::string> VideoCodecArgs(const std::filesystem::path& output_path,
                                        std::optional<std::uint64_t> target_bps) {
    std::string ext = ToLower(output_path.extension().string());
    if (ext == ".webm") {
        if (target_bps.has_value()) {
            std::uint64_t kbps = std::max<std::uint64_t>(100, target_bps.value() / 1000);
            return {"-c:v", "libvpx-vp9", "-b:v", std::to_string(kbps) + "k", "-crf", "33", "-pix_fmt", "yuv420p"};
        }
        return {"-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "32", "-pix_fmt", "yuv420p"};
    }
    if (target_bps.has_value()) {
        std::uint64_t kbps = std::max<std::uint64_t>(100, target_bps.value() / 1000);
        return {
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-b:v", std::to_string(kbps) + "k",
            "-maxrate", std::to_string(kbps) + "k",
            "-bufsize", std::to_string(kbps * 2) + "k",
            "-pix_fmt", "yuv420p"
        };
    }
    return {"-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p"};
}

std::vector<std::string> AudioCodecArgs(const std::filesystem::path& output_path,
                                        std::optional<std::uint64_t> target_bps) {
    std::string ext = ToLower(output_path.extension().string());
    std::uint64_t kbps = 0;
    if (target_bps.has_value()) {
        kbps = std::max<std::uint64_t>(48, target_bps.value() / 1000);
    }
    if (ext == ".mp3") {
        return {"-c:a", "libmp3lame", "-b:a", std::to_string(kbps > 0 ? kbps : 192) + "k"};
    }
    if (ext == ".flac") {
        return {"-c:a", "flac"};
    }
    if (ext == ".wav" || ext == ".aiff" || ext == ".aif") {
        return {"-c:a", "pcm_s16le"};
    }
    if (ext == ".ogg" || ext == ".opus" || ext == ".webm") {
        return {"-c:a", "libopus", "-b:a", std::to_string(kbps > 0 ? kbps : 96) + "k"};
    }
    if (ext == ".m4a" || ext == ".aac") {
        return {"-c:a", "aac", "-b:a", std::to_string(kbps > 0 ? kbps : 160) + "k"};
    }
    return {"-c:a", "aac", "-b:a", std::to_string(kbps > 0 ? kbps : 160) + "k"};
}

std::vector<std::string> ContainerArgs(const std::filesystem::path& output_path) {
    std::string ext = ToLower(output_path.extension().string());
    if (ext == ".mp4" || ext == ".m4v" || ext == ".mov" || ext == ".m4a") {
        return {"-movflags", "+faststart"};
    }
    return {};
}

}  // namespace

std::string EncryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool keep_meta,
                         bool keep_input) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password is required for media encryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }
    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    std::filesystem::path temp_output = output_path;
    if (NormalizePath(output_path.string()) == NormalizePath(input_path.string())) {
        temp_output = output_path.parent_path() / (output_path.stem().string() + "._jmg" + output_path.extension().string());
    }
    if (IsImageExt(input_path)) {
        std::string result = EncryptImageInv(input_path.string(), resolved, temp_output.string(), true);
        std::filesystem::path result_path = NormalizePath(result);
        if (result_path != temp_output) {
            temp_output = result_path;
        }
        if (NormalizePath(output_path.string()) != NormalizePath(temp_output.string())) {
            std::filesystem::rename(temp_output, output_path);
            temp_output = output_path;
        }
        if (!keep_input && NormalizePath(output_path.string()) != NormalizePath(input_path.string())) {
            std::error_code ec;
            std::filesystem::remove(input_path, ec);
        }
        return temp_output.string();
    }

    ProgressReporter progress;
    VideoInfo video;
    AudioInfo audio;
    try {
        video = ProbeVideo(input_path);
        audio = ProbeAudio(input_path);
    } catch (const std::exception&) {
        video.valid = false;
        audio.valid = false;
    }
    if (!video.valid && !audio.valid) {
        std::filesystem::path fallback_out = output.empty()
            ? input_path.parent_path() / (input_path.stem().string() + ".fwx")
            : output_path;
        basefwx::fwxaes::EncryptFile(input_path.string(), fallback_out.string(), resolved, {}, {}, {}, keep_input);
        return fallback_out.string();
    }

    BitrateTargets targets = EstimateBitrates(input_path, video, audio);
    std::filesystem::path temp_dir = CreateTempDir("basefwx-media");
    try {
        std::filesystem::path raw_video = temp_dir / "video.raw";
        std::filesystem::path raw_video_out = temp_dir / "video.scr.raw";
        std::filesystem::path raw_audio = temp_dir / "audio.raw";
        std::filesystem::path raw_audio_out = temp_dir / "audio.scr.raw";
        if (video.valid) {
            progress.Update(0.05, "decode-video", input_path);
            RunCommand({
                "ffmpeg", "-y", "-i", input_path.string(),
                "-map", "0:v:0",
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                raw_video.string()
            });
        }
        if (audio.valid) {
            progress.Update(0.15, "decode-audio", input_path);
            RunCommand({
                "ffmpeg", "-y", "-i", input_path.string(),
                "-map", "0:a:0",
                "-f", "s16le",
                "-acodec", "pcm_s16le",
                "-ar", std::to_string(audio.sample_rate),
                "-ac", std::to_string(audio.channels),
                raw_audio.string()
            });
        }

        Bytes base_key = BaseKeyFromPassword(resolved);
        if (video.valid) {
            auto video_cb = [&](double frac) {
                progress.Update(0.25 + 0.45 * frac, "jmg-video", input_path);
            };
            ScrambleVideoRaw(raw_video, raw_video_out, video, base_key, video_cb);
        }
        if (audio.valid) {
            auto audio_cb = [&](double frac) {
                progress.Update(0.70 + 0.20 * frac, "jmg-audio", input_path);
            };
            ScrambleAudioRaw(raw_audio, raw_audio_out, audio, base_key, audio_cb);
        }

        std::vector<std::string> cmd = {
            "ffmpeg", "-y"
        };
        if (video.valid) {
            cmd.insert(cmd.end(), {
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                "-s", std::to_string(video.width) + "x" + std::to_string(video.height),
                "-r", std::to_string(video.fps > 0.0 ? video.fps : 30.0),
                "-i", raw_video_out.string()
            });
        }
        if (audio.valid) {
            cmd.insert(cmd.end(), {
                "-f", "s16le",
                "-ar", std::to_string(audio.sample_rate),
                "-ac", std::to_string(audio.channels),
                "-i", raw_audio_out.string(),
                "-shortest"
            });
        }
        if (keep_meta) {
            auto tags = ProbeMetadata(input_path);
            for (const auto& meta : EncryptMetadataArgs(tags, resolved)) {
                cmd.push_back("-metadata");
                cmd.push_back(meta);
            }
        } else {
            cmd.push_back("-map_metadata");
            cmd.push_back("-1");
        }
        if (video.valid) {
            auto v_args = VideoCodecArgs(temp_output, targets.video);
            cmd.insert(cmd.end(), v_args.begin(), v_args.end());
        }
        if (audio.valid) {
            auto a_args = AudioCodecArgs(temp_output, targets.audio);
            cmd.insert(cmd.end(), a_args.begin(), a_args.end());
        }
        auto c_args = ContainerArgs(temp_output);
        cmd.insert(cmd.end(), c_args.begin(), c_args.end());
        cmd.push_back(temp_output.string());
        progress.Update(0.95, "encode", input_path);
        RunCommand(cmd);
        auto archive_cb = [&](double frac) {
            progress.Update(0.95 + 0.04 * frac, "archive", input_path);
        };
        AppendTrailerStream(temp_output, input_path, resolved, archive_cb);
        progress.Update(1.0, "done", input_path);
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir, ec);
        throw;
    }
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    if (NormalizePath(output_path.string()) != NormalizePath(temp_output.string())) {
        std::filesystem::rename(temp_output, output_path);
        temp_output = output_path;
    }
    if (!keep_input && NormalizePath(output_path.string()) != NormalizePath(input_path.string())) {
        std::filesystem::remove(input_path, ec);
    }
    progress.Finish();
    return temp_output.string();
}

std::string DecryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password is required for media decryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }
    if (IsImageExt(input_path)) {
        return DecryptImageInv(input_path.string(), resolved, output);
    }

    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    std::filesystem::path temp_output = output_path;
    std::error_code ec;
    if (std::filesystem::equivalent(output_path, input_path, ec)) {
        temp_output = output_path.parent_path() / (output_path.stem().string() + "._jmgdec" + output_path.extension().string());
    }

    ProgressReporter progress;
    auto trailer_cb = [&](double frac) {
        progress.Update(0.05 + 0.90 * frac, "archive", input_path);
    };
    if (TryDecryptTrailerStream(input_path, resolved, temp_output, trailer_cb)) {
        progress.Update(1.0, "done", input_path);
        if (!output_path.empty() && !std::filesystem::equivalent(output_path, temp_output, ec)) {
            std::filesystem::rename(temp_output, output_path);
            temp_output = output_path;
        }
        progress.Finish();
        return temp_output.string();
    }
    std::uint64_t fallback_limit = 64ull * 1024ull * 1024ull;
    auto file_size = std::filesystem::file_size(input_path, ec);
    if (!ec && file_size <= fallback_limit) {
        Bytes file_bytes = ReadFileBytes(input_path);
        Bytes payload;
        Bytes trailer;
        bool has_trailer = ExtractTrailer(file_bytes, payload, trailer);
        if (has_trailer && !trailer.empty()) {
            Bytes material = DeriveMaterial(resolved);
            Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo, material, 32);
            Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
                      basefwx::constants::kImageCipherArchiveInfo.end());
            Bytes original_bytes = basefwx::crypto::AeadDecrypt(archive_key, trailer, aad);
            WriteFileBytes(temp_output, original_bytes);
            progress.Update(1.0, "done", input_path);
            if (!output_path.empty() && !std::filesystem::equivalent(output_path, temp_output, ec)) {
                std::filesystem::rename(temp_output, output_path);
                temp_output = output_path;
            }
            progress.Finish();
            return temp_output.string();
        }
    }

    VideoInfo video;
    AudioInfo audio;
    try {
        video = ProbeVideo(input_path);
        audio = ProbeAudio(input_path);
    } catch (const std::exception&) {
        video.valid = false;
        audio.valid = false;
    }
    if (!video.valid && !audio.valid) {
        bool can_fwx = input_path.extension() == ".fwx";
        if (!can_fwx) {
            std::ifstream probe(input_path, std::ios::binary);
            char magic[4] = {};
            if (probe.read(magic, sizeof(magic))) {
                can_fwx = std::string_view(magic, sizeof(magic)) == "FWX1";
            }
        }
        if (can_fwx) {
            std::filesystem::path fallback_out = output.empty()
                ? input_path.parent_path() / input_path.stem()
                : output_path;
            basefwx::fwxaes::DecryptFile(input_path.string(), fallback_out.string(), resolved);
            return fallback_out.string();
        }
        throw std::runtime_error("Unsupported media format");
    }

    BitrateTargets targets = EstimateBitrates(input_path, video, audio);
    std::filesystem::path temp_dir = CreateTempDir("basefwx-media");
    try {
        std::filesystem::path raw_video = temp_dir / "video.raw";
        std::filesystem::path raw_video_out = temp_dir / "video.unscr.raw";
        std::filesystem::path raw_audio = temp_dir / "audio.raw";
        std::filesystem::path raw_audio_out = temp_dir / "audio.unscr.raw";
        if (video.valid) {
            progress.Update(0.05, "decode-video", input_path);
            RunCommand({
                "ffmpeg", "-y", "-i", input_path.string(),
                "-map", "0:v:0",
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                raw_video.string()
            });
        }
        if (audio.valid) {
            progress.Update(0.15, "decode-audio", input_path);
            RunCommand({
                "ffmpeg", "-y", "-i", input_path.string(),
                "-map", "0:a:0",
                "-f", "s16le",
                "-acodec", "pcm_s16le",
                "-ar", std::to_string(audio.sample_rate),
                "-ac", std::to_string(audio.channels),
                raw_audio.string()
            });
        }

        Bytes base_key = BaseKeyFromPassword(resolved);
        if (video.valid) {
            auto video_cb = [&](double frac) {
                progress.Update(0.25 + 0.45 * frac, "unjmg-video", input_path);
            };
            UnscrambleVideoRaw(raw_video, raw_video_out, video, base_key, video_cb);
        }
        if (audio.valid) {
            auto audio_cb = [&](double frac) {
                progress.Update(0.70 + 0.20 * frac, "unjmg-audio", input_path);
            };
            UnscrambleAudioRaw(raw_audio, raw_audio_out, audio, base_key, audio_cb);
        }

        std::vector<std::string> cmd = {
            "ffmpeg", "-y"
        };
        if (video.valid) {
            cmd.insert(cmd.end(), {
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                "-s", std::to_string(video.width) + "x" + std::to_string(video.height),
                "-r", std::to_string(video.fps > 0.0 ? video.fps : 30.0),
                "-i", raw_video_out.string()
            });
        }
        if (audio.valid) {
            cmd.insert(cmd.end(), {
                "-f", "s16le",
                "-ar", std::to_string(audio.sample_rate),
                "-ac", std::to_string(audio.channels),
                "-i", raw_audio_out.string(),
                "-shortest"
            });
        }
        auto tags = ProbeMetadata(input_path);
        auto decoded = DecryptMetadataArgs(tags, resolved);
        if (!decoded.empty()) {
            for (const auto& meta : decoded) {
                cmd.push_back("-metadata");
                cmd.push_back(meta);
            }
        } else {
            cmd.push_back("-map_metadata");
            cmd.push_back("-1");
        }
        if (video.valid) {
            auto v_args = VideoCodecArgs(temp_output, targets.video);
            cmd.insert(cmd.end(), v_args.begin(), v_args.end());
        }
        if (audio.valid) {
            auto a_args = AudioCodecArgs(temp_output, targets.audio);
            cmd.insert(cmd.end(), a_args.begin(), a_args.end());
        }
        auto c_args = ContainerArgs(temp_output);
        cmd.insert(cmd.end(), c_args.begin(), c_args.end());
        cmd.push_back(temp_output.string());
        progress.Update(0.95, "encode", input_path);
        RunCommand(cmd);
        progress.Update(1.0, "done", input_path);
    } catch (...) {
        std::filesystem::remove_all(temp_dir, ec);
        throw;
    }
    std::filesystem::remove_all(temp_dir, ec);

    if (!output_path.empty() && !std::filesystem::equivalent(output_path, temp_output, ec)) {
        std::filesystem::rename(temp_output, output_path);
        temp_output = output_path;
    }
    progress.Finish();
    return temp_output.string();
}

}  // namespace basefwx::imagecipher
