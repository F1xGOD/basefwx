/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx_kfm_internal.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <openssl/evp.h>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <zlib.h>

namespace basefwx::internal {

std::uint64_t Mix64(std::uint64_t value) {
    value += 0x9E3779B97F4A7C15ULL;
    value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31U);
}
void WriteU32BE(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void WriteU64BE(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
}

std::uint32_t ReadU32BE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("kFM header truncated");
    }
    return (static_cast<std::uint32_t>(data[offset]) << 24)
         | (static_cast<std::uint32_t>(data[offset + 1]) << 16)
         | (static_cast<std::uint32_t>(data[offset + 2]) << 8)
         | static_cast<std::uint32_t>(data[offset + 3]);
}

std::uint64_t ReadU64BE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 8 > data.size()) {
        throw std::runtime_error("kFM header truncated");
    }
    std::uint64_t out = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        out = (out << 8) | static_cast<std::uint64_t>(data[offset + i]);
    }
    return out;
}

std::uint32_t ReadU32LE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("kFM wav chunk truncated");
    }
    return static_cast<std::uint32_t>(data[offset])
         | (static_cast<std::uint32_t>(data[offset + 1]) << 8)
         | (static_cast<std::uint32_t>(data[offset + 2]) << 16)
         | (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint16_t ReadU16LE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 2 > data.size()) {
        throw std::runtime_error("kFM wav chunk truncated");
    }
    return static_cast<std::uint16_t>(data[offset])
         | static_cast<std::uint16_t>(data[offset + 1] << 8);
}

void WriteU16LE(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void WriteU32LE(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
}

std::string CleanKfmExt(std::string ext) {
    if (ext.empty()) {
        return ".bin";
    }
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (ext.front() != '.') {
        ext.insert(ext.begin(), '.');
    }
    if (ext.size() > 24) {
        return ".bin";
    }
    for (char ch : ext) {
        bool ok = (ch == '.') || (ch == '_') || (ch == '-')
            || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (!ok) {
            return ".bin";
        }
    }
    return ext;
}

std::string KfmPathExt(const std::filesystem::path& path) {
    return CleanKfmExt(path.has_extension() ? path.extension().string() : "");
}

bool IsKnownKfmAudioExt(const std::string& ext) {
    static constexpr std::array<std::string_view, 16> kAudioExts = {
        ".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus",
        ".wma", ".amr", ".aiff", ".aif", ".alac", ".m4b", ".caf", ".mka",
    };
    for (std::string_view value : kAudioExts) {
        if (ext == value) {
            return true;
        }
    }
    return false;
}

bool IsKnownKfmImageExt(const std::string& ext) {
    static constexpr std::array<std::string_view, 13> kImageExts = {
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif",
        ".tiff", ".ico", ".heic", ".heif", ".ppm", ".pgm",
    };
    for (std::string_view value : kImageExts) {
        if (ext == value) {
            return true;
        }
    }
    return false;
}

void WarnKfmUsage(const std::string& message) {
    if (basefwx::env::IsEnabled("BASEFWX_NO_LOG", false)) {
        return;
    }
    std::cerr << "WARN: " << message << "\n";
}

std::vector<std::uint8_t> KfmKeystream(std::uint64_t seed, std::size_t length) {
    std::vector<std::uint8_t> out(length);
    if (length == 0) {
        return out;
    }
    std::array<std::uint8_t, 16> seed_counter{};
    for (int i = 0; i < 8; ++i) {
        seed_counter[7 - i] = static_cast<std::uint8_t>((seed >> (i * 8)) & 0xFFu);
    }
    std::size_t offset = 0;
    std::uint64_t counter = 0;
    while (offset < length) {
        for (int i = 0; i < 8; ++i) {
            seed_counter[15 - i] = static_cast<std::uint8_t>((counter >> (i * 8)) & 0xFFu);
        }
        unsigned int digest_len = 0;
        std::array<std::uint8_t, 32> digest{};
        if (EVP_Digest(seed_counter.data(), seed_counter.size(), digest.data(), &digest_len, EVP_sha256(), nullptr) != 1
            || digest_len == 0) {
            throw std::runtime_error("kFM keystream digest failed");
        }
        std::size_t take = std::min<std::size_t>(digest_len, length - offset);
        std::memcpy(out.data() + offset, digest.data(), take);
        offset += take;
        ++counter;
    }
    return out;
}

void XorInPlace(std::vector<std::uint8_t>& target, const std::vector<std::uint8_t>& mask) {
    if (target.size() != mask.size()) {
        throw std::runtime_error("kFM mask length mismatch");
    }
    for (std::size_t i = 0; i < target.size(); ++i) {
        target[i] ^= mask[i];
    }
}

std::uint64_t RandomSeed64() {
    auto bytes = basefwx::crypto::RandomBytes(8);
    std::uint64_t seed = 0;
    for (std::uint8_t byte : bytes) {
        seed = (seed << 8) | static_cast<std::uint64_t>(byte);
    }
    return seed;
}

std::vector<std::uint8_t> BuildKfmContainer(std::uint8_t mode,
                                            const std::vector<std::uint8_t>& payload,
                                            const std::string& ext,
                                            std::uint8_t flags) {
    if (mode != kKfmModeImageAudio && mode != kKfmModeAudioImage) {
        throw std::runtime_error("kFM mode is invalid");
    }
    if (payload.size() > kKfmMaxPayload) {
        throw std::runtime_error("kFM payload is too large");
    }
    std::string cleaned_ext = CleanKfmExt(ext);
    std::vector<std::uint8_t> ext_bytes(cleaned_ext.begin(), cleaned_ext.end());
    if (ext_bytes.size() > 255) {
        ext_bytes.assign({'.', 'b', 'i', 'n'});
    }

    std::vector<std::uint8_t> body;
    body.reserve(ext_bytes.size() + payload.size());
    body.insert(body.end(), ext_bytes.begin(), ext_bytes.end());
    body.insert(body.end(), payload.begin(), payload.end());

    std::uint64_t seed = RandomSeed64();
    auto mask = KfmKeystream(seed, body.size());
    XorInPlace(body, mask);
    std::uint32_t crc = crc32(0L, payload.data(), static_cast<uInt>(payload.size()));

    std::vector<std::uint8_t> out;
    out.reserve(kKfmHeaderLen + body.size());
    out.insert(out.end(), kKfmMagic.begin(), kKfmMagic.end());
    out.push_back(kKfmVersion);
    out.push_back(mode);
    out.push_back(flags);
    out.push_back(static_cast<std::uint8_t>(ext_bytes.size()));
    WriteU64BE(out, static_cast<std::uint64_t>(payload.size()));
    WriteU32BE(out, crc);
    WriteU64BE(out, seed);
    WriteU32BE(out, 0u);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

std::optional<KfmDecoded> ParseKfmContainer(const std::vector<std::uint8_t>& blob) {
    if (blob.size() < kKfmHeaderLen) {
        return std::nullopt;
    }
    if (!std::equal(kKfmMagic.begin(), kKfmMagic.end(), blob.begin())) {
        return std::nullopt;
    }
    std::uint8_t version = blob[4];
    std::uint8_t mode = blob[5];
    std::uint8_t flags = blob[6];
    std::uint8_t ext_len = blob[7];
    if (version != kKfmVersion || (mode != kKfmModeImageAudio && mode != kKfmModeAudioImage)) {
        return std::nullopt;
    }
    std::uint64_t payload_len = ReadU64BE(blob, 8);
    std::uint32_t crc_expected = ReadU32BE(blob, 16);
    std::uint64_t seed = ReadU64BE(blob, 20);
    if (payload_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() - ext_len)) {
        return std::nullopt;
    }
    std::size_t body_len = static_cast<std::size_t>(ext_len) + static_cast<std::size_t>(payload_len);
    if (body_len < ext_len) {
        return std::nullopt;
    }
    if (kKfmHeaderLen + body_len > blob.size()) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> body(blob.begin() + static_cast<std::ptrdiff_t>(kKfmHeaderLen),
                                   blob.begin() + static_cast<std::ptrdiff_t>(kKfmHeaderLen + body_len));
    auto mask = KfmKeystream(seed, body.size());
    XorInPlace(body, mask);
    std::vector<std::uint8_t> payload(body.begin() + static_cast<std::ptrdiff_t>(ext_len), body.end());
    std::uint32_t crc_actual = crc32(0L, payload.data(), static_cast<uInt>(payload.size()));
    if (crc_actual != crc_expected) {
        return std::nullopt;
    }
    std::string ext(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(ext_len));
    KfmDecoded decoded;
    decoded.mode = mode;
    decoded.flags = flags;
    decoded.ext = CleanKfmExt(ext);
    decoded.payload = std::move(payload);
    return decoded;
}

const char* KfmCarrierKindName(KfmCarrierKind kind) {
    return kind == KfmCarrierKind::Audio ? "audio" : "image";
}

std::vector<KfmCarrierKind> DetectKfmCarrierKinds(const std::filesystem::path& path, const std::string& ext) {
    if (IsKnownKfmAudioExt(ext)) {
        return {KfmCarrierKind::Audio};
    }
    if (IsKnownKfmImageExt(ext)) {
        return {KfmCarrierKind::Image};
    }
    std::array<std::uint8_t, 16> head{};
    std::size_t head_len = 0;
    std::ifstream input(path, std::ios::binary);
    if (input) {
        input.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
        head_len = static_cast<std::size_t>(input.gcount());
    }
    std::vector<KfmCarrierKind> kinds;
    static constexpr std::array<std::uint8_t, 8> kPngMagic = {
        0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au
    };
    if (head_len >= kPngMagic.size() && std::equal(kPngMagic.begin(), kPngMagic.end(), head.begin())) {
        kinds.push_back(KfmCarrierKind::Image);
    }
    if (head_len >= 12
        && head[0] == 'R' && head[1] == 'I' && head[2] == 'F' && head[3] == 'F'
        && head[8] == 'W' && head[9] == 'A' && head[10] == 'V' && head[11] == 'E') {
        kinds.push_back(KfmCarrierKind::Audio);
    }
    if (kinds.empty()) {
        kinds.push_back(KfmCarrierKind::Audio);
        kinds.push_back(KfmCarrierKind::Image);
    } else {
        if (std::find(kinds.begin(), kinds.end(), KfmCarrierKind::Audio) == kinds.end()) {
            kinds.push_back(KfmCarrierKind::Audio);
        }
        if (std::find(kinds.begin(), kinds.end(), KfmCarrierKind::Image) == kinds.end()) {
            kinds.push_back(KfmCarrierKind::Image);
        }
    }
    return kinds;
}

std::optional<KfmDecoded> DecodeKfmCarrierContainer(const std::filesystem::path& path,
                                                    const std::string& ext,
                                                    std::vector<std::string>* errors_out) {
    auto kinds = DetectKfmCarrierKinds(path, ext);
    std::vector<std::string> errors;
    for (KfmCarrierKind kind : kinds) {
        std::vector<std::uint8_t> carrier;
        try {
            if (kind == KfmCarrierKind::Audio) {
                carrier = ReadAudioCarrierBytes(path);
            } else {
                carrier = ReadPngCarrierBytes(path);
            }
        } catch (const std::exception& exc) {
            if (kinds.size() == 1) {
                throw;
            }
            errors.push_back(std::string(KfmCarrierKindName(kind)) + ": " + exc.what());
            continue;
        }
        auto decoded = ParseKfmContainer(carrier);
        if (decoded) {
            if (errors_out) {
                *errors_out = std::move(errors);
            }
            return decoded;
        }
        errors.push_back(std::string(KfmCarrierKindName(kind)) + ": no BaseFWX header");
    }
    if (errors_out) {
        *errors_out = std::move(errors);
    }
    return std::nullopt;
}

void WriteBinaryFileRaw(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file: " + path.string());
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!out) {
        throw std::runtime_error("Failed to write output file: " + path.string());
    }
}

std::filesystem::path NormalizePathForCompare(const std::filesystem::path& path) {
    std::error_code ec;
    auto abs = std::filesystem::absolute(path, ec);
    if (ec) {
        return path.lexically_normal();
    }
    return abs.lexically_normal();
}

bool PathsEqual(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    return NormalizePathForCompare(lhs) == NormalizePathForCompare(rhs);
}

std::filesystem::path ResolveKfmOutputPath(const std::filesystem::path& src,
                                           const std::string& output,
                                           const std::string& ext,
                                           const std::string& tag) {
    if (!output.empty()) {
        std::filesystem::path out_path(output);
        if (PathsEqual(out_path, src)) {
            throw std::runtime_error("Refusing to overwrite input file; choose a different output path");
        }
        return out_path;
    }
    std::filesystem::path out_path = src;
    out_path.replace_extension(ext);
    if (PathsEqual(out_path, src)) {
        out_path = src.parent_path() / (src.stem().string() + "." + tag + ext);
    }
    return out_path;
}

std::filesystem::path ResolveKfmCarrierOutputPath(const std::filesystem::path& src,
                                                  const std::string& output,
                                                  const std::string& ext,
                                                  const std::string& tag) {
    if (output.empty()) {
        return ResolveKfmOutputPath(src, output, ext, tag);
    }

    std::filesystem::path out_path(output);
    if (!out_path.has_extension()) {
        out_path += ext;
    } else if (KfmPathExt(out_path) != ext) {
        throw std::runtime_error(
            "kFMe writes " + ext + " carriers for this input type; choose a " + ext + " output path");
    }

    if (PathsEqual(out_path, src)) {
        throw std::runtime_error("Refusing to overwrite input file; choose a different output path");
    }
    return out_path;
}

}  // namespace basefwx::internal

namespace basefwx {

using namespace basefwx::internal;

std::optional<KfmCarrierInspectResult> InspectKfmCarrierFile(const std::string& path) {
    std::filesystem::path input_path(path);
    std::error_code ec;
    if (!std::filesystem::exists(input_path, ec) || !std::filesystem::is_regular_file(input_path, ec)) {
        return std::nullopt;
    }

    std::string input_ext = KfmPathExt(input_path);
    auto kinds = DetectKfmCarrierKinds(input_path, input_ext);
    for (KfmCarrierKind kind : kinds) {
        std::vector<std::uint8_t> carrier;
        try {
            if (kind == KfmCarrierKind::Audio) {
                carrier = ReadAudioCarrierBytes(input_path);
            } else {
                carrier = ReadPngCarrierBytes(input_path);
            }
        } catch (const std::exception&) {
            continue;
        }
        auto decoded = ParseKfmContainer(carrier);
        if (!decoded.has_value()) {
            continue;
        }

        KfmCarrierInspectResult result;
        result.file_size = static_cast<std::uint64_t>(std::filesystem::file_size(input_path, ec));
        if (ec) {
            result.file_size = 0;
        }
        result.payload_len = decoded->payload.size();
        result.mode = decoded->mode;
        result.flags = decoded->flags;
        result.carrier_kind = (kind == KfmCarrierKind::Audio) ? "audio" : "image";
        result.payload_ext = decoded->ext;
        return result;
    }
    return std::nullopt;
}

std::string Kfme(const std::string& path, const std::string& output, bool bw_mode) {
    std::filesystem::path input_path(path);
    std::string input_ext = KfmPathExt(input_path);
    auto payload = ReadFile(path);
    if (IsKnownKfmAudioExt(input_ext)) {
        std::uint8_t flags = bw_mode ? kKfmFlagBw : 0u;
        auto container = BuildKfmContainer(kKfmModeAudioImage, payload, input_ext, flags);
        std::filesystem::path out_path = ResolveKfmCarrierOutputPath(input_path, output, ".png", "kfme");
        WritePngCarrierBytes(out_path, container, bw_mode);
        return out_path.string();
    }
    auto container = BuildKfmContainer(kKfmModeImageAudio, payload, input_ext, 0u);
    std::filesystem::path out_path = ResolveKfmCarrierOutputPath(input_path, output, ".wav", "kfme");
    WriteWavCarrierBytes(out_path, container);
    return out_path.string();
}

std::string Kfmd(const std::string& path, const std::string& output, bool bw_mode) {
    if (bw_mode) {
        WarnKfmUsage("kFMd --bw is deprecated and ignored in strict decode mode.");
    }
    std::filesystem::path input_path(path);
    std::string input_ext = KfmPathExt(input_path);
    std::vector<std::string> decode_errors;
    auto decoded = DecodeKfmCarrierContainer(input_path, input_ext, &decode_errors);
    if (!decoded) {
        std::string message =
            "kFMd refused input: file is not a BaseFWX kFM carrier. Use kFMe to encode first.";
        if (!decode_errors.empty()) {
            message += " (" + decode_errors.front() + ")";
        }
        throw std::runtime_error(message);
    }
    std::filesystem::path out_path = ResolveKfmOutputPath(input_path, output, decoded->ext, "kfmd");
    WriteBinaryFileRaw(out_path, decoded->payload);
    return out_path.string();
}

std::string Kfae(const std::string& path, const std::string& output, bool bw_mode) {
    WarnKfmUsage("kFAe is deprecated; using legacy PNG carrier mode. Prefer kFMe for auto mode.");
    std::filesystem::path input_path(path);
    std::string input_ext = KfmPathExt(input_path);
    auto payload = ReadFile(path);
    std::uint8_t flags = bw_mode ? kKfmFlagBw : 0u;
    auto container = BuildKfmContainer(kKfmModeAudioImage, payload, input_ext, flags);
    std::filesystem::path out_path = ResolveKfmCarrierOutputPath(input_path, output, ".png", "kfae");
    WritePngCarrierBytes(out_path, container, bw_mode);
    return out_path.string();
}

std::string Kfad(const std::string& path, const std::string& output) {
    WarnKfmUsage("kFAd is deprecated; use kFMd (auto-detect) instead.");
    return Kfmd(path, output, false);
}

}  // namespace basefwx
