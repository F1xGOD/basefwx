/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx_kfm_internal.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/crypto.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <zlib.h>

#include "stb_image.h"
#include "stb_image_write.h"

namespace basefwx::internal {

std::uint16_t Rotl16(std::uint16_t value, unsigned int shift) {
    shift &= 15u;
    if (shift == 0u) {
        return value;
    }
    return static_cast<std::uint16_t>((value << shift) | (value >> (16u - shift)));
}

std::uint16_t Rotr16(std::uint16_t value, unsigned int shift) {
    shift &= 15u;
    if (shift == 0u) {
        return value;
    }
    return static_cast<std::uint16_t>((value >> shift) | (value << (16u - shift)));
}

std::uint8_t Rotl8(std::uint8_t value, unsigned int shift) {
    shift &= 7u;
    if (shift == 0u) {
        return value;
    }
    return static_cast<std::uint8_t>((value << shift) | (value >> (8u - shift)));
}

std::uint64_t KfmCarrierSeed(std::uint32_t payload_len, std::uint32_t crc, std::uint64_t salt) {
    return Mix64((static_cast<std::uint64_t>(payload_len) << 32) ^ static_cast<std::uint64_t>(crc) ^ salt);
}

std::vector<std::uint8_t> BuildKfmCarrierFrame(const std::array<char, 4>& magic,
                                               const std::vector<std::uint8_t>& carrier) {
    if (carrier.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw std::runtime_error("kFM carrier is too large for media frame");
    }
    std::vector<std::uint8_t> frame;
    frame.reserve(kKfmCarrierFrameHeaderLen + carrier.size());
    frame.insert(frame.end(), magic.begin(), magic.end());
    WriteU32BE(frame, static_cast<std::uint32_t>(carrier.size()));
    std::uint32_t crc = crc32(0L, carrier.data(), static_cast<uInt>(carrier.size()));
    WriteU32BE(frame, crc);
    frame.insert(frame.end(), carrier.begin(), carrier.end());
    return frame;
}

std::optional<std::vector<std::uint8_t>> ParseKfmCarrierFrame(const std::array<char, 4>& magic,
                                                              const std::vector<std::uint8_t>& frame) {
    if (frame.size() < kKfmCarrierFrameHeaderLen) {
        return std::nullopt;
    }
    if (!std::equal(magic.begin(), magic.end(), frame.begin())) {
        return std::nullopt;
    }
    std::uint32_t payload_len = ReadU32BE(frame, 4);
    std::uint32_t expected_crc = ReadU32BE(frame, 8);
    if (payload_len > frame.size() - kKfmCarrierFrameHeaderLen) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> carrier(
        frame.begin() + static_cast<std::ptrdiff_t>(kKfmCarrierFrameHeaderLen),
        frame.begin() + static_cast<std::ptrdiff_t>(kKfmCarrierFrameHeaderLen + payload_len));
    std::uint32_t actual_crc = crc32(0L, carrier.data(), static_cast<uInt>(carrier.size()));
    if (actual_crc != expected_crc) {
        return std::nullopt;
    }
    return carrier;
}

std::vector<std::size_t> BuildShuffledPositions(std::size_t count, std::uint64_t seed) {
    std::vector<std::size_t> positions(count);
    for (std::size_t i = 0; i < count; ++i) {
        positions[i] = i;
    }
    std::mt19937_64 rng(seed);
    std::shuffle(positions.begin(), positions.end(), rng);
    return positions;
}

std::size_t KfmPngBytesPerPixel(int channels) {
    return (channels == 1) ? 1u : 3u;
}

std::size_t KfmPngHeaderPixels(int channels) {
    std::size_t bytes_per_pixel = KfmPngBytesPerPixel(channels);
    return (kKfmCarrierFrameHeaderLen + bytes_per_pixel - 1u) / bytes_per_pixel;
}

std::uint8_t KfmImageByteMask(std::size_t logical_index, std::size_t byte_index) {
    std::uint64_t mixed = Mix64((static_cast<std::uint64_t>(logical_index) << 8)
                                ^ static_cast<std::uint64_t>(byte_index)
                                ^ 0x6F3D2C1BA497E5D2ULL);
    return static_cast<std::uint8_t>(mixed & 0xFFu);
}

std::uint8_t KfmImageFillByte(std::size_t logical_index, std::size_t byte_index) {
    std::uint64_t mixed = Mix64((static_cast<std::uint64_t>(logical_index) << 8)
                                ^ static_cast<std::uint64_t>(byte_index)
                                ^ 0x91AE7C3D5B28F146ULL);
    return static_cast<std::uint8_t>(mixed & 0xFFu);
}

void EncodeKfmPixelBlock(std::vector<std::uint8_t>& pixels,
                         int channels,
                         std::size_t pixel_index,
                         const std::uint8_t* data,
                         std::size_t data_len,
                         std::size_t logical_index) {
    std::size_t bytes_per_pixel = KfmPngBytesPerPixel(channels);
    std::size_t offset = pixel_index * static_cast<std::size_t>(channels);
    std::array<std::uint8_t, 3> block{};
    for (std::size_t i = 0; i < bytes_per_pixel; ++i) {
        block[i] = (i < data_len) ? data[i] : KfmImageFillByte(logical_index, i);
    }

    if (bytes_per_pixel == 1u) {
        pixels[offset] = static_cast<std::uint8_t>(block[0] ^ KfmImageByteMask(logical_index, 0));
        return;
    }

    std::uint8_t x0 = static_cast<std::uint8_t>(block[0] ^ KfmImageByteMask(logical_index, 0));
    std::uint8_t x1 = static_cast<std::uint8_t>(block[1] ^ KfmImageByteMask(logical_index, 1));
    std::uint8_t x2 = static_cast<std::uint8_t>(block[2] ^ KfmImageByteMask(logical_index, 2));
    pixels[offset] = x0;
    pixels[offset + 1] = static_cast<std::uint8_t>(x1 ^ Rotl8(x0, 1));
    pixels[offset + 2] = static_cast<std::uint8_t>(x2 ^ Rotl8(x1, 3) ^ Rotl8(x0, 5));
}

std::array<std::uint8_t, 3> DecodeKfmPixelBlock(const std::uint8_t* pixel,
                                                int channels,
                                                std::size_t logical_index) {
    std::size_t bytes_per_pixel = KfmPngBytesPerPixel(channels);
    std::array<std::uint8_t, 3> out{};
    if (bytes_per_pixel == 1u) {
        out[0] = static_cast<std::uint8_t>(pixel[0] ^ KfmImageByteMask(logical_index, 0));
        return out;
    }

    std::uint8_t x0 = pixel[0];
    std::uint8_t x1 = static_cast<std::uint8_t>(pixel[1] ^ Rotl8(x0, 1));
    std::uint8_t x2 = static_cast<std::uint8_t>(pixel[2] ^ Rotl8(x1, 3) ^ Rotl8(x0, 5));
    out[0] = static_cast<std::uint8_t>(x0 ^ KfmImageByteMask(logical_index, 0));
    out[1] = static_cast<std::uint8_t>(x1 ^ KfmImageByteMask(logical_index, 1));
    out[2] = static_cast<std::uint8_t>(x2 ^ KfmImageByteMask(logical_index, 2));
    return out;
}

std::optional<std::vector<std::uint8_t>> TryDecodeMappedPngCarrier(const std::uint8_t* raw,
                                                                   int width,
                                                                   int height,
                                                                   int channels) {
    if (!raw || width <= 0 || height <= 0 || channels <= 0 || channels == 2) {
        return std::nullopt;
    }
    int logical_channels = (channels == 1) ? 1 : 3;
    std::size_t bytes_per_pixel = KfmPngBytesPerPixel(logical_channels);
    std::size_t header_pixels = KfmPngHeaderPixels(logical_channels);
    std::size_t pixel_count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    if (pixel_count < header_pixels) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> frame;
    frame.reserve(kKfmCarrierFrameHeaderLen);
    for (std::size_t i = 0; i < header_pixels; ++i) {
        const std::uint8_t* pixel = raw + i * static_cast<std::size_t>(channels);
        auto block = DecodeKfmPixelBlock(pixel, logical_channels, i);
        frame.insert(frame.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(bytes_per_pixel));
    }
    if (frame.size() < kKfmCarrierFrameHeaderLen) {
        return std::nullopt;
    }
    frame.resize(kKfmCarrierFrameHeaderLen);

    if (!std::equal(kKfmImageCarrierMagic.begin(), kKfmImageCarrierMagic.end(), frame.begin())) {
        return std::nullopt;
    }

    std::uint32_t payload_len = ReadU32BE(frame, 4);
    std::uint32_t expected_crc = ReadU32BE(frame, 8);
    std::size_t expected_frame_bytes = kKfmCarrierFrameHeaderLen + static_cast<std::size_t>(payload_len);
    std::size_t required_pixels = header_pixels
        + ((expected_frame_bytes - kKfmCarrierFrameHeaderLen + bytes_per_pixel - 1u) / bytes_per_pixel);
    if (required_pixels > pixel_count) {
        return std::nullopt;
    }
    std::uint64_t seed = KfmCarrierSeed(payload_len, expected_crc, 0xB4C38F6D5A1279E1ULL);
    auto positions = BuildShuffledPositions(pixel_count - header_pixels, seed);
    std::size_t remaining_bytes = expected_frame_bytes - kKfmCarrierFrameHeaderLen;
    std::size_t blocks_needed = (remaining_bytes + bytes_per_pixel - 1u) / bytes_per_pixel;
    for (std::size_t i = 0; i < blocks_needed; ++i) {
        std::size_t pixel_index = header_pixels + positions[i];
        const std::uint8_t* pixel = raw + pixel_index * static_cast<std::size_t>(channels);
        auto block = DecodeKfmPixelBlock(pixel, logical_channels, header_pixels + i);
        std::size_t take = std::min(bytes_per_pixel, expected_frame_bytes - frame.size());
        frame.insert(frame.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    if (frame.size() != expected_frame_bytes) {
        return std::nullopt;
    }
    return ParseKfmCarrierFrame(kKfmImageCarrierMagic, frame);
}

std::vector<std::uint8_t> LegacyReadPngCarrierBytes(const std::uint8_t* raw,
                                                    int width,
                                                    int height,
                                                    int channels) {
    std::vector<std::uint8_t> out;
    std::size_t pixels = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    if (channels == 1) {
        out.assign(raw, raw + static_cast<std::ptrdiff_t>(pixels));
    } else if (channels == 3) {
        out.assign(raw, raw + static_cast<std::ptrdiff_t>(pixels * 3));
    } else if (channels == 2) {
        out.resize(pixels * 3);
        for (std::size_t i = 0; i < pixels; ++i) {
            std::uint8_t l = raw[i * 2];
            out[i * 3] = l;
            out[i * 3 + 1] = l;
            out[i * 3 + 2] = l;
        }
    } else {
        out.resize(pixels * 3);
        for (std::size_t i = 0; i < pixels; ++i) {
            out[i * 3] = raw[i * static_cast<std::size_t>(channels)];
            out[i * 3 + 1] = raw[i * static_cast<std::size_t>(channels) + 1];
            out[i * 3 + 2] = raw[i * static_cast<std::size_t>(channels) + 2];
        }
    }
    return out;
}

std::uint16_t KfmAudioWordMask(std::size_t index) {
    return static_cast<std::uint16_t>(Mix64(static_cast<std::uint64_t>(index) ^ 0xC13FA9A902A6328FULL) & 0xFFFFu);
}

std::uint8_t KfmAudioFillByte(std::size_t sample_index, std::size_t byte_index) {
    std::uint64_t mixed = Mix64((static_cast<std::uint64_t>(sample_index) << 8)
                                ^ static_cast<std::uint64_t>(byte_index)
                                ^ 0xE23F47AB91C56D02ULL);
    return static_cast<std::uint8_t>(mixed & 0xFFu);
}

std::uint16_t EncodeKfmAudioWord(std::uint16_t word, std::size_t index) {
    return Rotl16(static_cast<std::uint16_t>(word ^ KfmAudioWordMask(index) ^ 0xA5D3u), 5u);
}

std::uint16_t DecodeKfmAudioWord(std::uint16_t encoded, std::size_t index) {
    return static_cast<std::uint16_t>(Rotr16(encoded, 5u) ^ KfmAudioWordMask(index) ^ 0xA5D3u);
}

std::vector<std::uint8_t> EncodeMappedAudioCarrier(const std::vector<std::uint8_t>& carrier) {
    std::vector<std::uint8_t> frame = BuildKfmCarrierFrame(kKfmAudioCarrierMagic, carrier);
    std::size_t sample_count = (frame.size() + 1u) / 2u;
    std::vector<std::uint8_t> pcm(sample_count * 2u);
    for (std::size_t i = 0; i < sample_count; ++i) {
        std::size_t offset = i * 2u;
        std::uint8_t lo = (offset < frame.size()) ? frame[offset] : KfmAudioFillByte(i, 0);
        std::uint8_t hi = (offset + 1u < frame.size()) ? frame[offset + 1u] : KfmAudioFillByte(i, 1);
        std::uint16_t word = static_cast<std::uint16_t>(lo)
                           | static_cast<std::uint16_t>(hi << 8);
        std::uint16_t encoded = EncodeKfmAudioWord(word, i);
        pcm[offset] = static_cast<std::uint8_t>(encoded & 0xFFu);
        pcm[offset + 1u] = static_cast<std::uint8_t>((encoded >> 8) & 0xFFu);
    }
    return pcm;
}

std::optional<std::vector<std::uint8_t>> TryDecodeMappedAudioCarrier(const std::vector<std::uint8_t>& pcm_input) {
    constexpr std::size_t kHeaderSamples = kKfmCarrierFrameHeaderLen / 2u;
    if (pcm_input.size() < kHeaderSamples * 2u) {
        return std::nullopt;
    }
    std::size_t sample_count = pcm_input.size() / 2u;
    std::vector<std::uint8_t> frame;
    frame.reserve(kKfmCarrierFrameHeaderLen);
    for (std::size_t i = 0; i < kHeaderSamples; ++i) {
        std::uint16_t encoded = static_cast<std::uint16_t>(pcm_input[i * 2u])
                              | static_cast<std::uint16_t>(pcm_input[i * 2u + 1u] << 8);
        std::uint16_t word = DecodeKfmAudioWord(encoded, i);
        frame.push_back(static_cast<std::uint8_t>(word & 0xFFu));
        frame.push_back(static_cast<std::uint8_t>((word >> 8) & 0xFFu));
    }
    if (!std::equal(kKfmAudioCarrierMagic.begin(), kKfmAudioCarrierMagic.end(), frame.begin())) {
        return std::nullopt;
    }
    std::uint32_t payload_len = ReadU32BE(frame, 4);
    std::size_t expected_frame_bytes = kKfmCarrierFrameHeaderLen + static_cast<std::size_t>(payload_len);
    std::size_t required_samples = (expected_frame_bytes + 1u) / 2u;
    if (required_samples > sample_count) {
        return std::nullopt;
    }
    frame.reserve(expected_frame_bytes);
    for (std::size_t i = kHeaderSamples; i < required_samples; ++i) {
        std::uint16_t encoded = static_cast<std::uint16_t>(pcm_input[i * 2u])
                              | static_cast<std::uint16_t>(pcm_input[i * 2u + 1u] << 8);
        std::uint16_t word = DecodeKfmAudioWord(encoded, i);
        if (frame.size() < expected_frame_bytes) {
            frame.push_back(static_cast<std::uint8_t>(word & 0xFFu));
        }
        if (frame.size() < expected_frame_bytes) {
            frame.push_back(static_cast<std::uint8_t>((word >> 8) & 0xFFu));
        }
    }
    return ParseKfmCarrierFrame(kKfmAudioCarrierMagic, frame);
}

std::vector<std::uint8_t> LegacyPcm16MonoToCarrierBytes(const std::vector<std::uint8_t>& pcm_input) {
    std::vector<std::uint8_t> pcm = pcm_input;
    if (pcm.size() % 2 != 0) {
        pcm.push_back(0);
    }
    std::vector<std::uint8_t> out(pcm.size());
    for (std::size_t i = 0; i < pcm.size(); i += 2) {
        std::int16_t sample = static_cast<std::int16_t>(
            static_cast<std::uint16_t>(pcm[i]) |
            static_cast<std::uint16_t>(pcm[i + 1] << 8));
        std::uint16_t value = static_cast<std::uint16_t>(sample + 32768);
        out[i] = static_cast<std::uint8_t>(value & 0xFFu);
        out[i + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    }
    return out;
}

std::vector<std::uint8_t> ReadWavCarrierBytes(const std::filesystem::path& path) {
    std::vector<std::uint8_t> file = basefwx::ReadFile(path.string());
    if (file.size() < 44) {
        throw std::runtime_error("kFM wav input is too short");
    }
    if (!std::equal(file.begin(), file.begin() + 4, "RIFF")
        || !std::equal(file.begin() + 8, file.begin() + 12, "WAVE")) {
        throw std::runtime_error("kFM wav input has invalid header");
    }

    bool has_fmt = false;
    bool has_data = false;
    std::uint16_t channels = 0;
    std::uint16_t bits_per_sample = 0;
    std::vector<std::uint8_t> data_chunk;

    std::size_t offset = 12;
    while (offset + 8 <= file.size()) {
        std::array<char, 4> chunk_id{};
        std::memcpy(chunk_id.data(), file.data() + offset, 4);
        std::uint32_t chunk_len = ReadU32LE(file, offset + 4);
        std::size_t data_offset = offset + 8;
        std::size_t next = data_offset + static_cast<std::size_t>(chunk_len);
        if (next > file.size()) {
            break;
        }
        if (std::equal(chunk_id.begin(), chunk_id.end(), "fmt ")) {
            if (chunk_len >= 16) {
                std::uint16_t format = ReadU16LE(file, data_offset);
                channels = ReadU16LE(file, data_offset + 2);
                bits_per_sample = ReadU16LE(file, data_offset + 14);
                has_fmt = (format == 1);
            }
        } else if (std::equal(chunk_id.begin(), chunk_id.end(), "data")) {
            data_chunk.assign(file.begin() + static_cast<std::ptrdiff_t>(data_offset),
                              file.begin() + static_cast<std::ptrdiff_t>(next));
            has_data = true;
        }
        offset = next + (chunk_len % 2u);
    }

    if (!has_data) {
        throw std::runtime_error("kFM wav input missing data chunk");
    }
    if (!(has_fmt && channels == 1 && bits_per_sample == 16)) {
        return data_chunk;
    }
    std::vector<std::uint8_t> pcm = std::move(data_chunk);
    if (pcm.size() % 2 != 0) {
        pcm.push_back(0);
    }
    auto mapped = TryDecodeMappedAudioCarrier(pcm);
    if (mapped.has_value()) {
        return *mapped;
    }
    return LegacyPcm16MonoToCarrierBytes(pcm);
}

std::string QuoteShellArg(const std::string& value) {
#ifdef _WIN32
    std::string out = "\"";
    for (char ch : value) {
        if (ch == '"') {
            out += "\\\"";
        } else {
            out.push_back(ch);
        }
    }
    out += "\"";
    return out;
#else
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\'') {
            out += "'\\''";
        } else {
            out.push_back(ch);
        }
    }
    out += "'";
    return out;
#endif
}

std::string KfmFfmpegHwAccelArgs() {
    std::string mode;
    if (const char* raw = std::getenv("BASEFWX_HWACCEL")) {
        mode = raw;
    }
    for (char& ch : mode) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (mode.empty()) {
        if (const char* visible = std::getenv("NVIDIA_VISIBLE_DEVICES")) {
            std::string v = visible;
            for (char& ch : v) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            if (!v.empty() && v != "none" && v != "void") {
                mode = "nvidia";
            }
        }
    }
    if (mode == "cuda" || mode == "nvenc" || mode == "nvidia") {
        return " -hwaccel cuda";
    }
    if (mode == "qsv" || mode == "intel") {
        return " -hwaccel qsv";
    }
    if (mode == "vaapi") {
        return " -hwaccel vaapi";
    }
    return "";
}

std::filesystem::path MakeKfmTempPath(const std::string& suffix) {
    const auto now = static_cast<std::uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for (std::uint32_t i = 0; i < 32; ++i) {
        auto candidate = std::filesystem::temp_directory_path() /
            ("basefwx_kfm_" + std::to_string(now) + "_" + std::to_string(i) + suffix);
        if (!std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    throw std::runtime_error("Failed to allocate temporary path for ffmpeg decode");
}

std::vector<std::uint8_t> DecodeAudioViaFfmpeg(const std::filesystem::path& path) {
    const char* ffmpeg_env = std::getenv("BASEFWX_FFMPEG_BIN");
    std::string ffmpeg_bin = (ffmpeg_env && *ffmpeg_env) ? ffmpeg_env : "ffmpeg";
    auto temp_raw = MakeKfmTempPath(".raw");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            if (!path.empty()) {
                std::error_code ec;
                std::filesystem::remove(path, ec);
            }
        }
    } cleanup{temp_raw};

    std::string command = QuoteShellArg(ffmpeg_bin)
        + " -v error -y"
        + KfmFfmpegHwAccelArgs()
        + " -i " + QuoteShellArg(path.string())
        + " -f s16le -ac 1 -ar " + std::to_string(kKfmAudioRate)
        + " " + QuoteShellArg(temp_raw.string());
#ifdef _WIN32
    command += " >NUL 2>&1";
#else
    command += " >/dev/null 2>&1";
#endif
    int rc = std::system(command.c_str());
    if (rc != 0) {
        throw std::runtime_error(
            "ffmpeg failed to decode audio carrier (install ffmpeg or use WAV input)");
    }
    std::vector<std::uint8_t> pcm = basefwx::ReadFile(temp_raw.string());
    if (pcm.empty()) {
        throw std::runtime_error("ffmpeg decode produced an empty PCM stream");
    }
    auto mapped = TryDecodeMappedAudioCarrier(pcm);
    if (mapped.has_value()) {
        return *mapped;
    }
    return LegacyPcm16MonoToCarrierBytes(pcm);
}

std::vector<std::uint8_t> ReadAudioCarrierBytes(const std::filesystem::path& path) {
    std::string wav_error;
    try {
        return ReadWavCarrierBytes(path);
    } catch (const std::exception& exc) {
        wav_error = exc.what();
    }
    try {
        return DecodeAudioViaFfmpeg(path);
    } catch (const std::exception& ff_exc) {
        throw std::runtime_error(
            "Failed to decode audio carrier '" + path.string() + "' (WAV parse: "
            + wav_error + "; ffmpeg: " + ff_exc.what() + ")");
    }
}

void WriteWavCarrierBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& carrier) {
    std::vector<std::uint8_t> pcm = EncodeMappedAudioCarrier(carrier);

    std::vector<std::uint8_t> out;
    out.reserve(44 + pcm.size());
    out.insert(out.end(), {'R', 'I', 'F', 'F'});
    WriteU32LE(out, static_cast<std::uint32_t>(36 + pcm.size()));
    out.insert(out.end(), {'W', 'A', 'V', 'E'});
    out.insert(out.end(), {'f', 'm', 't', ' '});
    WriteU32LE(out, 16u);
    WriteU16LE(out, 1u);
    WriteU16LE(out, 1u);
    WriteU32LE(out, kKfmAudioRate);
    WriteU32LE(out, kKfmAudioRate * 2u);
    WriteU16LE(out, 2u);
    WriteU16LE(out, 16u);
    out.insert(out.end(), {'d', 'a', 't', 'a'});
    WriteU32LE(out, static_cast<std::uint32_t>(pcm.size()));
    out.insert(out.end(), pcm.begin(), pcm.end());
    WriteBinaryFileRaw(path, out);
}

std::vector<std::uint8_t> ReadPngCarrierBytes(const std::filesystem::path& path) {
    int width = 0;
    int height = 0;
    int channels = 0;
    stbi_uc* raw = stbi_load(path.string().c_str(), &width, &height, &channels, 0);
    if (!raw || width <= 0 || height <= 0 || channels <= 0) {
        std::string reason = stbi_failure_reason() ? stbi_failure_reason() : "unknown";
        throw std::runtime_error("Failed to load PNG carrier: " + reason);
    }

    auto mapped = TryDecodeMappedPngCarrier(raw, width, height, channels);
    std::vector<std::uint8_t> out = mapped.has_value()
        ? *mapped
        : LegacyReadPngCarrierBytes(raw, width, height, channels);
    stbi_image_free(raw);
    return out;
}

void WritePngCarrierBytes(const std::filesystem::path& path,
                          const std::vector<std::uint8_t>& carrier,
                          bool bw_mode) {
    std::vector<std::uint8_t> frame = BuildKfmCarrierFrame(kKfmImageCarrierMagic, carrier);
    int channels = bw_mode ? 1 : 3;
    std::size_t bytes_per_pixel = KfmPngBytesPerPixel(channels);
    std::size_t header_pixels = KfmPngHeaderPixels(channels);
    std::size_t remaining_bytes = (frame.size() > kKfmCarrierFrameHeaderLen)
        ? (frame.size() - kKfmCarrierFrameHeaderLen)
        : 0u;
    std::size_t payload_pixels = (remaining_bytes + bytes_per_pixel - 1u) / bytes_per_pixel;
    std::size_t used_pixels = header_pixels + payload_pixels;
    int width = static_cast<int>(std::ceil(std::sqrt(static_cast<double>(used_pixels))));
    if (width < 1) {
        width = 1;
    }
    int height = static_cast<int>((used_pixels + static_cast<std::size_t>(width) - 1u) / static_cast<std::size_t>(width));
    std::size_t capacity_pixels = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    std::size_t capacity = capacity_pixels * static_cast<std::size_t>(channels);

    std::vector<std::uint8_t> pixels_data = basefwx::crypto::RandomBytes(capacity);
    for (std::size_t i = 0; i < header_pixels; ++i) {
        std::size_t offset = i * bytes_per_pixel;
        std::size_t take = std::min(bytes_per_pixel, frame.size() - offset);
        EncodeKfmPixelBlock(pixels_data, channels, i, frame.data() + static_cast<std::ptrdiff_t>(offset), take, i);
    }

    std::uint32_t crc = crc32(0L, carrier.data(), static_cast<uInt>(carrier.size()));
    std::uint64_t seed = KfmCarrierSeed(static_cast<std::uint32_t>(carrier.size()), crc, 0xB4C38F6D5A1279E1ULL);
    auto positions = BuildShuffledPositions(capacity_pixels - header_pixels, seed);
    for (std::size_t i = 0; i < payload_pixels; ++i) {
        std::size_t offset = kKfmCarrierFrameHeaderLen + i * bytes_per_pixel;
        std::size_t take = std::min(bytes_per_pixel, frame.size() - offset);
        std::size_t pixel_index = header_pixels + positions[i];
        EncodeKfmPixelBlock(pixels_data,
                            channels,
                            pixel_index,
                            frame.data() + static_cast<std::ptrdiff_t>(offset),
                            take,
                            header_pixels + i);
    }

    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }
    int stride = width * channels;
    if (stbi_write_png(path.string().c_str(),
                       width,
                       height,
                       channels,
                       pixels_data.data(),
                       stride) == 0) {
        throw std::runtime_error("Failed to write PNG carrier");
    }
}


}  // namespace basefwx::internal
