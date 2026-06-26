/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace basefwx::internal {

inline constexpr std::array<char, 4> kKfmMagic = {'K', 'F', 'M', '!'};
inline constexpr std::uint8_t kKfmVersion = 1;
inline constexpr std::uint8_t kKfmModeImageAudio = 1;
inline constexpr std::uint8_t kKfmModeAudioImage = 2;
inline constexpr std::uint8_t kKfmFlagBw = 1;
inline constexpr std::size_t kKfmHeaderLen = 32;
inline constexpr std::size_t kKfmMaxPayload = 1u << 30;
inline constexpr std::uint32_t kKfmAudioRate = 24000;
inline constexpr std::array<char, 4> kKfmAudioCarrierMagic = {'K', 'F', 'M', 'W'};
inline constexpr std::array<char, 4> kKfmImageCarrierMagic = {'K', 'F', 'M', 'P'};
inline constexpr std::size_t kKfmCarrierFrameHeaderLen = 12;

struct KfmDecoded {
    std::uint8_t mode = 0;
    std::uint8_t flags = 0;
    std::string ext;
    std::vector<std::uint8_t> payload;
};

enum class KfmCarrierKind {
    Audio,
    Image,
};

std::uint64_t Mix64(std::uint64_t value);
void WriteU32BE(std::vector<std::uint8_t>& out, std::uint32_t value);
void WriteU64BE(std::vector<std::uint8_t>& out, std::uint64_t value);
std::uint32_t ReadU32BE(const std::vector<std::uint8_t>& data, std::size_t offset);
std::uint64_t ReadU64BE(const std::vector<std::uint8_t>& data, std::size_t offset);
std::uint32_t ReadU32LE(const std::vector<std::uint8_t>& data, std::size_t offset);
std::uint16_t ReadU16LE(const std::vector<std::uint8_t>& data, std::size_t offset);
void WriteU16LE(std::vector<std::uint8_t>& out, std::uint16_t value);
void WriteU32LE(std::vector<std::uint8_t>& out, std::uint32_t value);
std::string CleanKfmExt(std::string ext);
std::string KfmPathExt(const std::filesystem::path& path);
bool IsKnownKfmAudioExt(const std::string& ext);
bool IsKnownKfmImageExt(const std::string& ext);
void WarnKfmUsage(const std::string& message);
std::vector<std::uint8_t> KfmKeystream(std::uint64_t seed, std::size_t length);
void XorInPlace(std::vector<std::uint8_t>& target, const std::vector<std::uint8_t>& mask);
std::uint64_t RandomSeed64();
std::vector<std::uint8_t> BuildKfmContainer(std::uint8_t mode,
                                            const std::vector<std::uint8_t>& payload,
                                            const std::string& ext,
                                            std::uint8_t flags);
std::optional<KfmDecoded> ParseKfmContainer(const std::vector<std::uint8_t>& blob);
const char* KfmCarrierKindName(KfmCarrierKind kind);
std::vector<KfmCarrierKind> DetectKfmCarrierKinds(const std::filesystem::path& path, const std::string& ext);
std::optional<KfmDecoded> DecodeKfmCarrierContainer(const std::filesystem::path& path,
                                                    const std::string& ext,
                                                    std::vector<std::string>* errors_out = nullptr);
void WriteBinaryFileRaw(const std::filesystem::path& path, const std::vector<std::uint8_t>& data);
std::filesystem::path NormalizePathForCompare(const std::filesystem::path& path);
bool PathsEqual(const std::filesystem::path& lhs, const std::filesystem::path& rhs);
std::filesystem::path ResolveKfmOutputPath(const std::filesystem::path& src,
                                           const std::string& output,
                                           const std::string& ext,
                                           const std::string& tag);
std::filesystem::path ResolveKfmCarrierOutputPath(const std::filesystem::path& src,
                                                  const std::string& output,
                                                  const std::string& ext,
                                                  const std::string& tag);
std::vector<std::uint8_t> ReadAudioCarrierBytes(const std::filesystem::path& path);
std::vector<std::uint8_t> ReadPngCarrierBytes(const std::filesystem::path& path);
void WriteWavCarrierBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& carrier);
void WritePngCarrierBytes(const std::filesystem::path& path,
                          const std::vector<std::uint8_t>& carrier,
                          bool bw_mode);

}  // namespace basefwx::internal
