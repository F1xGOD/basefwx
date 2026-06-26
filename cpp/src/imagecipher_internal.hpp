/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include "basefwx/crypto.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace basefwx::imagecipher::internal {

using basefwx::crypto::Bytes;

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

struct BitrateTargets {
    std::optional<std::uint64_t> video;
    std::optional<std::uint64_t> audio;
};

struct JmgResolvedKeys {
    std::size_t header_len = 0;
    std::uint8_t profile_id = 0;
    Bytes material;
    Bytes base_key;
    Bytes archive_key;
};

enum class HwAccel {
    None,
    Nvenc,
    Qsv,
    Vaapi
};

std::string ToLower(std::string value);
std::filesystem::path NormalizePath(const std::string& path);
Bytes ReadFileBytes(const std::filesystem::path& path);
void WriteFileBytes(const std::filesystem::path& path, const Bytes& data);
Bytes DeriveMaterial(const std::string& password);
Bytes DeriveMaterialFromMask(const Bytes& mask_key, std::uint8_t profile_id);
Bytes BaseKeyFromPassword(const std::string& password);
std::string ExtensionLower(const std::filesystem::path& path);
std::uint64_t ReadU64Be(const std::uint8_t* data);
void Ensure(bool ok, const char* msg);
std::string JmgProfileLabel(std::string_view label, std::uint8_t profile_id);
std::string JmgArchiveInfoForProfile(std::uint8_t profile_id);
std::uint8_t JmgVideoMaskBitsForProfile(std::uint8_t profile_id);
std::uint16_t JmgAudioMaskBitsForProfile(std::uint8_t profile_id);
Bytes BaseKeyFromMask(const Bytes& mask_key, std::uint8_t profile_id);
Bytes ArchiveKeyFromMask(const Bytes& mask_key, std::uint8_t profile_id);
Bytes BuildJmgHeader(const Bytes& user_blob, const Bytes& master_blob, std::uint8_t profile_id);
bool ParseJmgHeader(const Bytes& blob,
                    std::size_t& header_len,
                    Bytes& user_blob,
                    Bytes& master_blob,
                    std::uint8_t* profile_out);
void AppendBalancedTrailer(const std::filesystem::path& path,
                           std::string_view magic,
                           const Bytes& payload);
void AppendTrailerStream(const std::filesystem::path& output_path,
                         const std::filesystem::path& original_path,
                         const std::string& password,
                         const std::function<void(double)>& progress_cb,
                         const Bytes& archive_key_override,
                         const Bytes& key_header,
                         std::string_view archive_info);
bool TryDecryptTrailerStream(const std::filesystem::path& input_path,
                             const std::string& password,
                             const std::filesystem::path& output_path,
                             bool use_master,
                             const std::function<void(double)>& progress_cb);
bool ExtractTrailerWithMagic(const Bytes& data,
                             std::string_view magic,
                             Bytes& stripped,
                             Bytes& trailer);
Bytes LoadBaseKeyFromKeyTrailerFile(const std::filesystem::path& input_path,
                                    const std::string& password,
                                    bool use_master,
                                    std::uint8_t* profile_out);
Bytes LoadBaseKeyFromKeyTrailerBytes(const Bytes& file_bytes,
                                     const std::string& password,
                                     bool use_master,
                                     std::uint8_t* profile_out);
std::optional<JmgResolvedKeys> ResolveJmgHeaderKeys(const Bytes& blob,
                                                    const std::string& password,
                                                    bool use_master);
void WarnNoArchivePayload();

std::string RunCommandCapture(const std::vector<std::string>& args);
void RunCommand(const std::vector<std::string>& args);
VideoInfo ProbeVideo(const std::filesystem::path& path);
AudioInfo ProbeAudio(const std::filesystem::path& path);
std::map<std::string, std::string> ProbeMetadata(const std::filesystem::path& path);
FormatInfo ProbeFormat(const std::filesystem::path& path);
BitrateTargets EstimateBitrates(const std::filesystem::path& path,
                                const VideoInfo& video,
                                const AudioInfo& audio);
HwAccel SelectHwAccel();
bool IsJmgVideoEnabled();
bool LogEnabled();
std::string HwAccelName(HwAccel accel);
void LogHwPlan(const std::string& op, HwAccel accel, const std::string& reason);
std::filesystem::path CreateTempDir(const std::string& prefix);

void ScrambleVideoRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const VideoInfo& video,
                      const Bytes& base_key,
                      std::uint8_t security_profile,
                      const std::function<void(double)>& progress_cb);
void ScrambleAudioRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const AudioInfo& audio,
                      const Bytes& base_key,
                      std::uint8_t security_profile,
                      const std::function<void(double)>& progress_cb);
void UnscrambleVideoRaw(const std::filesystem::path& raw_in,
                        const std::filesystem::path& raw_out,
                        const VideoInfo& video,
                        const Bytes& base_key,
                        std::uint8_t security_profile,
                        const std::function<void(double)>& progress_cb);
void UnscrambleAudioRaw(const std::filesystem::path& raw_in,
                        const std::filesystem::path& raw_out,
                        const AudioInfo& audio,
                        const Bytes& base_key,
                        std::uint8_t security_profile,
                        const std::function<void(double)>& progress_cb);

std::vector<std::string> EncryptMetadataArgs(const std::map<std::string, std::string>& tags,
                                             const std::string& password);
std::vector<std::string> DecryptMetadataArgs(const std::map<std::string, std::string>& tags,
                                             const std::string& password);
bool IsImageExt(const std::filesystem::path& path);
std::vector<std::string> VideoCodecArgs(const std::filesystem::path& output_path,
                                        std::optional<std::uint64_t> target_bps,
                                        HwAccel accel);
std::vector<std::string> VideoDecodeArgs(HwAccel accel);
std::vector<std::string> AudioCodecArgs(const std::filesystem::path& output_path,
                                        std::optional<std::uint64_t> target_bps);
std::vector<std::string> ContainerArgs(const std::filesystem::path& output_path);

std::string EncryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool include_trailer,
                            bool archive_original,
                            bool use_master);
std::string DecryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool use_master);
std::string EncryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool keep_meta,
                         bool keep_input,
                         bool archive_original,
                         bool use_master);
std::string DecryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool use_master);

}  // namespace basefwx::imagecipher::internal
