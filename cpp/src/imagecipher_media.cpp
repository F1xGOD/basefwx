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


namespace {

struct ProgressReporter {
    bool enabled = true;
    bool printed = false;
    bool use_ansi = false;
    std::chrono::steady_clock::time_point last_tick{};
    std::chrono::steady_clock::time_point last_metrics_tick{};
    double last_fraction = -1.0;
    std::string telemetry;
    std::uint64_t prev_cpu_total = 0;
    std::uint64_t prev_cpu_idle = 0;

    ProgressReporter() {
        enabled = LogEnabled();
        if (!enabled) {
            return;
        }
        const char* term = std::getenv("TERM");
        const char* no_color = std::getenv("NO_COLOR");
        use_ansi = !no_color && term && std::string(term) != "dumb";
        last_tick = std::chrono::steady_clock::now();
        last_metrics_tick = last_tick;
    }

    std::optional<double> SampleCpuPercent() {
#if defined(__linux__)
        std::ifstream in("/proc/stat");
        if (!in) {
            return std::nullopt;
        }
        std::string label;
        std::uint64_t user = 0;
        std::uint64_t nice = 0;
        std::uint64_t system = 0;
        std::uint64_t idle = 0;
        std::uint64_t iowait = 0;
        std::uint64_t irq = 0;
        std::uint64_t softirq = 0;
        std::uint64_t steal = 0;
        in >> label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        if (label != "cpu") {
            return std::nullopt;
        }
        std::uint64_t idle_total = idle + iowait;
        std::uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
        if (prev_cpu_total == 0 || total <= prev_cpu_total) {
            prev_cpu_total = total;
            prev_cpu_idle = idle_total;
            return std::nullopt;
        }
        std::uint64_t delta_total = total - prev_cpu_total;
        std::uint64_t delta_idle = idle_total - prev_cpu_idle;
        prev_cpu_total = total;
        prev_cpu_idle = idle_total;
        if (delta_total == 0) {
            return std::nullopt;
        }
        double usage = 100.0 * (1.0 - (static_cast<double>(delta_idle) / static_cast<double>(delta_total)));
        usage = std::clamp(usage, 0.0, 100.0);
        return usage;
#else
        return std::nullopt;
#endif
    }

    std::optional<double> SampleTempC() {
#if defined(__linux__)
        std::filesystem::path root("/sys/class/thermal");
        std::error_code ec;
        if (!std::filesystem::exists(root, ec)) {
            return std::nullopt;
        }
        double sum = 0.0;
        std::size_t count = 0;
        for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
            if (ec || !entry.is_directory()) {
                continue;
            }
            std::ifstream in(entry.path() / "temp");
            double raw = 0.0;
            if (!(in >> raw)) {
                continue;
            }
            if (raw > 1000.0) {
                raw /= 1000.0;
            }
            if (raw < 5.0 || raw > 130.0) {
                continue;
            }
            sum += raw;
            ++count;
        }
        if (count == 0) {
            return std::nullopt;
        }
        return sum / static_cast<double>(count);
#else
        return std::nullopt;
#endif
    }

    std::string BuildTelemetrySnapshot(bool force = false) {
        auto now = std::chrono::steady_clock::now();
        if (!force && !telemetry.empty()
            && std::chrono::duration_cast<std::chrono::seconds>(now - last_metrics_tick).count() < 5) {
            return telemetry;
        }
        last_metrics_tick = now;
        std::ostringstream out;
        auto cpu = SampleCpuPercent();
        if (cpu.has_value()) {
            out << " | CPU " << std::fixed << std::setprecision(0) << *cpu << "%";
        }
        auto mem = basefwx::system::DetectMemoryInfo();
        if (mem.total_bytes > 0) {
            double ram = (static_cast<double>(mem.used_bytes) * 100.0) / static_cast<double>(mem.total_bytes);
            out << " \\ RAM " << std::fixed << std::setprecision(0) << ram << "%";
        }
        auto temp = SampleTempC();
        if (temp.has_value()) {
            out << " \\ " << std::fixed << std::setprecision(0) << *temp << "C";
        }
        telemetry = out.str();
        return telemetry;
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
        std::string line1 = "Overall " + bar + " " + std::to_string(pct) + "% " + phase + BuildTelemetrySnapshot();
        std::string line2 = "File    " + bar + " " + std::to_string(pct) + "% " + name;
        if (use_ansi) {
            if (printed) {
                std::cerr << "\033[2A";
            }
            std::cerr << "\r\033[2K" << line1 << "\n"
                      << "\r\033[2K" << line2 << std::flush;
        } else {
            std::cerr << line1 << "\n" << line2 << std::endl;
        }
        printed = true;
    }

    void Finish() {
        if (printed) {
            std::cerr << std::endl;
            printed = false;
        }
    }
};

}  // namespace

std::string EncryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool keep_meta,
                         bool keep_input,
                         bool archive_original,
                         bool use_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    basefwx::RequireStrongPasswordForEncryption(resolved, "jMG");
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
        std::string result = EncryptImageInv(
            input_path.string(),
            resolved,
            temp_output.string(),
            true,
            archive_original,
            use_master
        );
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
    if (video.valid && !IsJmgVideoEnabled()) {
        throw std::runtime_error(
            "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable.");
    }
    if (!video.valid && !audio.valid) {
        std::filesystem::path fallback_out = output.empty()
            ? input_path.parent_path() / (input_path.stem().string() + ".fwx")
            : output_path;
        basefwx::fwxaes::EncryptFile(input_path.string(), fallback_out.string(), resolved, {}, {}, {}, keep_input);
        return fallback_out.string();
    }

    BitrateTargets targets = EstimateBitrates(input_path, video, audio);
    HwAccel accel = SelectHwAccel();
    LogHwPlan("jMGe", accel, "media encode/decode routed from BASEFWX_HWACCEL selection");
    std::filesystem::path temp_dir = CreateTempDir("basefwx-media");
    try {
        std::filesystem::path raw_video = temp_dir / "video.raw";
        std::filesystem::path raw_video_out = temp_dir / "video.scr.raw";
        std::filesystem::path raw_audio = temp_dir / "audio.raw";
        std::filesystem::path raw_audio_out = temp_dir / "audio.scr.raw";
        if (video.valid) {
            progress.Update(0.05, "decode-video", input_path);
            std::vector<std::string> decode_video = {"ffmpeg", "-y"};
            auto hwdecode = VideoDecodeArgs(accel);
            decode_video.insert(decode_video.end(), hwdecode.begin(), hwdecode.end());
            decode_video.insert(decode_video.end(), {
                "-i", input_path.string(),
                "-map", "0:v:0",
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                raw_video.string()
            });
            if (!hwdecode.empty()) {
                try {
                    RunCommand(decode_video);
                } catch (const std::exception&) {
                    std::vector<std::string> decode_video_cpu = {
                        "ffmpeg", "-y",
                        "-i", input_path.string(),
                        "-map", "0:v:0",
                        "-f", "rawvideo",
                        "-pix_fmt", "rgb24",
                        raw_video.string()
                    };
                    RunCommand(decode_video_cpu);
                }
            } else {
                RunCommand(decode_video);
            }
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

        basefwx::pb512::KdfOptions kdf;
        auto mask_key = basefwx::keywrap::PrepareMaskKey(
            resolved,
            use_master,
            basefwx::constants::kJmgMaskInfo,
            false,
            basefwx::constants::kMaskAadJmg,
            kdf
        );
        const std::uint8_t security_profile = basefwx::constants::kJmgSecurityProfileDefault;
        Bytes base_key = BaseKeyFromMask(mask_key.mask_key, security_profile);
        Bytes archive_key;
        if (archive_original) {
            archive_key = ArchiveKeyFromMask(mask_key.mask_key, security_profile);
        }
        Bytes trailer_header = BuildJmgHeader(mask_key.user_blob, mask_key.master_blob, security_profile);
        if (video.valid) {
            auto video_cb = [&](double frac) {
                progress.Update(0.25 + 0.45 * frac, "jmg-video", input_path);
            };
            ScrambleVideoRaw(raw_video, raw_video_out, video, base_key, security_profile, video_cb);
        }
        if (audio.valid) {
            auto audio_cb = [&](double frac) {
                progress.Update(0.70 + 0.20 * frac, "jmg-audio", input_path);
            };
            ScrambleAudioRaw(raw_audio, raw_audio_out, audio, base_key, security_profile, audio_cb);
        }

        std::vector<std::string> cmd_base = {
            "ffmpeg", "-y"
        };
        if (video.valid) {
            cmd_base.insert(cmd_base.end(), {
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                "-s", std::to_string(video.width) + "x" + std::to_string(video.height),
                "-r", std::to_string(video.fps > 0.0 ? video.fps : 30.0),
                "-i", raw_video_out.string()
            });
        }
        if (audio.valid) {
            cmd_base.insert(cmd_base.end(), {
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
                cmd_base.push_back("-metadata");
                cmd_base.push_back(meta);
            }
        } else {
            cmd_base.push_back("-map_metadata");
            cmd_base.push_back("-1");
        }

        std::vector<std::string> cmd = cmd_base;
        std::vector<std::string> cmd_fallback;
        bool use_fallback = false;
        if (video.valid) {
            auto v_args = VideoCodecArgs(temp_output, targets.video, accel);
            cmd.insert(cmd.end(), v_args.begin(), v_args.end());
            if (accel != HwAccel::None) {
                auto v_args_sw = VideoCodecArgs(temp_output, targets.video, HwAccel::None);
                if (v_args != v_args_sw) {
                    cmd_fallback = cmd_base;
                    cmd_fallback.insert(cmd_fallback.end(), v_args_sw.begin(), v_args_sw.end());
                    use_fallback = true;
                }
            }
        }
        if (audio.valid) {
            auto a_args = AudioCodecArgs(temp_output, targets.audio);
            cmd.insert(cmd.end(), a_args.begin(), a_args.end());
            if (use_fallback) {
                cmd_fallback.insert(cmd_fallback.end(), a_args.begin(), a_args.end());
            }
        }
        auto c_args = ContainerArgs(temp_output);
        cmd.insert(cmd.end(), c_args.begin(), c_args.end());
        cmd.push_back(temp_output.string());
        if (use_fallback) {
            cmd_fallback.insert(cmd_fallback.end(), c_args.begin(), c_args.end());
            cmd_fallback.push_back(temp_output.string());
        }
        progress.Update(0.95, "encode", input_path);
        if (use_fallback) {
            try {
                RunCommand(cmd);
            } catch (const std::exception&) {
                RunCommand(cmd_fallback);
            }
        } else {
            RunCommand(cmd);
        }
        if (archive_original) {
            auto archive_cb = [&](double frac) {
                progress.Update(0.95 + 0.04 * frac, "archive", input_path);
            };
            AppendTrailerStream(
                temp_output,
                input_path,
                resolved,
                archive_cb,
                archive_key,
                trailer_header,
                JmgArchiveInfoForProfile(security_profile)
            );
        } else {
            AppendBalancedTrailer(temp_output, basefwx::constants::kImageCipherKeyTrailerMagic, trailer_header);
        }
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
                         const std::string& output,
                         bool use_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }
    if (IsImageExt(input_path)) {
        return DecryptImageInv(input_path.string(), resolved, output, use_master);
    }
    try {
        VideoInfo gate_video = ProbeVideo(input_path);
        if (gate_video.valid && !IsJmgVideoEnabled()) {
            throw std::runtime_error(
                "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable.");
        }
    } catch (const std::runtime_error& exc) {
        std::string msg = exc.what();
        if (msg.find("jMG video mode is temporarily disabled") != std::string::npos) {
            throw;
        }
    } catch (const std::exception&) {
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
    if (TryDecryptTrailerStream(input_path, resolved, temp_output, use_master, trailer_cb)) {
        progress.Update(1.0, "done", input_path);
        if (!output_path.empty() && !std::filesystem::equivalent(output_path, temp_output, ec)) {
            std::filesystem::rename(temp_output, output_path);
            temp_output = output_path;
        }
        progress.Finish();
        return temp_output.string();
    }

    std::uint8_t trailer_profile = basefwx::constants::kJmgSecurityProfileLegacy;
    Bytes base_key_override = LoadBaseKeyFromKeyTrailerFile(input_path, resolved, use_master, &trailer_profile);
    bool has_base_key_override = !base_key_override.empty();
    if (has_base_key_override) {
        WarnNoArchivePayload();
    }

    std::uint64_t fallback_limit = 64ull * 1024ull * 1024ull;
    auto file_size = std::filesystem::file_size(input_path, ec);
    if (!ec && file_size <= fallback_limit) {
        Bytes file_bytes = ReadFileBytes(input_path);
        if (!has_base_key_override) {
            base_key_override = LoadBaseKeyFromKeyTrailerBytes(file_bytes, resolved, use_master, &trailer_profile);
            has_base_key_override = !base_key_override.empty();
            if (has_base_key_override) {
                WarnNoArchivePayload();
            }
        }
        Bytes payload;
        Bytes trailer;
        bool has_trailer = ExtractTrailerWithMagic(
            file_bytes,
            basefwx::constants::kImageCipherTrailerMagic,
            payload,
            trailer
        );
        if (has_trailer && !trailer.empty()) {
            bool header_seen = false;
            try {
                std::size_t header_len = 0;
                Bytes user_blob;
                Bytes master_blob;
                std::uint8_t profile_id = basefwx::constants::kJmgSecurityProfileLegacy;
                std::size_t magic_len = basefwx::constants::kJmgKeyMagic.size();
                if (trailer.size() >= magic_len
                    && std::memcmp(trailer.data(), basefwx::constants::kJmgKeyMagic.data(), magic_len) == 0) {
                    header_seen = true;
                }
                bool header_parsed = ParseJmgHeader(trailer, header_len, user_blob, master_blob, &profile_id);
                if (header_seen && !header_parsed) {
                    throw std::runtime_error("Invalid JMG key header");
                }
                header_seen = header_seen || header_parsed;
                Bytes archive_key;
                std::string archive_info = std::string(basefwx::constants::kImageCipherArchiveInfo);
                if (header_seen) {
                    basefwx::pb512::KdfOptions kdf;
                    Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
                        user_blob,
                        master_blob,
                        resolved,
                        use_master,
                        basefwx::constants::kJmgMaskInfo,
                        basefwx::constants::kMaskAadJmg,
                        kdf
                    );
                    archive_key = ArchiveKeyFromMask(mask_key, profile_id);
                    archive_info = JmgArchiveInfoForProfile(profile_id);
                } else {
                    Bytes material = DeriveMaterial(resolved);
                    archive_key = basefwx::crypto::HkdfSha256(material, basefwx::constants::kImageCipherArchiveInfo, 32);
                }
                Bytes aad(archive_info.begin(), archive_info.end());
                Bytes archive_blob = header_seen
                    ? Bytes(trailer.begin() + static_cast<std::ptrdiff_t>(header_len), trailer.end())
                    : trailer;
                Bytes original_bytes = basefwx::crypto::AeadDecrypt(archive_key, archive_blob, aad);
                WriteFileBytes(temp_output, original_bytes);
                progress.Update(1.0, "done", input_path);
                if (!output_path.empty() && !std::filesystem::equivalent(output_path, temp_output, ec)) {
                    std::filesystem::rename(temp_output, output_path);
                    temp_output = output_path;
                }
                progress.Finish();
                return temp_output.string();
            } catch (const std::exception&) {
                if (header_seen) {
                    throw;
                }
            }
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
    if (video.valid && !IsJmgVideoEnabled()) {
        throw std::runtime_error(
            "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable.");
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
            basefwx::fwxaes::DecryptFile(input_path.string(), fallback_out.string(), resolved, true);
            return fallback_out.string();
        }
        throw std::runtime_error("Unsupported media format");
    }

    BitrateTargets targets = EstimateBitrates(input_path, video, audio);
    HwAccel accel = SelectHwAccel();
    LogHwPlan("jMGd", accel, "media encode/decode routed from BASEFWX_HWACCEL selection");
    std::filesystem::path temp_dir = CreateTempDir("basefwx-media");
    try {
        std::filesystem::path raw_video = temp_dir / "video.raw";
        std::filesystem::path raw_video_out = temp_dir / "video.unscr.raw";
        std::filesystem::path raw_audio = temp_dir / "audio.raw";
        std::filesystem::path raw_audio_out = temp_dir / "audio.unscr.raw";
        if (video.valid) {
            progress.Update(0.05, "decode-video", input_path);
            std::vector<std::string> decode_video = {"ffmpeg", "-y"};
            auto hwdecode = VideoDecodeArgs(accel);
            decode_video.insert(decode_video.end(), hwdecode.begin(), hwdecode.end());
            decode_video.insert(decode_video.end(), {
                "-i", input_path.string(),
                "-map", "0:v:0",
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                raw_video.string()
            });
            if (!hwdecode.empty()) {
                try {
                    RunCommand(decode_video);
                } catch (const std::exception&) {
                    std::vector<std::string> decode_video_cpu = {
                        "ffmpeg", "-y",
                        "-i", input_path.string(),
                        "-map", "0:v:0",
                        "-f", "rawvideo",
                        "-pix_fmt", "rgb24",
                        raw_video.string()
                    };
                    RunCommand(decode_video_cpu);
                }
            } else {
                RunCommand(decode_video);
            }
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

        Bytes base_key = has_base_key_override ? base_key_override : BaseKeyFromPassword(resolved);
        if (video.valid) {
            auto video_cb = [&](double frac) {
                progress.Update(0.25 + 0.45 * frac, "unjmg-video", input_path);
            };
            UnscrambleVideoRaw(raw_video, raw_video_out, video, base_key, trailer_profile, video_cb);
        }
        if (audio.valid) {
            auto audio_cb = [&](double frac) {
                progress.Update(0.70 + 0.20 * frac, "unjmg-audio", input_path);
            };
            UnscrambleAudioRaw(raw_audio, raw_audio_out, audio, base_key, trailer_profile, audio_cb);
        }

        std::vector<std::string> cmd_base = {
            "ffmpeg", "-y"
        };
        if (video.valid) {
            cmd_base.insert(cmd_base.end(), {
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                "-s", std::to_string(video.width) + "x" + std::to_string(video.height),
                "-r", std::to_string(video.fps > 0.0 ? video.fps : 30.0),
                "-i", raw_video_out.string()
            });
        }
        if (audio.valid) {
            cmd_base.insert(cmd_base.end(), {
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
                cmd_base.push_back("-metadata");
                cmd_base.push_back(meta);
            }
        } else {
            cmd_base.push_back("-map_metadata");
            cmd_base.push_back("-1");
        }

        std::vector<std::string> cmd = cmd_base;
        std::vector<std::string> cmd_fallback;
        bool use_fallback = false;
        if (video.valid) {
            auto v_args = VideoCodecArgs(temp_output, targets.video, accel);
            cmd.insert(cmd.end(), v_args.begin(), v_args.end());
            if (accel != HwAccel::None) {
                auto v_args_sw = VideoCodecArgs(temp_output, targets.video, HwAccel::None);
                if (v_args != v_args_sw) {
                    cmd_fallback = cmd_base;
                    cmd_fallback.insert(cmd_fallback.end(), v_args_sw.begin(), v_args_sw.end());
                    use_fallback = true;
                }
            }
        }
        if (audio.valid) {
            auto a_args = AudioCodecArgs(temp_output, targets.audio);
            cmd.insert(cmd.end(), a_args.begin(), a_args.end());
            if (use_fallback) {
                cmd_fallback.insert(cmd_fallback.end(), a_args.begin(), a_args.end());
            }
        }
        auto c_args = ContainerArgs(temp_output);
        cmd.insert(cmd.end(), c_args.begin(), c_args.end());
        cmd.push_back(temp_output.string());
        if (use_fallback) {
            cmd_fallback.insert(cmd_fallback.end(), c_args.begin(), c_args.end());
            cmd_fallback.push_back(temp_output.string());
        }
        progress.Update(0.95, "encode", input_path);
        if (use_fallback) {
            try {
                RunCommand(cmd);
            } catch (const std::exception&) {
                RunCommand(cmd_fallback);
            }
        } else {
            RunCommand(cmd);
        }
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

}  // namespace basefwx::imagecipher::internal
