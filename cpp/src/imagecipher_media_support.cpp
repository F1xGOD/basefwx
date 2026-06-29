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



constexpr double kJmgTargetGrowth = 1.1;
constexpr double kJmgMaxGrowth = 2.0;
constexpr std::uint64_t kJmgMinAudioBps = 64000;
constexpr std::uint64_t kJmgMinVideoBps = 200000;

std::string FormatCommandForError(const std::vector<std::string>& args) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& arg : args) {
        if (!first) {
            oss << ' ';
        }
        first = false;
        oss << std::quoted(arg);
    }
    return oss.str();
}

#if defined(_WIN32)
std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     value.data(), static_cast<int>(value.size()),
                                     nullptr, 0);
    if (needed <= 0) {
        needed = MultiByteToWideChar(CP_ACP, 0,
                                     value.data(), static_cast<int>(value.size()),
                                     nullptr, 0);
    }
    if (needed <= 0) {
        throw std::runtime_error("Failed to convert command argument to wide string");
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            value.data(), static_cast<int>(value.size()),
                            out.data(), needed) == 0) {
        if (MultiByteToWideChar(CP_ACP, 0,
                                value.data(), static_cast<int>(value.size()),
                                out.data(), needed) == 0) {
            throw std::runtime_error("Failed to convert command argument to wide string");
        }
    }
    return out;
}

std::wstring QuoteArgWindows(const std::wstring& arg) {
    if (arg.empty()) {
        return L"\"\"";
    }
    bool needs_quotes = arg.find_first_of(L" \t\n\v\"") != std::wstring::npos;
    if (!needs_quotes) {
        return arg;
    }
    std::wstring out;
    out.reserve(arg.size() + 2);
    out.push_back(L'"');
    std::size_t i = 0;
    while (i < arg.size()) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == L'\\') {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (arg[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(arg[i]);
        }
        ++i;
    }
    out.push_back(L'"');
    return out;
}

std::wstring BuildCommandLine(const std::vector<std::string>& args) {
    std::wstring out;
    bool first = true;
    for (const auto& arg : args) {
        if (!first) {
            out.push_back(L' ');
        }
        first = false;
        out.append(QuoteArgWindows(Utf8ToWide(arg)));
    }
    return out;
}

int RunProcess(const std::vector<std::string>& args, std::string* output) {
    if (args.empty()) {
        throw std::runtime_error("Command is empty");
    }
    std::wstring cmdline = BuildCommandLine(args);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    BOOL inherit_handles = FALSE;
    if (output) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
            throw std::runtime_error("Failed to create pipe for command output");
        }
        if (!SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            throw std::runtime_error("Failed to configure pipe for command output");
        }
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = write_pipe;
        si.hStdError = write_pipe;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        inherit_handles = TRUE;
    }

    BOOL ok = CreateProcessW(nullptr,
                             cmdline.data(),
                             nullptr,
                             nullptr,
                             inherit_handles,
                             0,
                             nullptr,
                             nullptr,
                             &si,
                             &pi);
    if (!ok) {
        if (write_pipe) {
            CloseHandle(write_pipe);
        }
        if (read_pipe) {
            CloseHandle(read_pipe);
        }
        throw std::runtime_error("Failed to run command: " + FormatCommandForError(args));
    }
    if (write_pipe) {
        CloseHandle(write_pipe);
    }
    if (output && read_pipe) {
        std::array<char, 4096> buffer{};
        DWORD read = 0;
        while (::ReadFile(read_pipe, buffer.data(),
                        static_cast<DWORD>(buffer.size()), &read, nullptr)
               && read > 0) {
            output->append(buffer.data(), buffer.data() + read);
        }
        CloseHandle(read_pipe);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
        exit_code = 1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(exit_code);
}
#else
int RunProcess(const std::vector<std::string>& args, std::string* output) {
    if (args.empty()) {
        throw std::runtime_error("Command is empty");
    }
    int pipefd[2] = {-1, -1};
    if (output) {
        if (pipe(pipefd) != 0) {
            throw std::runtime_error("Failed to create pipe for command output");
        }
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (output) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        throw std::runtime_error("Failed to fork for command execution");
    }
    if (pid == 0) {
        if (output) {
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[0]);
            close(pipefd[1]);
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    if (output) {
        close(pipefd[1]);
        std::array<char, 4096> buffer{};
        while (true) {
            ssize_t got = read(pipefd[0], buffer.data(), buffer.size());
            if (got > 0) {
                output->append(buffer.data(), buffer.data() + got);
            } else if (got == 0) {
                break;
            } else if (errno != EINTR) {
                break;
            }
        }
        close(pipefd[0]);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}
#endif

std::string RunCommandCapture(const std::vector<std::string>& args) {
    std::string output;
    int rc = RunProcess(args, &output);
    if (rc != 0) {
        throw std::runtime_error("Command failed (" + std::to_string(rc) + "): "
                                 + FormatCommandForError(args));
    }
    return output;
}

void RunCommand(const std::vector<std::string>& args) {
    std::string sink;
    std::string* capture = basefwx::env::IsEnabled("BASEFWX_NO_LOG", false) ? &sink : nullptr;
    int rc = RunProcess(args, capture);
    if (rc != 0) {
        throw std::runtime_error("Command failed (" + std::to_string(rc) + "): "
                                 + FormatCommandForError(args));
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

HwAccel SelectHwAccel() {
    static std::optional<HwAccel> cached;
    if (cached.has_value()) {
        return cached.value();
    }
    const char* gha = std::getenv("GITHUB_ACTIONS");
    const char* ci = std::getenv("CI");
    if ((gha && std::string(gha) == "true") || (ci && std::string(ci) == "true")) {
        cached = HwAccel::None;
        return cached.value();
    }
    std::string raw = basefwx::env::Get("BASEFWX_HWACCEL");
    std::string mode = ToLower(raw);
    if (mode.empty()) {
        mode = "auto";
    }
    if (mode == "0" || mode == "off" || mode == "false" || mode == "no") {
        cached = HwAccel::None;
        return cached.value();
    }
    bool has_nvidia_runtime = false;
    std::string nvidia_visible = ToLower(basefwx::env::Get("NVIDIA_VISIBLE_DEVICES"));
    if (!nvidia_visible.empty() && nvidia_visible != "void" && nvidia_visible != "none") {
        has_nvidia_runtime = true;
    } else if (basefwx::env::IsEnabled("BASEFWX_ASSUME_NVIDIA", false)) {
        has_nvidia_runtime = true;
    } else {
        try {
            std::string smi = RunCommandCapture({"nvidia-smi", "-L"});
            has_nvidia_runtime = smi.find("GPU ") != std::string::npos;
        } catch (const std::exception&) {
            has_nvidia_runtime = false;
        }
    }
    std::string encoders;
    try {
        encoders = RunCommandCapture({"ffmpeg", "-hide_banner", "-encoders"});
    } catch (const std::exception&) {
        cached = HwAccel::None;
        return cached.value();
    }
    bool has_nvenc = encoders.find("h264_nvenc") != std::string::npos;
    bool has_qsv = encoders.find("h264_qsv") != std::string::npos;
    bool has_vaapi = encoders.find("h264_vaapi") != std::string::npos;
    HwAccel selected = HwAccel::None;
    if (mode == "cuda" || mode == "nvenc" || mode == "nvidia") {
        selected = (has_nvenc && has_nvidia_runtime) ? HwAccel::Nvenc : HwAccel::None;
    } else if (mode == "qsv" || mode == "intel") {
        selected = has_qsv ? HwAccel::Qsv : HwAccel::None;
    } else if (mode == "vaapi") {
        selected = has_vaapi ? HwAccel::Vaapi : HwAccel::None;
    } else {
        if (has_nvenc && has_nvidia_runtime) {
            selected = HwAccel::Nvenc;
        } else if (has_qsv) {
            selected = HwAccel::Qsv;
        } else if (has_vaapi) {
            selected = HwAccel::Vaapi;
        }
    }
    cached = selected;
    return cached.value();
}

bool IsJmgVideoEnabled() {
    return basefwx::env::IsEnabled("BASEFWX_ENABLE_JMG_VIDEO", false);
}

bool LogEnabled() {
    return !basefwx::env::IsEnabled("BASEFWX_NO_LOG", false);
}

bool VerboseEnabled() {
    return basefwx::env::IsEnabled("BASEFWX_VERBOSE", false);
}

std::string HwAccelName(HwAccel accel) {
    switch (accel) {
        case HwAccel::Nvenc:
            return "NVENC";
        case HwAccel::Qsv:
            return "QSV";
        case HwAccel::Vaapi:
            return "VAAPI";
        default:
            return "CPU";
    }
}

std::string ParallelText() {
    if (basefwx::env::IsEnabled("BASEFWX_FORCE_SINGLE_THREAD", false)) {
        return "OFF";
    }
    std::size_t workers = 1;
    const char* raw = std::getenv("BASEFWX_MEDIA_WORKERS");
    if (raw && *raw) {
        try {
            std::size_t parsed = static_cast<std::size_t>(std::stoul(raw));
            if (parsed > 0) {
                workers = parsed;
            }
        } catch (const std::exception&) {
        }
    } else {
        unsigned int hw = std::thread::hardware_concurrency();
        workers = hw > 0 ? static_cast<std::size_t>(hw) : 1;
    }
    if (workers <= 1) {
        return "OFF";
    }
    return "ON(" + std::to_string(workers) + "w)";
}

void LogHwPlan(const std::string& op, HwAccel accel, const std::string& reason) {
    if (!LogEnabled()) {
        return;
    }
    const std::string device = HwAccelName(accel);
    const bool expect_gpu = accel != HwAccel::None;
    std::cerr << "🎛 [basefwx.hw] op=" << op
              << " encode=" << device
              << " decode=" << device
              << " pixels=CPU"
              << " parallel=" << ParallelText()
              << " crypto=CPU"
              << " aes_accel=aesni"
              << "\n";
    if (VerboseEnabled()) {
        std::cerr << "   reason: " << reason
                  << "; AES operations remain on CPU path\n";
    }
    if (expect_gpu) {
        (void)expect_gpu;
    }
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
                                        std::optional<std::uint64_t> target_bps,
                                        HwAccel accel) {
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
        if (accel == HwAccel::Nvenc) {
            return {
                "-c:v", "h264_nvenc",
                "-preset", "p4",
                "-b:v", std::to_string(kbps) + "k",
                "-maxrate", std::to_string(kbps) + "k",
                "-bufsize", std::to_string(kbps * 2) + "k",
                "-pix_fmt", "yuv420p"
            };
        }
        if (accel == HwAccel::Qsv) {
            return {
                "-c:v", "h264_qsv",
                "-b:v", std::to_string(kbps) + "k",
                "-maxrate", std::to_string(kbps) + "k",
                "-bufsize", std::to_string(kbps * 2) + "k",
                "-pix_fmt", "yuv420p"
            };
        }
        if (accel == HwAccel::Vaapi) {
            std::string device = basefwx::env::Get("BASEFWX_VAAPI_DEVICE");
            if (device.empty()) {
                device = "/dev/dri/renderD128";
            }
            return {
                "-vaapi_device", device,
                "-vf", "format=nv12,hwupload",
                "-c:v", "h264_vaapi",
                "-b:v", std::to_string(kbps) + "k",
                "-maxrate", std::to_string(kbps) + "k",
                "-bufsize", std::to_string(kbps * 2) + "k"
            };
        }
        return {
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-b:v", std::to_string(kbps) + "k",
            "-maxrate", std::to_string(kbps) + "k",
            "-bufsize", std::to_string(kbps * 2) + "k",
            "-pix_fmt", "yuv420p"
        };
    }
    if (accel == HwAccel::Nvenc) {
        return {"-c:v", "h264_nvenc", "-preset", "p4", "-cq", "23", "-pix_fmt", "yuv420p"};
    }
    if (accel == HwAccel::Qsv) {
        return {"-c:v", "h264_qsv", "-global_quality", "23", "-pix_fmt", "yuv420p"};
    }
    if (accel == HwAccel::Vaapi) {
        std::string device = basefwx::env::Get("BASEFWX_VAAPI_DEVICE");
        if (device.empty()) {
            device = "/dev/dri/renderD128";
        }
        return {"-vaapi_device", device, "-vf", "format=nv12,hwupload", "-c:v", "h264_vaapi", "-qp", "23"};
    }
    return {"-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p"};
}

std::vector<std::string> VideoDecodeArgs(HwAccel accel) {
    if (accel == HwAccel::Nvenc) {
        return {"-hwaccel", "cuda", "-hwaccel_output_format", "cuda"};
    }
    if (accel == HwAccel::Qsv) {
        return {"-hwaccel", "qsv"};
    }
    if (accel == HwAccel::Vaapi) {
        std::string device = basefwx::env::Get("BASEFWX_VAAPI_DEVICE");
        if (device.empty()) {
            device = "/dev/dri/renderD128";
        }
        return {"-hwaccel", "vaapi", "-hwaccel_device", device};
    }
    return {};
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

}  // namespace basefwx::imagecipher::internal
