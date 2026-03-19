#include "basefwx/basefwx.hpp"
#include "basefwx_build_info.hpp"
#include "basefwx/cli_colors.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/runtime.hpp"
#include "basefwx/system_info.hpp"

#include <chrono>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif
#else
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif

namespace {

bool g_verbose = false;
bool g_no_log = false;

#ifndef BASEFWX_CLI_GIT_COMMIT
#define BASEFWX_CLI_GIT_COMMIT "unknown"
#endif

#ifndef BASEFWX_CLI_BUILD_UTC
#define BASEFWX_CLI_BUILD_UTC "unknown"
#endif

#ifndef BASEFWX_CLI_BUILD_TYPE
#define BASEFWX_CLI_BUILD_TYPE "unknown"
#endif

#ifndef BASEFWX_CLI_GITHUB_BUILD
#define BASEFWX_CLI_GITHUB_BUILD "no"
#endif

#ifndef BASEFWX_CLI_TARGET_ARCH
#define BASEFWX_CLI_TARGET_ARCH "unknown"
#endif

#ifndef BASEFWX_CLI_LINKAGE
#define BASEFWX_CLI_LINKAGE "unknown"
#endif

#ifndef BASEFWX_CLI_GPG_FINGERPRINT
#define BASEFWX_CLI_GPG_FINGERPRINT ""
#endif

#ifndef BASEFWX_CLI_GPG_PUBLIC_KEY_AVAILABLE
#define BASEFWX_CLI_GPG_PUBLIC_KEY_AVAILABLE 0
#endif

#ifndef BASEFWX_CLI_GPG_PUBLIC_KEY
#define BASEFWX_CLI_GPG_PUBLIC_KEY ""
#endif

#ifndef BASEFWX_HAS_ARGON2
#define BASEFWX_HAS_ARGON2 0
#endif

#ifndef BASEFWX_HAS_OQS
#define BASEFWX_HAS_OQS 0
#endif

#ifndef BASEFWX_HAS_LZMA
#define BASEFWX_HAS_LZMA 0
#endif

void HandleStopSignal(int /*signum*/) {
    basefwx::runtime::RequestStop();
}

void InstallStopHandlers() {
    std::signal(SIGINT, HandleStopSignal);
#if defined(SIGTERM)
    std::signal(SIGTERM, HandleStopSignal);
#endif
}

std::string ToLower(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size()
        && value.substr(value.size() - suffix.size()) == suffix;
}

std::optional<std::uint32_t> ReadU32Be(std::ifstream& in) {
    std::array<std::uint8_t, 4> buf{};
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (in.gcount() != static_cast<std::streamsize>(buf.size())) {
        return std::nullopt;
    }
    std::uint32_t value = (static_cast<std::uint32_t>(buf[0]) << 24)
                        | (static_cast<std::uint32_t>(buf[1]) << 16)
                        | (static_cast<std::uint32_t>(buf[2]) << 8)
                        | static_cast<std::uint32_t>(buf[3]);
    return value;
}

std::optional<std::uint64_t> EstimatePlainTmpTargetSize(const std::filesystem::path& input_path) {
    constexpr std::uint64_t kTagLen = 16;
    constexpr std::uint64_t kNonceLen = 12;
    std::ifstream in(input_path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    auto len_user = ReadU32Be(in);
    if (!len_user.has_value()) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(*len_user), std::ios::cur);
    auto len_master = ReadU32Be(in);
    if (!len_master.has_value()) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(*len_master), std::ios::cur);
    auto len_payload = ReadU32Be(in);
    if (!len_payload.has_value()) {
        return std::nullopt;
    }
    auto metadata_len = ReadU32Be(in);
    if (!metadata_len.has_value()) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(*metadata_len), std::ios::cur);
    in.seekg(static_cast<std::streamoff>(kNonceLen), std::ios::cur);
    std::streampos body_start_pos = in.tellg();
    if (body_start_pos < 0) {
        return std::nullopt;
    }

    std::error_code ec;
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(input_path, ec));
    if (ec) {
        return std::nullopt;
    }
    std::uint64_t body_start = static_cast<std::uint64_t>(body_start_pos);
    if (file_size < body_start + kTagLen) {
        return std::nullopt;
    }
    std::uint64_t body_len = file_size - body_start - kTagLen;

    std::uint64_t payload_len = 4ull
        + static_cast<std::uint64_t>(*metadata_len)
        + kNonceLen
        + body_len
        + kTagLen;
    if (payload_len != static_cast<std::uint64_t>(*len_payload)) {
        return std::nullopt;
    }
    return body_len;
}

bool IsLightCommand(const std::string& command) {
    static const std::unordered_set<std::string> kLightCommands = {
        "info", "identify", "probe",
        "b64-enc", "b64-dec",
        "n10-enc", "n10-dec",
        "b256-enc", "b256-dec",
        "a512-enc", "a512-dec",
        "bi512-enc", "b1024-enc",
        "hash512", "uhash513"
    };
    return kLightCommands.count(command) > 0;
}

std::string MoveOutputPath(const std::string& current_path, const std::string& requested_path) {
    if (requested_path.empty() || current_path == requested_path) {
        return current_path;
    }
    std::filesystem::path src(current_path);
    std::filesystem::path dst(requested_path);
    std::error_code ec;
    if (std::filesystem::exists(dst, ec) && std::filesystem::is_directory(dst, ec)) {
        dst /= src.filename();
    }
    if (!dst.parent_path().empty()) {
        std::filesystem::create_directories(dst.parent_path(), ec);
        if (ec) {
            throw std::runtime_error("Failed to prepare output path: " + dst.string());
        }
    }
    std::filesystem::rename(src, dst, ec);
    if (ec) {
        ec.clear();
        std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            throw std::runtime_error("Failed to move output to: " + dst.string());
        }
        ec.clear();
        std::filesystem::remove(src, ec);
        if (ec) {
            throw std::runtime_error("Failed to finalize moved output: " + dst.string());
        }
    }
    return dst.string();
}

bool IsTruthy(std::string value) {
    value = ToLower(std::move(value));
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

void SetCliEnvVar(const char* key, const char* value) {
#if defined(_WIN32)
    _putenv_s(key, value);
#else
    setenv(key, value, 1);
#endif
}

bool ShouldLog() {
    return !g_no_log && !basefwx::env::IsEnabled("BASEFWX_NO_LOG", false);
}

bool IsVerbose() {
    return g_verbose || basefwx::env::IsEnabled("BASEFWX_VERBOSE", false);
}

bool CliPlain() {
    if (basefwx::env::IsEnabled("BASEFWX_CLI_PLAIN", false)) {
        return true;
    }
    if (!basefwx::env::Get("NO_COLOR").empty()) {
        return true;
    }
    std::string style = ToLower(basefwx::env::Get("BASEFWX_CLI_STYLE"));
    if (style == "plain" || style == "boring" || style == "0" || style == "false" || style == "off") {
        return true;
    }
    if (style == "color" || style == "emoji" || style == "on") {
        return false;
    }
    std::filesystem::path config_path;
    std::string cfg = basefwx::env::Get("BASEFWX_CLI_CONFIG");
    if (!cfg.empty()) {
        config_path = std::filesystem::path(cfg);
    } else {
        std::string appdata = basefwx::env::Get("APPDATA");
        if (!appdata.empty()) {
            config_path = std::filesystem::path(appdata) / "basefwx" / "cli.conf";
        } else {
            std::string home = basefwx::env::HomeDir();
            if (!home.empty()) {
                config_path = std::filesystem::path(home) / ".config" / "basefwx" / "cli.conf";
            }
        }
    }
    if (!config_path.empty()) {
        std::ifstream input(config_path);
        if (input) {
            std::string data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
            data = ToLower(data);
            if (data.find("plain=1") != std::string::npos || data.find("plain=true") != std::string::npos
                || data.find("style=plain") != std::string::npos || data.find("mode=plain") != std::string::npos
                || data.find("boring=1") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool IsStderrInteractive() {
#if defined(_WIN32)
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

std::string StyleText(const std::string& text, const char* color, bool plain) {
    if (plain) {
        return text;
    }
    return std::string(color) + text + "\033[0m";
}

std::string EmojiPrefix(const char* emoji, bool plain) {
    if (plain || !emoji) {
        return {};
    }
    return std::string(emoji) + " ";
}

bool LooksLikeMediaPath(const std::filesystem::path& path) {
    static const std::unordered_set<std::string> kImageExts = {
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp", ".tif", ".tiff",
        ".heic", ".heif", ".avif", ".ico"
    };
    static const std::unordered_set<std::string> kVideoExts = {
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".flv", ".wmv",
        ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".m2ts"
    };
    static const std::unordered_set<std::string> kAudioExts = {
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".alac"
    };
    std::string ext = ToLower(path.extension().string());
    if (ext.empty()) {
        return false;
    }
    return kImageExts.count(ext) || kVideoExts.count(ext) || kAudioExts.count(ext);
}

void EnableBinaryStdio(bool use_stdin, bool use_stdout) {
#ifdef _WIN32
    if (use_stdin) {
        _setmode(_fileno(stdin), _O_BINARY);
    }
    if (use_stdout) {
        _setmode(_fileno(stdout), _O_BINARY);
    }
#else
    (void)use_stdin;
    (void)use_stdout;
#endif
}

void PrintSystemInfo() {
    if (!IsVerbose() || !ShouldLog()) {
        return;
    }
    
    auto sysinfo = basefwx::system::DetectSystemInfo();
    bool plain = CliPlain();
    
    if (plain) {
        basefwx::cli::SetColorsEnabled(false);
    }
    
    // CPU info
    std::cerr << "CPU: "
              << basefwx::cli::Yellow(std::to_string(sysinfo.cpu.logical_cores))
              << " | "
              << basefwx::cli::Blue(basefwx::system::FormatFrequency(sysinfo.cpu.max_frequency_mhz))
              << "\n";
    
    // RAM info
    std::cerr << "RAM: "
              << basefwx::cli::Yellow(basefwx::system::FormatBytes(sysinfo.memory.total_bytes))
              << " | Used: "
              << basefwx::cli::Yellow(basefwx::system::FormatBytes(sysinfo.memory.used_bytes))
              << " | Free: "
              << basefwx::cli::Yellow(basefwx::system::FormatBytes(sysinfo.memory.available_bytes));
    
    if (sysinfo.memory.frequency_mhz > 0) {
        std::cerr << " | " << basefwx::cli::Blue(basefwx::system::FormatFrequency(sysinfo.memory.frequency_mhz));
    }
    std::cerr << "\n";
    
    // Chunk size recommendation
    auto policy = basefwx::system::GetChunkSizePolicy(sysinfo.memory);
    std::size_t chunk_size = basefwx::system::ChunkSizeFromPolicy(policy);
    std::cerr << "Chunk Size: "
              << basefwx::cli::BoldGreen(basefwx::system::FormatBytes(chunk_size))
              << " (optimized for this system)\n";
    std::cerr << "\n";
}

void ApplyMasterPubPath(const std::string& path) {
    if (path.empty()) {
        return;
    }
#if defined(_WIN32)
    _putenv_s("BASEFWX_MASTER_PQ_PUB", path.c_str());
#else
    setenv("BASEFWX_MASTER_PQ_PUB", path.c_str(), 1);
#endif
}

void EnableMasterEcAutogen() {
    SetCliEnvVar("BASEFWX_MASTER_EC_CREATE_IF_MISSING", "1");
}

void EnableBakedMasterPub() {
    SetCliEnvVar("BASEFWX_MASTER_PQ_ALLOW_BAKED", "1");
}

bool HandleMasterFlag(const std::string& flag,
                      int argc,
                      char** argv,
                      int* idx,
                      bool* use_master) {
    if (flag == "--use-master") {
        if (use_master) {
            *use_master = true;
        }
        return true;
    }
    if (flag == "--no-master") {
        if (use_master) {
            *use_master = false;
        }
        return true;
    }
    if (flag == "--master-autogen") {
        EnableMasterEcAutogen();
        if (use_master) {
            *use_master = true;
        }
        return true;
    }
    if (flag == "--allow-embedded-master") {
        EnableBakedMasterPub();
        if (use_master) {
            *use_master = true;
        }
        return true;
    }
    if (flag == "--master-pub" || flag == "--use-master-pub") {
        if (!idx || *idx + 1 >= argc) {
            throw std::runtime_error("Missing master public key path");
        }
        ApplyMasterPubPath(argv[*idx + 1]);
        if (use_master) {
            *use_master = true;
        }
        *idx += 1;
        return true;
    }
    return false;
}

std::atomic<std::size_t> g_bench_sink{0};

std::string ReadTextFile(const std::string& path) {
    auto data = basefwx::ReadFile(path);
    return std::string(data.begin(), data.end());
}

std::vector<std::uint8_t> ReadBinaryFile(const std::string& path) {
    return basefwx::ReadFile(path);
}

void WriteTextFile(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file: " + path);
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) {
        throw std::runtime_error("Failed to write output file: " + path);
    }
}

void WriteBinaryFile(const std::string& path, const std::string& data) {
    WriteTextFile(path, data);
}

std::string StripAsciiWhitespace(std::string value) {
    value.erase(std::remove_if(value.begin(),
                               value.end(),
                               [](unsigned char ch) { return std::isspace(ch) != 0; }),
                value.end());
    return value;
}

std::string ExtractJsonField(const std::string& json, const std::string& key) {
    if (json.empty() || key.empty()) {
        return {};
    }
    std::string needle = "\"" + key + "\":";
    std::size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return {};
    }
    pos += needle.size();
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
        ++pos;
    }
    if (pos >= json.size()) {
        return {};
    }
    if (json[pos] == '"') {
        ++pos;
        std::string out;
        out.reserve(32);
        bool escape = false;
        while (pos < json.size()) {
            char ch = json[pos++];
            if (escape) {
                out.push_back(ch);
                escape = false;
                continue;
            }
            if (ch == '\\') {
                escape = true;
                continue;
            }
            if (ch == '"') {
                break;
            }
            out.push_back(ch);
        }
        return out;
    }
    std::size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}') {
        ++end;
    }
    return StripAsciiWhitespace(json.substr(pos, end - pos));
}

std::string FormatSize(std::uint64_t bytes) {
    std::ostringstream out;
    out << bytes << " bytes (" << basefwx::system::FormatBytes(bytes) << ")";
    return out.str();
}

void PrintIdentifyField(const std::string& key, const std::string& value) {
    std::cout << basefwx::cli::Cyan(key) << ": " << value << "\n";
}

struct FwxAesHeaderInfo {
    std::uint8_t algo = 0;
    std::uint8_t kdf = 0;
    std::uint8_t salt_len = 0;
    std::uint8_t iv_len = 0;
    std::uint32_t field0 = 0;
    std::uint32_t ct_len32 = 0;
    std::optional<std::uint64_t> ct_len64;
    std::uint64_t file_size = 0;
};

bool ReadU32Be(std::istream& in, std::uint32_t* out) {
    std::array<std::uint8_t, 4> buf{};
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (in.gcount() != static_cast<std::streamsize>(buf.size())) {
        return false;
    }
    *out = (static_cast<std::uint32_t>(buf[0]) << 24)
           | (static_cast<std::uint32_t>(buf[1]) << 16)
           | (static_cast<std::uint32_t>(buf[2]) << 8)
           | static_cast<std::uint32_t>(buf[3]);
    return true;
}

struct LightweightInspect {
    basefwx::InspectResult info;
    std::uint64_t file_size = 0;
};

std::optional<LightweightInspect> InspectLengthPrefixedFile(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec || file_size < 12) {
        return std::nullopt;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }

    std::uint64_t offset = 0;
    std::uint32_t len_user = 0;
    if (!ReadU32Be(in, &len_user)) {
        return std::nullopt;
    }
    offset += 4;
    if (offset + len_user + 4 > file_size) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(len_user), std::ios::cur);
    if (!in) {
        return std::nullopt;
    }
    offset += len_user;

    std::uint32_t len_master = 0;
    if (!ReadU32Be(in, &len_master)) {
        return std::nullopt;
    }
    offset += 4;
    if (offset + len_master + 4 > file_size) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(len_master), std::ios::cur);
    if (!in) {
        return std::nullopt;
    }
    offset += len_master;

    std::uint32_t len_payload_u32 = 0;
    if (!ReadU32Be(in, &len_payload_u32)) {
        return std::nullopt;
    }
    offset += 4;
    if (offset > file_size) {
        return std::nullopt;
    }
    std::uint64_t payload_available = file_size - offset;
    if (static_cast<std::uint32_t>(payload_available) != len_payload_u32) {
        return std::nullopt;
    }

    LightweightInspect result;
    result.file_size = file_size;
    result.info.user_blob_len = len_user;
    result.info.master_blob_len = len_master;
    result.info.payload_len = static_cast<std::size_t>(payload_available);

    if (payload_available < 4) {
        return result;
    }

    std::uint32_t metadata_len = 0;
    if (!ReadU32Be(in, &metadata_len)) {
        return std::nullopt;
    }
    if (metadata_len > payload_available - 4) {
        return std::nullopt;
    }

    result.info.has_metadata = true;
    result.info.metadata_len = metadata_len;
    if (metadata_len == 0) {
        return result;
    }

    constexpr std::uint32_t kMaxMetadataInspectBytes = 1u << 20;
    if (metadata_len > kMaxMetadataInspectBytes) {
        result.info.metadata_json = {};
        return result;
    }

    std::vector<std::uint8_t> metadata_blob(metadata_len);
    in.read(reinterpret_cast<char*>(metadata_blob.data()), static_cast<std::streamsize>(metadata_blob.size()));
    if (in.gcount() != static_cast<std::streamsize>(metadata_blob.size())) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> payload_prefix;
    payload_prefix.reserve(4u + metadata_blob.size());
    payload_prefix.push_back(static_cast<std::uint8_t>((metadata_len >> 24) & 0xFF));
    payload_prefix.push_back(static_cast<std::uint8_t>((metadata_len >> 16) & 0xFF));
    payload_prefix.push_back(static_cast<std::uint8_t>((metadata_len >> 8) & 0xFF));
    payload_prefix.push_back(static_cast<std::uint8_t>(metadata_len & 0xFF));
    payload_prefix.insert(payload_prefix.end(), metadata_blob.begin(), metadata_blob.end());

    auto preview = basefwx::format::TryDecodeMetadata(payload_prefix);
    if (preview.has_value()) {
        result.info.metadata_base64 = preview->metadata_base64;
        result.info.metadata_json = preview->metadata_json;
    } else {
        result.info.metadata_json = {};
    }
    return result;
}

bool MetadataNeedsFullFallback(const basefwx::InspectResult& info) {
    return info.has_metadata && info.metadata_len > 0 && info.metadata_json.empty();
}

std::uint64_t InspectFallbackMaxBytes() {
    constexpr std::uint64_t kDefault = 256ull << 20;  // 256 MiB
    std::string raw = basefwx::env::Get("BASEFWX_INSPECT_FALLBACK_MAX_BYTES");
    if (raw.empty()) {
        return kDefault;
    }
    try {
        std::uint64_t parsed = std::stoull(raw);
        if (parsed < (1ull << 20)) {
            return 1ull << 20;
        }
        return parsed;
    } catch (const std::exception&) {
        return kDefault;
    }
}

std::optional<std::vector<std::uint8_t>> TryReadFullInspectSafe(const std::filesystem::path& path,
                                                                std::string* reason) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        if (reason) {
            *reason = "file does not exist or is not a regular file";
        }
        return std::nullopt;
    }
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        if (reason) {
            *reason = "failed to stat file";
        }
        return std::nullopt;
    }

    bool unsafe = basefwx::env::IsEnabled("BASEFWX_INSPECT_FALLBACK_UNSAFE", false);
    std::uint64_t max_bytes = InspectFallbackMaxBytes();
    if (!unsafe && file_size > max_bytes) {
        if (reason) {
            std::ostringstream msg;
            msg << "full-read fallback skipped for safety (file="
                << basefwx::system::FormatBytes(file_size)
                << ", limit=" << basefwx::system::FormatBytes(max_bytes)
                << "; set BASEFWX_INSPECT_FALLBACK_UNSAFE=1 to force)";
            *reason = msg.str();
        }
        return std::nullopt;
    }

    try {
        return basefwx::ReadFile(path.string());
    } catch (const std::bad_alloc&) {
        if (reason) {
            *reason = "full-read fallback aborted: out of memory";
        }
        return std::nullopt;
    } catch (const std::exception& ex) {
        if (reason) {
            *reason = std::string("full-read fallback failed: ") + ex.what();
        }
        return std::nullopt;
    }
}

void MaybeWarnInspectFallback(const std::string& reason) {
    if (reason.empty() || !ShouldLog()) {
        return;
    }
    std::cerr << basefwx::cli::BoldYellow("[WARN] ") << reason << "\n";
}

std::optional<FwxAesHeaderInfo> ParseFwxAesHeader(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec || file_size < 16) {
        return std::nullopt;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::array<std::uint8_t, 16> head{};
    in.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
    if (in.gcount() != static_cast<std::streamsize>(head.size())) {
        return std::nullopt;
    }
    if (head[0] != 'F' || head[1] != 'W' || head[2] != 'X' || head[3] != '1') {
        return std::nullopt;
    }

    auto u32 = [&](std::size_t off) -> std::uint32_t {
        return (static_cast<std::uint32_t>(head[off]) << 24)
               | (static_cast<std::uint32_t>(head[off + 1]) << 16)
               | (static_cast<std::uint32_t>(head[off + 2]) << 8)
               | static_cast<std::uint32_t>(head[off + 3]);
    };

    FwxAesHeaderInfo out;
    out.algo = head[4];
    out.kdf = head[5];
    out.salt_len = head[6];
    out.iv_len = head[7];
    out.field0 = u32(8);
    out.ct_len32 = u32(12);
    out.file_size = file_size;

    std::uint64_t offset = 16;
    if (out.kdf == 0x01) {
        offset += static_cast<std::uint64_t>(out.salt_len) + static_cast<std::uint64_t>(out.iv_len);
    } else if (out.kdf == 0x02) {
        offset += static_cast<std::uint64_t>(out.field0) + static_cast<std::uint64_t>(out.iv_len);
    }

    if (out.algo == 0x02 && offset + 8 <= file_size) {
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        std::array<std::uint8_t, 8> buf{};
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (in.gcount() == static_cast<std::streamsize>(buf.size())) {
            std::uint64_t v = 0;
            for (std::uint8_t b : buf) {
                v = (v << 8) | b;
            }
            out.ct_len64 = v;
        }
    }
    return out;
}

bool PrintIdentifyLengthPrefixed(const std::string& file_path,
                                 const LightweightInspect& inspect) {
    const basefwx::InspectResult& info = inspect.info;
    std::string method = ExtractJsonField(info.metadata_json, "ENC-METHOD");
    std::string version = ExtractJsonField(info.metadata_json, "ENC-VERSION");
    std::string mode = ExtractJsonField(info.metadata_json, "ENC-MODE");
    std::string kdf = ExtractJsonField(info.metadata_json, "ENC-KDF");
    std::string aead = ExtractJsonField(info.metadata_json, "ENC-AEAD");
    std::string master = ExtractJsonField(info.metadata_json, "ENC-MASTER");
    std::string obf = ExtractJsonField(info.metadata_json, "ENC-OBF");
    std::string time = ExtractJsonField(info.metadata_json, "ENC-TIME");
    std::string kem = ExtractJsonField(info.metadata_json, "ENC-KEM");

    if (method.empty()) {
        method = "unknown";
    }
    if (version.empty()) {
        version = "unknown";
    }
    if (mode.empty()) {
        mode = "normal";
    }
    if (kdf.empty()) {
        kdf = "unknown";
    }
    if (aead.empty()) {
        aead = "unknown";
    }
    if (master.empty()) {
        master = "unknown";
    }
    if (obf.empty()) {
        obf = "unknown";
    }
    if (kem.empty()) {
        kem = "unknown";
    }
    if (time.empty()) {
        time = "unknown";
    }

    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", file_path);
    PrintIdentifyField("format", "basefwx length-prefixed container");
    PrintIdentifyField("integrity", basefwx::cli::BoldGreen("OK"));
    PrintIdentifyField("method", method);
    PrintIdentifyField("version", version);
    PrintIdentifyField("mode", mode);
    PrintIdentifyField("kdf", kdf);
    PrintIdentifyField("aead", aead);
    PrintIdentifyField("master", master);
    PrintIdentifyField("kem", kem);
    PrintIdentifyField("obfuscation", obf);
    PrintIdentifyField("encrypted_at", time);
    PrintIdentifyField("file_size", FormatSize(inspect.file_size));
    PrintIdentifyField("payload_size", FormatSize(static_cast<std::uint64_t>(info.payload_len)));
    PrintIdentifyField("user_blob", FormatSize(static_cast<std::uint64_t>(info.user_blob_len)));
    PrintIdentifyField("master_blob", FormatSize(static_cast<std::uint64_t>(info.master_blob_len)));
    if (info.has_metadata) {
        PrintIdentifyField("metadata_size", FormatSize(static_cast<std::uint64_t>(info.metadata_len)));
    } else {
        PrintIdentifyField("metadata_size", "unavailable");
    }
    return true;
}

bool PrintIdentifyFwxAes(const std::string& file_path, const FwxAesHeaderInfo& header) {
    std::string algo_name = "unknown";
    if (header.algo == 0x01) {
        algo_name = "fwxaes-v1";
    } else if (header.algo == 0x02) {
        algo_name = "fwxaes-stream-v2";
    }
    std::string kdf_name = "unknown";
    if (header.kdf == 0x01) {
        kdf_name = "pbkdf2";
    } else if (header.kdf == 0x02) {
        kdf_name = "wrapped";
    }

    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", file_path);
    PrintIdentifyField("format", "FWX1 header container");
    PrintIdentifyField("integrity", basefwx::cli::BoldGreen("OK"));
    PrintIdentifyField("algo", algo_name + " (" + std::to_string(static_cast<unsigned int>(header.algo)) + ")");
    PrintIdentifyField("kdf", kdf_name + " (" + std::to_string(static_cast<unsigned int>(header.kdf)) + ")");
    PrintIdentifyField("salt_len", std::to_string(static_cast<unsigned int>(header.salt_len)) + " bytes");
    PrintIdentifyField("iv_len", std::to_string(static_cast<unsigned int>(header.iv_len)) + " bytes");
    if (header.kdf == 0x01) {
        PrintIdentifyField("pbkdf2_iters", std::to_string(header.field0));
    } else if (header.kdf == 0x02) {
        PrintIdentifyField("key_header_len", std::to_string(header.field0) + " bytes");
    }
    if (header.ct_len64.has_value()) {
        PrintIdentifyField("ciphertext_len", FormatSize(*header.ct_len64));
    } else {
        PrintIdentifyField("ciphertext_len", FormatSize(header.ct_len32));
    }
    PrintIdentifyField("file_size", FormatSize(static_cast<std::uint64_t>(header.file_size)));
    return true;
}

void PrintFwxAesInfo(const FwxAesHeaderInfo& header) {

    std::string algo_name = "unknown";
    if (header.algo == 0x01) {
        algo_name = "fwxaes-v1";
    } else if (header.algo == 0x02) {
        algo_name = "fwxaes-stream-v2";
    }
    std::string kdf_name = "unknown";
    if (header.kdf == 0x01) {
        kdf_name = "pbkdf2";
    } else if (header.kdf == 0x02) {
        kdf_name = "wrapped";
    }

    std::cout << "format: fwxAES\n";
    std::cout << "algo: " << algo_name << " (" << static_cast<unsigned int>(header.algo) << ")\n";
    std::cout << "kdf: " << kdf_name << " (" << static_cast<unsigned int>(header.kdf) << ")\n";
    std::cout << "salt_len: " << static_cast<unsigned int>(header.salt_len) << " bytes\n";
    std::cout << "iv_len: " << static_cast<unsigned int>(header.iv_len) << " bytes\n";
    if (header.kdf == 0x01) {
        std::cout << "pbkdf2_iters: " << header.field0 << "\n";
    } else if (header.kdf == 0x02) {
        std::cout << "key_header_len: " << header.field0 << " bytes\n";
    }
    if (header.ct_len64.has_value()) {
        std::cout << "ciphertext_len: " << *header.ct_len64 << " bytes\n";
    } else {
        std::cout << "ciphertext_len: " << header.ct_len32 << " bytes\n";
    }
    std::cout << "file_size: " << header.file_size << " bytes\n";
}

void PrintInspectInfo(const basefwx::InspectResult& info) {
    std::cout << "user_blob_len: " << info.user_blob_len << " bytes\n";
    std::cout << "master_blob_len: " << info.master_blob_len << " bytes\n";
    std::cout << "payload_len: " << info.payload_len << " bytes\n";
    if (info.has_metadata) {
        std::cout << "metadata_len: " << info.metadata_len << " bytes\n";
        if (!info.metadata_json.empty()) {
            std::cout << "metadata_json: " << info.metadata_json << "\n";
        } else if (info.metadata_len == 0) {
            std::cout << "metadata_json: <empty>\n";
        } else {
            std::cout << "metadata_json: <unavailable>\n";
        }
    } else {
        std::cout << "metadata_json: <unavailable>\n";
    }
}

int ReadEnvInt(const char* name, int default_value, int min_value) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return default_value;
    }
    char* end = nullptr;
    long value = std::strtol(raw, &end, 10);
    if (end == raw) {
        return default_value;
    }
    if (value < min_value) {
        return default_value;
    }
    if (value > static_cast<long>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(value);
}

int BenchWarmup() {
    return ReadEnvInt("BASEFWX_BENCH_WARMUP", 2, 0);
}

int BenchIters() {
    return ReadEnvInt("BASEFWX_BENCH_ITERS", 50, 1);
}

bool BenchParallelEnabled() {
    std::string raw = ToLower(basefwx::env::Get("BASEFWX_BENCH_PARALLEL"));
    if (raw.empty()) {
        return true;
    }
    return !(raw == "0" || raw == "false" || raw == "off" || raw == "no");
}

int BenchWorkers() {
    if (!BenchParallelEnabled()) {
        return 1;
    }
    unsigned int hw = std::thread::hardware_concurrency();
    int default_workers = hw == 0 ? 1 : static_cast<int>(hw);
    return ReadEnvInt("BASEFWX_BENCH_WORKERS", default_workers, 1);
}

bool SingleThreadForced(std::size_t workers) {
    // Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
    std::string force_single = basefwx::env::Get("BASEFWX_FORCE_SINGLE_THREAD");
    unsigned int hw = std::thread::hardware_concurrency();
    return (force_single == "1" && hw > 1);
}

void WarnSingleThreadIfForced() {
    static bool warned = false;
    if (warned) {
        return;
    }
    if (!SingleThreadForced(1)) {
        return;
    }
    warned = true;
    if (!ShouldLog()) {
        return;
    }
    std::cerr << "\033[38;5;208mWARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION\033[0m\n";
    std::cerr << "\033[38;5;208mWARN: SINGLE-THREAD MODE MAY REDUCE SECURITY MARGIN\033[0m\n";
}

void ConfirmSingleThreadCli(std::size_t workers) {
    if (!SingleThreadForced(workers)) {
        return;
    }
    WarnSingleThreadIfForced();
    const char* allow_single = std::getenv("BASEFWX_ALLOW_SINGLE_THREAD");
    const char* noninteractive = std::getenv("BASEFWX_NONINTERACTIVE");
    if ((allow_single && std::string_view(allow_single) == "1") || (noninteractive && std::string_view(noninteractive) == "1")) {
        return;
    }
    std::cout << "Type YES to continue with single-thread mode: ";
    std::string line;
    if (!std::getline(std::cin, line)) {
        throw std::runtime_error("Aborted: multi-thread disabled by user override");
    }
    if (line != "YES") {
        throw std::runtime_error("Aborted: multi-thread disabled by user override");
    }
}

long long MedianNs(std::vector<long long>& samples) {
    if (samples.empty()) {
        return 0;
    }
    std::size_t mid = samples.size() / 2;
    std::nth_element(samples.begin(), samples.begin() + static_cast<std::ptrdiff_t>(mid), samples.end());
    long long high = samples[mid];
    if (samples.size() % 2 == 1) {
        return high;
    }
    auto lower_max = std::max_element(samples.begin(), samples.begin() + static_cast<std::ptrdiff_t>(mid));
    long long low = lower_max == samples.begin() + static_cast<std::ptrdiff_t>(mid) ? high : *lower_max;
    return low + (high - low) / 2;
}

template <typename Fn>
long long BenchMedian(int warmup, int iters, Fn&& fn) {
    if (warmup < 0) {
        warmup = 0;
    }
    if (iters < 1) {
        iters = 1;
    }
    for (int i = 0; i < warmup; ++i) {
        fn();
    }
    std::vector<long long> samples;
    samples.reserve(static_cast<std::size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        auto start = std::chrono::steady_clock::now();
        fn();
        auto end = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
    }
    return MedianNs(samples);
}

std::size_t RunFwxaesParallel(const std::vector<std::uint8_t>& data,
                              const std::string& password,
                              bool use_master,
                              std::size_t workers) {
    std::atomic<std::size_t> total{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    basefwx::fwxaes::Options opts;
    opts.use_master = use_master;
    std::exception_ptr first_exc = nullptr;
    std::mutex exc_mutex;
    for (std::size_t i = 0; i < workers; ++i) {
        threads.emplace_back([&]() {
            try {
                auto blob = basefwx::fwxaes::EncryptRaw(data, password, opts);
                auto plain = basefwx::fwxaes::DecryptRaw(blob, password, use_master);
                g_bench_sink.fetch_xor(plain.size(), std::memory_order_relaxed);
                total.fetch_add(plain.size(), std::memory_order_relaxed);
            } catch (...) {
                std::lock_guard<std::mutex> lock(exc_mutex);
                if (!first_exc) {
                    first_exc = std::current_exception();
                }
            }
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    if (first_exc) {
        std::rethrow_exception(first_exc);
    }
    return total.load(std::memory_order_relaxed);
}

template <typename Fn>
std::size_t RunParallel(std::size_t workers, Fn fn) {
    std::atomic<std::size_t> total{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    std::exception_ptr first_exc = nullptr;
    std::mutex exc_mutex;
    for (std::size_t i = 0; i < workers; ++i) {
        threads.emplace_back([&, i]() {
            try {
                total.fetch_add(fn(i), std::memory_order_relaxed);
            } catch (...) {
                std::lock_guard<std::mutex> lock(exc_mutex);
                if (!first_exc) {
                    first_exc = std::current_exception();
                }
            }
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    if (first_exc) {
        std::rethrow_exception(first_exc);
    }
    return total.load(std::memory_order_relaxed);
}

std::string CompilerVersionString() {
#if defined(__clang__)
    return std::string("clang ") + __clang_version__;
#elif defined(__GNUC__)
    return std::string("gcc ") + __VERSION__;
#elif defined(_MSC_VER)
    return std::string("msvc ") + std::to_string(_MSC_VER);
#else
    return "unknown";
#endif
}

std::string CxxStdString() {
#if __cplusplus >= 202302L
    return "C++23";
#elif __cplusplus >= 202002L
    return "C++20";
#elif __cplusplus >= 201703L
    return "C++17";
#elif __cplusplus >= 201402L
    return "C++14";
#elif __cplusplus >= 201103L
    return "C++11";
#else
    return "pre-C++11";
#endif
}

const char* OnOff(bool value) {
    return value ? "ON" : "OFF";
}

std::string HumanizeUtcTimestamp(std::string value) {
    if (value.size() < 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T') {
        return value;
    }
    value[10] = ' ';
    if (!value.empty() && value.back() == 'Z') {
        value.pop_back();
        value += " UTC";
    }
    return value;
}

std::string RuntimeArchString() {
#if defined(__x86_64__) || defined(_M_X64)
    return "amd64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#else
    return "unknown";
#endif
}

std::string EffectiveArchString() {
    std::string arch = BASEFWX_CLI_TARGET_ARCH;
    if (arch.empty() || arch == "unknown") {
        return RuntimeArchString();
    }
    return arch;
}

std::string QuoteForShell(const std::string& value) {
#if defined(_WIN32)
    std::string out = "\"";
    for (char ch : value) {
        if (ch == '"') {
            out += "\\\"";
        } else {
            out.push_back(ch);
        }
    }
    out.push_back('"');
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
    out.push_back('\'');
    return out;
#endif
}

std::string QuietRedirect() {
#if defined(_WIN32)
    return " >NUL 2>&1";
#else
    return " >/dev/null 2>&1";
#endif
}

std::filesystem::path CurrentExecutablePath() {
#if defined(_WIN32)
    std::string buffer(MAX_PATH, '\0');
    DWORD len = GetModuleFileNameA(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (len == 0) {
        return {};
    }
    buffer.resize(static_cast<std::size_t>(len));
    return std::filesystem::path(buffer);
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string buffer(size, '\0');
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        return {};
    }
    return std::filesystem::weakly_canonical(std::filesystem::path(buffer.c_str()));
#else
    std::error_code ec;
    auto path = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec) {
        return {};
    }
    return path;
#endif
}

std::filesystem::path MakeTempDirectory() {
    std::error_code ec;
    std::filesystem::path base = std::filesystem::temp_directory_path(ec);
    if (ec) {
        throw std::runtime_error("Failed to resolve temp directory");
    }
    const auto seed = static_cast<unsigned long long>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for (unsigned int i = 0; i < 128; ++i) {
        auto candidate = base / ("basefwx-gpg-" + std::to_string(seed + i));
        if (std::filesystem::create_directory(candidate, ec)) {
            return candidate;
        }
        ec.clear();
    }
    throw std::runtime_error("Failed to create temp directory");
}

struct SignatureCheckResult {
    std::string summary;
    std::string detail;
};

SignatureCheckResult VerifyEmbeddedDetachedSignature() {
    const std::string fingerprint = BASEFWX_CLI_GPG_FINGERPRINT;
    const std::string public_key = BASEFWX_CLI_GPG_PUBLIC_KEY;
    if (BASEFWX_CLI_GPG_PUBLIC_KEY_AVAILABLE == 0 || public_key.empty()) {
        return {"metadata unavailable", "no embedded release public key"};
    }

    const auto exe_path = CurrentExecutablePath();
    if (exe_path.empty()) {
        return {"not checked", "failed to resolve executable path"};
    }
    std::filesystem::path sig_path = exe_path;
    sig_path += ".sig";
    if (!std::filesystem::exists(sig_path)) {
        return {"not checked", "detached signature missing next to binary"};
    }

    std::filesystem::path temp_dir;
    try {
        temp_dir = MakeTempDirectory();
        const auto key_path = temp_dir / "basefwx-release-public.asc";
        {
            std::ofstream out(key_path, std::ios::binary);
            if (!out) {
                return {"not checked", "failed to write embedded public key"};
            }
            out.write(public_key.data(), static_cast<std::streamsize>(public_key.size()));
            if (!out) {
                return {"not checked", "failed to persist embedded public key"};
            }
        }

        const std::string homedir = QuoteForShell(temp_dir.string());
        const std::string import_cmd =
            "gpg --homedir " + homedir + " --batch --import "
            + QuoteForShell(key_path.string()) + QuietRedirect();
        if (std::system(import_cmd.c_str()) != 0) {
            std::error_code cleanup_ec;
            std::filesystem::remove_all(temp_dir, cleanup_ec);
            return {"not checked", "gpg unavailable or embedded key import failed"};
        }

        const std::string verify_cmd =
            "gpg --homedir " + homedir + " --batch --verify "
            + QuoteForShell(sig_path.string()) + " "
            + QuoteForShell(exe_path.string()) + QuietRedirect();
        const int rc = std::system(verify_cmd.c_str());
        std::error_code cleanup_ec;
        std::filesystem::remove_all(temp_dir, cleanup_ec);
        if (rc != 0) {
            return {"verification failed", fingerprint.empty()
                ? "adjacent detached signature did not validate"
                : "adjacent detached signature did not validate for " + fingerprint};
        }
        return {"verified", fingerprint.empty()
            ? "adjacent detached signature validated"
            : "adjacent detached signature validated for " + fingerprint};
    } catch (const std::exception& exc) {
        if (!temp_dir.empty()) {
            std::error_code cleanup_ec;
            std::filesystem::remove_all(temp_dir, cleanup_ec);
        }
        return {"not checked", exc.what()};
    }
}

void PrintVersionInfo() {
    bool plain = CliPlain();
    const char* cyan = "\033[36m";
    std::string banner = "basefwx_cpp " + std::string(basefwx::constants::kEngineVersion);
    const auto signature = VerifyEmbeddedDetachedSignature();
    std::cout << StyleText(banner, cyan, plain) << "\n";
    std::cout << "git: " << BASEFWX_CLI_GIT_COMMIT << "\n";
    std::cout << "build_time: " << HumanizeUtcTimestamp(BASEFWX_CLI_BUILD_UTC)
              << " (" << BASEFWX_CLI_BUILD_UTC << ")\n";
    std::cout << "build_origin: "
              << (std::string(BASEFWX_CLI_GITHUB_BUILD) == "yes" ? "GitHub Actions" : "local/manual")
              << "\n";
    std::cout << "build_type: " << BASEFWX_CLI_BUILD_TYPE << "\n";
    std::cout << "arch: " << EffectiveArchString() << "\n";
    std::cout << "linkage: " << BASEFWX_CLI_LINKAGE << "\n";
    std::cout << "compiler: " << CompilerVersionString() << "\n";
    std::cout << "cxx_std: " << CxxStdString() << "\n";
    std::cout << "gpg_fingerprint: "
              << (std::string(BASEFWX_CLI_GPG_FINGERPRINT).empty() ? "none" : BASEFWX_CLI_GPG_FINGERPRINT)
              << "\n";
    std::cout << "gpg_signature: " << signature.summary;
    if (!signature.detail.empty()) {
        std::cout << " (" << signature.detail << ")";
    }
    std::cout << "\n";
    std::cout << "features: "
              << "argon2=" << OnOff(BASEFWX_HAS_ARGON2 != 0)
              << " oqs=" << OnOff(BASEFWX_HAS_OQS != 0)
              << " lzma=" << OnOff(BASEFWX_HAS_LZMA != 0)
              << "\n";
}

void PrintUsage() {
    bool plain = CliPlain();
    const char* cyan = "\033[36m";
    const std::string master_flags =
        "[--use-master] [--master-pub <path>] [--master-autogen] [--allow-embedded-master] [--no-master]";
    std::cout << StyleText(EmojiPrefix("✨", plain) + "basefwx_cpp help", cyan, plain) << "\n";
    std::cout << "Usage: basefwx_cpp [global] <command> [args]\n";
    std::cout << "Global: --verbose|-v --no-log --no-color --version|-V\n";
    std::cout << "\n";
    std::cout << "General commands:\n";
    std::cout << "  help\n";
    std::cout << "  version\n";
    std::cout << "  completion bash\n";
    std::cout << "  info <file.fwx>\n";
    std::cout << "  identify <file>    (formatted container summary)\n";
    std::cout << "  probe <file>       (alias of identify)\n";
    std::cout << "\n";
    std::cout << "Codec commands:\n";
    std::cout << "  b64-enc <text>\n";
    std::cout << "  b64-dec <text>\n";
    std::cout << "  n10-enc <text>\n";
    std::cout << "  n10-dec <digits>\n";
    std::cout << "  n10file-enc <in-file> <out-file>\n";
    std::cout << "  n10file-dec <in-file> <out-file>\n";
    std::cout << "  b256-enc <text>\n";
    std::cout << "  b256-dec <text>\n";
    std::cout << "  a512-enc <text>\n";
    std::cout << "  a512-dec <text>\n";
    std::cout << "  bi512-enc <text>\n";
    std::cout << "  b1024-enc <text>\n";
    std::cout << "  hash512 <text>\n";
    std::cout << "  uhash513 <text>\n";
    std::cout << "  b512-enc <text> [-p <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  b512-dec <text> [-p <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512-enc <text> [-p <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512-dec <text> [-p <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "\n";
    std::cout << "File commands:\n";
    std::cout << "  b512file-enc <file> [-p <password>] " << master_flags << " [--strip-meta] [--no-aead] [--compress] [--keep-input] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  b512file-dec <file.fwx> [-p <password>] " << master_flags << " [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  b512file-bytes-rt <in> <out> [-p <password>] " << master_flags << " [--strip-meta] [--no-aead] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512file-bytes-rt <in> <out> [-p <password>] " << master_flags << " [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512file-enc <file> [-p <password>] " << master_flags << " [--strip-meta] [--no-obf] [--compress] [--keep-input] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512file-dec <file.fwx> [-p <password>] " << master_flags << " [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "\n";
    std::cout << "fwxAES commands:\n";
    std::cout << "  fwxaes-enc <file> [-p <password>] " << master_flags << " [--out <path>] [--heavy] [--normalize] [--threshold <n>] [--cover-phrase <text>] [--compress] [--ignore-media] [--keep-meta] [--keep-input] [--no-archive] [--kdf <label>] [--pbkdf2-iters <n>] [--argon2-time <n>] [--argon2-mem <n>] [--argon2-par <n>] [--no-fallback] [--legacy-pbkdf2]\n";
    std::cout << "  fwxaes-dec <file> [-p <password>] " << master_flags << " [--out <path>] [--heavy]\n";
    std::cout << "  fwxaes-heavy-enc <file> [-p <password>] " << master_flags << " [--out <path>] [--compress] [--keep-input]\n";
    std::cout << "  fwxaes-heavy-dec <file> [-p <password>] " << master_flags << " [--out <path>]\n";
    std::cout << "  fwxaes-stream-enc <file> [-p <password>] " << master_flags << " [--out <path>] [--kdf <label>] [--pbkdf2-iters <n>] [--argon2-time <n>] [--argon2-mem <n>] [--argon2-par <n>] [--no-fallback] [--legacy-pbkdf2]\n";
    std::cout << "  fwxaes-stream-dec <file> [-p <password>] " << master_flags << " [--out <path>]\n";
    std::cout << "  fwxaes-live-enc <file|- > [-p <password>] " << master_flags << " [--out <path|- >]\n";
    std::cout << "  fwxaes-live-dec <file|- > [-p <password>] " << master_flags << " [--out <path|- >]\n";
    std::cout << "  an7 <file.fwx> -p <password> [--out <path>] [--keep-input] [--force-any]\n";
    std::cout << "  dean7 <file> -p <password> [--out <path>] [--keep-input]\n";
    std::cout << "\n";
    std::cout << "Media/carrier commands:\n";
    std::cout << "  jmge <media> [-p <password>] " << master_flags << " [--out <path>] [--keep-meta] [--keep-input] [--no-archive]\n";
    std::cout << "  jmgd <media> [-p <password>] " << master_flags << " [--out <path>]\n";
    std::cout << "  kFMe <in-file> [--out <path>] [--bw]\n";
    std::cout << "  kFMd <in-file> [--out <path>] [--bw]\n";
    std::cout << "  kFAe <in-file> [--out <path>] [--bw]    (deprecated alias)\n";
    std::cout << "  kFAd <in-file> [--out <path>]           (deprecated alias)\n";
    std::cout << "\n";
    std::cout << "Benchmark commands:\n";
    std::cout << "  bench-text <method> <text-file> [-p <password>] " << master_flags << "\n";
    std::cout << "  bench-hash <method> <text-file>\n";
    std::cout << "  bench-fwxaes <file> <password> " << master_flags << "\n";
    std::cout << "  bench-fwxaes-par <file> <password> " << master_flags << "\n";
    std::cout << "  bench-an7 <file> <password> " << master_flags << "\n";
    std::cout << "  bench-dean7 <file> <password> " << master_flags << "\n";
    std::cout << "  bench-live <file> <password> " << master_flags << "\n";
    std::cout << "  bench-b512file <file> <password> " << master_flags << " [--no-aead]\n";
    std::cout << "  bench-pb512file <file> <password> " << master_flags << " [--no-aead]\n";
    std::cout << "  bench-jmg <media> <password> " << master_flags << "\n";
}

void PrintBashCompletion(const std::string& argv0) {
    std::string bin = std::filesystem::path(argv0).filename().string();
    if (bin.empty()) {
        bin = "basefwx_cpp";
    }
    std::cout
        << "# bash completion for " << bin << "\n"
        << "_basefwx_complete() {\n"
        << "  local cur cmd\n"
        << "  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
        << "  cmd=\"${COMP_WORDS[1]}\"\n"
        << "  local commands=\"help version completion info identify probe b64-enc b64-dec n10-enc n10-dec n10file-enc n10file-dec "
           "kFMe kFMd kFAe kFAd hash512 uhash513 a512-enc a512-dec bi512-enc b1024-enc b256-enc b256-dec "
           "b512-enc b512-dec pb512-enc pb512-dec b512file-enc b512file-dec b512file-bytes-rt pb512file-bytes-rt "
           "pb512file-enc pb512file-dec fwxaes-enc fwxaes-dec fwxaes-heavy-enc fwxaes-heavy-dec fwxaes-stream-enc fwxaes-stream-dec fwxaes-live-enc "
           "fwxaes-live-dec an7 dean7 jmge jmgd bench-text bench-hash bench-fwxaes bench-fwxaes-par bench-an7 bench-dean7 bench-live bench-b512file "
           "bench-pb512file bench-jmg\"\n"
        << "  local master_opts=\"--use-master --no-master --master-pub --use-master-pub --master-autogen --allow-embedded-master\"\n"
        << "  if [[ ${COMP_CWORD} -eq 1 ]]; then\n"
        << "    COMPREPLY=( $(compgen -W \"$commands\" -- \"$cur\") )\n"
        << "    return 0\n"
        << "  fi\n"
        << "  case \"$cmd\" in\n"
        << "    completion)\n"
        << "      COMPREPLY=( $(compgen -W \"bash\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    b512-enc|b512-dec|pb512-enc|pb512-dec)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --kdf --pbkdf2-iters --no-fallback $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    b512file-enc|b512file-dec|b512file-bytes-rt|pb512file-bytes-rt|pb512file-enc|pb512file-dec)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --strip-meta --no-aead --no-obf --compress --keep-input --kdf --pbkdf2-iters --no-fallback $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    fwxaes-enc|fwxaes-dec|fwxaes-heavy-enc|fwxaes-heavy-dec|fwxaes-stream-enc|fwxaes-stream-dec|fwxaes-live-enc|fwxaes-live-dec)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --heavy --light --normalize --threshold --cover-phrase --compress --ignore-media --keep-meta --keep-input --no-archive --kdf --pbkdf2-iters --argon2-time --argon2-mem --argon2-par --no-fallback --legacy-pbkdf2 --no-wrap-kdf $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    an7)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --keep-input --force-any\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    dean7)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --keep-input\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    jmge|jmgd|bench-jmg)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --keep-meta --keep-input --no-archive $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    kFMe|kFMd|kFAe|kFAd)\n"
        << "      COMPREPLY=( $(compgen -W \"--out -o --bw\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    bench-text|bench-fwxaes|bench-fwxaes-par|bench-an7|bench-dean7|bench-live|bench-b512file|bench-pb512file)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --no-aead $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    *)\n"
        << "      COMPREPLY=()\n"
        << "      ;;\n"
        << "  esac\n"
        << "}\n"
        << "complete -F _basefwx_complete " << bin << "\n";
}

struct CommandHwPlan {
    std::string op;
    std::string encode = "CPU";
    std::string decode = "CPU";
    std::string pixels = "CPU";
    std::string parallel = "OFF";
    std::string crypto = "CPU";
    std::string aes = "unknown";
    bool expect_gpu = false;
    std::string reason;
};

std::string ReadCommandCapture(const std::string& cmd) {
#if defined(_WIN32)
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) {
        return {};
    }
    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }
#if defined(_WIN32)
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return output;
}

std::optional<double> ProbeCpuTempC() {
#if defined(__linux__)
    std::filesystem::path root("/sys/class/thermal");
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) {
        return std::nullopt;
    }
    double sum = 0.0;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_directory()) {
            continue;
        }
        auto temp_path = entry.path() / "temp";
        if (!std::filesystem::exists(temp_path, ec)) {
            continue;
        }
        std::ifstream in(temp_path);
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

class CommandTelemetry {
  public:
    explicit CommandTelemetry(CommandHwPlan plan)
        : plan_(std::move(plan)) {
        enabled_ = ShouldLog();
        if (!enabled_) {
            return;
        }
        EmitHeader();
        running_.store(true, std::memory_order_relaxed);
        worker_ = std::thread([this]() { Loop(); });
    }

    ~CommandTelemetry() {
        Stop();
    }

    CommandTelemetry(const CommandTelemetry&) = delete;
    CommandTelemetry& operator=(const CommandTelemetry&) = delete;

    void ConfigureFileProgress(const std::string& input_path, const std::string& output_path) {
        if (!enabled_) {
            return;
        }
        std::error_code ec;
        std::filesystem::path in(input_path);
        if (input_path.empty() || !std::filesystem::is_regular_file(in, ec)) {
            return;
        }
        std::uint64_t in_size = static_cast<std::uint64_t>(std::filesystem::file_size(in, ec));
        if (ec || in_size == 0) {
            return;
        }
        std::filesystem::path out(output_path);
        bool is_temp_plain = EndsWith(out.string(), ".plain.tmp");
        if (is_temp_plain) {
            auto estimated = EstimatePlainTmpTargetSize(in);
            if (estimated.has_value() && *estimated > 0) {
                in_size = *estimated;
            }
        }
        std::lock_guard<std::mutex> lock(progress_mu_);
        progress_input_path_ = in;
        progress_output_path_ = out;
        progress_input_size_ = in_size;
        progress_enabled_ = true;
        progress_sample_size_ = 0;
        progress_sample_time_ = std::chrono::steady_clock::time_point{};
        progress_sample_ready_ = false;
        progress_rate_bps_ = 0.0;
        progress_last_growth_time_ = std::chrono::steady_clock::now();
        progress_is_temp_plain_ = is_temp_plain;
        progress_completed_ = false;
    }

    void MarkProgressComplete() {
        if (!enabled_) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(progress_mu_);
            if (!progress_enabled_) {
                return;
            }
            progress_completed_ = true;
        }
        EmitTelemetry();
    }

  private:
    void Stop() {
        if (!enabled_) {
            return;
        }
        running_.store(false, std::memory_order_relaxed);
        cv_.notify_all();
        if (worker_.joinable()) {
            worker_.join();
        }
        if (inline_stats_ && had_stats_line_) {
            std::cerr << "\n" << std::flush;
            had_stats_line_ = false;
            last_stats_width_ = 0;
        }
        enabled_ = false;
    }

    void EmitHeader() {
        std::cerr << "🎛 [basefwx.hw] op=" << plan_.op
                  << " encode=" << plan_.encode
                  << " decode=" << plan_.decode
                  << " pixels=" << plan_.pixels
                  << " parallel=" << plan_.parallel
                  << " crypto=" << plan_.crypto
                  << " aes_accel=" << plan_.aes
                  << "\n";
        if (IsVerbose() && !plan_.reason.empty()) {
            std::cerr << "   reason: " << plan_.reason << "\n";
        }
    }

    static std::optional<double> ParseGpuField(const std::string& field) {
        try {
            return std::stod(field);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    static std::string Trim(std::string value) {
        while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
            value.pop_back();
        }
        std::size_t start = 0;
        while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
            ++start;
        }
        return value.substr(start);
    }

    void Loop() {
        while (running_.load(std::memory_order_relaxed)) {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait_for(lock, std::chrono::seconds(1));
            if (!running_.load(std::memory_order_relaxed)) {
                break;
            }
            lock.unlock();
            EmitTelemetry();
        }
    }

    void EmitTelemetry() {
        auto mem = basefwx::system::DetectMemoryInfo();
        std::ostringstream line;
        line << "📊 [basefwx.stats]";

        auto cpu_pct = SampleCpuPercent();
        if (cpu_pct.has_value()) {
            line << " CPU " << std::fixed << std::setprecision(0) << *cpu_pct << "%";
        }
        if (mem.total_bytes > 0) {
            double ram_pct = (static_cast<double>(mem.used_bytes) * 100.0) / static_cast<double>(mem.total_bytes);
            line << " \\ RAM " << std::fixed << std::setprecision(0) << ram_pct << "%";
        }
        if (plan_.expect_gpu) {
            auto gpu = SampleGpuPercentTemp();
            if (gpu.first.has_value()) {
                line << " \\ GPU " << std::fixed << std::setprecision(0) << *gpu.first << "%";
            }
            if (gpu.second.has_value()) {
                line << " \\ " << std::fixed << std::setprecision(0) << *gpu.second << "C";
                std::cerr << line.str() << "\n";
                return;
            }
        }
        auto cpu_temp = ProbeCpuTempC();
        if (cpu_temp.has_value()) {
            line << " \\ " << std::fixed << std::setprecision(0) << *cpu_temp << "C";
        }
        AppendProgress(line);
        EmitStatsLine(line.str());
    }

    void AppendProgress(std::ostringstream& line) {
        std::filesystem::path in_path;
        std::filesystem::path out_path;
        std::uint64_t in_size = 0;
        bool is_temp_plain = false;
        bool progress_completed = false;
        {
            std::lock_guard<std::mutex> lock(progress_mu_);
            if (!progress_enabled_) {
                return;
            }
            in_path = progress_input_path_;
            out_path = progress_output_path_;
            in_size = progress_input_size_;
            is_temp_plain = progress_is_temp_plain_;
            progress_completed = progress_completed_;
        }
        if (in_size == 0 || out_path.empty()) {
            return;
        }
        std::uint64_t out_size = 0;
        bool phase_finalize = false;
        double pct = 0.0;
        if (progress_completed) {
            out_size = in_size;
            pct = 100.0;
        } else {
            std::error_code ec;
            if (!std::filesystem::exists(out_path, ec) || !std::filesystem::is_regular_file(out_path, ec)) {
                return;
            }
            out_size = static_cast<std::uint64_t>(std::filesystem::file_size(out_path, ec));
            if (ec) {
                return;
            }
            phase_finalize = is_temp_plain && out_size >= in_size;
            pct = (static_cast<double>(out_size) * 100.0) / static_cast<double>(in_size);
        }
        if (pct < 0.0) {
            pct = 0.0;
        }
        if (pct > 100.0) {
            pct = 100.0;
        }
        if (phase_finalize && !progress_completed) {
            // Keep bar just under 100% while follow-up stages are still running.
            pct = 99.9;
        }
        constexpr std::size_t kBarWidth = 24;
        std::size_t filled = static_cast<std::size_t>((pct * static_cast<double>(kBarWidth)) / 100.0);
        if (progress_completed || pct >= 99.95) {
            filled = kBarWidth;
        }
        if (filled > kBarWidth) {
            filled = kBarWidth;
        }

        auto now = std::chrono::steady_clock::now();
        std::optional<double> speed_bps;
        std::optional<std::uint64_t> eta_seconds;
        std::chrono::steady_clock::time_point last_growth_time = now;
        {
            std::lock_guard<std::mutex> lock(progress_mu_);
            if (!progress_completed && progress_sample_ready_) {
                double dt = std::chrono::duration<double>(now - progress_sample_time_).count();
                if (dt > 0.15 && out_size > progress_sample_size_) {
                    double inst_bps = static_cast<double>(out_size - progress_sample_size_) / dt;
                    if (inst_bps >= 0.0) {
                        if (progress_rate_bps_ <= 0.0) {
                            progress_rate_bps_ = inst_bps;
                        } else {
                            progress_rate_bps_ = (progress_rate_bps_ * 0.7) + (inst_bps * 0.3);
                        }
                    }
                    progress_last_growth_time_ = now;
                }
            }
            progress_sample_size_ = out_size;
            progress_sample_time_ = now;
            progress_sample_ready_ = true;
            last_growth_time = progress_last_growth_time_;
            if (!progress_completed && !phase_finalize && progress_rate_bps_ > 1.0) {
                speed_bps = progress_rate_bps_;
                if (out_size < in_size) {
                    std::uint64_t remain = in_size - out_size;
                    eta_seconds = static_cast<std::uint64_t>(remain / progress_rate_bps_);
                }
            }
        }

        line << " \\ ["
             << std::string(filled, '#')
             << std::string(kBarWidth - filled, '-')
             << "] "
             << std::fixed << std::setprecision(1) << pct << "%"
             << " " << basefwx::system::FormatBytes(out_size)
             << "/" << basefwx::system::FormatBytes(in_size);
        if (speed_bps.has_value()) {
            line << " " << basefwx::system::FormatBytes(static_cast<std::uint64_t>(*speed_bps)) << "/s";
        }
        if (eta_seconds.has_value()) {
            std::uint64_t total = *eta_seconds;
            std::uint64_t h = total / 3600;
            std::uint64_t m = (total % 3600) / 60;
            std::uint64_t s = total % 60;
            std::ostringstream eta;
            eta << std::setw(2) << std::setfill('0') << h
                << ":" << std::setw(2) << std::setfill('0') << m
                << ":" << std::setw(2) << std::setfill('0') << s;
            line << " ETA " << eta.str();
        }
        if (phase_finalize) {
            static constexpr std::array<char, 4> kSpin = {'|', '/', '-', '\\'};
            auto spin_tick = static_cast<std::size_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() / 1000);
            char spin = kSpin[spin_tick % kSpin.size()];
            double stall_s = std::chrono::duration<double>(now - last_growth_time).count();
            if (stall_s >= 0.8) {
                line << " phase2 " << spin << " deobf/unpack";
            } else {
                line << " phase1 " << spin;
            }
        }
    }

    void EmitStatsLine(const std::string& text) {
        if (!inline_stats_) {
            std::cerr << text << "\n";
            return;
        }
        std::string line = text;
        if (line.size() < last_stats_width_) {
            line.append(last_stats_width_ - line.size(), ' ');
        }
        last_stats_width_ = line.size();
        had_stats_line_ = true;
        std::cerr << "\r" << line << std::flush;
    }

    std::pair<std::optional<double>, std::optional<double>> SampleGpuPercentTemp() {
        std::string output = ReadCommandCapture(
            "nvidia-smi --query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader,nounits");
        if (output.empty()) {
            return {std::nullopt, std::nullopt};
        }
        std::istringstream iss(output);
        std::string row;
        std::vector<double> gpu;
        std::vector<double> temp;
        while (std::getline(iss, row)) {
            std::size_t comma = row.find(',');
            if (comma == std::string::npos) {
                continue;
            }
            std::string gpu_raw = Trim(row.substr(0, comma));
            std::string temp_raw = Trim(row.substr(comma + 1));
            auto gpu_val = ParseGpuField(gpu_raw);
            auto temp_val = ParseGpuField(temp_raw);
            if (gpu_val.has_value()) {
                gpu.push_back(*gpu_val);
            }
            if (temp_val.has_value() && *temp_val > 0.0) {
                temp.push_back(*temp_val);
            }
        }
        std::optional<double> gpu_avg;
        std::optional<double> temp_avg;
        if (!gpu.empty()) {
            double sum = 0.0;
            for (double value : gpu) {
                sum += value;
            }
            gpu_avg = sum / static_cast<double>(gpu.size());
        }
        if (!temp.empty()) {
            double sum = 0.0;
            for (double value : temp) {
                sum += value;
            }
            temp_avg = sum / static_cast<double>(temp.size());
        }
        return {gpu_avg, temp_avg};
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
        if (prev_total_ == 0 || total <= prev_total_) {
            prev_total_ = total;
            prev_idle_ = idle_total;
            return std::nullopt;
        }
        std::uint64_t delta_total = total - prev_total_;
        std::uint64_t delta_idle = idle_total - prev_idle_;
        prev_total_ = total;
        prev_idle_ = idle_total;
        if (delta_total == 0) {
            return std::nullopt;
        }
        double usage = 100.0 * (1.0 - (static_cast<double>(delta_idle) / static_cast<double>(delta_total)));
        if (usage < 0.0) {
            usage = 0.0;
        }
        if (usage > 100.0) {
            usage = 100.0;
        }
        return usage;
#else
        return std::nullopt;
#endif
    }

    CommandHwPlan plan_;
    bool enabled_ = false;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::uint64_t prev_total_ = 0;
    std::uint64_t prev_idle_ = 0;
    bool inline_stats_ = IsStderrInteractive() && !basefwx::env::IsEnabled("BASEFWX_STATS_LINES", false);
    bool had_stats_line_ = false;
    std::size_t last_stats_width_ = 0;
    std::mutex progress_mu_;
    std::filesystem::path progress_input_path_;
    std::filesystem::path progress_output_path_;
    std::uint64_t progress_input_size_ = 0;
    bool progress_enabled_ = false;
    std::uint64_t progress_sample_size_ = 0;
    std::chrono::steady_clock::time_point progress_sample_time_{};
    bool progress_sample_ready_ = false;
    double progress_rate_bps_ = 0.0;
    std::chrono::steady_clock::time_point progress_last_growth_time_{};
    bool progress_is_temp_plain_ = false;
    bool progress_completed_ = false;
};

CommandHwPlan BuildHwPlan(const std::string& command) {
    CommandHwPlan plan;
    plan.op = command;
    const unsigned int hw = std::thread::hardware_concurrency();
    const std::size_t workers = hw > 0 ? static_cast<std::size_t>(hw) : 1;
    plan.parallel = workers > 1 ? ("ON(" + std::to_string(workers) + "w)") : "OFF";
    if (basefwx::env::IsEnabled("BASEFWX_FORCE_SINGLE_THREAD", false)) {
        plan.parallel = "OFF";
    }
    if (basefwx::env::IsEnabled("BASEFWX_AES_NI", true)) {
        plan.aes = "aesni";
    } else {
        plan.aes = "cpu";
    }
    if (command == "jmge" || command == "jmgd") {
        const std::string hwaccel = ToLower(basefwx::env::Get("BASEFWX_HWACCEL"));
        if (hwaccel == "nvenc" || hwaccel == "cuda" || hwaccel == "nvidia") {
            plan.encode = "NVENC";
            plan.decode = "NVENC";
            plan.expect_gpu = true;
            plan.reason = "BASEFWX_HWACCEL requested NVIDIA encode/decode path";
        } else if (hwaccel == "qsv" || hwaccel == "intel") {
            plan.encode = "QSV";
            plan.decode = "QSV";
            plan.reason = "BASEFWX_HWACCEL requested Intel QSV path";
        } else if (hwaccel == "vaapi") {
            plan.encode = "VAAPI";
            plan.decode = "VAAPI";
            plan.reason = "BASEFWX_HWACCEL requested VAAPI path";
        } else {
            plan.reason = "auto hwaccel routing with CPU crypto";
        }
    } else {
        plan.reason = "command uses CPU crypto path";
    }
    return plan;
}

struct ParsedOptions {
    std::string input;
    std::string password;
    bool use_master = false;
    basefwx::KdfOptions kdf;
};

struct FwxAesArgs {
    std::string input;
    std::string output;
    std::string password;
    bool use_master = false;
    basefwx::pb512::KdfOptions kdf;
    bool force_legacy_pbkdf2 = false;
    bool heavy = false;
    bool normalize = false;
    std::size_t threshold = 8 * 1024;
    std::string cover_phrase = "low taper fade";
    bool compress = false;
    bool ignore_media = false;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = true;
};

struct ImageArgs {
    std::string input;
    std::string output;
    std::string password;
    bool use_master = false;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = true;
};

struct An7Args {
    std::string input;
    std::string output;
    std::string password;
    bool keep_input = false;
    bool force_any = false;
};

struct FileArgs {
    std::string input;
    std::string password;
    bool use_master = false;
    bool strip_metadata = false;
    bool enable_aead = true;
    bool enable_obf = true;
    bool compress = false;
    bool keep_input = false;
    basefwx::pb512::KdfOptions kdf;
};

ParsedOptions ParseCodecArgs(int argc, char** argv, int start_index) {
    ParsedOptions opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing payload");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--kdf") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing kdf label");
            }
            opts.kdf.label = argv[idx + 1];
            idx += 2;
        } else if (flag == "--pbkdf2-iters") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing pbkdf2 iteration count");
            }
            opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--no-fallback") {
            opts.kdf.allow_pbkdf2_fallback = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

FileArgs ParseFileArgs(int argc, char** argv, int start_index) {
    FileArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--strip-meta") {
            opts.strip_metadata = true;
            idx += 1;
        } else if (flag == "--no-aead") {
            opts.enable_aead = false;
            idx += 1;
        } else if (flag == "--no-obf") {
            opts.enable_obf = false;
            idx += 1;
        } else if (flag == "--compress") {
            opts.compress = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--kdf") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing kdf label");
            }
            opts.kdf.label = argv[idx + 1];
            idx += 2;
        } else if (flag == "--pbkdf2-iters") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing pbkdf2 iteration count");
            }
            opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--no-fallback") {
            opts.kdf.allow_pbkdf2_fallback = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

FwxAesArgs ParseFwxAesArgs(int argc, char** argv, int start_index) {
    FwxAesArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--kdf") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing kdf label");
            }
            opts.kdf.label = argv[idx + 1];
            idx += 2;
        } else if (flag == "--pbkdf2-iters") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing pbkdf2 iteration count");
            }
            opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--argon2-time") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing argon2 time cost");
            }
            opts.kdf.argon2_time_cost = static_cast<std::uint32_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--argon2-mem") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing argon2 memory cost");
            }
            opts.kdf.argon2_memory_cost = static_cast<std::uint32_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--argon2-par") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing argon2 parallelism");
            }
            opts.kdf.argon2_parallelism = static_cast<std::uint32_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--no-fallback") {
            opts.kdf.allow_pbkdf2_fallback = false;
            idx += 1;
        } else if (flag == "--legacy-pbkdf2" || flag == "--no-wrap-kdf") {
            opts.force_legacy_pbkdf2 = true;
            idx += 1;
        } else if (flag == "--normalize") {
            opts.normalize = true;
            idx += 1;
        } else if (flag == "--heavy") {
            opts.heavy = true;
            idx += 1;
        } else if (flag == "--light") {
            opts.heavy = false;
            idx += 1;
        } else if (flag == "--threshold") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing threshold value");
            }
            opts.threshold = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--cover-phrase") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing cover phrase value");
            }
            opts.cover_phrase = argv[idx + 1];
            idx += 2;
        } else if (flag == "--compress") {
            opts.compress = true;
            idx += 1;
        } else if (flag == "--ignore-media") {
            opts.ignore_media = true;
            idx += 1;
        } else if (flag == "--keep-meta") {
            opts.keep_meta = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--no-archive") {
            opts.archive_original = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

ImageArgs ParseImageArgs(int argc, char** argv, int start_index) {
    ImageArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--keep-meta") {
            opts.keep_meta = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--no-archive") {
            opts.archive_original = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

An7Args ParseAn7Args(int argc, char** argv, int start_index, bool allow_force_any) {
    An7Args opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--force-any") {
            if (!allow_force_any) {
                throw std::runtime_error("--force-any is only valid for an7");
            }
            opts.force_any = true;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> cleaned_args;
    cleaned_args.reserve(static_cast<std::size_t>(argc));
    cleaned_args.emplace_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--verbose" || arg == "-v") {
            g_verbose = true;
            continue;
        }
        if (arg == "--no-log") {
            g_no_log = true;
            continue;
        }
        if (arg == "--no-color") {
            basefwx::cli::SetColorsEnabled(false);
            SetCliEnvVar("NO_COLOR", "1");
            continue;
        }
        cleaned_args.push_back(std::move(arg));
    }
    std::vector<char*> argv_storage;
    argv_storage.reserve(cleaned_args.size());
    for (auto& arg : cleaned_args) {
        argv_storage.push_back(arg.data());
    }
    argc = static_cast<int>(argv_storage.size());
    argv = argv_storage.data();

    SetCliEnvVar("BASEFWX_VERBOSE", g_verbose ? "1" : "0");
    SetCliEnvVar("BASEFWX_NO_LOG", g_no_log ? "1" : "0");

    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    std::string command(argv[1]);
    if (command == "version" || command == "--version" || command == "-V") {
        PrintVersionInfo();
        return 0;
    }
    if (command == "help" || command == "--help" || command == "-h") {
        PrintUsage();
        return 0;
    }
    if (command == "completion") {
        if (argc < 3) {
            PrintUsage();
            return 2;
        }
        std::string shell = ToLower(argv[2]);
        if (shell != "bash") {
            std::cerr << "Error: unsupported shell for completion: " << shell << "\n";
            return 1;
        }
        PrintBashCompletion(argv[0]);
        return 0;
    }
    std::optional<CommandTelemetry> telemetry;
    if (!IsLightCommand(command) && command != "jmge" && command != "jmgd") {
        telemetry.emplace(BuildHwPlan(command));
    }

    // Print system info if verbose
    PrintSystemInfo();

    try {
        if (command == "info") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::filesystem::path input_path(argv[2]);
            auto lp = InspectLengthPrefixedFile(input_path);
            if (lp.has_value() && !MetadataNeedsFullFallback(lp->info)) {
                PrintInspectInfo(lp->info);
                return 0;
            }
            auto fwx = ParseFwxAesHeader(input_path);
            if (fwx.has_value()) {
                PrintFwxAesInfo(*fwx);
                return 0;
            }
            std::string fallback_reason;
            auto full = TryReadFullInspectSafe(input_path, &fallback_reason);
            if (full.has_value()) {
                try {
                    auto full_info = basefwx::InspectBlob(*full);
                    PrintInspectInfo(full_info);
                    return 0;
                } catch (const std::exception&) {
                    // Continue with lightweight output or error.
                }
            } else {
                MaybeWarnInspectFallback(fallback_reason);
            }
            if (lp.has_value()) {
                if (MetadataNeedsFullFallback(lp->info)) {
                    MaybeWarnInspectFallback("metadata was incomplete in lightweight inspect; showing partial output");
                }
                PrintInspectInfo(lp->info);
                return 0;
            }
            throw std::runtime_error("Unsupported or corrupted BaseFWX container");
        }
        if (command == "identify" || command == "probe") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::filesystem::path input_path(argv[2]);
            auto lp = InspectLengthPrefixedFile(input_path);
            if (lp.has_value() && !MetadataNeedsFullFallback(lp->info)) {
                PrintIdentifyLengthPrefixed(input_path.string(), *lp);
                return 0;
            }
            auto fwx = ParseFwxAesHeader(input_path);
            if (fwx.has_value()) {
                PrintIdentifyFwxAes(input_path.string(), *fwx);
                return 0;
            }
            std::string fallback_reason;
            auto full = TryReadFullInspectSafe(input_path, &fallback_reason);
            if (full.has_value()) {
                try {
                    auto full_info = basefwx::InspectBlob(*full);
                    LightweightInspect inspect;
                    inspect.file_size = static_cast<std::uint64_t>(full->size());
                    inspect.info = std::move(full_info);
                    PrintIdentifyLengthPrefixed(input_path.string(), inspect);
                    return 0;
                } catch (const std::exception&) {
                    // Continue with lightweight output or error.
                }
            } else {
                MaybeWarnInspectFallback(fallback_reason);
            }
            if (lp.has_value()) {
                if (MetadataNeedsFullFallback(lp->info)) {
                    MaybeWarnInspectFallback("metadata was incomplete in lightweight inspect; showing partial output");
                }
                PrintIdentifyLengthPrefixed(input_path.string(), *lp);
                return 0;
            }
            throw std::runtime_error("Unsupported or corrupted BaseFWX container");
        }
        if (command == "an7" || command == "dean7") {
            An7Args parsed = ParseAn7Args(argc, argv, 2, command == "an7");
            if (parsed.password.empty()) {
                throw std::runtime_error("Password is required");
            }
            basefwx::runtime::ResetStop();
            InstallStopHandlers();
            if (command == "an7") {
                basefwx::An7Options an7_opts;
                an7_opts.keep_input = parsed.keep_input;
                an7_opts.force_any = parsed.force_any;
                if (!parsed.output.empty()) {
                    an7_opts.out = std::filesystem::path(parsed.output);
                }
                basefwx::an7_file(std::filesystem::path(parsed.input), parsed.password, an7_opts);
                std::cout << "an7 completed\n";
            } else {
                basefwx::Dean7Options dean_opts;
                dean_opts.keep_input = parsed.keep_input;
                if (!parsed.output.empty()) {
                    dean_opts.out = std::filesystem::path(parsed.output);
                }
                basefwx::Dean7Result result =
                    basefwx::dean7_file(std::filesystem::path(parsed.input), parsed.password, dean_opts);
                std::cout << result.output_path.string() << "\n";
            }
            return 0;
        }
        if (command == "bench-text") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string method = ToLower(argv[2]);
            ParsedOptions opts = ParseCodecArgs(argc, argv, 3);
            std::string text = ReadTextFile(opts.input);
            if ((method == "b512" || method == "pb512") && opts.password.empty()) {
                throw std::runtime_error("Password required for b512/pb512 benchmark");
            }
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            std::function<std::size_t()> op;
            if (method == "b64") {
                op = [&]() {
                    std::string enc = basefwx::B64Encode(text);
                    std::string dec = basefwx::B64Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "b256") {
                op = [&]() {
                    std::string enc = basefwx::B256Encode(text);
                    std::string dec = basefwx::B256Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "a512") {
                op = [&]() {
                    std::string enc = basefwx::A512Encode(text);
                    std::string dec = basefwx::A512Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "n10") {
                op = [&]() {
                    std::string enc = basefwx::N10Encode(text);
                    std::string dec = basefwx::N10Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "b512") {
                op = [&]() {
                    std::string enc = basefwx::B512Encode(text, opts.password, opts.use_master, opts.kdf);
                    std::string dec = basefwx::B512Decode(enc, opts.password, opts.use_master, opts.kdf);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "pb512") {
                op = [&]() {
                    std::string enc = basefwx::Pb512Encode(text, opts.password, opts.use_master, opts.kdf);
                    std::string dec = basefwx::Pb512Decode(enc, opts.password, opts.use_master, opts.kdf);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else {
                throw std::runtime_error("Unsupported benchmark method: " + method);
            }
            auto run = [&]() {
                if (workers > 1) {
                    RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-hash") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string method = ToLower(argv[2]);
            std::string text = ReadTextFile(argv[3]);
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            std::function<std::size_t()> op;
            if (method == "hash512") {
                op = [&]() {
                    std::string digest = basefwx::Hash512(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "uhash513") {
                op = [&]() {
                    std::string digest = basefwx::Uhash513(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "bi512") {
                op = [&]() {
                    std::string digest = basefwx::Bi512Encode(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "b1024") {
                op = [&]() {
                    std::string digest = basefwx::B1024Encode(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else {
                throw std::runtime_error("Unsupported hash benchmark method: " + method);
            }
            auto run = [&]() {
                if (workers > 1) {
                    RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-fwxaes") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            basefwx::fwxaes::Options opts;
            opts.use_master = use_master;
            int warmup = BenchWarmup();
            int iters = BenchIters();
            auto run = [&]() {
                auto blob = basefwx::fwxaes::EncryptRaw(data, password, opts);
                auto plain = basefwx::fwxaes::DecryptRaw(blob, password, use_master);
                g_bench_sink.fetch_xor(plain.size(), std::memory_order_relaxed);
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-fwxaes-par") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            for (int i = 0; i < warmup; ++i) {
                RunFwxaesParallel(data, password, use_master, workers);
            }
            std::vector<long long> samples;
            samples.reserve(static_cast<std::size_t>(iters));
            std::size_t bytes_per_run = 0;
            for (int i = 0; i < iters; ++i) {
                auto start = std::chrono::steady_clock::now();
                bytes_per_run = RunFwxaesParallel(data, password, use_master, workers);
                auto end = std::chrono::steady_clock::now();
                samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
            }
            auto median = MedianNs(samples);
            std::cout << "BENCH_NS=" << median << "\n";
            if (median > 0 && bytes_per_run > 0) {
                double seconds = static_cast<double>(median) / 1'000'000'000.0;
                double gib = static_cast<double>(bytes_per_run) / static_cast<double>(1ULL << 30);
                double throughput = gib / seconds;
                std::ostringstream out;
                out.setf(std::ios::fixed);
                out << std::setprecision(3) << throughput;
                std::cout << "THROUGHPUT_GiBps=" << out.str() << " WORKERS=" << workers << "\n";
            }
            return 0;
        }
        if (command == "bench-an7" || command == "bench-dean7") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::filesystem::path src_path(argv[2]);
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            if (!std::filesystem::exists(src_path)) {
                throw std::runtime_error("Failed to open file: " + src_path.string());
            }
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            int warmup = BenchWarmup();
            int iters = BenchIters();

            auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            std::vector<std::filesystem::path> worker_dirs;
            std::vector<std::filesystem::path> seed_fwx;
            std::vector<std::filesystem::path> seed_an7;
            worker_dirs.reserve(workers);
            seed_fwx.reserve(workers);
            seed_an7.reserve(workers);

            basefwx::fwxaes::Options fwx_opts;
            fwx_opts.use_master = use_master;
            for (std::size_t i = 0; i < workers; ++i) {
                std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                    / ("basefwx-bench-an7-" + stamp + "-" + std::to_string(i));
                std::filesystem::create_directories(temp_dir);
                worker_dirs.push_back(temp_dir);

                std::filesystem::path worker_input = temp_dir / src_path.filename();
                std::filesystem::copy_file(src_path, worker_input, std::filesystem::copy_options::overwrite_existing);

                std::filesystem::path worker_fwx = temp_dir / ("seed_" + std::to_string(i) + ".fwx");
                basefwx::fwxaes::EncryptFile(
                    worker_input.string(),
                    worker_fwx.string(),
                    password,
                    fwx_opts,
                    {},
                    {},
                    true
                );
                std::error_code remove_ec;
                std::filesystem::remove(worker_input, remove_ec);
                seed_fwx.push_back(worker_fwx);

                std::filesystem::path worker_an7 = temp_dir / ("seed_" + std::to_string(i) + ".an7");
                basefwx::An7Options an7_seed_opts;
                an7_seed_opts.keep_input = true;
                an7_seed_opts.out = worker_an7;
                basefwx::an7_file(worker_fwx, password, an7_seed_opts);
                seed_an7.push_back(worker_an7);
            }

            auto run_an7_once = [&](std::size_t idx) -> std::size_t {
                const auto& temp_dir = worker_dirs[idx];
                std::filesystem::path out_path = temp_dir / ("bench_an7_" + std::to_string(idx) + ".out");
                std::error_code cleanup_ec;
                std::filesystem::remove(out_path, cleanup_ec);
                basefwx::An7Options an7_opts;
                an7_opts.keep_input = true;
                an7_opts.out = out_path;
                basefwx::an7_file(seed_fwx[idx], password, an7_opts);
                std::error_code size_ec;
                auto out_size = std::filesystem::file_size(out_path, size_ec);
                std::filesystem::remove(out_path, cleanup_ec);
                if (!size_ec) {
                    g_bench_sink.fetch_xor(static_cast<std::size_t>(out_size), std::memory_order_relaxed);
                    return static_cast<std::size_t>(out_size);
                }
                return 0;
            };

            auto run_dean7_once = [&](std::size_t idx) -> std::size_t {
                const auto& temp_dir = worker_dirs[idx];
                std::filesystem::path out_path = temp_dir / ("bench_dean7_" + std::to_string(idx) + ".out");
                std::error_code cleanup_ec;
                std::filesystem::remove(out_path, cleanup_ec);
                basefwx::Dean7Options dean_opts;
                dean_opts.keep_input = true;
                dean_opts.out = out_path;
                basefwx::Dean7Result result = basefwx::dean7_file(seed_an7[idx], password, dean_opts);
                std::error_code size_ec;
                auto out_size = std::filesystem::file_size(result.output_path, size_ec);
                std::filesystem::remove(result.output_path, cleanup_ec);
                if (!size_ec) {
                    g_bench_sink.fetch_xor(static_cast<std::size_t>(out_size), std::memory_order_relaxed);
                    return static_cast<std::size_t>(out_size);
                }
                return 0;
            };

            auto run = [&]() {
                if (workers > 1) {
                    if (command == "bench-an7") {
                        RunParallel(workers, run_an7_once);
                    } else {
                        RunParallel(workers, run_dean7_once);
                    }
                    return;
                }
                if (command == "bench-an7") {
                    run_an7_once(0);
                } else {
                    run_dean7_once(0);
                }
            };

            long long ns = 0;
            try {
                ns = BenchMedian(warmup, iters, run);
            } catch (...) {
                for (const auto& dir : worker_dirs) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
                throw;
            }
            std::cout << "BENCH_NS=" << ns << "\n";
            for (const auto& dir : worker_dirs) {
                std::error_code ec;
                std::filesystem::remove_all(dir, ec);
            }
            return 0;
        }
        if (command == "bench-live") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            std::string payload(reinterpret_cast<const char*>(data.data()), data.size());
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            auto op = [&]() -> std::size_t {
                std::istringstream source(payload, std::ios::in | std::ios::binary);
                std::ostringstream encrypted(std::ios::out | std::ios::binary);
                basefwx::FwxAesLiveEncryptStream(source, encrypted, password, use_master);
                std::string enc_blob = encrypted.str();
                std::istringstream enc_in(enc_blob, std::ios::in | std::ios::binary);
                std::ostringstream restored(std::ios::out | std::ios::binary);
                basefwx::FwxAesLiveDecryptStream(enc_in, restored, password, use_master);
                std::size_t len = restored.str().size();
                g_bench_sink.fetch_xor(len, std::memory_order_relaxed);
                return len;
            };
            auto run = [&]() {
                if (workers > 1) {
                    RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-b512file" || command == "bench-pb512file") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            bool disable_aead = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else if (flag == "--no-aead") {
                    disable_aead = true;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            basefwx::filecodec::FileOptions file_opts;
            file_opts.use_master = use_master;
            file_opts.enable_aead = !disable_aead;
            file_opts.keep_input = true;
            try {
                std::filesystem::path src_path(input);
                std::size_t workers = static_cast<std::size_t>(BenchWorkers());
                if (workers == 0) {
                    workers = 1;
                }
                ConfirmSingleThreadCli(workers);
                std::vector<std::filesystem::path> temp_dirs;
                std::vector<std::filesystem::path> bench_inputs;
                temp_dirs.reserve(workers);
                bench_inputs.reserve(workers);
                auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
                for (std::size_t i = 0; i < workers; ++i) {
                    std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                        / ("basefwx-bench-" + stamp + "-" + std::to_string(i));
                    std::filesystem::create_directories(temp_dir);
                    std::filesystem::path bench_input = temp_dir / src_path.filename();
                    std::filesystem::copy_file(src_path, bench_input, std::filesystem::copy_options::overwrite_existing);
                    temp_dirs.push_back(temp_dir);
                    bench_inputs.push_back(bench_input);
                }

                int warmup = BenchWarmup();
                int iters = BenchIters();
                auto run_once = [&](std::size_t idx) -> std::size_t {
                    const auto& bench_input = bench_inputs[idx];
                    std::filesystem::path enc_path;
                    std::filesystem::path dec_path;
                    if (command == "bench-b512file") {
                        enc_path = basefwx::filecodec::B512EncodeFile(bench_input.string(), password, file_opts);
                        dec_path = basefwx::filecodec::B512DecodeFile(enc_path.string(), password, file_opts);
                    } else {
                        enc_path = basefwx::filecodec::Pb512EncodeFile(bench_input.string(), password, file_opts);
                        dec_path = basefwx::filecodec::Pb512DecodeFile(enc_path.string(), password, file_opts);
                    }
                    std::error_code size_ec;
                    auto dec_size = std::filesystem::file_size(dec_path, size_ec);
                    std::error_code cleanup_ec;
                    if (!enc_path.empty()) {
                        std::filesystem::remove(enc_path, cleanup_ec);
                    }
                    if (!dec_path.empty() && dec_path != bench_input) {
                        std::filesystem::remove(dec_path, cleanup_ec);
                    }
                    if (!size_ec) {
                        g_bench_sink.fetch_xor(static_cast<std::size_t>(dec_size), std::memory_order_relaxed);
                        return static_cast<std::size_t>(dec_size);
                    }
                    return 0;
                };
                auto run = [&]() {
                    if (workers > 1) {
                        RunParallel(workers, run_once);
                        return;
                    }
                    run_once(0);
                };

                long long ns = BenchMedian(warmup, iters, run);
                std::cout << "BENCH_NS=" << ns << "\n";
                for (const auto& dir : temp_dirs) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
                return 0;
            } catch (const std::exception& exc) {
                throw;
            }
        }
        if (command == "bench-jmg") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string media_path = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            try {
                std::filesystem::path src_path(media_path);
                if (!std::filesystem::exists(src_path)) {
                    throw std::runtime_error("Media file not found: " + media_path);
                }
                std::size_t workers = static_cast<std::size_t>(BenchWorkers());
                if (workers == 0) {
                    workers = 1;
                }
                ConfirmSingleThreadCli(workers);
                std::vector<std::filesystem::path> temp_dirs;
                auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
                for (std::size_t i = 0; i < workers; ++i) {
                    std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                        / ("basefwx-bench-jmg-" + stamp + "-" + std::to_string(i));
                    std::filesystem::create_directories(temp_dir);
                    temp_dirs.push_back(temp_dir);
                }

                int warmup = BenchWarmup();
                int iters = BenchIters();
                auto run_once = [&](std::size_t idx) -> std::size_t {
                    const auto& temp_dir = temp_dirs[idx];
                    std::string enc_name = "bench_enc_" + std::to_string(idx) + src_path.extension().string();
                    std::string dec_name = "bench_dec_" + std::to_string(idx) + src_path.extension().string();
                    std::filesystem::path enc_path = temp_dir / enc_name;
                    std::filesystem::path dec_path = temp_dir / dec_name;
                    
                    basefwx::Jmge(src_path.string(), password, enc_path.string(), false, true, true, use_master);
                    basefwx::Jmgd(enc_path.string(), password, dec_path.string(), use_master);
                    
                    std::error_code size_ec;
                    auto dec_size = std::filesystem::file_size(dec_path, size_ec);
                    std::error_code cleanup_ec;
                    if (!enc_path.empty()) {
                        std::filesystem::remove(enc_path, cleanup_ec);
                    }
                    if (!dec_path.empty()) {
                        std::filesystem::remove(dec_path, cleanup_ec);
                    }
                    if (!size_ec) {
                        g_bench_sink.fetch_xor(static_cast<std::size_t>(dec_size), std::memory_order_relaxed);
                        return static_cast<std::size_t>(dec_size);
                    }
                    return 0;
                };
                auto run = [&]() {
                    if (workers > 1) {
                        RunParallel(workers, run_once);
                        return;
                    }
                    run_once(0);
                };

                long long ns = BenchMedian(warmup, iters, run);
                std::cout << "BENCH_NS=" << ns << "\n";
                for (const auto& dir : temp_dirs) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
                return 0;
            } catch (const std::exception& exc) {
                throw;
            }
        }
        if (command == "b64-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B64Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b64-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B64Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::N10Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::N10Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10file-enc") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            auto bytes = ReadBinaryFile(argv[2]);
            std::string input(bytes.begin(), bytes.end());
            WriteTextFile(argv[3], basefwx::N10Encode(input));
            return 0;
        }
        if (command == "n10file-dec") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string digits = StripAsciiWhitespace(ReadTextFile(argv[2]));
            WriteBinaryFile(argv[3], basefwx::N10Decode(digits));
            return 0;
        }
        if (command == "kFMe" || command == "kFMd" || command == "kFAe" || command == "kFAd") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string output;
            bool bw_mode = false;
            for (int idx = 3; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--out" || flag == "-o") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing value for --out");
                    }
                    output = argv[++idx];
                } else if (flag == "--bw") {
                    bw_mode = true;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }

            std::string out_path;
            if (command == "kFMe") {
                out_path = basefwx::Kfme(input, output, bw_mode);
            } else if (command == "kFMd") {
                out_path = basefwx::Kfmd(input, output, bw_mode);
            } else if (command == "kFAe") {
                out_path = basefwx::Kfae(input, output, bw_mode);
            } else {
                out_path = basefwx::Kfad(input, output);
            }
            std::cout << out_path << "\n";
            return 0;
        }
        if (command == "hash512") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::Hash512(argv[2]) << "\n";
            return 0;
        }
        if (command == "uhash513") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::Uhash513(argv[2]) << "\n";
            return 0;
        }
        if (command == "a512-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::A512Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "a512-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::A512Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "bi512-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::Bi512Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b1024-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B1024Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b256-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b256-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b512-enc" || command == "b512-dec" || command == "pb512-enc" || command == "pb512-dec") {
            ParsedOptions opts = ParseCodecArgs(argc, argv, 2);
            if (command == "b512-enc") {
                std::cout << basefwx::B512Encode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "b512-dec") {
                std::cout << basefwx::B512Decode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "pb512-enc") {
                std::cout << basefwx::Pb512Encode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "pb512-dec") {
                std::cout << basefwx::Pb512Decode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "b512file-enc" || command == "b512file-dec"
            || command == "pb512file-enc" || command == "pb512file-dec"
            || command == "b512file-bytes-rt" || command == "pb512file-bytes-rt") {
            if (command == "b512file-bytes-rt" || command == "pb512file-bytes-rt") {
                if (argc < 4) {
                    PrintUsage();
                    return 2;
                }
                std::string input = argv[2];
                std::string output = argv[3];
                FileArgs opts;
                opts.input = input;
                int idx = 4;
                while (idx < argc) {
                    std::string flag(argv[idx]);
                    if (flag == "-p" || flag == "--password") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing password value");
                        }
                        opts.password = argv[idx + 1];
                        idx += 2;
                    } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
                        idx += 1;
                    } else if (flag == "--strip-meta") {
                        opts.strip_metadata = true;
                        idx += 1;
                    } else if (flag == "--no-aead") {
                        if (command == "b512file-bytes-rt") {
                            opts.enable_aead = false;
                            idx += 1;
                        } else {
                            throw std::runtime_error("Unsupported flag for pb512file-bytes-rt: " + flag);
                        }
                    } else if (flag == "--kdf") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing kdf label");
                        }
                        opts.kdf.label = argv[idx + 1];
                        idx += 2;
                    } else if (flag == "--pbkdf2-iters") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing pbkdf2 iteration count");
                        }
                        opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
                        idx += 2;
                    } else if (flag == "--no-fallback") {
                        opts.kdf.allow_pbkdf2_fallback = false;
                        idx += 1;
                    } else {
                        throw std::runtime_error("Unknown flag: " + flag);
                    }
                }
                basefwx::filecodec::FileOptions file_opts;
                file_opts.strip_metadata = opts.strip_metadata;
                file_opts.use_master = opts.use_master;
                file_opts.enable_aead = opts.enable_aead;
                std::filesystem::path input_path(input);
                auto data = basefwx::ReadFile(input_path.string());
                std::string ext = input_path.extension().string();
                basefwx::filecodec::DecodedBytes decoded;
                if (command == "b512file-bytes-rt") {
                    auto blob = basefwx::filecodec::B512EncodeBytes(data, ext, opts.password, file_opts, opts.kdf);
                    decoded = basefwx::filecodec::B512DecodeBytes(blob, opts.password, file_opts, opts.kdf);
                } else {
                    auto blob = basefwx::filecodec::Pb512EncodeBytes(data, ext, opts.password, file_opts, opts.kdf);
                    decoded = basefwx::filecodec::Pb512DecodeBytes(blob, opts.password, file_opts, opts.kdf);
                }
                std::ofstream out(output, std::ios::binary);
                if (!out) {
                    throw std::runtime_error("Failed to open output file: " + output);
                }
                if (!decoded.data.empty()) {
                    out.write(reinterpret_cast<const char*>(decoded.data.data()),
                              static_cast<std::streamsize>(decoded.data.size()));
                }
                return 0;
            }
            FileArgs opts = ParseFileArgs(argc, argv, 2);
            basefwx::filecodec::FileOptions file_opts;
            file_opts.strip_metadata = opts.strip_metadata;
            file_opts.use_master = opts.use_master;
            file_opts.enable_aead = opts.enable_aead;
            file_opts.enable_obfuscation = opts.enable_obf;
            file_opts.compress = opts.compress;
            file_opts.keep_input = opts.keep_input;
            if (command == "b512file-enc") {
                std::cout << basefwx::filecodec::B512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "b512file-dec") {
                std::cout << basefwx::filecodec::B512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-enc") {
                std::cout << basefwx::filecodec::Pb512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-dec") {
                std::cout << basefwx::filecodec::Pb512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "fwxaes-enc" || command == "fwxaes-dec"
            || command == "fwxaes-heavy-enc" || command == "fwxaes-heavy-dec"
            || command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec"
            || command == "fwxaes-live-enc" || command == "fwxaes-live-dec") {
            FwxAesArgs opts = ParseFwxAesArgs(argc, argv, 2);
            if (command == "fwxaes-heavy-enc" || command == "fwxaes-heavy-dec") {
                opts.heavy = true;
            }
            bool user_output = !opts.output.empty();
            if (opts.password.empty() && !opts.use_master) {
                throw std::runtime_error("Password required when master key usage is disabled");
            }
            if (opts.output.empty()) {
                if (command == "fwxaes-enc" || command == "fwxaes-heavy-enc") {
                    if (opts.heavy) {
                        std::filesystem::path out_path(opts.input);
                        out_path.replace_extension(".fwx");
                        opts.output = out_path.string();
                    } else if (!opts.ignore_media && LooksLikeMediaPath(std::filesystem::path(opts.input))) {
                        opts.output = opts.input;
                    } else {
                        opts.output = opts.input + ".fwx";
                    }
                } else if (command == "fwxaes-live-enc") {
                    opts.output = (opts.input == "-") ? "-" : (opts.input + ".live.fwx");
                } else if (command == "fwxaes-live-dec" && opts.input == "-") {
                    opts.output = "-";
                } else if (opts.input.size() >= 4 && opts.input.rfind(".fwx") == opts.input.size() - 4) {
                    opts.output = opts.input.substr(0, opts.input.size() - 4);
                } else {
                    opts.output = opts.input + ".out";
                }
            }
            if (telemetry) {
                std::string progress_output = opts.output;
                bool is_decode = (command == "fwxaes-dec" || command == "fwxaes-heavy-dec");
                if (is_decode && opts.heavy) {
                    progress_output = opts.input + ".plain.tmp";
                }
                telemetry->ConfigureFileProgress(opts.input, progress_output);
            }
            auto complete_progress = [&telemetry]() {
                if (telemetry) {
                    telemetry->MarkProgressComplete();
                }
            };
            if (command == "fwxaes-live-enc" || command == "fwxaes-live-dec") {
                if (opts.heavy) {
                    throw std::runtime_error("Live fwxAES does not support heavy mode");
                }
                if (opts.normalize || opts.compress) {
                    throw std::runtime_error("Live fwxAES does not support normalize or pack options");
                }

                std::ifstream input_file;
                std::istream* input = nullptr;
                bool use_stdin = (opts.input == "-");
                if (use_stdin) {
                    input = &std::cin;
                } else {
                    input_file.open(opts.input, std::ios::binary);
                    if (!input_file) {
                        throw std::runtime_error("Failed to open input file: " + opts.input);
                    }
                    input = &input_file;
                }

                std::ofstream output_file;
                std::ostream* output = nullptr;
                bool use_stdout = (opts.output == "-");
                if (use_stdout) {
                    output = &std::cout;
                } else {
                    output_file.open(opts.output, std::ios::binary);
                    if (!output_file) {
                        throw std::runtime_error("Failed to open output file: " + opts.output);
                    }
                    output = &output_file;
                }
                EnableBinaryStdio(use_stdin, use_stdout);
                if (command == "fwxaes-live-enc") {
                    basefwx::FwxAesLiveEncryptStream(*input, *output, opts.password, opts.use_master);
                } else {
                    basefwx::FwxAesLiveDecryptStream(*input, *output, opts.password, opts.use_master);
                }
                complete_progress();
                return 0;
            }
            if (command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec") {
                if (opts.heavy) {
                    throw std::runtime_error("Streaming fwxAES does not support heavy mode");
                }
                if (opts.normalize || opts.compress) {
                    throw std::runtime_error("Streaming fwxAES does not support normalize or pack options");
                }
                std::ifstream input(opts.input, std::ios::binary);
                if (!input) {
                    throw std::runtime_error("Failed to open input file: " + opts.input);
                }
                std::ofstream output(opts.output, std::ios::binary);
                if (!output) {
                    throw std::runtime_error("Failed to open output file: " + opts.output);
                }
                basefwx::fwxaes::Options stream_opts;
                stream_opts.use_master = opts.use_master;
                stream_opts.user_kdf = opts.kdf;
                stream_opts.force_legacy_pbkdf2 = opts.force_legacy_pbkdf2;
                if (command == "fwxaes-stream-enc") {
                    basefwx::fwxaes::EncryptStream(input, output, opts.password, stream_opts);
                } else {
                    basefwx::fwxaes::DecryptStream(input, output, opts.password, opts.use_master);
                }
                complete_progress();
                return 0;
            }
            if (opts.heavy) {
                bool is_decode = (command == "fwxaes-dec" || command == "fwxaes-heavy-dec");
                if (is_decode) {
                    basefwx::runtime::ResetStop();
                    InstallStopHandlers();
                }
                if (opts.normalize) {
                    throw std::runtime_error("fwxAES heavy mode does not support normalize options");
                }
                if (opts.threshold != 8 * 1024 || opts.cover_phrase != "low taper fade") {
                    throw std::runtime_error("fwxAES heavy mode does not support normalize options");
                }
                if (opts.ignore_media || opts.keep_meta || !opts.archive_original) {
                    throw std::runtime_error("fwxAES heavy mode does not support media-only options");
                }
                basefwx::filecodec::FileOptions file_opts;
                file_opts.use_master = opts.use_master;
                file_opts.compress = opts.compress;
                file_opts.keep_input = opts.keep_input;
                if (command == "fwxaes-enc" || command == "fwxaes-heavy-enc") {
                    std::string produced = basefwx::filecodec::Pb512EncodeFile(opts.input, opts.password, file_opts, opts.kdf);
                    std::string final_output = produced;
                    if (user_output) {
                        final_output = MoveOutputPath(produced, opts.output);
                    }
                    if (telemetry) {
                        telemetry->MarkProgressComplete();
                        telemetry.reset();
                    }
                    std::cout << final_output << "\n";
                } else {
                    std::string produced = basefwx::filecodec::Pb512DecodeFile(opts.input, opts.password, file_opts, opts.kdf);
                    std::string final_output = produced;
                    if (user_output) {
                        final_output = MoveOutputPath(produced, opts.output);
                    }
                    if (telemetry) {
                        telemetry->MarkProgressComplete();
                        telemetry.reset();
                    }
                    std::cout << final_output << "\n";
                }
            } else if (command == "fwxaes-enc" || command == "fwxaes-heavy-enc") {
                if (!opts.ignore_media && LooksLikeMediaPath(std::filesystem::path(opts.input))) {
                    try {
                        std::string media_output = basefwx::Jmge(
                            opts.input,
                            opts.password,
                            opts.output,
                            opts.keep_meta,
                            opts.keep_input,
                            opts.archive_original,
                            opts.use_master
                        );
                        if (telemetry) {
                            telemetry->MarkProgressComplete();
                            telemetry.reset();
                        }
                        std::cout << media_output << "\n";
                        return 0;
                    } catch (const std::exception&) {
                        // Fall back to standard fwxAES if media processing fails.
                    }
                }
                basefwx::fwxaes::NormalizeOptions norm;
                norm.enabled = opts.normalize;
                norm.threshold = opts.threshold;
                norm.cover_phrase = opts.cover_phrase;
                basefwx::fwxaes::PackOptions pack_opts;
                pack_opts.compress = opts.compress;
                basefwx::fwxaes::Options fwxaes_opts;
                fwxaes_opts.use_master = opts.use_master;
                fwxaes_opts.user_kdf = opts.kdf;
                fwxaes_opts.force_legacy_pbkdf2 = opts.force_legacy_pbkdf2;
                basefwx::fwxaes::EncryptFile(opts.input, opts.output, opts.password, fwxaes_opts, norm, pack_opts, opts.keep_input);
            } else {
                basefwx::fwxaes::DecryptFile(opts.input, opts.output, opts.password, opts.use_master);
            }
            complete_progress();
            return 0;
        }
        if (command == "jmge" || command == "jmgd") {
            ImageArgs opts = ParseImageArgs(argc, argv, 2);
            if (command == "jmge") {
                std::cout << basefwx::Jmge(
                    opts.input,
                    opts.password,
                    opts.output,
                    opts.keep_meta,
                    opts.keep_input,
                    opts.archive_original,
                    opts.use_master
                ) << "\n";
            } else {
                std::cout << basefwx::Jmgd(opts.input, opts.password, opts.output, opts.use_master) << "\n";
            }
            return 0;
        }
        PrintUsage();
        return 2;
    } catch (const std::exception& exc) {
        if (std::string_view(exc.what()) == "Interrupted") {
            std::cerr << "Interrupted\n";
            return 130;
        }
        bool plain = CliPlain();
        const char* red = "\033[31m";
        std::string msg = EmojiPrefix("❌", plain) + "Error: " + exc.what();
        std::cerr << StyleText(msg, red, plain) << "\n";
        return 1;
    }
}
