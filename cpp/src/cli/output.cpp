/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/cli/output.hpp"
#include "basefwx/constants.hpp"
#include "basefwx_build_info.hpp"
#include "basefwx_build_stamp.hpp"
#include "basefwx/cli_colors.hpp"
#include "basefwx/system_info.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

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

namespace basefwx::cli {

namespace {

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

}  // namespace

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
void PrintVersionInfo() {
    bool plain = CliPlain();
    const char* cyan = "\033[36m";
    std::string banner = "basefwx " + std::string(basefwx::constants::kEngineVersion);
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
    std::cout << StyleText(EmojiPrefix("✨", plain) + "basefwx help", cyan, plain) << "\n";
    std::cout << "Usage: basefwx [global flags] <command> [args]\n";
    std::cout << "Global flags: --verbose|-v --no-log --no-color --version|-V\n";
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
    std::cout << "  hash512 <text>\n";
    std::cout << "  uhash513 <text>\n";
    std::cout << "  b512-enc <text> [--password <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  b512-dec <text> [--password <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512-enc <text> [--password <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512-dec <text> [--password <password>] " << master_flags << " [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "\n";
    std::cout << "File commands:\n";
    std::cout << "  b512file-enc <file> [--password <password>] " << master_flags << " [--strip-meta] [--no-aead] [--compress] [--keep-input] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  b512file-dec <file.fwx> [--password <password>] " << master_flags << " [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  b512file-bytes-rt <in> <out> [--password <password>] " << master_flags << " [--strip-meta] [--no-aead] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512file-bytes-rt <in> <out> [--password <password>] " << master_flags << " [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512file-enc <file> [--password <password>] " << master_flags << " [--strip-meta] [--no-obf] [--compress] [--keep-input] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "  pb512file-dec <file.fwx> [--password <password>] " << master_flags << " [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>] [--no-fallback]\n";
    std::cout << "\n";
    std::cout << "fwxAES commands:\n";
    std::cout << "  fwxaes-enc <file> [--password <password>] " << master_flags << " [--out <path>] [--heavy] [--normalize] [--threshold <n>] [--cover-phrase <text>] [--compress] [--ignore-media] [--keep-meta] [--keep-input] [--archive|--no-archive] [--kdf <label>] [--pbkdf2-iters <n>] [--argon2-time <n>] [--argon2-mem <n>] [--argon2-par <n>] [--no-fallback] [--legacy-pbkdf2] [--plugin <path>] [--plugin-id <hex>] [--plugin-pos pre|post] [--plugin-config <file>]\n";
    std::cout << "  fwxaes-dec <file> [--password <password>] " << master_flags << " [--out <path>] [--heavy]\n";
    std::cout << "  fwxaes-heavy-enc <file> [--password <password>] " << master_flags << " [--out <path>] [--compress] [--keep-input]  (alias of fwxaes-enc --heavy)\n";
    std::cout << "  fwxaes-heavy-dec <file> [--password <password>] " << master_flags << " [--out <path>]                (alias of fwxaes-dec --heavy)\n";
    std::cout << "  fwxaes-stream-enc <file> [--password <password>] " << master_flags << " [--out <path>] [--kdf <label>] [--pbkdf2-iters <n>] [--argon2-time <n>] [--argon2-mem <n>] [--argon2-par <n>] [--no-fallback] [--legacy-pbkdf2]\n";
    std::cout << "  fwxaes-stream-dec <file> [--password <password>] " << master_flags << " [--out <path>]\n";
    std::cout << "  fwxaes-live-enc <file|-> [--password <password>] " << master_flags << " [--out <path|->]\n";
    std::cout << "  fwxaes-live-dec <file|-> [--password <password>] " << master_flags << " [--out <path|->]\n";
    std::cout << "  an7 <file.fwx> [--password <password>] [--out <path>] [--keep-input] [--force-any]\n";
    std::cout << "  dean7 <file> [--password <password>] [--out <path>] [--keep-input]\n";
    std::cout << "\n";
    std::cout << "Media/carrier commands:\n";
    std::cout << "  jmge <media> [--password <password>] " << master_flags << " [--out <path>] [--keep-meta] [--keep-input] [--archive|--no-archive]\n";
    std::cout << "  jmgd <media> [--password <password>] " << master_flags << " [--out <path>]\n";
    std::cout << "  kFMe <in-file> [--out <path>] [--bw]\n";
    std::cout << "  kFMd <in-file> [--out <path>] [--bw]\n";
    std::cout << "\n";
    std::cout << "Benchmark commands:\n";
    std::cout << "  bench-text <method> <text-file> [--password <password>] " << master_flags << "\n";
    std::cout << "  bench-hash <method> <text-file>\n";
    std::cout << "  bench-fwxaes <file> <password> " << master_flags << "\n";
    std::cout << "  bench-fwxaes-par <file> <password> " << master_flags << "\n";
    std::cout << "  bench-an7 <file> <password> " << master_flags << "\n";
    std::cout << "  bench-dean7 <file> <password> " << master_flags << "\n";
    std::cout << "  bench-live <file> <password> " << master_flags << "\n";
    std::cout << "  bench-b512file <file> <password> " << master_flags << " [--no-aead]\n";
    std::cout << "  bench-pb512file <file> <password> " << master_flags << " [--no-aead]\n";
    std::cout << "  bench-jmg <media> <password> " << master_flags << "\n";
    std::cout << "\n";
    std::cout << "Passworded commands prompt on a TTY when --password is omitted.\n";
}

void PrintBashCompletion(const std::string& argv0) {
    std::string bin = std::filesystem::path(argv0).filename().string();
    if (bin.empty()) {
        bin = "basefwx";
    }
    std::cout
        << "# bash completion for " << bin << "\n"
        << "_basefwx_complete() {\n"
        << "  local cur cmd\n"
        << "  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
        << "  cmd=\"${COMP_WORDS[1]}\"\n"
        << "  local commands=\"help version completion info identify probe b64-enc b64-dec n10-enc n10-dec n10file-enc n10file-dec "
           "kFMe kFMd hash512 uhash513 a512-enc a512-dec bi512-enc b256-enc b256-dec "
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
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --heavy --light --normalize --threshold --cover-phrase --compress --ignore-media --keep-meta --keep-input --archive --no-archive --kdf --pbkdf2-iters --argon2-time --argon2-mem --argon2-par --no-fallback --legacy-pbkdf2 --no-wrap-kdf $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    an7)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --keep-input --force-any\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    dean7)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --keep-input\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    jmge|jmgd|bench-jmg)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o --keep-meta --keep-input --archive --no-archive $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    kFMe|kFMd)\n"
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

}  // namespace basefwx::cli
