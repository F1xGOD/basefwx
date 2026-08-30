/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "retired/cli.hpp"

#include "basefwx/basefwx.hpp"
#include "cli/colors.hpp"
#include "cli/output.hpp"
#include "cli/password.hpp"
#include "basefwx/system_info.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace basefwx::retired::cli {

namespace {

struct ImageArgs {
    std::string input;
    std::string output;
    std::string password;
    bool password_provided = false;
    bool use_master = false;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = false;
};

std::string DescribeKfmMode(std::uint8_t mode) {
    if (mode == 1u) {
        return "image->audio";
    }
    if (mode == 2u) {
        return "audio->image";
    }
    return "unknown";
}

std::string DescribeKfmFlags(std::uint8_t flags) {
    if (flags == 0u) {
        return "none";
    }
    std::string output;
    if ((flags & 0x01u) != 0u) {
        output = "bw";
    }
    const std::uint8_t remaining =
        static_cast<std::uint8_t>(flags & ~0x01u);
    if (remaining != 0u) {
        if (!output.empty()) {
            output += ", ";
        }
        std::ostringstream hex;
        hex << "0x" << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(remaining);
        output += hex.str();
    }
    return output;
}

std::string FormatSize(std::uint64_t bytes) {
    std::ostringstream output;
    output << bytes << " bytes ("
           << basefwx::system::FormatBytes(bytes) << ")";
    return output.str();
}

void PrintIdentifyField(
    const std::string& key, const std::string& value) {
    std::cout << basefwx::cli::Cyan(key) << ": " << value << "\n";
}

ImageArgs ParseImageArgs(int argc, char** argv, int start_index) {
    ImageArgs options;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    options.input = argv[start_index];
    int index = start_index + 1;
    while (index < argc) {
        std::string flag(argv[index]);
        if (flag == "-p" || flag == "--password") {
            if (index + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            options.password = argv[index + 1];
            options.password_provided = true;
            index += 2;
        } else if (basefwx::cli::HandleMasterFlag(
                       flag, argc, argv, &index, &options.use_master)) {
            index += 1;
        } else if (flag == "--out" || flag == "-o") {
            if (index + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            options.output = argv[index + 1];
            index += 2;
        } else if (flag == "--keep-meta") {
            options.keep_meta = true;
            index += 1;
        } else if (flag == "--keep-input") {
            options.keep_input = true;
            index += 1;
        } else if (flag == "--archive") {
            options.archive_original = true;
            index += 1;
        } else if (flag == "--no-archive") {
            options.archive_original = false;
            index += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return options;
}

int RunKfmCommand(const std::string& command, int argc, char** argv) {
    if (argc < 3) {
        basefwx::cli::PrintUsage();
        return 2;
    }
    const std::string input = argv[2];
    std::string output;
    bool black_and_white = false;
    for (int index = 3; index < argc; ++index) {
        const std::string flag(argv[index]);
        if (flag == "--out" || flag == "-o") {
            if (index + 1 >= argc) {
                throw std::runtime_error("Missing value for --out");
            }
            output = argv[++index];
        } else if (flag == "--bw") {
            black_and_white = true;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }

    std::string output_path;
    if (command == "kFMe") {
        output_path = basefwx::Kfme(input, output, black_and_white);
    } else if (command == "kFMd") {
        output_path = basefwx::Kfmd(input, output, black_and_white);
    } else if (command == "kFAe") {
        output_path = basefwx::Kfae(input, output, black_and_white);
    } else {
        output_path = basefwx::Kfad(input, output);
    }
    std::cout << output_path << "\n";
    return 0;
}

int RunJmgCommand(
    const std::string& command, int argc, char** argv) {
    ImageArgs options = ParseImageArgs(argc, argv, 2);
    basefwx::cli::ResolveCliPassword(
        options.password, options.password_provided,
        !options.use_master, command == "jmge");
    if (command == "jmge") {
        std::cout << basefwx::Jmge(
            options.input,
            options.password,
            options.output,
            options.keep_meta,
            options.keep_input,
            options.archive_original,
            options.use_master
        ) << "\n";
    } else {
        std::cout << basefwx::Jmgd(
            options.input, options.password, options.output,
            options.use_master) << "\n";
    }
    return 0;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
std::optional<int> TryRunRetiredCodecCommand(
    const std::string& command, int argc, char** argv) {
    if (command != "b256-enc" && command != "b256-dec"
        && command != "a512-enc" && command != "a512-dec"
        && command != "bi512-enc" && command != "uhash513") {
        return std::nullopt;
    }
    if (argc < 3) {
        basefwx::cli::PrintUsage();
        return 2;
    }
    if (command == "b256-enc") {
        std::cout << basefwx::B256Encode(argv[2]) << "\n";
    } else if (command == "b256-dec") {
        std::cout << basefwx::B256Decode(argv[2]) << "\n";
    } else if (command == "a512-enc") {
        std::cout << basefwx::A512Encode(argv[2]) << "\n";
    } else if (command == "a512-dec") {
        std::cout << basefwx::A512Decode(argv[2]) << "\n";
    } else if (command == "bi512-enc") {
        std::cout << basefwx::Bi512Encode(argv[2]) << "\n";
    } else {
        std::cout << basefwx::Uhash513(argv[2]) << "\n";
    }
    return 0;
}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

}  // namespace

std::optional<int> TryHandleCliCommand(
    const std::string& command, int argc, char** argv) {
    if (const auto status =
            TryRunRetiredCodecCommand(command, argc, argv)) {
        return status;
    }
    if (command == "kFMe" || command == "kFMd"
        || command == "kFAe" || command == "kFAd") {
        return RunKfmCommand(command, argc, argv);
    }
    if (command == "jmge" || command == "jmgd") {
        return RunJmgCommand(command, argc, argv);
    }
    return std::nullopt;
}

bool SkipsCoreTelemetry(const std::string& command) {
    static const std::unordered_set<std::string> kCommands = {
        "b256-enc", "b256-dec",
        "a512-enc", "a512-dec",
        "bi512-enc", "uhash513",
        "jmge", "jmgd",
    };
    return kCommands.count(command) > 0;
}

bool TryParseFwxAesFlag(
    const std::string& flag,
    int* index,
    basefwx::cli::FwxAesArgs* options) {
    if (index == nullptr || options == nullptr) {
        return false;
    }
    if (flag == "--ignore-media") {
        options->ignore_media = true;
    } else if (flag == "--keep-meta") {
        options->keep_meta = true;
    } else if (flag == "--archive") {
        options->archive_original = true;
    } else if (flag == "--no-archive") {
        options->archive_original = false;
    } else {
        return false;
    }
    ++*index;
    return true;
}

void ValidateHeavyFwxAesOptions(
    const basefwx::cli::FwxAesArgs& options) {
    if (options.ignore_media
        || options.keep_meta
        || options.archive_original) {
        throw std::runtime_error(
            "fwxAES heavy mode does not support media-only options");
    }
}

std::optional<std::string> TryDefaultFwxAesOutput(
    const basefwx::cli::FwxAesArgs& options) {
    if (!options.ignore_media
        && LooksLikeMediaPath(std::filesystem::path(options.input))) {
        return options.input;
    }
    return std::nullopt;
}

bool LooksLikeMediaPath(const std::filesystem::path& path) {
    static const std::unordered_set<std::string> kImageExtensions = {
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp",
        ".tif", ".tiff", ".heic", ".heif", ".avif", ".ico"
    };
    static const std::unordered_set<std::string> kVideoExtensions = {
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".flv",
        ".wmv", ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".m2ts"
    };
    static const std::unordered_set<std::string> kAudioExtensions = {
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus",
        ".wma", ".aiff", ".alac"
    };
    const std::string extension =
        basefwx::cli::ToLower(path.extension().string());
    if (extension.empty()) {
        return false;
    }
    return kImageExtensions.count(extension)
        || kVideoExtensions.count(extension)
        || kAudioExtensions.count(extension);
}

std::optional<std::string> TryEncryptMedia(
    const basefwx::cli::FwxAesArgs& options) {
    if (options.ignore_media
        || !LooksLikeMediaPath(std::filesystem::path(options.input))) {
        return std::nullopt;
    }
    try {
        return basefwx::Jmge(
            options.input,
            options.password,
            options.output,
            options.keep_meta,
            options.keep_input,
            options.archive_original,
            options.use_master);
    } catch (const std::exception&) {
        // Preserve the legacy compatibility profile's fwxAES fallback.
        return std::nullopt;
    }
}

bool TryPrintKfmInfo(const std::string& path) {
    const auto info = basefwx::InspectKfmCarrierFile(path);
    if (!info.has_value()) {
        return false;
    }
    std::cout << "format: kFM carrier\n";
    std::cout << "carrier_kind: " << info->carrier_kind << "\n";
    std::cout << "mode: " << DescribeKfmMode(info->mode)
              << " (" << static_cast<unsigned int>(info->mode) << ")\n";
    std::cout << "flags: " << DescribeKfmFlags(info->flags) << "\n";
    std::cout << "payload_ext: "
              << (info->payload_ext.empty() ? ".bin" : info->payload_ext)
              << "\n";
    std::cout << "payload_len: " << info->payload_len << " bytes\n";
    std::cout << "file_size: " << info->file_size << " bytes\n";
    return true;
}

bool TryPrintKfmIdentify(const std::string& path) {
    const auto info = basefwx::InspectKfmCarrierFile(path);
    if (!info.has_value()) {
        return false;
    }
    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", path);
    PrintIdentifyField("format", "basefwx kFM carrier");
    PrintIdentifyField("integrity", basefwx::cli::BoldGreen("OK"));
    PrintIdentifyField("carrier_kind", info->carrier_kind);
    PrintIdentifyField(
        "mode",
        DescribeKfmMode(info->mode) + " ("
            + std::to_string(static_cast<unsigned int>(info->mode)) + ")");
    PrintIdentifyField("flags", DescribeKfmFlags(info->flags));
    PrintIdentifyField(
        "payload_ext",
        info->payload_ext.empty() ? ".bin" : info->payload_ext);
    PrintIdentifyField(
        "payload_size",
        FormatSize(static_cast<std::uint64_t>(info->payload_len)));
    PrintIdentifyField("file_size", FormatSize(info->file_size));
    return true;
}

void AppendFwxAesUsageOptions(std::ostream& output) {
    output << " [--ignore-media] [--keep-meta] [--archive|--no-archive]";
}

void PrintUsageCommands(
    std::ostream& output, const std::string& master_flags) {
    output << "Retired compatibility commands:\n";
    output << "  b256-enc <text>\n";
    output << "  b256-dec <text>\n";
    output << "  a512-enc <text>\n";
    output << "  a512-dec <text>\n";
    output << "  bi512-enc <text>\n";
    output << "  uhash513 <text>\n";
    output << "  jmge <media> [--password <password>] " << master_flags
           << " [--out <path>] [--keep-meta] [--keep-input]"
              " [--archive|--no-archive]\n";
    output << "  jmgd <media> [--password <password>] " << master_flags
           << " [--out <path>]\n";
    output << "  kFMe <in-file> [--out <path>] [--bw]\n";
    output << "  kFMd <in-file> [--out <path>] [--bw]\n\n";
}

void AppendCompletionCommandNames(std::ostream& output) {
    output << "b256-enc b256-dec a512-enc a512-dec bi512-enc uhash513 "
              "kFMe kFMd kFAe kFAd jmge jmgd ";
}

void AppendFwxAesCompletionOptions(std::ostream& output) {
    output << "--ignore-media --keep-meta --archive --no-archive ";
}

void AppendCompletionCases(std::ostream& output) {
    output
        << "    jmge|jmgd)\n"
        << "      COMPREPLY=( $(compgen -W \"-p --password --out -o"
           " --keep-meta --keep-input --archive --no-archive"
           " $master_opts\" -- \"$cur\") )\n"
        << "      ;;\n"
        << "    kFMe|kFMd)\n"
        << "      COMPREPLY=( $(compgen -W \"--out -o --bw\""
           " -- \"$cur\") )\n"
        << "      ;;\n";
}

}  // namespace basefwx::retired::cli
