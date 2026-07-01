/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/cli/globals.hpp"

#include "basefwx/env.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <unordered_set>

#ifdef _WIN32
#include <io.h>
#endif
#ifndef _WIN32
#include <unistd.h>
#endif

namespace basefwx::cli {

bool g_verbose = false;
bool g_no_log = false;
std::atomic<std::size_t> g_bench_sink{0};

std::atomic<int> TelemetrySuspender::pause_count{0};
std::mutex TelemetrySuspender::io_mu;
std::function<void()> TelemetrySuspender::clear_active_line;

TelemetryPauseGuard::TelemetryPauseGuard() {
    TelemetrySuspender::pause_count.fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard<std::mutex> lock(TelemetrySuspender::io_mu);
    if (TelemetrySuspender::clear_active_line) {
        TelemetrySuspender::clear_active_line();
    }
}

TelemetryPauseGuard::~TelemetryPauseGuard() {
    TelemetrySuspender::pause_count.fetch_sub(1, std::memory_order_acq_rel);
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

bool IsLightCommand(const std::string& command) {
    static const std::unordered_set<std::string> kLightCommands = {
        "info", "identify", "probe",
        "b64-enc", "b64-dec",
        "n10-enc", "n10-dec",
        "b256-enc", "b256-dec",
        "a512-enc", "a512-dec",
        "bi512-enc",
        "hash512", "uhash513"
    };
    return kLightCommands.count(command) > 0;
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

bool IsStdinInteractive() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
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

}  // namespace basefwx::cli
