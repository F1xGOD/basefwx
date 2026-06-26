/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/cli/password.hpp"

#ifdef _WIN32
#include <conio.h>
#endif
#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

#include <iostream>
#include <stdexcept>

namespace basefwx::cli {

std::string ReadHiddenPassword(std::string_view prompt) {
    TelemetryPauseGuard pause_telemetry;
    std::cerr << prompt;
    std::cerr.flush();
#if defined(_WIN32)
    std::string value;
    while (true) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            std::cerr << "\n";
            return value;
        }
        if (ch == 3) {
            throw std::runtime_error("Interrupted");
        }
        if (ch == '\b' || ch == 127) {
            if (!value.empty()) {
                value.pop_back();
            }
            continue;
        }
        if (ch == 0 || ch == 224) {
            (void)_getch();
            continue;
        }
        value.push_back(static_cast<char>(ch));
    }
#else
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) {
        throw std::runtime_error("Failed to access terminal for hidden password prompt");
    }
    termios hidden = original;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        throw std::runtime_error("Failed to disable terminal echo for password prompt");
    }
    struct EchoRestore {
        termios state{};
        bool active = false;
        ~EchoRestore() {
            if (active) {
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &state);
            }
        }
    } restore;
    restore.state = original;
    restore.active = true;
    std::string value;
    if (!std::getline(std::cin, value)) {
        std::cerr << "\n";
        throw std::runtime_error("Failed to read password from terminal");
    }
    std::cerr << "\n";
    return value;
#endif
}

void ResolveCliPassword(std::string& password, bool password_provided, bool requires_password, bool confirm_password) {
    if (password_provided) {
        if (requires_password && password.empty()) {
            throw std::runtime_error("Password cannot be empty");
        }
        return;
    }
    if (!requires_password) {
        return;
    }
    if (!IsStdinInteractive()) {
        throw std::runtime_error("Password required; rerun in an interactive terminal or pass --password");
    }
    while (true) {
        std::string first = ReadHiddenPassword("Password: ");
        if (first.empty()) {
            std::cerr << "Password cannot be empty.\n";
            continue;
        }
        if (!confirm_password) {
            password = std::move(first);
            return;
        }
        std::string second = ReadHiddenPassword("Confirm password: ");
        if (first == second) {
            password = std::move(first);
            return;
        }
        std::cerr << "Passwords did not match. Try again.\n";
    }
}

}  // namespace basefwx::cli
