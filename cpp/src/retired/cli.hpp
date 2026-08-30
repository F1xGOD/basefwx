/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#pragma once

#include "cli/options.hpp"

#include <filesystem>
#include <optional>
#include <ostream>
#include <string>

namespace basefwx::retired::cli {

std::optional<int> TryHandleCliCommand(
    const std::string& command, int argc, char** argv);

bool SkipsCoreTelemetry(const std::string& command);

bool TryParseFwxAesFlag(
    const std::string& flag,
    int* index,
    basefwx::cli::FwxAesArgs* options);

void ValidateHeavyFwxAesOptions(
    const basefwx::cli::FwxAesArgs& options);

std::optional<std::string> TryDefaultFwxAesOutput(
    const basefwx::cli::FwxAesArgs& options);

bool LooksLikeMediaPath(const std::filesystem::path& path);

std::optional<std::string> TryEncryptMedia(
    const basefwx::cli::FwxAesArgs& options);

bool TryPrintKfmInfo(const std::string& path);
bool TryPrintKfmIdentify(const std::string& path);

void AppendFwxAesUsageOptions(std::ostream& output);
void PrintUsageCommands(
    std::ostream& output, const std::string& master_flags);
void AppendCompletionCommandNames(std::ostream& output);
void AppendFwxAesCompletionOptions(std::ostream& output);
void AppendCompletionCases(std::ostream& output);

}  // namespace basefwx::retired::cli
