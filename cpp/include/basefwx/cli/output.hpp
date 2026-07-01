/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#pragma once

#include "basefwx/cli/globals.hpp"
#include <string>

namespace basefwx::cli {

void PrintSystemInfo();
void PrintVersionInfo();
void PrintUsage();
void PrintBashCompletion(const std::string& argv0);

}  // namespace basefwx::cli
