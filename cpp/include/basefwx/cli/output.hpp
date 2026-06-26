#pragma once

#include "basefwx/cli/globals.hpp"
#include <string>

namespace basefwx::cli {

void PrintSystemInfo();
void PrintVersionInfo();
void PrintUsage();
void PrintBashCompletion(const std::string& argv0);

}  // namespace basefwx::cli
