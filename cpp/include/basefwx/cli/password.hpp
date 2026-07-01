/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#pragma once

#include "basefwx/cli/globals.hpp"
#include <string>
#include <string_view>

namespace basefwx::cli {

std::string ReadHiddenPassword(std::string_view prompt);
void ResolveCliPassword(std::string& password,
                        bool password_provided,
                        bool requires_password,
                        bool confirm_password);

}  // namespace basefwx::cli
