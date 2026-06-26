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
