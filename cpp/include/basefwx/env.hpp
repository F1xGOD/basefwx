#pragma once

#include <string>
#include <string_view>

namespace basefwx::env {

std::string Get(std::string_view name);
bool IsEnabled(std::string_view name, bool default_value = false);

}  // namespace basefwx::env
