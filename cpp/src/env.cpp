#include "basefwx/env.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace basefwx::env {

namespace {

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

}  // namespace

std::string Get(std::string_view name) {
    std::string key(name);
    const char* value = std::getenv(key.c_str());
    if (!value) {
        return {};
    }
    return std::string(value);
}

bool IsEnabled(std::string_view name, bool default_value) {
    std::string value = Get(name);
    if (value.empty()) {
        return default_value;
    }
    value = ToLower(value);
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

}  // namespace basefwx::env
