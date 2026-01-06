#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace basefwx::base64 {

std::string Encode(const std::vector<std::uint8_t>& data);
std::string Encode(std::string_view input);
std::vector<std::uint8_t> Decode(const std::string& input, bool* ok = nullptr);
std::string DecodeToString(std::string_view input, bool* ok = nullptr);
bool IsLikelyBase64(const std::string& input);

}  // namespace basefwx::base64
