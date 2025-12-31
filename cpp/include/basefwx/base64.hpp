#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace basefwx::base64 {

std::string Encode(const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> Decode(const std::string& input, bool* ok = nullptr);
bool IsLikelyBase64(const std::string& input);

}  // namespace basefwx::base64
