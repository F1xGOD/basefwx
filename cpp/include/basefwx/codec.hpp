#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace basefwx::codec {

std::string Code(const std::string& input);
std::string Decode(const std::string& input);

std::string Base32HexEncode(const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> Base32HexDecode(const std::string& input, bool* ok = nullptr);

std::string B256Encode(const std::string& input);
std::string B256Decode(const std::string& input);

}  // namespace basefwx::codec
