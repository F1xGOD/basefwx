/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

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
