/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace basefwx::codec {

// Historical low-level helpers retained only in the compatibility profile.
std::string B256Encode(const std::string& input);
std::string B256Decode(const std::string& input);

}  // namespace basefwx::codec

namespace basefwx {

[[deprecated("Retired since 3.7.0; use base64 for reversible encoding")]]
std::string B256Encode(const std::string& input);
[[deprecated("Retired since 3.7.0; use base64 for reversible encoding")]]
std::string B256Decode(const std::string& input);
[[deprecated("Use Hash512 or SHA3-512; Uhash513 includes a SHA-1 compatibility hop")]]
std::string Uhash513(const std::string& input);
[[deprecated("Use Hash512; Bi512 is SHA-256 with a non-standard prefilter")]]
std::string Bi512Encode(const std::string& input);
[[deprecated("Use base64; A512 is reversible obfuscation without a security goal")]]
std::string A512Encode(const std::string& input);
[[deprecated("Use base64; A512 is reversible obfuscation without a security goal")]]
std::string A512Decode(const std::string& input);

}  // namespace basefwx
