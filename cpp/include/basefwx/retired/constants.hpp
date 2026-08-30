/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace basefwx::constants {

// Compatibility wire values for retired jMG data. These values are fixed by
// existing encoded files and must not change while compatibility remains.
inline constexpr std::string_view kImageCipherStreamInfo =
    "basefwx.imagecipher.stream.v1";
inline constexpr std::string_view kImageCipherArchiveInfo =
    "basefwx.imagecipher.archive.v1";
inline constexpr std::string_view kImageCipherTrailerMagic = "JMG0";
inline constexpr std::string_view kImageCipherKeyTrailerMagic = "JMG1";
inline constexpr std::string_view kJmgKeyMagic = "JMGK";
inline constexpr std::uint8_t kJmgKeyVersionLegacy = 1;
inline constexpr std::uint8_t kJmgKeyVersion = 2;
inline constexpr std::uint8_t kJmgSecurityProfileLegacy = 0;
inline constexpr std::uint8_t kJmgSecurityProfileMax = 1;
inline constexpr std::uint8_t kJmgSecurityProfileDefault =
    kJmgSecurityProfileMax;
inline constexpr std::string_view kJmgMaskInfo = "basefwx.jmg.mask.v1";
inline constexpr std::string_view kMaskAadJmg = "jmg";

}  // namespace basefwx::constants
