/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>
#include <string_view>

namespace basefwx::env {

std::string Get(std::string_view name);
bool IsEnabled(std::string_view name, bool default_value = false);
std::string HomeDir();

// Returns the BASEFWX_TEST_KDF_ITERS env var value only when this build
// was configured with BASEFWX_TESTING=1 (CMake option). Release builds
// always return an empty string regardless of the env, so the test-only
// KDF weakening cannot accidentally land in production.
inline std::string TestKdfIters() {
#if defined(BASEFWX_TESTING) && BASEFWX_TESTING
    return Get("BASEFWX_TEST_KDF_ITERS");
#else
    return std::string{};
#endif
}

}  // namespace basefwx::env
