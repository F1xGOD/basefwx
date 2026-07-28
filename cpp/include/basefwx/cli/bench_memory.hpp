/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace basefwx::cli {

std::size_t BoundLiveBenchWorkers(std::size_t requested_workers,
                                  std::uint64_t input_bytes,
                                  std::uint64_t memory_limit_bytes);

}  // namespace basefwx::cli
