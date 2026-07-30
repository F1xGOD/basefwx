/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "cli/bench_memory.hpp"

#include <algorithm>
#include <limits>

namespace basefwx::cli {

namespace {

constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
constexpr std::uint64_t kFallbackMemoryLimit = 2ULL * 1024ULL * kMiB;
constexpr std::uint64_t kWorkerFixedOverhead = 8ULL * kMiB;
constexpr std::uint64_t kWorkerInputMultiplier = 6ULL;

std::uint64_t SaturatingMultiply(std::uint64_t left, std::uint64_t right) {
    if (left != 0
        && right > std::numeric_limits<std::uint64_t>::max() / left) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return left * right;
}

std::uint64_t SaturatingAdd(std::uint64_t left, std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return left + right;
}

}  // namespace

std::size_t BoundLiveBenchWorkers(std::size_t requested_workers,
                                  std::uint64_t input_bytes,
                                  std::uint64_t memory_limit_bytes) {
    requested_workers = std::max<std::size_t>(requested_workers, 1);
    if (input_bytes == 0) {
        return requested_workers;
    }
    if (memory_limit_bytes == 0) {
        memory_limit_bytes = kFallbackMemoryLimit;
    }

    // Keep 25% of the known limit for the process image, crypto providers,
    // allocator fragmentation, and unrelated runner state. The six-input
    // per-worker estimate deliberately exceeds the optimized bench-live
    // implementation's live buffers so future library growth remains safe.
    const std::uint64_t usable_bytes =
            memory_limit_bytes - (memory_limit_bytes / 4ULL);
    if (usable_bytes <= input_bytes) {
        return 1;
    }
    const std::uint64_t worker_bytes = SaturatingAdd(
            SaturatingMultiply(input_bytes, kWorkerInputMultiplier),
            kWorkerFixedOverhead);
    if (worker_bytes == 0
        || worker_bytes == std::numeric_limits<std::uint64_t>::max()) {
        return 1;
    }

    const std::uint64_t worker_budget = usable_bytes - input_bytes;
    const std::uint64_t by_memory = worker_budget / worker_bytes;
    if (by_memory == 0) {
        return 1;
    }
    const std::size_t bounded = by_memory
            > static_cast<std::uint64_t>(
                    std::numeric_limits<std::size_t>::max())
            ? std::numeric_limits<std::size_t>::max()
            : static_cast<std::size_t>(by_memory);
    return std::max<std::size_t>(
            1, std::min(requested_workers, bounded));
}

}  // namespace basefwx::cli
