/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "cli/bench_memory.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>

namespace {

constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
constexpr std::uint64_t kGiB = 1024ULL * kMiB;

bool Require(bool condition, const char* message) {
    if (condition) {
        return true;
    }
    std::cerr << "FAIL: " << message << "\n";
    return false;
}

}  // namespace

int main() {
    bool ok = true;

    const std::size_t heavy_workers =
            basefwx::cli::BoundLiveBenchWorkers(
                    31, 256ULL * kMiB, (469ULL * kGiB) / 10ULL);
    ok &= Require(heavy_workers >= 1, "heavy worker bound reached zero");
    ok &= Require(
            heavy_workers < 31,
            "31 workers were not bounded for the 256 MiB heavy case");

    ok &= Require(
            basefwx::cli::BoundLiveBenchWorkers(
                    8, 1ULL * kMiB, 8ULL * kGiB) == 8,
            "small input lost requested concurrency");
    ok &= Require(
            basefwx::cli::BoundLiveBenchWorkers(
                    0, 256ULL * kMiB, 8ULL * kGiB) == 1,
            "zero requested workers did not normalize to one");
    ok &= Require(
            basefwx::cli::BoundLiveBenchWorkers(
                    31,
                    std::numeric_limits<std::uint64_t>::max(),
                    8ULL * kGiB) == 1,
            "overflow-sized input did not fail closed to one worker");

    return ok ? 0 : 1;
}
