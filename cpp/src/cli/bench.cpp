/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/cli/bench.hpp"

#include "basefwx/env.hpp"
#include "basefwx/fwxaes.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace basefwx::cli {

namespace {

int ReadEnvInt(const char* name, int default_value, int min_value) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return default_value;
    }
    char* end = nullptr;
    long value = std::strtol(raw, &end, 10);
    if (end == raw) {
        return default_value;
    }
    if (value < min_value) {
        return default_value;
    }
    if (value > static_cast<long>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(value);
}

}  // namespace

int BenchWarmup() {
    return ReadEnvInt("BASEFWX_BENCH_WARMUP", 2, 0);
}

int BenchIters() {
    return ReadEnvInt("BASEFWX_BENCH_ITERS", 50, 1);
}

bool BenchParallelEnabled() {
    std::string raw = ToLower(basefwx::env::Get("BASEFWX_BENCH_PARALLEL"));
    if (raw.empty()) {
        return true;
    }
    return !(raw == "0" || raw == "false" || raw == "off" || raw == "no");
}

int BenchWorkers() {
    if (!BenchParallelEnabled()) {
        return 1;
    }
    unsigned int hw = std::thread::hardware_concurrency();
    int default_workers = hw == 0 ? 1 : static_cast<int>(hw);
    return ReadEnvInt("BASEFWX_BENCH_WORKERS", default_workers, 1);
}

bool SingleThreadForced(std::size_t workers) {
    (void)workers;
    std::string force_single = basefwx::env::Get("BASEFWX_FORCE_SINGLE_THREAD");
    unsigned int hw = std::thread::hardware_concurrency();
    return (force_single == "1" && hw > 1);
}

void WarnSingleThreadIfForced() {
    static bool warned = false;
    if (warned) {
        return;
    }
    if (!SingleThreadForced(1)) {
        return;
    }
    warned = true;
    if (!ShouldLog()) {
        return;
    }
    std::cerr << "\033[38;5;208mWARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION\033[0m\n";
    std::cerr << "\033[38;5;208mWARN: SINGLE-THREAD MODE MAY REDUCE SECURITY MARGIN\033[0m\n";
}

void ConfirmSingleThreadCli(std::size_t workers) {
    if (!SingleThreadForced(workers)) {
        return;
    }
    WarnSingleThreadIfForced();
    const char* allow_single = std::getenv("BASEFWX_ALLOW_SINGLE_THREAD");
    const char* noninteractive = std::getenv("BASEFWX_NONINTERACTIVE");
    if ((allow_single && std::string_view(allow_single) == "1")
        || (noninteractive && std::string_view(noninteractive) == "1")) {
        return;
    }
    std::cout << "Type YES to continue with single-thread mode: ";
    std::string line;
    if (!std::getline(std::cin, line)) {
        throw std::runtime_error("Aborted: multi-thread disabled by user override");
    }
    if (line != "YES") {
        throw std::runtime_error("Aborted: multi-thread disabled by user override");
    }
}

long long MedianNs(std::vector<long long>& samples) {
    if (samples.empty()) {
        return 0;
    }
    std::size_t mid = samples.size() / 2;
    std::nth_element(samples.begin(), samples.begin() + static_cast<std::ptrdiff_t>(mid), samples.end());
    long long high = samples[mid];
    if (samples.size() % 2 == 1) {
        return high;
    }
    auto lower_max = std::max_element(samples.begin(), samples.begin() + static_cast<std::ptrdiff_t>(mid));
    long long low = lower_max == samples.begin() + static_cast<std::ptrdiff_t>(mid) ? high : *lower_max;
    return low + (high - low) / 2;
}

std::size_t RunFwxaesParallel(const std::vector<std::uint8_t>& data,
                              const std::string& password,
                              bool use_master,
                              std::size_t workers) {
    std::atomic<std::size_t> total{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    basefwx::fwxaes::Options opts;
    opts.use_master = use_master;
    std::exception_ptr first_exc = nullptr;
    std::mutex exc_mutex;
    for (std::size_t i = 0; i < workers; ++i) {
        threads.emplace_back([&]() {
            try {
                auto blob = basefwx::fwxaes::EncryptRaw(data, password, opts);
                auto plain = basefwx::fwxaes::DecryptRaw(blob, password, use_master);
                g_bench_sink.fetch_xor(plain.size(), std::memory_order_relaxed);
                total.fetch_add(plain.size(), std::memory_order_relaxed);
            } catch (...) {
                std::lock_guard<std::mutex> lock(exc_mutex);
                if (!first_exc) {
                    first_exc = std::current_exception();
                }
            }
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    if (first_exc) {
        std::rethrow_exception(first_exc);
    }
    return total.load(std::memory_order_relaxed);
}

}  // namespace basefwx::cli
