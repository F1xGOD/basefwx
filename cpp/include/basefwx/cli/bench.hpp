/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#pragma once

#include "basefwx/cli/globals.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace basefwx::cli {

int BenchWarmup();
int BenchIters();
bool BenchParallelEnabled();
int BenchWorkers();
bool SingleThreadForced(std::size_t workers);
void WarnSingleThreadIfForced();
void ConfirmSingleThreadCli(std::size_t workers);

long long MedianNs(std::vector<long long>& samples);

template <typename Fn>
long long BenchMedian(int warmup, int iters, Fn&& fn) {
    if (warmup < 0) {
        warmup = 0;
    }
    if (iters < 1) {
        iters = 1;
    }
    for (int i = 0; i < warmup; ++i) {
        fn();
    }
    std::vector<long long> samples;
    samples.reserve(static_cast<std::size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        auto start = std::chrono::steady_clock::now();
        fn();
        auto end = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
    }
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
                              std::size_t workers);

template <typename Fn>
std::size_t RunParallel(std::size_t workers, Fn fn) {
    std::atomic<std::size_t> total{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    std::exception_ptr first_exc = nullptr;
    std::mutex exc_mutex;
    for (std::size_t i = 0; i < workers; ++i) {
        threads.emplace_back([&, i]() {
            try {
                total.fetch_add(fn(i), std::memory_order_relaxed);
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
