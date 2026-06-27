/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/basefwx.hpp"
#include "basefwx_build_info.hpp"
#include "basefwx_build_stamp.hpp"
#include "basefwx/cli_colors.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/runtime.hpp"
#include "basefwx/system_info.hpp"

#include <chrono>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif
#else
#include <termios.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif
#include "basefwx/cli/bench.hpp"
#include "basefwx/cli/globals.hpp"
#include "basefwx/cli/inspect.hpp"
#include "basefwx/cli/options.hpp"
#include "basefwx/cli/output.hpp"
#include "basefwx/cli/password.hpp"
#include "basefwx/cli/telemetry.hpp"

namespace {

void HandleStopSignal(int /*signum*/) {
    basefwx::runtime::RequestStop();
}

void InstallStopHandlers() {
    std::signal(SIGINT, HandleStopSignal);
#if defined(SIGTERM)
    std::signal(SIGTERM, HandleStopSignal);
#endif
}
std::string MoveOutputPath(const std::string& current_path, const std::string& requested_path) {
    if (requested_path.empty() || current_path == requested_path) {
        return current_path;
    }
    std::filesystem::path src(current_path);
    std::filesystem::path dst(requested_path);
    std::error_code ec;
    if (std::filesystem::exists(dst, ec) && std::filesystem::is_directory(dst, ec)) {
        dst /= src.filename();
    }
    if (!dst.parent_path().empty()) {
        std::filesystem::create_directories(dst.parent_path(), ec);
        if (ec) {
            throw std::runtime_error("Failed to prepare output path: " + dst.string());
        }
    }
    std::filesystem::rename(src, dst, ec);
    if (ec) {
        ec.clear();
        std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            throw std::runtime_error("Failed to move output to: " + dst.string());
        }
        ec.clear();
        std::filesystem::remove(src, ec);
        if (ec) {
            throw std::runtime_error("Failed to finalize moved output: " + dst.string());
        }
    }
    return dst.string();
}
bool LooksLikeMediaPath(const std::filesystem::path& path) {
    static const std::unordered_set<std::string> kImageExts = {
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp", ".tif", ".tiff",
        ".heic", ".heif", ".avif", ".ico"
    };
    static const std::unordered_set<std::string> kVideoExts = {
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".flv", ".wmv",
        ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".m2ts"
    };
    static const std::unordered_set<std::string> kAudioExts = {
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".alac"
    };
    std::string ext = basefwx::cli::ToLower(path.extension().string());
    if (ext.empty()) {
        return false;
    }
    return kImageExts.count(ext) || kVideoExts.count(ext) || kAudioExts.count(ext);
}
void EnableBinaryStdio(bool use_stdin, bool use_stdout) {
#ifdef _WIN32
    if (use_stdin) {
        _setmode(_fileno(stdin), _O_BINARY);
    }
    if (use_stdout) {
        _setmode(_fileno(stdout), _O_BINARY);
    }
#else
    (void)use_stdin;
    (void)use_stdout;
#endif
}
std::string ReadTextFile(const std::string& path) {
    auto data = basefwx::ReadFile(path);
    return std::string(data.begin(), data.end());
}

std::vector<std::uint8_t> ReadBinaryFile(const std::string& path) {
    return basefwx::ReadFile(path);
}

void WriteTextFile(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file: " + path);
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) {
        throw std::runtime_error("Failed to write output file: " + path);
    }
}

void WriteBinaryFile(const std::string& path, const std::string& data) {
    WriteTextFile(path, data);
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> cleaned_args;
    cleaned_args.reserve(static_cast<std::size_t>(argc));
    cleaned_args.emplace_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--verbose" || arg == "-v") {
            basefwx::cli::g_verbose = true;
            continue;
        }
        if (arg == "--no-log") {
            basefwx::cli::g_no_log = true;
            continue;
        }
        if (arg == "--no-color") {
            basefwx::cli::SetColorsEnabled(false);
            basefwx::cli::SetCliEnvVar("NO_COLOR", "1");
            continue;
        }
        cleaned_args.push_back(std::move(arg));
    }
    std::vector<char*> argv_storage;
    argv_storage.reserve(cleaned_args.size());
    for (auto& arg : cleaned_args) {
        argv_storage.push_back(arg.data());
    }
    argc = static_cast<int>(argv_storage.size());
    argv = argv_storage.data();

    basefwx::cli::SetCliEnvVar("BASEFWX_VERBOSE", basefwx::cli::g_verbose ? "1" : "0");
    basefwx::cli::SetCliEnvVar("BASEFWX_NO_LOG", basefwx::cli::g_no_log ? "1" : "0");

    if (argc < 2) {
        basefwx::cli::PrintUsage();
        return 2;
    }
    std::string command(argv[1]);
    if (command == "version" || command == "--version" || command == "-V") {
        basefwx::cli::PrintVersionInfo();
        return 0;
    }
    if (command == "help" || command == "--help" || command == "-h") {
        basefwx::cli::PrintUsage();
        return 0;
    }
    if (command == "completion") {
        if (argc < 3) {
            basefwx::cli::PrintUsage();
            return 2;
        }
        std::string shell = basefwx::cli::ToLower(argv[2]);
        if (shell != "bash") {
            std::cerr << "Error: unsupported shell for completion: " << shell << "\n";
            return 1;
        }
        basefwx::cli::PrintBashCompletion(argv[0]);
        return 0;
    }
    std::optional<basefwx::cli::CommandTelemetry> telemetry;
    if (!basefwx::cli::IsLightCommand(command) && command != "jmge" && command != "jmgd") {
        telemetry.emplace(basefwx::cli::BuildHwPlan(command));
    }

    // Print system info if verbose
    basefwx::cli::PrintSystemInfo();

    try {
        if (command == "info") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::filesystem::path input_path(argv[2]);
            auto lp = basefwx::cli::InspectLengthPrefixedFile(input_path);
            if (lp.has_value() && !basefwx::cli::MetadataNeedsFullFallback(lp->info)) {
                basefwx::cli::PrintInspectInfo(lp->info);
                return 0;
            }
            auto fwx = basefwx::cli::ParseFwxAesHeader(input_path);
            if (fwx.has_value()) {
                basefwx::cli::PrintFwxAesInfo(*fwx);
                return 0;
            }
            auto kfm = basefwx::InspectKfmCarrierFile(input_path.string());
            if (kfm.has_value()) {
                basefwx::cli::PrintKfmCarrierInfo(*kfm);
                return 0;
            }
            std::string fallback_reason;
            auto full = basefwx::cli::TryReadFullInspectSafe(input_path, &fallback_reason);
            if (full.has_value()) {
                try {
                    auto full_info = basefwx::InspectBlob(*full);
                    basefwx::cli::PrintInspectInfo(full_info);
                    return 0;
                } catch (const std::exception&) {
                    // Continue with lightweight output or error.
                }
            } else {
                basefwx::cli::MaybeWarnInspectFallback(fallback_reason);
            }
            if (lp.has_value()) {
                if (basefwx::cli::MetadataNeedsFullFallback(lp->info)) {
                    basefwx::cli::MaybeWarnInspectFallback("metadata was incomplete in lightweight inspect; showing partial output");
                }
                basefwx::cli::PrintInspectInfo(lp->info);
                return 0;
            }
            auto unknown = basefwx::cli::AnalyzeUnknownFile(input_path);
            if (unknown.has_value()) {
                basefwx::cli::PrintUnknownInfo(*unknown);
                return 0;
            }
            throw std::runtime_error("Unsupported BaseFWX container or unreadable file");
        }
        if (command == "identify" || command == "probe") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::filesystem::path input_path(argv[2]);
            auto lp = basefwx::cli::InspectLengthPrefixedFile(input_path);
            if (lp.has_value() && !basefwx::cli::MetadataNeedsFullFallback(lp->info)) {
                basefwx::cli::PrintIdentifyLengthPrefixed(input_path.string(), *lp);
                return 0;
            }
            auto fwx = basefwx::cli::ParseFwxAesHeader(input_path);
            if (fwx.has_value()) {
                basefwx::cli::PrintIdentifyFwxAes(input_path.string(), *fwx);
                return 0;
            }
            auto kfm = basefwx::InspectKfmCarrierFile(input_path.string());
            if (kfm.has_value()) {
                basefwx::cli::PrintIdentifyKfmCarrier(input_path.string(), *kfm);
                return 0;
            }
            std::string fallback_reason;
            auto full = basefwx::cli::TryReadFullInspectSafe(input_path, &fallback_reason);
            if (full.has_value()) {
                try {
                    auto full_info = basefwx::InspectBlob(*full);
                    basefwx::cli::LightweightInspect inspect;
                    inspect.file_size = static_cast<std::uint64_t>(full->size());
                    inspect.info = std::move(full_info);
                    basefwx::cli::PrintIdentifyLengthPrefixed(input_path.string(), inspect);
                    return 0;
                } catch (const std::exception&) {
                    // Continue with lightweight output or error.
                }
            } else {
                basefwx::cli::MaybeWarnInspectFallback(fallback_reason);
            }
            if (lp.has_value()) {
                if (basefwx::cli::MetadataNeedsFullFallback(lp->info)) {
                    basefwx::cli::MaybeWarnInspectFallback("metadata was incomplete in lightweight inspect; showing partial output");
                }
                basefwx::cli::PrintIdentifyLengthPrefixed(input_path.string(), *lp);
                return 0;
            }
            auto unknown = basefwx::cli::AnalyzeUnknownFile(input_path);
            if (unknown.has_value()) {
                basefwx::cli::PrintIdentifyUnknown(input_path.string(), *unknown);
                return 0;
            }
            throw std::runtime_error("Unsupported BaseFWX container or unreadable file");
        }
        if (command == "an7" || command == "dean7") {
            basefwx::cli::An7Args parsed = basefwx::cli::ParseAn7Args(argc, argv, 2, command == "an7");
            basefwx::cli::ResolveCliPassword(parsed.password, parsed.password_provided, true, command == "an7");
            basefwx::runtime::ResetStop();
            InstallStopHandlers();
            if (command == "an7") {
                basefwx::RequireStrongPasswordForEncryption(
                    basefwx::ResolvePassword(parsed.password),
                    "an7"
                );
                basefwx::An7Options an7_opts;
                an7_opts.keep_input = parsed.keep_input;
                an7_opts.force_any = parsed.force_any;
                if (!parsed.output.empty()) {
                    an7_opts.out = std::filesystem::path(parsed.output);
                }
                basefwx::an7_file(std::filesystem::path(parsed.input), parsed.password, an7_opts);
                std::cout << "an7 completed\n";
            } else {
                basefwx::Dean7Options dean_opts;
                dean_opts.keep_input = parsed.keep_input;
                if (!parsed.output.empty()) {
                    dean_opts.out = std::filesystem::path(parsed.output);
                }
                basefwx::Dean7Result result =
                    basefwx::dean7_file(std::filesystem::path(parsed.input), parsed.password, dean_opts);
                std::cout << result.output_path.string() << "\n";
            }
            return 0;
        }
        if (command == "bench-text") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string method = basefwx::cli::ToLower(argv[2]);
            basefwx::cli::ParsedOptions opts = basefwx::cli::ParseCodecArgs(argc, argv, 3);
            std::string text = ReadTextFile(opts.input);
            if (method == "b512" || method == "pb512") {
                basefwx::cli::ResolveCliPassword(opts.password, opts.password_provided, !opts.use_master, true);
            }
            int warmup = basefwx::cli::BenchWarmup();
            int iters = basefwx::cli::BenchIters();
            std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            basefwx::cli::ConfirmSingleThreadCli(workers);
            std::function<std::size_t()> op;
            if (method == "b64") {
                op = [&]() {
                    std::string enc = basefwx::B64Encode(text);
                    std::string dec = basefwx::B64Decode(enc);
                    basefwx::cli::g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "b256") {
                op = [&]() {
                    // b256 is retired since 3.7.0; the CLI still dispatches it
                    // so existing scripts / blobs keep working. Suppress the
                    // deprecation warning here only — user-written code that
                    // calls basefwx::B256Encode will still see it.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
                    std::string enc = basefwx::B256Encode(text);
                    std::string dec = basefwx::B256Decode(enc);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
                    basefwx::cli::g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "a512") {
                op = [&]() {
                    std::string enc = basefwx::A512Encode(text);
                    std::string dec = basefwx::A512Decode(enc);
                    basefwx::cli::g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "n10") {
                op = [&]() {
                    std::string enc = basefwx::N10Encode(text);
                    std::string dec = basefwx::N10Decode(enc);
                    basefwx::cli::g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "b512") {
                op = [&]() {
                    std::string enc = basefwx::B512Encode(text, opts.password, opts.use_master, opts.kdf);
                    std::string dec = basefwx::B512Decode(enc, opts.password, opts.use_master, opts.kdf);
                    basefwx::cli::g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "pb512") {
                op = [&]() {
                    std::string enc = basefwx::Pb512Encode(text, opts.password, opts.use_master, opts.kdf);
                    std::string dec = basefwx::Pb512Decode(enc, opts.password, opts.use_master, opts.kdf);
                    basefwx::cli::g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else {
                throw std::runtime_error("Unsupported benchmark method: " + method);
            }
            auto run = [&]() {
                if (workers > 1) {
                    basefwx::cli::RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = basefwx::cli::BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-hash") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string method = basefwx::cli::ToLower(argv[2]);
            std::string text = ReadTextFile(argv[3]);
            int warmup = basefwx::cli::BenchWarmup();
            int iters = basefwx::cli::BenchIters();
            std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            basefwx::cli::ConfirmSingleThreadCli(workers);
            std::function<std::size_t()> op;
            if (method == "hash512") {
                op = [&]() {
                    std::string digest = basefwx::Hash512(text);
                    basefwx::cli::g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "uhash513") {
                op = [&]() {
                    // uhash513 deprecated in 3.7.0; suppress the
                    // compile-time warning at the CLI bench dispatch
                    // only — user code calling basefwx::Uhash513 still
                    // sees it.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
                    std::string digest = basefwx::Uhash513(text);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
                    basefwx::cli::g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "bi512") {
                op = [&]() {
                    std::string digest = basefwx::Bi512Encode(text);
                    basefwx::cli::g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else {
                // b1024 was a Bi512(A512(...)) alias — retired in 3.7.0.
                // Chain the primitives in your own code if you need that
                // composition.
                throw std::runtime_error("Unsupported hash benchmark method: " + method);
            }
            auto run = [&]() {
                if (workers > 1) {
                    basefwx::cli::RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = basefwx::cli::BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-fwxaes") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            basefwx::fwxaes::Options opts;
            opts.use_master = use_master;
            int warmup = basefwx::cli::BenchWarmup();
            int iters = basefwx::cli::BenchIters();
            auto run = [&]() {
                auto blob = basefwx::fwxaes::EncryptRaw(data, password, opts);
                auto plain = basefwx::fwxaes::DecryptRaw(blob, password, use_master);
                basefwx::cli::g_bench_sink.fetch_xor(plain.size(), std::memory_order_relaxed);
            };
            auto ns = basefwx::cli::BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-fwxaes-par") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            int warmup = basefwx::cli::BenchWarmup();
            int iters = basefwx::cli::BenchIters();
            std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            basefwx::cli::ConfirmSingleThreadCli(workers);
            for (int i = 0; i < warmup; ++i) {
                basefwx::cli::RunFwxaesParallel(data, password, use_master, workers);
            }
            std::vector<long long> samples;
            samples.reserve(static_cast<std::size_t>(iters));
            std::size_t bytes_per_run = 0;
            for (int i = 0; i < iters; ++i) {
                auto start = std::chrono::steady_clock::now();
                bytes_per_run = basefwx::cli::RunFwxaesParallel(data, password, use_master, workers);
                auto end = std::chrono::steady_clock::now();
                samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
            }
            auto median = basefwx::cli::MedianNs(samples);
            std::cout << "BENCH_NS=" << median << "\n";
            if (median > 0 && bytes_per_run > 0) {
                double seconds = static_cast<double>(median) / 1'000'000'000.0;
                double gib = static_cast<double>(bytes_per_run) / static_cast<double>(1ULL << 30);
                double throughput = gib / seconds;
                std::ostringstream out;
                out.setf(std::ios::fixed);
                out << std::setprecision(3) << throughput;
                std::cout << "THROUGHPUT_GiBps=" << out.str() << " WORKERS=" << workers << "\n";
            }
            return 0;
        }
        if (command == "bench-an7" || command == "bench-dean7") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::filesystem::path src_path(argv[2]);
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            if (!std::filesystem::exists(src_path)) {
                throw std::runtime_error("Failed to open file: " + src_path.string());
            }
            std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            basefwx::cli::ConfirmSingleThreadCli(workers);
            int warmup = basefwx::cli::BenchWarmup();
            int iters = basefwx::cli::BenchIters();

            auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            std::vector<std::filesystem::path> worker_dirs;
            std::vector<std::filesystem::path> seed_fwx;
            std::vector<std::filesystem::path> seed_an7;
            worker_dirs.reserve(workers);
            seed_fwx.reserve(workers);
            seed_an7.reserve(workers);

            basefwx::fwxaes::Options fwx_opts;
            fwx_opts.use_master = use_master;
            for (std::size_t i = 0; i < workers; ++i) {
                std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                    / ("basefwx-bench-an7-" + stamp + "-" + std::to_string(i));
                std::filesystem::create_directories(temp_dir);
                worker_dirs.push_back(temp_dir);

                std::filesystem::path worker_input = temp_dir / src_path.filename();
                std::filesystem::copy_file(src_path, worker_input, std::filesystem::copy_options::overwrite_existing);

                std::filesystem::path worker_fwx = temp_dir / ("seed_" + std::to_string(i) + ".fwx");
                basefwx::fwxaes::EncryptFile(
                    worker_input.string(),
                    worker_fwx.string(),
                    password,
                    fwx_opts,
                    {},
                    {},
                    true
                );
                std::error_code remove_ec;
                std::filesystem::remove(worker_input, remove_ec);
                seed_fwx.push_back(worker_fwx);

                std::filesystem::path worker_an7 = temp_dir / ("seed_" + std::to_string(i) + ".an7");
                basefwx::An7Options an7_seed_opts;
                an7_seed_opts.keep_input = true;
                an7_seed_opts.out = worker_an7;
                basefwx::an7_file(worker_fwx, password, an7_seed_opts);
                seed_an7.push_back(worker_an7);
            }

            auto run_an7_once = [&](std::size_t idx) -> std::size_t {
                const auto& temp_dir = worker_dirs[idx];
                std::filesystem::path out_path = temp_dir / ("bench_an7_" + std::to_string(idx) + ".out");
                std::error_code cleanup_ec;
                std::filesystem::remove(out_path, cleanup_ec);
                basefwx::An7Options an7_opts;
                an7_opts.keep_input = true;
                an7_opts.out = out_path;
                basefwx::an7_file(seed_fwx[idx], password, an7_opts);
                std::error_code size_ec;
                auto out_size = std::filesystem::file_size(out_path, size_ec);
                std::filesystem::remove(out_path, cleanup_ec);
                if (!size_ec) {
                    basefwx::cli::g_bench_sink.fetch_xor(static_cast<std::size_t>(out_size), std::memory_order_relaxed);
                    return static_cast<std::size_t>(out_size);
                }
                return 0;
            };

            auto run_dean7_once = [&](std::size_t idx) -> std::size_t {
                const auto& temp_dir = worker_dirs[idx];
                std::filesystem::path out_path = temp_dir / ("bench_dean7_" + std::to_string(idx) + ".out");
                std::error_code cleanup_ec;
                std::filesystem::remove(out_path, cleanup_ec);
                basefwx::Dean7Options dean_opts;
                dean_opts.keep_input = true;
                dean_opts.out = out_path;
                basefwx::Dean7Result result = basefwx::dean7_file(seed_an7[idx], password, dean_opts);
                std::error_code size_ec;
                auto out_size = std::filesystem::file_size(result.output_path, size_ec);
                std::filesystem::remove(result.output_path, cleanup_ec);
                if (!size_ec) {
                    basefwx::cli::g_bench_sink.fetch_xor(static_cast<std::size_t>(out_size), std::memory_order_relaxed);
                    return static_cast<std::size_t>(out_size);
                }
                return 0;
            };

            auto run = [&]() {
                if (workers > 1) {
                    if (command == "bench-an7") {
                        basefwx::cli::RunParallel(workers, run_an7_once);
                    } else {
                        basefwx::cli::RunParallel(workers, run_dean7_once);
                    }
                    return;
                }
                if (command == "bench-an7") {
                    run_an7_once(0);
                } else {
                    run_dean7_once(0);
                }
            };

            long long ns = 0;
            try {
                ns = basefwx::cli::BenchMedian(warmup, iters, run);
            } catch (...) {
                for (const auto& dir : worker_dirs) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
                throw;
            }
            std::cout << "BENCH_NS=" << ns << "\n";
            for (const auto& dir : worker_dirs) {
                std::error_code ec;
                std::filesystem::remove_all(dir, ec);
            }
            return 0;
        }
        if (command == "bench-live") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            std::string payload(reinterpret_cast<const char*>(data.data()), data.size());
            int warmup = basefwx::cli::BenchWarmup();
            int iters = basefwx::cli::BenchIters();
            std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            basefwx::cli::ConfirmSingleThreadCli(workers);
            auto op = [&]() -> std::size_t {
                std::istringstream source(payload, std::ios::in | std::ios::binary);
                std::ostringstream encrypted(std::ios::out | std::ios::binary);
                basefwx::FwxAesLiveEncryptStream(source, encrypted, password, use_master);
                std::string enc_blob = encrypted.str();
                std::istringstream enc_in(enc_blob, std::ios::in | std::ios::binary);
                std::ostringstream restored(std::ios::out | std::ios::binary);
                basefwx::FwxAesLiveDecryptStream(enc_in, restored, password, use_master);
                std::size_t len = restored.str().size();
                basefwx::cli::g_bench_sink.fetch_xor(len, std::memory_order_relaxed);
                return len;
            };
            auto run = [&]() {
                if (workers > 1) {
                    basefwx::cli::RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = basefwx::cli::BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-b512file" || command == "bench-pb512file") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            bool disable_aead = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else if (flag == "--no-aead") {
                    disable_aead = true;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            basefwx::filecodec::FileOptions file_opts;
            file_opts.use_master = use_master;
            file_opts.enable_aead = !disable_aead;
            file_opts.keep_input = true;
            try {
                std::filesystem::path src_path(input);
                std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
                if (workers == 0) {
                    workers = 1;
                }
                basefwx::cli::ConfirmSingleThreadCli(workers);
                std::vector<std::filesystem::path> temp_dirs;
                std::vector<std::filesystem::path> bench_inputs;
                temp_dirs.reserve(workers);
                bench_inputs.reserve(workers);
                auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
                for (std::size_t i = 0; i < workers; ++i) {
                    std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                        / ("basefwx-bench-" + stamp + "-" + std::to_string(i));
                    std::filesystem::create_directories(temp_dir);
                    std::filesystem::path bench_input = temp_dir / src_path.filename();
                    std::filesystem::copy_file(src_path, bench_input, std::filesystem::copy_options::overwrite_existing);
                    temp_dirs.push_back(temp_dir);
                    bench_inputs.push_back(bench_input);
                }

                int warmup = basefwx::cli::BenchWarmup();
                int iters = basefwx::cli::BenchIters();
                auto run_once = [&](std::size_t idx) -> std::size_t {
                    const auto& bench_input = bench_inputs[idx];
                    std::filesystem::path enc_path;
                    std::filesystem::path dec_path;
                    if (command == "bench-b512file") {
                        enc_path = basefwx::filecodec::B512EncodeFile(bench_input.string(), password, file_opts);
                        dec_path = basefwx::filecodec::B512DecodeFile(enc_path.string(), password, file_opts);
                    } else {
                        enc_path = basefwx::filecodec::Pb512EncodeFile(bench_input.string(), password, file_opts);
                        dec_path = basefwx::filecodec::Pb512DecodeFile(enc_path.string(), password, file_opts);
                    }
                    std::error_code size_ec;
                    auto dec_size = std::filesystem::file_size(dec_path, size_ec);
                    std::error_code cleanup_ec;
                    if (!enc_path.empty()) {
                        std::filesystem::remove(enc_path, cleanup_ec);
                    }
                    if (!dec_path.empty() && dec_path != bench_input) {
                        std::filesystem::remove(dec_path, cleanup_ec);
                    }
                    if (!size_ec) {
                        basefwx::cli::g_bench_sink.fetch_xor(static_cast<std::size_t>(dec_size), std::memory_order_relaxed);
                        return static_cast<std::size_t>(dec_size);
                    }
                    return 0;
                };
                auto run = [&]() {
                    if (workers > 1) {
                        basefwx::cli::RunParallel(workers, run_once);
                        return;
                    }
                    run_once(0);
                };

                long long ns = basefwx::cli::BenchMedian(warmup, iters, run);
                std::cout << "BENCH_NS=" << ns << "\n";
                for (const auto& dir : temp_dirs) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
                return 0;
            } catch (const std::exception& exc) {
                throw;
            }
        }
        if (command == "bench-jmg") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string media_path = argv[2];
            std::string password = argv[3];
            bool use_master = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &use_master)) {
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            try {
                std::filesystem::path src_path(media_path);
                if (!std::filesystem::exists(src_path)) {
                    throw std::runtime_error("Media file not found: " + media_path);
                }
                std::size_t workers = static_cast<std::size_t>(basefwx::cli::BenchWorkers());
                if (workers == 0) {
                    workers = 1;
                }
                basefwx::cli::ConfirmSingleThreadCli(workers);
                std::vector<std::filesystem::path> temp_dirs;
                auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
                for (std::size_t i = 0; i < workers; ++i) {
                    std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                        / ("basefwx-bench-jmg-" + stamp + "-" + std::to_string(i));
                    std::filesystem::create_directories(temp_dir);
                    temp_dirs.push_back(temp_dir);
                }

                int warmup = basefwx::cli::BenchWarmup();
                int iters = basefwx::cli::BenchIters();
                auto run_once = [&](std::size_t idx) -> std::size_t {
                    const auto& temp_dir = temp_dirs[idx];
                    std::string enc_name = "bench_enc_" + std::to_string(idx) + src_path.extension().string();
                    std::string dec_name = "bench_dec_" + std::to_string(idx) + src_path.extension().string();
                    std::filesystem::path enc_path = temp_dir / enc_name;
                    std::filesystem::path dec_path = temp_dir / dec_name;
                    
                    basefwx::Jmge(src_path.string(), password, enc_path.string(), false, true, true, use_master);
                    basefwx::Jmgd(enc_path.string(), password, dec_path.string(), use_master);
                    
                    std::error_code size_ec;
                    auto dec_size = std::filesystem::file_size(dec_path, size_ec);
                    std::error_code cleanup_ec;
                    if (!enc_path.empty()) {
                        std::filesystem::remove(enc_path, cleanup_ec);
                    }
                    if (!dec_path.empty()) {
                        std::filesystem::remove(dec_path, cleanup_ec);
                    }
                    if (!size_ec) {
                        basefwx::cli::g_bench_sink.fetch_xor(static_cast<std::size_t>(dec_size), std::memory_order_relaxed);
                        return static_cast<std::size_t>(dec_size);
                    }
                    return 0;
                };
                auto run = [&]() {
                    if (workers > 1) {
                        basefwx::cli::RunParallel(workers, run_once);
                        return;
                    }
                    run_once(0);
                };

                long long ns = basefwx::cli::BenchMedian(warmup, iters, run);
                std::cout << "BENCH_NS=" << ns << "\n";
                for (const auto& dir : temp_dirs) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
                return 0;
            } catch (const std::exception& exc) {
                throw;
            }
        }
        if (command == "b64-enc") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::B64Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b64-dec") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::B64Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10-enc") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::N10Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10-dec") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::N10Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10file-enc") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            auto bytes = ReadBinaryFile(argv[2]);
            std::string input(bytes.begin(), bytes.end());
            WriteTextFile(argv[3], basefwx::N10Encode(input));
            return 0;
        }
        if (command == "n10file-dec") {
            if (argc < 4) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string digits = basefwx::cli::StripAsciiWhitespace(ReadTextFile(argv[2]));
            WriteBinaryFile(argv[3], basefwx::N10Decode(digits));
            return 0;
        }
        if (command == "kFMe" || command == "kFMd" || command == "kFAe" || command == "kFAd") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string output;
            bool bw_mode = false;
            for (int idx = 3; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--out" || flag == "-o") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing value for --out");
                    }
                    output = argv[++idx];
                } else if (flag == "--bw") {
                    bw_mode = true;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }

            std::string out_path;
            if (command == "kFMe") {
                out_path = basefwx::Kfme(input, output, bw_mode);
            } else if (command == "kFMd") {
                out_path = basefwx::Kfmd(input, output, bw_mode);
            } else if (command == "kFAe") {
                out_path = basefwx::Kfae(input, output, bw_mode);
            } else {
                out_path = basefwx::Kfad(input, output);
            }
            std::cout << out_path << "\n";
            return 0;
        }
        if (command == "hash512") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::Hash512(argv[2]) << "\n";
            return 0;
        }
        // uhash513 deprecated in 3.7.0 — CLI keeps dispatching for
        // backwards compat. Suppress the [[deprecated]] warning at
        // this internal site only; user code still sees it.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        if (command == "uhash513") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::Uhash513(argv[2]) << "\n";
            return 0;
        }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
        if (command == "a512-enc") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::A512Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "a512-dec") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::A512Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "bi512-enc") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::Bi512Encode(argv[2]) << "\n";
            return 0;
        }
        // b1024-enc retired in 3.7.0; was an alias for `bi512-enc $(a512-enc text)`.
        // b256 is retired since 3.7.0 — see basefwx.hpp / CHANGELOG.
        // The CLI keeps dispatching it so existing scripts keep working;
        // the runtime warning emits from inside the function. Suppress
        // the [[deprecated]] compile-time warning only at these two CLI
        // dispatch sites — user code calling basefwx::B256Encode still
        // sees it.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        if (command == "b256-enc") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b256-dec") {
            if (argc < 3) {
                basefwx::cli::PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Decode(argv[2]) << "\n";
            return 0;
        }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
        if (command == "b512-enc" || command == "b512-dec" || command == "pb512-enc" || command == "pb512-dec") {
            basefwx::cli::ParsedOptions opts = basefwx::cli::ParseCodecArgs(argc, argv, 2);
            basefwx::cli::ResolveCliPassword(
                opts.password,
                opts.password_provided,
                !opts.use_master,
                command == "b512-enc" || command == "pb512-enc"
            );
            if (command == "b512-enc") {
                std::cout << basefwx::B512Encode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "b512-dec") {
                std::cout << basefwx::B512Decode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "pb512-enc") {
                std::cout << basefwx::Pb512Encode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "pb512-dec") {
                std::cout << basefwx::Pb512Decode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "b512file-enc" || command == "b512file-dec"
            || command == "pb512file-enc" || command == "pb512file-dec"
            || command == "b512file-bytes-rt" || command == "pb512file-bytes-rt") {
            if (command == "b512file-bytes-rt" || command == "pb512file-bytes-rt") {
                if (argc < 4) {
                    basefwx::cli::PrintUsage();
                    return 2;
                }
                std::string input = argv[2];
                std::string output = argv[3];
                basefwx::cli::FileArgs opts;
                opts.input = input;
                int idx = 4;
                while (idx < argc) {
                    std::string flag(argv[idx]);
                    if (flag == "-p" || flag == "--password") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing password value");
                        }
                        opts.password = argv[idx + 1];
                        opts.password_provided = true;
                        idx += 2;
                    } else if (basefwx::cli::HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
                        idx += 1;
                    } else if (flag == "--strip-meta") {
                        opts.strip_metadata = true;
                        idx += 1;
                    } else if (flag == "--no-aead") {
                        if (command == "b512file-bytes-rt") {
                            opts.enable_aead = false;
                            idx += 1;
                        } else {
                            throw std::runtime_error("Unsupported flag for pb512file-bytes-rt: " + flag);
                        }
                    } else if (flag == "--kdf") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing kdf label");
                        }
                        opts.kdf.label = argv[idx + 1];
                        idx += 2;
                    } else if (flag == "--pbkdf2-iters") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing pbkdf2 iteration count");
                        }
                        opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
                        idx += 2;
                    } else if (flag == "--no-fallback") {
                        opts.kdf.allow_pbkdf2_fallback = false;
                        idx += 1;
                    } else {
                        throw std::runtime_error("Unknown flag: " + flag);
                    }
                }
                basefwx::filecodec::FileOptions file_opts;
                file_opts.strip_metadata = opts.strip_metadata;
                file_opts.use_master = opts.use_master;
                file_opts.enable_aead = opts.enable_aead;
                std::filesystem::path input_path(input);
                auto data = basefwx::ReadFile(input_path.string());
                std::string ext = input_path.extension().string();
                basefwx::cli::ResolveCliPassword(
                    opts.password,
                    opts.password_provided,
                    !opts.use_master,
                    true
                );
                basefwx::RequireStrongPasswordForEncryption(
                    basefwx::ResolvePassword(opts.password),
                    command == "pb512file-bytes-rt" ? "fwxAES-heavy" : "b512file"
                );
                basefwx::filecodec::DecodedBytes decoded;
                if (command == "b512file-bytes-rt") {
                    auto blob = basefwx::filecodec::B512EncodeBytes(data, ext, opts.password, file_opts, opts.kdf);
                    decoded = basefwx::filecodec::B512DecodeBytes(blob, opts.password, file_opts, opts.kdf);
                } else {
                    auto blob = basefwx::filecodec::Pb512EncodeBytes(data, ext, opts.password, file_opts, opts.kdf);
                    decoded = basefwx::filecodec::Pb512DecodeBytes(blob, opts.password, file_opts, opts.kdf);
                }
                std::ofstream out(output, std::ios::binary);
                if (!out) {
                    throw std::runtime_error("Failed to open output file: " + output);
                }
                if (!decoded.data.empty()) {
                    out.write(reinterpret_cast<const char*>(decoded.data.data()),
                              static_cast<std::streamsize>(decoded.data.size()));
                }
                return 0;
            }
            basefwx::cli::FileArgs opts = basefwx::cli::ParseFileArgs(argc, argv, 2);
            basefwx::filecodec::FileOptions file_opts;
            file_opts.strip_metadata = opts.strip_metadata;
            file_opts.use_master = opts.use_master;
            file_opts.enable_aead = opts.enable_aead;
            file_opts.enable_obfuscation = opts.enable_obf;
            file_opts.compress = opts.compress;
            file_opts.keep_input = opts.keep_input;
            basefwx::cli::ResolveCliPassword(
                opts.password,
                opts.password_provided,
                !opts.use_master,
                command == "b512file-enc" || command == "pb512file-enc"
            );
            if (command == "b512file-enc") {
                basefwx::RequireStrongPasswordForEncryption(basefwx::ResolvePassword(opts.password), "b512file");
                std::cout << basefwx::filecodec::B512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "b512file-dec") {
                std::cout << basefwx::filecodec::B512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-enc") {
                basefwx::RequireStrongPasswordForEncryption(basefwx::ResolvePassword(opts.password), "fwxAES-heavy");
                std::cout << basefwx::filecodec::Pb512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-dec") {
                std::cout << basefwx::filecodec::Pb512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "fwxaes-enc" || command == "fwxaes-dec"
            || command == "fwxaes-heavy-enc" || command == "fwxaes-heavy-dec"
            || command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec"
            || command == "fwxaes-live-enc" || command == "fwxaes-live-dec") {
            basefwx::cli::FwxAesArgs opts = basefwx::cli::ParseFwxAesArgs(argc, argv, 2);
            if (command == "fwxaes-heavy-enc" || command == "fwxaes-heavy-dec") {
                opts.heavy = true;
            }
            const bool is_encrypt_command =
                command == "fwxaes-enc"
                || command == "fwxaes-heavy-enc"
                || command == "fwxaes-stream-enc"
                || command == "fwxaes-live-enc";
            bool user_output = !opts.output.empty();
            basefwx::cli::ResolveCliPassword(opts.password, opts.password_provided, !opts.use_master, is_encrypt_command);
            if (opts.output.empty()) {
                if (command == "fwxaes-enc" || command == "fwxaes-heavy-enc") {
                    if (opts.heavy) {
                        std::filesystem::path out_path(opts.input);
                        out_path.replace_extension(".fwx");
                        opts.output = out_path.string();
                    } else if (!opts.ignore_media && LooksLikeMediaPath(std::filesystem::path(opts.input))) {
                        opts.output = opts.input;
                    } else {
                        opts.output = opts.input + ".fwx";
                    }
                } else if (command == "fwxaes-live-enc") {
                    opts.output = (opts.input == "-") ? "-" : (opts.input + ".live.fwx");
                } else if (command == "fwxaes-live-dec" && opts.input == "-") {
                    opts.output = "-";
                } else if (opts.input.size() >= 4 && opts.input.rfind(".fwx") == opts.input.size() - 4) {
                    opts.output = opts.input.substr(0, opts.input.size() - 4);
                } else {
                    opts.output = opts.input + ".out";
                }
            }
            if (telemetry) {
                std::string progress_output = opts.output;
                bool is_decode = (command == "fwxaes-dec" || command == "fwxaes-heavy-dec");
                if (is_decode && opts.heavy) {
                    progress_output = opts.input + ".plain.tmp";
                }
                telemetry->ConfigureFileProgress(opts.input, progress_output);
            }
            auto complete_progress = [&telemetry]() {
                if (telemetry) {
                    telemetry->MarkProgressComplete();
                }
            };
            if (command == "fwxaes-live-enc" || command == "fwxaes-live-dec") {
                if (opts.heavy) {
                    throw std::runtime_error("Live fwxAES does not support heavy mode");
                }
                if (opts.normalize || opts.compress) {
                    throw std::runtime_error("Live fwxAES does not support normalize or pack options");
                }

                std::ifstream input_file;
                std::istream* input = nullptr;
                bool use_stdin = (opts.input == "-");
                if (use_stdin) {
                    input = &std::cin;
                } else {
                    input_file.open(opts.input, std::ios::binary);
                    if (!input_file) {
                        throw std::runtime_error("Failed to open input file: " + opts.input);
                    }
                    input = &input_file;
                }

                std::ofstream output_file;
                std::ostream* output = nullptr;
                bool use_stdout = (opts.output == "-");
                if (use_stdout) {
                    output = &std::cout;
                } else {
                    output_file.open(opts.output, std::ios::binary);
                    if (!output_file) {
                        throw std::runtime_error("Failed to open output file: " + opts.output);
                    }
                    output = &output_file;
                }
                EnableBinaryStdio(use_stdin, use_stdout);
                if (command == "fwxaes-live-enc") {
                    basefwx::FwxAesLiveEncryptStream(*input, *output, opts.password, opts.use_master);
                } else {
                    basefwx::FwxAesLiveDecryptStream(*input, *output, opts.password, opts.use_master);
                }
                complete_progress();
                return 0;
            }
            if (command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec") {
                if (opts.heavy) {
                    throw std::runtime_error("Streaming fwxAES does not support heavy mode");
                }
                if (opts.normalize || opts.compress) {
                    throw std::runtime_error("Streaming fwxAES does not support normalize or pack options");
                }
                std::ifstream input(opts.input, std::ios::binary);
                if (!input) {
                    throw std::runtime_error("Failed to open input file: " + opts.input);
                }
                std::ofstream output(opts.output, std::ios::binary);
                if (!output) {
                    throw std::runtime_error("Failed to open output file: " + opts.output);
                }
                basefwx::fwxaes::Options stream_opts;
                stream_opts.use_master = opts.use_master;
                stream_opts.user_kdf = opts.kdf;
                stream_opts.force_legacy_pbkdf2 = opts.force_legacy_pbkdf2;
                if (command == "fwxaes-stream-enc") {
                    basefwx::RequireStrongPasswordForEncryption(basefwx::ResolvePassword(opts.password), "fwxAES stream");
                    basefwx::fwxaes::EncryptStream(input, output, opts.password, stream_opts);
                } else {
                    basefwx::fwxaes::DecryptStream(input, output, opts.password, opts.use_master);
                }
                complete_progress();
                return 0;
            }
            if (opts.heavy) {
                bool is_decode = (command == "fwxaes-dec" || command == "fwxaes-heavy-dec");
                if (is_decode) {
                    basefwx::runtime::ResetStop();
                    InstallStopHandlers();
                }
                if (opts.normalize) {
                    throw std::runtime_error("fwxAES heavy mode does not support normalize options");
                }
                if (opts.threshold != 8 * 1024 || opts.cover_phrase != "low taper fade") {
                    throw std::runtime_error("fwxAES heavy mode does not support normalize options");
                }
                if (opts.ignore_media || opts.keep_meta || opts.archive_original) {
                    throw std::runtime_error("fwxAES heavy mode does not support media-only options");
                }
                basefwx::filecodec::FileOptions file_opts;
                file_opts.use_master = opts.use_master;
                file_opts.compress = opts.compress;
                file_opts.keep_input = opts.keep_input;
                if (command == "fwxaes-enc" || command == "fwxaes-heavy-enc") {
                    std::string produced = basefwx::filecodec::Pb512EncodeFile(opts.input, opts.password, file_opts, opts.kdf);
                    std::string final_output = produced;
                    if (user_output) {
                        final_output = MoveOutputPath(produced, opts.output);
                    }
                    if (telemetry) {
                        telemetry->MarkProgressComplete();
                        telemetry.reset();
                    }
                    std::cout << final_output << "\n";
                } else {
                    std::string produced = basefwx::filecodec::Pb512DecodeFile(opts.input, opts.password, file_opts, opts.kdf);
                    std::string final_output = produced;
                    if (user_output) {
                        final_output = MoveOutputPath(produced, opts.output);
                    }
                    if (telemetry) {
                        telemetry->MarkProgressComplete();
                        telemetry.reset();
                    }
                    std::cout << final_output << "\n";
                }
            } else if (command == "fwxaes-enc" || command == "fwxaes-heavy-enc") {
                basefwx::RequireStrongPasswordForEncryption(
                    basefwx::ResolvePassword(opts.password),
                    opts.heavy ? "fwxAES-heavy" : "fwxAES"
                );
                if (!opts.ignore_media && LooksLikeMediaPath(std::filesystem::path(opts.input))) {
                    try {
                        std::string media_output = basefwx::Jmge(
                            opts.input,
                            opts.password,
                            opts.output,
                            opts.keep_meta,
                            opts.keep_input,
                            opts.archive_original,
                            opts.use_master
                        );
                        if (telemetry) {
                            telemetry->MarkProgressComplete();
                            telemetry.reset();
                        }
                        std::cout << media_output << "\n";
                        return 0;
                    } catch (const std::exception&) {
                        // Fall back to standard fwxAES if media processing fails.
                    }
                }
                basefwx::fwxaes::NormalizeOptions norm;
                norm.enabled = opts.normalize;
                norm.threshold = opts.threshold;
                norm.cover_phrase = opts.cover_phrase;
                basefwx::fwxaes::PackOptions pack_opts;
                pack_opts.compress = opts.compress;
                basefwx::fwxaes::Options fwxaes_opts;
                fwxaes_opts.use_master = opts.use_master;
                fwxaes_opts.user_kdf = opts.kdf;
                fwxaes_opts.force_legacy_pbkdf2 = opts.force_legacy_pbkdf2;
                basefwx::fwxaes::EncryptFile(opts.input, opts.output, opts.password, fwxaes_opts, norm, pack_opts, opts.keep_input);
            } else {
                basefwx::fwxaes::DecryptFile(opts.input, opts.output, opts.password, opts.use_master);
            }
            complete_progress();
            return 0;
        }
        if (command == "jmge" || command == "jmgd") {
            basefwx::cli::ImageArgs opts = basefwx::cli::ParseImageArgs(argc, argv, 2);
            basefwx::cli::ResolveCliPassword(opts.password, opts.password_provided, !opts.use_master, command == "jmge");
            if (command == "jmge") {
                std::cout << basefwx::Jmge(
                    opts.input,
                    opts.password,
                    opts.output,
                    opts.keep_meta,
                    opts.keep_input,
                    opts.archive_original,
                    opts.use_master
                ) << "\n";
            } else {
                std::cout << basefwx::Jmgd(opts.input, opts.password, opts.output, opts.use_master) << "\n";
            }
            return 0;
        }
        basefwx::cli::PrintUsage();
        return 2;
    } catch (const std::exception& exc) {
        if (std::string_view(exc.what()) == "Interrupted") {
            std::cerr << "Interrupted\n";
            return 130;
        }
        bool plain = basefwx::cli::CliPlain();
        const char* red = "\033[31m";
        std::string msg = basefwx::cli::EmojiPrefix("❌", plain) + "Error: " + exc.what();
        std::cerr << basefwx::cli::StyleText(msg, red, plain) << "\n";
        return 1;
    }
}
