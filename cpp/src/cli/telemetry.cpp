/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/cli/telemetry.hpp"

#include "basefwx/env.hpp"
#include "basefwx/system_info.hpp"

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

namespace basefwx::cli::detail {

namespace {

std::optional<std::uint32_t> ReadU32Be(std::ifstream& in) {
    std::array<std::uint8_t, 4> buf{};
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (in.gcount() != static_cast<std::streamsize>(buf.size())) {
        return std::nullopt;
    }
    std::uint32_t value = (static_cast<std::uint32_t>(buf[0]) << 24)
                        | (static_cast<std::uint32_t>(buf[1]) << 16)
                        | (static_cast<std::uint32_t>(buf[2]) << 8)
                        | static_cast<std::uint32_t>(buf[3]);
    return value;
}

}  // namespace

std::optional<std::uint64_t> EstimatePlainTmpTargetSize(const std::filesystem::path& input_path) {
    constexpr std::uint64_t kTagLen = 16;
    constexpr std::uint64_t kNonceLen = 12;
    std::ifstream in(input_path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    auto len_user = ReadU32Be(in);
    if (!len_user.has_value()) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(*len_user), std::ios::cur);
    auto len_master = ReadU32Be(in);
    if (!len_master.has_value()) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(*len_master), std::ios::cur);
    auto len_payload = ReadU32Be(in);
    if (!len_payload.has_value()) {
        return std::nullopt;
    }
    auto metadata_len = ReadU32Be(in);
    if (!metadata_len.has_value()) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(*metadata_len), std::ios::cur);
    in.seekg(static_cast<std::streamoff>(kNonceLen), std::ios::cur);
    std::streampos body_start_pos = in.tellg();
    if (body_start_pos < 0) {
        return std::nullopt;
    }

    std::error_code ec;
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(input_path, ec));
    if (ec) {
        return std::nullopt;
    }
    std::uint64_t body_start = static_cast<std::uint64_t>(body_start_pos);
    if (file_size < body_start + kTagLen) {
        return std::nullopt;
    }
    std::uint64_t body_len = file_size - body_start - kTagLen;

    std::uint64_t payload_len = 4ull
        + static_cast<std::uint64_t>(*metadata_len)
        + kNonceLen
        + body_len
        + kTagLen;
    if (payload_len != static_cast<std::uint64_t>(*len_payload)) {
        return std::nullopt;
    }
    return body_len;
}

std::string ReadCommandCapture(const std::string& cmd) {
#if defined(_WIN32)
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) {
        return {};
    }
    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }
#if defined(_WIN32)
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return output;
}

std::optional<double> ProbeCpuTempC() {
#if defined(__linux__)
    std::filesystem::path root("/sys/class/thermal");
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) {
        return std::nullopt;
    }
    double sum = 0.0;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_directory()) {
            continue;
        }
        auto temp_path = entry.path() / "temp";
        if (!std::filesystem::exists(temp_path, ec)) {
            continue;
        }
        std::ifstream in(temp_path);
        double raw = 0.0;
        if (!(in >> raw)) {
            continue;
        }
        if (raw > 1000.0) {
            raw /= 1000.0;
        }
        if (raw < 5.0 || raw > 130.0) {
            continue;
        }
        sum += raw;
        ++count;
    }
    if (count == 0) {
        return std::nullopt;
    }
    return sum / static_cast<double>(count);
#else
    return std::nullopt;
#endif
}

}  // namespace basefwx::cli::detail

namespace basefwx::cli {

void CommandTelemetry::EmitTelemetry() {
    auto mem = basefwx::system::DetectMemoryInfo();
    std::ostringstream line;
    line << "📊 [basefwx.stats]";

    auto cpu_pct = SampleCpuPercent();
    if (cpu_pct.has_value()) {
        line << " CPU " << std::fixed << std::setprecision(0) << *cpu_pct << "%";
    }
    if (mem.total_bytes > 0) {
        double ram_pct = (static_cast<double>(mem.used_bytes) * 100.0) / static_cast<double>(mem.total_bytes);
        line << " \\ RAM " << std::fixed << std::setprecision(0) << ram_pct << "%";
    }
    if (plan_.expect_gpu) {
        auto gpu = SampleGpuPercentTemp();
        if (gpu.first.has_value()) {
            line << " \\ GPU " << std::fixed << std::setprecision(0) << *gpu.first << "%";
        }
        if (gpu.second.has_value()) {
            line << " \\ " << std::fixed << std::setprecision(0) << *gpu.second << "C";
            EmitStatsLine(line.str());
            return;
        }
    }
    auto cpu_temp = detail::ProbeCpuTempC();
    if (cpu_temp.has_value()) {
        line << " \\ " << std::fixed << std::setprecision(0) << *cpu_temp << "C";
    }
    AppendProgress(line);
    EmitStatsLine(line.str());
}

void CommandTelemetry::AppendProgress(std::ostringstream& line) {
    std::filesystem::path in_path;
    std::filesystem::path out_path;
    std::uint64_t in_size = 0;
    bool is_temp_plain = false;
    bool progress_completed = false;
    {
        std::lock_guard<std::mutex> lock(progress_mu_);
        if (!progress_enabled_) {
            return;
        }
        in_path = progress_input_path_;
        out_path = progress_output_path_;
        in_size = progress_input_size_;
        is_temp_plain = progress_is_temp_plain_;
        progress_completed = progress_completed_;
    }
    if (in_size == 0 || out_path.empty()) {
        return;
    }
    std::uint64_t out_size = 0;
    bool phase_finalize = false;
    double pct = 0.0;
    if (progress_completed) {
        out_size = in_size;
        pct = 100.0;
    } else {
        std::error_code ec;
        if (!std::filesystem::exists(out_path, ec) || !std::filesystem::is_regular_file(out_path, ec)) {
            return;
        }
        out_size = static_cast<std::uint64_t>(std::filesystem::file_size(out_path, ec));
        if (ec) {
            return;
        }
        phase_finalize = is_temp_plain && out_size >= in_size;
        pct = (static_cast<double>(out_size) * 100.0) / static_cast<double>(in_size);
    }
    if (pct < 0.0) {
        pct = 0.0;
    }
    if (pct > 100.0) {
        pct = 100.0;
    }
    if (phase_finalize && !progress_completed) {
        pct = 99.9;
    }
    constexpr std::size_t kBarWidth = 24;
    std::size_t filled = static_cast<std::size_t>((pct * static_cast<double>(kBarWidth)) / 100.0);
    if (progress_completed || pct >= 99.95) {
        filled = kBarWidth;
    }
    if (filled > kBarWidth) {
        filled = kBarWidth;
    }

    auto now = std::chrono::steady_clock::now();
    std::optional<double> speed_bps;
    std::optional<std::uint64_t> eta_seconds;
    std::chrono::steady_clock::time_point last_growth_time = now;
    {
        std::lock_guard<std::mutex> lock(progress_mu_);
        if (!progress_completed && progress_sample_ready_) {
            double dt = std::chrono::duration<double>(now - progress_sample_time_).count();
            if (dt > 0.15 && out_size > progress_sample_size_) {
                double inst_bps = static_cast<double>(out_size - progress_sample_size_) / dt;
                if (inst_bps >= 0.0) {
                    if (progress_rate_bps_ <= 0.0) {
                        progress_rate_bps_ = inst_bps;
                    } else {
                        progress_rate_bps_ = (progress_rate_bps_ * 0.7) + (inst_bps * 0.3);
                    }
                }
                progress_last_growth_time_ = now;
            }
        }
        progress_sample_size_ = out_size;
        progress_sample_time_ = now;
        progress_sample_ready_ = true;
        last_growth_time = progress_last_growth_time_;
        if (!progress_completed && !phase_finalize && progress_rate_bps_ > 1.0) {
            speed_bps = progress_rate_bps_;
            if (out_size < in_size) {
                std::uint64_t remain = in_size - out_size;
                eta_seconds = static_cast<std::uint64_t>(remain / progress_rate_bps_);
            }
        }
    }

    line << " \\ ["
         << std::string(filled, '#')
         << std::string(kBarWidth - filled, '-')
         << "] "
         << std::fixed << std::setprecision(1) << pct << "%"
         << " " << basefwx::system::FormatBytes(out_size)
         << "/" << basefwx::system::FormatBytes(in_size);
    if (speed_bps.has_value()) {
        line << " " << basefwx::system::FormatBytes(static_cast<std::uint64_t>(*speed_bps)) << "/s";
    }
    if (eta_seconds.has_value()) {
        std::uint64_t total = *eta_seconds;
        std::uint64_t h = total / 3600;
        std::uint64_t m = (total % 3600) / 60;
        std::uint64_t s = total % 60;
        std::ostringstream eta;
        eta << std::setw(2) << std::setfill('0') << h
            << ":" << std::setw(2) << std::setfill('0') << m
            << ":" << std::setw(2) << std::setfill('0') << s;
        line << " ETA " << eta.str();
    }
    if (phase_finalize) {
        static constexpr std::array<char, 4> kSpin = {'|', '/', '-', '\\'};
        auto spin_tick = static_cast<std::size_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() / 1000);
        char spin = kSpin[spin_tick % kSpin.size()];
        double stall_s = std::chrono::duration<double>(now - last_growth_time).count();
        if (stall_s >= 0.8) {
            line << " phase2 " << spin << " deobf/unpack";
        } else {
            line << " phase1 " << spin;
        }
    }
}

std::pair<std::optional<double>, std::optional<double>> CommandTelemetry::SampleGpuPercentTemp() {
    std::string output = detail::ReadCommandCapture(
        "nvidia-smi --query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader,nounits");
    if (output.empty()) {
        return {std::nullopt, std::nullopt};
    }
    std::istringstream iss(output);
    std::string row;
    std::vector<double> gpu;
    std::vector<double> temp;
    while (std::getline(iss, row)) {
        std::size_t comma = row.find(',');
        if (comma == std::string::npos) {
            continue;
        }
        std::string gpu_raw = Trim(row.substr(0, comma));
        std::string temp_raw = Trim(row.substr(comma + 1));
        auto gpu_val = ParseGpuField(gpu_raw);
        auto temp_val = ParseGpuField(temp_raw);
        if (gpu_val.has_value()) {
            gpu.push_back(*gpu_val);
        }
        if (temp_val.has_value() && *temp_val > 0.0) {
            temp.push_back(*temp_val);
        }
    }
    std::optional<double> gpu_avg;
    std::optional<double> temp_avg;
    if (!gpu.empty()) {
        double sum = 0.0;
        for (double value : gpu) {
            sum += value;
        }
        gpu_avg = sum / static_cast<double>(gpu.size());
    }
    if (!temp.empty()) {
        double sum = 0.0;
        for (double value : temp) {
            sum += value;
        }
        temp_avg = sum / static_cast<double>(temp.size());
    }
    return {gpu_avg, temp_avg};
}

CommandHwPlan BuildHwPlan(const std::string& command) {
    CommandHwPlan plan;
    plan.op = command;
    const unsigned int hw = std::thread::hardware_concurrency();
    const std::size_t workers = hw > 0 ? static_cast<std::size_t>(hw) : 1;
    plan.parallel = workers > 1 ? ("ON(" + std::to_string(workers) + "w)") : "OFF";
    if (basefwx::env::IsEnabled("BASEFWX_FORCE_SINGLE_THREAD", false)) {
        plan.parallel = "OFF";
    }
    if (basefwx::env::IsEnabled("BASEFWX_AES_NI", true)) {
        plan.aes = "aesni";
    } else {
        plan.aes = "cpu";
    }
    if (command == "jmge" || command == "jmgd") {
        const std::string hwaccel = ToLower(basefwx::env::Get("BASEFWX_HWACCEL"));
        if (hwaccel == "nvenc" || hwaccel == "cuda" || hwaccel == "nvidia") {
            plan.encode = "NVENC";
            plan.decode = "NVENC";
            plan.expect_gpu = true;
            plan.reason = "BASEFWX_HWACCEL requested NVIDIA encode/decode path";
        } else if (hwaccel == "qsv" || hwaccel == "intel") {
            plan.encode = "QSV";
            plan.decode = "QSV";
            plan.reason = "BASEFWX_HWACCEL requested Intel QSV path";
        } else if (hwaccel == "vaapi") {
            plan.encode = "VAAPI";
            plan.decode = "VAAPI";
            plan.reason = "BASEFWX_HWACCEL requested VAAPI path";
        } else {
            plan.reason = "auto hwaccel routing with CPU crypto";
        }
    } else {
        plan.reason = "command uses CPU crypto path";
    }
    return plan;
}

}  // namespace basefwx::cli
