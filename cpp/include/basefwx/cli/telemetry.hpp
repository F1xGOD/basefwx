#pragma once

#include "basefwx/cli/globals.hpp"
#include "basefwx/env.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace basefwx::cli {

struct CommandHwPlan {
    std::string op;
    std::string encode = "CPU";
    std::string decode = "CPU";
    std::string pixels = "CPU";
    std::string parallel = "OFF";
    std::string crypto = "CPU";
    std::string aes = "unknown";
    bool expect_gpu = false;
    std::string reason;
};

namespace detail {
std::optional<std::uint64_t> EstimatePlainTmpTargetSize(const std::filesystem::path& input_path);
std::string ReadCommandCapture(const std::string& cmd);
std::optional<double> ProbeCpuTempC();
}  // namespace detail

class CommandTelemetry {
  public:
    explicit CommandTelemetry(CommandHwPlan plan)
        : plan_(std::move(plan)) {
        enabled_ = ShouldLog();
        inline_stats_ = IsStderrInteractive()
            && !basefwx::env::IsEnabled("BASEFWX_STATS_LINES", false);
        if (!enabled_) {
            return;
        }
        EmitHeader();
        {
            std::lock_guard<std::mutex> lock(TelemetrySuspender::io_mu);
            TelemetrySuspender::clear_active_line = [this]() { ClearInlineStatsLineLocked(); };
        }
        running_.store(true, std::memory_order_relaxed);
        worker_ = std::thread([this]() { Loop(); });
    }

    ~CommandTelemetry() {
        Stop();
        std::lock_guard<std::mutex> lock(TelemetrySuspender::io_mu);
        TelemetrySuspender::clear_active_line = nullptr;
    }

    CommandTelemetry(const CommandTelemetry&) = delete;
    CommandTelemetry& operator=(const CommandTelemetry&) = delete;

    void ConfigureFileProgress(const std::string& input_path, const std::string& output_path) {
        if (!enabled_) {
            return;
        }
        std::error_code ec;
        std::filesystem::path in(input_path);
        if (input_path.empty() || !std::filesystem::is_regular_file(in, ec)) {
            return;
        }
        std::uint64_t in_size = static_cast<std::uint64_t>(std::filesystem::file_size(in, ec));
        if (ec || in_size == 0) {
            return;
        }
        std::filesystem::path out(output_path);
        bool is_temp_plain = EndsWith(out.string(), ".plain.tmp");
        if (is_temp_plain) {
            auto estimated = detail::EstimatePlainTmpTargetSize(in);
            if (estimated.has_value() && *estimated > 0) {
                in_size = *estimated;
            }
        }
        std::lock_guard<std::mutex> lock(progress_mu_);
        progress_input_path_ = in;
        progress_output_path_ = out;
        progress_input_size_ = in_size;
        progress_enabled_ = true;
        progress_sample_size_ = 0;
        progress_sample_time_ = std::chrono::steady_clock::time_point{};
        progress_sample_ready_ = false;
        progress_rate_bps_ = 0.0;
        progress_last_growth_time_ = std::chrono::steady_clock::now();
        progress_is_temp_plain_ = is_temp_plain;
        progress_completed_ = false;
    }

    void MarkProgressComplete() {
        if (!enabled_) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(progress_mu_);
            if (!progress_enabled_) {
                return;
            }
            progress_completed_ = true;
        }
        EmitTelemetry();
    }

  private:
    void Stop() {
        if (!enabled_) {
            return;
        }
        running_.store(false, std::memory_order_relaxed);
        cv_.notify_all();
        if (worker_.joinable()) {
            worker_.join();
        }
        if (inline_stats_ && had_stats_line_) {
            std::cerr << "\n" << std::flush;
            had_stats_line_ = false;
            last_stats_width_ = 0;
        }
        enabled_ = false;
    }

    void EmitHeader() {
        std::cerr << "🎛 [basefwx.hw] op=" << plan_.op
                  << " encode=" << plan_.encode
                  << " decode=" << plan_.decode
                  << " pixels=" << plan_.pixels
                  << " parallel=" << plan_.parallel
                  << " crypto=" << plan_.crypto
                  << " aes_accel=" << plan_.aes
                  << "\n";
        if (IsVerbose() && !plan_.reason.empty()) {
            std::cerr << "   reason: " << plan_.reason << "\n";
        }
    }

    static std::optional<double> ParseGpuField(const std::string& field) {
        try {
            return std::stod(field);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    static std::string Trim(std::string value) {
        while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' '
                                  || value.back() == '\t')) {
            value.pop_back();
        }
        std::size_t start = 0;
        while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
            ++start;
        }
        return value.substr(start);
    }

    void Loop() {
        while (running_.load(std::memory_order_relaxed)) {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait_for(lock, std::chrono::seconds(1));
            if (!running_.load(std::memory_order_relaxed)) {
                break;
            }
            lock.unlock();
            EmitTelemetry();
        }
    }

    void EmitTelemetry();

    void AppendProgress(std::ostringstream& line);

    void EmitStatsLine(const std::string& text) {
        std::lock_guard<std::mutex> lock(TelemetrySuspender::io_mu);
        if (TelemetrySuspender::pause_count.load(std::memory_order_acquire) > 0) {
            return;
        }
        if (!inline_stats_) {
            std::cerr << text << "\n";
            return;
        }
        std::string out_line = text;
        if (out_line.size() < last_stats_width_) {
            out_line.append(last_stats_width_ - out_line.size(), ' ');
        }
        last_stats_width_ = out_line.size();
        had_stats_line_ = true;
        std::cerr << "\r" << out_line << std::flush;
    }

    void ClearInlineStatsLineLocked() {
        if (!inline_stats_ || !had_stats_line_) {
            return;
        }
        std::cerr << "\r" << std::string(last_stats_width_, ' ') << "\r" << std::flush;
        had_stats_line_ = false;
        last_stats_width_ = 0;
    }

    std::pair<std::optional<double>, std::optional<double>> SampleGpuPercentTemp();

    std::optional<double> SampleCpuPercent() {
#if defined(__linux__)
        std::ifstream in("/proc/stat");
        if (!in) {
            return std::nullopt;
        }
        std::string label;
        std::uint64_t user = 0;
        std::uint64_t nice = 0;
        std::uint64_t system = 0;
        std::uint64_t idle = 0;
        std::uint64_t iowait = 0;
        std::uint64_t irq = 0;
        std::uint64_t softirq = 0;
        std::uint64_t steal = 0;
        in >> label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        if (label != "cpu") {
            return std::nullopt;
        }
        std::uint64_t idle_total = idle + iowait;
        std::uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
        if (prev_total_ == 0 || total <= prev_total_) {
            prev_total_ = total;
            prev_idle_ = idle_total;
            return std::nullopt;
        }
        std::uint64_t delta_total = total - prev_total_;
        std::uint64_t delta_idle = idle_total - prev_idle_;
        prev_total_ = total;
        prev_idle_ = idle_total;
        if (delta_total == 0) {
            return std::nullopt;
        }
        double usage = 100.0 * (1.0 - (static_cast<double>(delta_idle) / static_cast<double>(delta_total)));
        if (usage < 0.0) {
            usage = 0.0;
        }
        if (usage > 100.0) {
            usage = 100.0;
        }
        return usage;
#else
        return std::nullopt;
#endif
    }

    CommandHwPlan plan_;
    bool enabled_ = false;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::uint64_t prev_total_ = 0;
    std::uint64_t prev_idle_ = 0;
    bool inline_stats_ = false;
    bool had_stats_line_ = false;
    std::size_t last_stats_width_ = 0;
    std::mutex progress_mu_;
    std::filesystem::path progress_input_path_;
    std::filesystem::path progress_output_path_;
    std::uint64_t progress_input_size_ = 0;
    bool progress_enabled_ = false;
    std::uint64_t progress_sample_size_ = 0;
    std::chrono::steady_clock::time_point progress_sample_time_{};
    bool progress_sample_ready_ = false;
    double progress_rate_bps_ = 0.0;
    std::chrono::steady_clock::time_point progress_last_growth_time_{};
    bool progress_is_temp_plain_ = false;
    bool progress_completed_ = false;
};

CommandHwPlan BuildHwPlan(const std::string& command);

}  // namespace basefwx::cli
