#pragma once

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

namespace basefwx::cli {

extern bool g_verbose;
extern bool g_no_log;
extern std::atomic<std::size_t> g_bench_sink;

struct TelemetrySuspender {
    static std::atomic<int> pause_count;
    static std::mutex io_mu;
    static std::function<void()> clear_active_line;
};

class TelemetryPauseGuard {
  public:
    TelemetryPauseGuard();
    ~TelemetryPauseGuard();
    TelemetryPauseGuard(const TelemetryPauseGuard&) = delete;
    TelemetryPauseGuard& operator=(const TelemetryPauseGuard&) = delete;
};

std::string ToLower(std::string value);
bool EndsWith(std::string_view value, std::string_view suffix);
void SetCliEnvVar(const char* key, const char* value);
bool ShouldLog();
bool IsVerbose();
bool CliPlain();
bool IsStderrInteractive();
bool IsStdinInteractive();
bool IsLightCommand(const std::string& command);
std::string StyleText(const std::string& text, const char* color, bool plain);
std::string EmojiPrefix(const char* emoji, bool plain);

}  // namespace basefwx::cli
