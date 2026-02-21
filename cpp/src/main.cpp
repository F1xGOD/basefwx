#include "basefwx/basefwx.hpp"
#include "basefwx/cli_colors.hpp"
#include "basefwx/env.hpp"
#include "basefwx/system_info.hpp"

#include <chrono>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <condition_variable>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {

bool g_verbose = false;
bool g_no_log = false;

std::string ToLower(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

bool IsTruthy(std::string value) {
    value = ToLower(std::move(value));
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

void SetCliEnvVar(const char* key, const char* value) {
#if defined(_WIN32)
    _putenv_s(key, value);
#else
    setenv(key, value, 1);
#endif
}

bool ShouldLog() {
    return !g_no_log && !basefwx::env::IsEnabled("BASEFWX_NO_LOG", false);
}

bool IsVerbose() {
    return g_verbose || basefwx::env::IsEnabled("BASEFWX_VERBOSE", false);
}

bool CliPlain() {
    if (basefwx::env::IsEnabled("BASEFWX_CLI_PLAIN", false)) {
        return true;
    }
    if (!basefwx::env::Get("NO_COLOR").empty()) {
        return true;
    }
    std::string style = ToLower(basefwx::env::Get("BASEFWX_CLI_STYLE"));
    if (style == "plain" || style == "boring" || style == "0" || style == "false" || style == "off") {
        return true;
    }
    if (style == "color" || style == "emoji" || style == "on") {
        return false;
    }
    std::filesystem::path config_path;
    std::string cfg = basefwx::env::Get("BASEFWX_CLI_CONFIG");
    if (!cfg.empty()) {
        config_path = std::filesystem::path(cfg);
    } else {
        std::string appdata = basefwx::env::Get("APPDATA");
        if (!appdata.empty()) {
            config_path = std::filesystem::path(appdata) / "basefwx" / "cli.conf";
        } else {
            std::string home = basefwx::env::HomeDir();
            if (!home.empty()) {
                config_path = std::filesystem::path(home) / ".config" / "basefwx" / "cli.conf";
            }
        }
    }
    if (!config_path.empty()) {
        std::ifstream input(config_path);
        if (input) {
            std::string data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
            data = ToLower(data);
            if (data.find("plain=1") != std::string::npos || data.find("plain=true") != std::string::npos
                || data.find("style=plain") != std::string::npos || data.find("mode=plain") != std::string::npos
                || data.find("boring=1") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

std::string StyleText(const std::string& text, const char* color, bool plain) {
    if (plain) {
        return text;
    }
    return std::string(color) + text + "\033[0m";
}

std::string EmojiPrefix(const char* emoji, bool plain) {
    if (plain || !emoji) {
        return {};
    }
    return std::string(emoji) + " ";
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
    std::string ext = ToLower(path.extension().string());
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

void PrintSystemInfo() {
    if (!IsVerbose() || !ShouldLog()) {
        return;
    }
    
    auto sysinfo = basefwx::system::DetectSystemInfo();
    bool plain = CliPlain();
    
    if (plain) {
        basefwx::cli::SetColorsEnabled(false);
    }
    
    // CPU info
    std::cerr << "CPU: "
              << basefwx::cli::Yellow(std::to_string(sysinfo.cpu.logical_cores))
              << " | "
              << basefwx::cli::Blue(basefwx::system::FormatFrequency(sysinfo.cpu.max_frequency_mhz))
              << "\n";
    
    // RAM info
    std::cerr << "RAM: "
              << basefwx::cli::Yellow(basefwx::system::FormatBytes(sysinfo.memory.total_bytes))
              << " | Used: "
              << basefwx::cli::Yellow(basefwx::system::FormatBytes(sysinfo.memory.used_bytes))
              << " | Free: "
              << basefwx::cli::Yellow(basefwx::system::FormatBytes(sysinfo.memory.available_bytes));
    
    if (sysinfo.memory.frequency_mhz > 0) {
        std::cerr << " | " << basefwx::cli::Blue(basefwx::system::FormatFrequency(sysinfo.memory.frequency_mhz));
    }
    std::cerr << "\n";
    
    // Chunk size recommendation
    auto policy = basefwx::system::GetChunkSizePolicy(sysinfo.memory);
    std::size_t chunk_size = basefwx::system::ChunkSizeFromPolicy(policy);
    std::cerr << "Chunk Size: "
              << basefwx::cli::BoldGreen(basefwx::system::FormatBytes(chunk_size))
              << " (optimized for this system)\n";
    std::cerr << "\n";
}

void ApplyMasterPubPath(const std::string& path) {
    if (path.empty()) {
        return;
    }
#if defined(_WIN32)
    _putenv_s("BASEFWX_MASTER_PQ_PUB", path.c_str());
#else
    setenv("BASEFWX_MASTER_PQ_PUB", path.c_str(), 1);
#endif
}

std::atomic<std::size_t> g_bench_sink{0};

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

std::string StripAsciiWhitespace(std::string value) {
    value.erase(std::remove_if(value.begin(),
                               value.end(),
                               [](unsigned char ch) { return std::isspace(ch) != 0; }),
                value.end());
    return value;
}

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
    // Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
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
    if ((allow_single && std::string_view(allow_single) == "1") || (noninteractive && std::string_view(noninteractive) == "1")) {
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
    return MedianNs(samples);
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
    for (std::size_t i = 0; i < workers; ++i) {
        threads.emplace_back([&]() {
            auto blob = basefwx::fwxaes::EncryptRaw(data, password, opts);
            auto plain = basefwx::fwxaes::DecryptRaw(blob, password, use_master);
            g_bench_sink.fetch_xor(plain.size(), std::memory_order_relaxed);
            total.fetch_add(plain.size(), std::memory_order_relaxed);
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    return total.load(std::memory_order_relaxed);
}

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

void PrintUsage() {
    bool plain = CliPlain();
    const char* cyan = "\033[36m";
    std::cout << StyleText(EmojiPrefix("✨", plain) + "Usage:", cyan, plain) << "\n";
    std::cout << "  [global] --verbose|-v --no-log --no-color\n";
    std::cout << "  basefwx_cpp info <file.fwx>\n";
    std::cout << "  basefwx_cpp b64-enc <text>\n";
    std::cout << "  basefwx_cpp b64-dec <text>\n";
    std::cout << "  basefwx_cpp n10-enc <text>\n";
    std::cout << "  basefwx_cpp n10-dec <digits>\n";
    std::cout << "  basefwx_cpp n10file-enc <in-file> <out-file>\n";
    std::cout << "  basefwx_cpp n10file-dec <in-file> <out-file>\n";
    std::cout << "  basefwx_cpp kFMe <in-file> [--out <path>] [--bw]\n";
    std::cout << "  basefwx_cpp kFMd <in-file> [--out <path>] [--bw]\n";
    std::cout << "  basefwx_cpp kFAe <in-file> [--out <path>] [--bw]    (deprecated alias)\n";
    std::cout << "  basefwx_cpp kFAd <in-file> [--out <path>]           (deprecated alias)\n";
    std::cout << "  basefwx_cpp hash512 <text>\n";
    std::cout << "  basefwx_cpp uhash513 <text>\n";
    std::cout << "  basefwx_cpp a512-enc <text>\n";
    std::cout << "  basefwx_cpp a512-dec <text>\n";
    std::cout << "  basefwx_cpp bi512-enc <text>\n";
    std::cout << "  basefwx_cpp b1024-enc <text>\n";
    std::cout << "  basefwx_cpp b256-enc <text>\n";
    std::cout << "  basefwx_cpp b256-dec <text>\n";
    std::cout << "  basefwx_cpp b512-enc <text> [-p <password>] [--master-pub <path>] [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512-dec <text> [-p <password>] [--master-pub <path>] [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512-enc <text> [-p <password>] [--master-pub <path>] [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512-dec <text> [-p <password>] [--master-pub <path>] [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512file-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--strip-meta] [--no-aead] [--compress] [--keep-input] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512file-dec <file.fwx> [-p <password>] [--master-pub <path>] [--no-master] [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512file-bytes-rt <in> <out> [-p <password>] [--master-pub <path>] [--no-master] [--strip-meta] [--no-aead] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512file-bytes-rt <in> <out> [-p <password>] [--master-pub <path>] [--no-master] [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512file-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--strip-meta] [--no-obf] [--compress] [--keep-input] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512file-dec <file.fwx> [-p <password>] [--master-pub <path>] [--no-master] [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp fwxaes-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>] [--normalize] [--threshold <n>] [--cover-phrase <text>] [--compress] [--ignore-media] [--keep-meta] [--keep-input] [--no-archive]\n";
    std::cout << "  basefwx_cpp fwxaes-dec <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp fwxaes-stream-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp fwxaes-stream-dec <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp fwxaes-live-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp fwxaes-live-dec <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp jmge <media> [-p <password>] [--master-pub <path>] [--out <path>] [--keep-meta] [--keep-input] [--no-archive]\n";
    std::cout << "  basefwx_cpp jmgd <media> [-p <password>] [--master-pub <path>] [--out <path>]\n";
    std::cout << "  basefwx_cpp bench-text <method> <text-file> [-p <password>] [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-hash <method> <text-file>\n";
    std::cout << "  basefwx_cpp bench-fwxaes <file> <password> [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-fwxaes-par <file> <password> [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-live <file> <password> [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-b512file <file> <password> [--master-pub <path>] [--no-master] [--no-aead]\n";
    std::cout << "  basefwx_cpp bench-pb512file <file> <password> [--master-pub <path>] [--no-master] [--no-aead]\n";
    std::cout << "  basefwx_cpp bench-jmg <media> <password> [--master-pub <path>] [--no-master]\n";
}

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

class CommandTelemetry {
  public:
    explicit CommandTelemetry(CommandHwPlan plan)
        : plan_(std::move(plan)) {
        enabled_ = ShouldLog();
        if (!enabled_) {
            return;
        }
        EmitHeader();
        running_.store(true, std::memory_order_relaxed);
        worker_ = std::thread([this]() { Loop(); });
    }

    ~CommandTelemetry() {
        Stop();
    }

    CommandTelemetry(const CommandTelemetry&) = delete;
    CommandTelemetry& operator=(const CommandTelemetry&) = delete;

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
        while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
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
            cv_.wait_for(lock, std::chrono::seconds(5));
            if (!running_.load(std::memory_order_relaxed)) {
                break;
            }
            lock.unlock();
            EmitTelemetry();
        }
    }

    void EmitTelemetry() {
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
                std::cerr << line.str() << "\n";
                return;
            }
        }
        auto cpu_temp = ProbeCpuTempC();
        if (cpu_temp.has_value()) {
            line << " \\ " << std::fixed << std::setprecision(0) << *cpu_temp << "C";
        }
        std::cerr << line.str() << "\n";
    }

    std::pair<std::optional<double>, std::optional<double>> SampleGpuPercentTemp() {
        std::string output = ReadCommandCapture(
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
};

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

struct ParsedOptions {
    std::string input;
    std::string password;
    bool use_master = true;
    basefwx::KdfOptions kdf;
};

struct FwxAesArgs {
    std::string input;
    std::string output;
    std::string password;
    bool use_master = true;
    bool normalize = false;
    std::size_t threshold = 8 * 1024;
    std::string cover_phrase = "low taper fade";
    bool compress = false;
    bool ignore_media = false;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = true;
};

struct ImageArgs {
    std::string input;
    std::string output;
    std::string password;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = true;
};

struct FileArgs {
    std::string input;
    std::string password;
    bool use_master = true;
    bool strip_metadata = false;
    bool enable_aead = true;
    bool enable_obf = true;
    bool compress = false;
    bool keep_input = false;
    basefwx::pb512::KdfOptions kdf;
};

ParsedOptions ParseCodecArgs(int argc, char** argv, int start_index) {
    ParsedOptions opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing payload");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (flag == "--no-master") {
            opts.use_master = false;
            idx += 1;
        } else if (flag == "--master-pub" || flag == "--use-master-pub") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing master public key path");
            }
            ApplyMasterPubPath(argv[idx + 1]);
            idx += 2;
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
    return opts;
}

FileArgs ParseFileArgs(int argc, char** argv, int start_index) {
    FileArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (flag == "--no-master") {
            opts.use_master = false;
            idx += 1;
        } else if (flag == "--master-pub" || flag == "--use-master-pub") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing master public key path");
            }
            ApplyMasterPubPath(argv[idx + 1]);
            idx += 2;
        } else if (flag == "--strip-meta") {
            opts.strip_metadata = true;
            idx += 1;
        } else if (flag == "--no-aead") {
            opts.enable_aead = false;
            idx += 1;
        } else if (flag == "--no-obf") {
            opts.enable_obf = false;
            idx += 1;
        } else if (flag == "--compress") {
            opts.compress = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
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
    return opts;
}

FwxAesArgs ParseFwxAesArgs(int argc, char** argv, int start_index) {
    FwxAesArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (flag == "--no-master") {
            opts.use_master = false;
            idx += 1;
        } else if (flag == "--master-pub" || flag == "--use-master-pub") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing master public key path");
            }
            ApplyMasterPubPath(argv[idx + 1]);
            idx += 2;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--normalize") {
            opts.normalize = true;
            idx += 1;
        } else if (flag == "--threshold") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing threshold value");
            }
            opts.threshold = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--cover-phrase") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing cover phrase value");
            }
            opts.cover_phrase = argv[idx + 1];
            idx += 2;
        } else if (flag == "--compress") {
            opts.compress = true;
            idx += 1;
        } else if (flag == "--ignore-media") {
            opts.ignore_media = true;
            idx += 1;
        } else if (flag == "--keep-meta") {
            opts.keep_meta = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--no-archive") {
            opts.archive_original = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

ImageArgs ParseImageArgs(int argc, char** argv, int start_index) {
    ImageArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            idx += 2;
        } else if (flag == "--master-pub" || flag == "--use-master-pub") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing master public key path");
            }
            ApplyMasterPubPath(argv[idx + 1]);
            idx += 2;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--keep-meta") {
            opts.keep_meta = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--no-archive") {
            opts.archive_original = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> cleaned_args;
    cleaned_args.reserve(static_cast<std::size_t>(argc));
    cleaned_args.emplace_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--verbose" || arg == "-v") {
            g_verbose = true;
            continue;
        }
        if (arg == "--no-log") {
            g_no_log = true;
            continue;
        }
        if (arg == "--no-color") {
            basefwx::cli::SetColorsEnabled(false);
            SetCliEnvVar("NO_COLOR", "1");
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

    SetCliEnvVar("BASEFWX_VERBOSE", g_verbose ? "1" : "0");
    SetCliEnvVar("BASEFWX_NO_LOG", g_no_log ? "1" : "0");

    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    std::string command(argv[1]);
    std::optional<CommandTelemetry> telemetry;
    if (command != "jmge" && command != "jmgd") {
        telemetry.emplace(BuildHwPlan(command));
    }

    // Print system info if verbose
    PrintSystemInfo();

    try {
        if (command == "info") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            auto data = basefwx::ReadFile(argv[2]);
            auto info = basefwx::InspectBlob(data);
            std::cout << "user_blob_len: " << info.user_blob_len << " bytes\n";
            std::cout << "master_blob_len: " << info.master_blob_len << " bytes\n";
            std::cout << "payload_len: " << info.payload_len << " bytes\n";
            if (info.has_metadata) {
                std::cout << "metadata_len: " << info.metadata_len << " bytes\n";
                if (!info.metadata_json.empty()) {
                    std::cout << "metadata_json: " << info.metadata_json << "\n";
                } else if (info.metadata_len == 0) {
                    std::cout << "metadata_json: <empty>\n";
                } else {
                    std::cout << "metadata_json: <unavailable>\n";
                }
            } else {
                std::cout << "metadata_json: <unavailable>\n";
            }
            return 0;
        }
        if (command == "bench-text") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string method = ToLower(argv[2]);
            ParsedOptions opts = ParseCodecArgs(argc, argv, 3);
            std::string text = ReadTextFile(opts.input);
            if ((method == "b512" || method == "pb512") && opts.password.empty()) {
                throw std::runtime_error("Password required for b512/pb512 benchmark");
            }
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            std::function<std::size_t()> op;
            if (method == "b64") {
                op = [&]() {
                    std::string enc = basefwx::B64Encode(text);
                    std::string dec = basefwx::B64Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "b256") {
                op = [&]() {
                    std::string enc = basefwx::B256Encode(text);
                    std::string dec = basefwx::B256Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "a512") {
                op = [&]() {
                    std::string enc = basefwx::A512Encode(text);
                    std::string dec = basefwx::A512Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "n10") {
                op = [&]() {
                    std::string enc = basefwx::N10Encode(text);
                    std::string dec = basefwx::N10Decode(enc);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "b512") {
                op = [&]() {
                    std::string enc = basefwx::B512Encode(text, opts.password, opts.use_master, opts.kdf);
                    std::string dec = basefwx::B512Decode(enc, opts.password, opts.use_master, opts.kdf);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else if (method == "pb512") {
                op = [&]() {
                    std::string enc = basefwx::Pb512Encode(text, opts.password, opts.use_master, opts.kdf);
                    std::string dec = basefwx::Pb512Decode(enc, opts.password, opts.use_master, opts.kdf);
                    g_bench_sink.fetch_xor(dec.size(), std::memory_order_relaxed);
                    return dec.size();
                };
            } else {
                throw std::runtime_error("Unsupported benchmark method: " + method);
            }
            auto run = [&]() {
                if (workers > 1) {
                    RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-hash") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string method = ToLower(argv[2]);
            std::string text = ReadTextFile(argv[3]);
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            std::function<std::size_t()> op;
            if (method == "hash512") {
                op = [&]() {
                    std::string digest = basefwx::Hash512(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "uhash513") {
                op = [&]() {
                    std::string digest = basefwx::Uhash513(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "bi512") {
                op = [&]() {
                    std::string digest = basefwx::Bi512Encode(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else if (method == "b1024") {
                op = [&]() {
                    std::string digest = basefwx::B1024Encode(text);
                    g_bench_sink.fetch_xor(digest.size(), std::memory_order_relaxed);
                    return digest.size();
                };
            } else {
                throw std::runtime_error("Unsupported hash benchmark method: " + method);
            }
            auto run = [&]() {
                if (workers > 1) {
                    RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-fwxaes") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = true;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--no-master") {
                    use_master = false;
                } else if (flag == "--master-pub" || flag == "--use-master-pub") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing master public key path");
                    }
                    ApplyMasterPubPath(argv[idx + 1]);
                    idx += 1;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            basefwx::fwxaes::Options opts;
            opts.use_master = use_master;
            int warmup = BenchWarmup();
            int iters = BenchIters();
            auto run = [&]() {
                auto blob = basefwx::fwxaes::EncryptRaw(data, password, opts);
                auto plain = basefwx::fwxaes::DecryptRaw(blob, password, use_master);
                g_bench_sink.fetch_xor(plain.size(), std::memory_order_relaxed);
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-fwxaes-par") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = true;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--no-master") {
                    use_master = false;
                } else if (flag == "--master-pub" || flag == "--use-master-pub") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing master public key path");
                    }
                    ApplyMasterPubPath(argv[idx + 1]);
                    idx += 1;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            for (int i = 0; i < warmup; ++i) {
                RunFwxaesParallel(data, password, use_master, workers);
            }
            std::vector<long long> samples;
            samples.reserve(static_cast<std::size_t>(iters));
            std::size_t bytes_per_run = 0;
            for (int i = 0; i < iters; ++i) {
                auto start = std::chrono::steady_clock::now();
                bytes_per_run = RunFwxaesParallel(data, password, use_master, workers);
                auto end = std::chrono::steady_clock::now();
                samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
            }
            auto median = MedianNs(samples);
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
        if (command == "bench-live") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = true;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--no-master") {
                    use_master = false;
                } else if (flag == "--master-pub" || flag == "--use-master-pub") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing master public key path");
                    }
                    ApplyMasterPubPath(argv[idx + 1]);
                    idx += 1;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            auto data = ReadBinaryFile(input);
            std::string payload(reinterpret_cast<const char*>(data.data()), data.size());
            int warmup = BenchWarmup();
            int iters = BenchIters();
            std::size_t workers = static_cast<std::size_t>(BenchWorkers());
            if (workers == 0) {
                workers = 1;
            }
            ConfirmSingleThreadCli(workers);
            auto op = [&]() -> std::size_t {
                std::istringstream source(payload, std::ios::in | std::ios::binary);
                std::ostringstream encrypted(std::ios::out | std::ios::binary);
                basefwx::FwxAesLiveEncryptStream(source, encrypted, password, use_master);
                std::string enc_blob = encrypted.str();
                std::istringstream enc_in(enc_blob, std::ios::in | std::ios::binary);
                std::ostringstream restored(std::ios::out | std::ios::binary);
                basefwx::FwxAesLiveDecryptStream(enc_in, restored, password, use_master);
                std::size_t len = restored.str().size();
                g_bench_sink.fetch_xor(len, std::memory_order_relaxed);
                return len;
            };
            auto run = [&]() {
                if (workers > 1) {
                    RunParallel(workers, [&](std::size_t) { return op(); });
                    return;
                }
                op();
            };
            auto ns = BenchMedian(warmup, iters, run);
            std::cout << "BENCH_NS=" << ns << "\n";
            return 0;
        }
        if (command == "bench-b512file" || command == "bench-pb512file") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string input = argv[2];
            std::string password = argv[3];
            bool use_master = true;
            bool disable_aead = false;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--no-master") {
                    use_master = false;
                } else if (flag == "--no-aead") {
                    disable_aead = true;
                } else if (flag == "--master-pub" || flag == "--use-master-pub") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing master public key path");
                    }
                    ApplyMasterPubPath(argv[idx + 1]);
                    idx += 1;
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
                std::size_t workers = static_cast<std::size_t>(BenchWorkers());
                if (workers == 0) {
                    workers = 1;
                }
                ConfirmSingleThreadCli(workers);
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

                int warmup = BenchWarmup();
                int iters = BenchIters();
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
                        g_bench_sink.fetch_xor(static_cast<std::size_t>(dec_size), std::memory_order_relaxed);
                        return static_cast<std::size_t>(dec_size);
                    }
                    return 0;
                };
                auto run = [&]() {
                    if (workers > 1) {
                        RunParallel(workers, run_once);
                        return;
                    }
                    run_once(0);
                };

                long long ns = BenchMedian(warmup, iters, run);
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
                PrintUsage();
                return 2;
            }
            std::string media_path = argv[2];
            std::string password = argv[3];
            bool use_master = true;
            for (int idx = 4; idx < argc; ++idx) {
                std::string flag(argv[idx]);
                if (flag == "--no-master") {
                    use_master = false;
                } else if (flag == "--master-pub" || flag == "--use-master-pub") {
                    if (idx + 1 >= argc) {
                        throw std::runtime_error("Missing master public key path");
                    }
                    ApplyMasterPubPath(argv[idx + 1]);
                    idx += 1;
                } else {
                    throw std::runtime_error("Unknown flag: " + flag);
                }
            }
            try {
                std::filesystem::path src_path(media_path);
                if (!std::filesystem::exists(src_path)) {
                    throw std::runtime_error("Media file not found: " + media_path);
                }
                std::size_t workers = static_cast<std::size_t>(BenchWorkers());
                if (workers == 0) {
                    workers = 1;
                }
                ConfirmSingleThreadCli(workers);
                std::vector<std::filesystem::path> temp_dirs;
                auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
                for (std::size_t i = 0; i < workers; ++i) {
                    std::filesystem::path temp_dir = std::filesystem::temp_directory_path()
                        / ("basefwx-bench-jmg-" + stamp + "-" + std::to_string(i));
                    std::filesystem::create_directories(temp_dir);
                    temp_dirs.push_back(temp_dir);
                }

                int warmup = BenchWarmup();
                int iters = BenchIters();
                auto run_once = [&](std::size_t idx) -> std::size_t {
                    const auto& temp_dir = temp_dirs[idx];
                    std::string enc_name = "bench_enc_" + std::to_string(idx) + src_path.extension().string();
                    std::string dec_name = "bench_dec_" + std::to_string(idx) + src_path.extension().string();
                    std::filesystem::path enc_path = temp_dir / enc_name;
                    std::filesystem::path dec_path = temp_dir / dec_name;
                    
                    basefwx::Jmge(src_path.string(), password, enc_path.string(), false, true);
                    basefwx::Jmgd(enc_path.string(), password, dec_path.string());
                    
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
                        g_bench_sink.fetch_xor(static_cast<std::size_t>(dec_size), std::memory_order_relaxed);
                        return static_cast<std::size_t>(dec_size);
                    }
                    return 0;
                };
                auto run = [&]() {
                    if (workers > 1) {
                        RunParallel(workers, run_once);
                        return;
                    }
                    run_once(0);
                };

                long long ns = BenchMedian(warmup, iters, run);
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
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B64Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b64-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B64Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::N10Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::N10Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "n10file-enc") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            auto bytes = ReadBinaryFile(argv[2]);
            std::string input(bytes.begin(), bytes.end());
            WriteTextFile(argv[3], basefwx::N10Encode(input));
            return 0;
        }
        if (command == "n10file-dec") {
            if (argc < 4) {
                PrintUsage();
                return 2;
            }
            std::string digits = StripAsciiWhitespace(ReadTextFile(argv[2]));
            WriteBinaryFile(argv[3], basefwx::N10Decode(digits));
            return 0;
        }
        if (command == "kFMe" || command == "kFMd" || command == "kFAe" || command == "kFAd") {
            if (argc < 3) {
                PrintUsage();
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
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::Hash512(argv[2]) << "\n";
            return 0;
        }
        if (command == "uhash513") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::Uhash513(argv[2]) << "\n";
            return 0;
        }
        if (command == "a512-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::A512Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "a512-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::A512Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "bi512-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::Bi512Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b1024-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B1024Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b256-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b256-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b512-enc" || command == "b512-dec" || command == "pb512-enc" || command == "pb512-dec") {
            ParsedOptions opts = ParseCodecArgs(argc, argv, 2);
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
                    PrintUsage();
                    return 2;
                }
                std::string input = argv[2];
                std::string output = argv[3];
                FileArgs opts;
                opts.input = input;
                int idx = 4;
                while (idx < argc) {
                    std::string flag(argv[idx]);
                    if (flag == "-p" || flag == "--password") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing password value");
                        }
                        opts.password = argv[idx + 1];
                        idx += 2;
                    } else if (flag == "--no-master") {
                        opts.use_master = false;
                        idx += 1;
                    } else if (flag == "--master-pub" || flag == "--use-master-pub") {
                        if (idx + 1 >= argc) {
                            throw std::runtime_error("Missing master public key path");
                        }
                        ApplyMasterPubPath(argv[idx + 1]);
                        idx += 2;
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
            FileArgs opts = ParseFileArgs(argc, argv, 2);
            basefwx::filecodec::FileOptions file_opts;
            file_opts.strip_metadata = opts.strip_metadata;
            file_opts.use_master = opts.use_master;
            file_opts.enable_aead = opts.enable_aead;
            file_opts.enable_obfuscation = opts.enable_obf;
            file_opts.compress = opts.compress;
            file_opts.keep_input = opts.keep_input;
            if (command == "b512file-enc") {
                std::cout << basefwx::filecodec::B512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "b512file-dec") {
                std::cout << basefwx::filecodec::B512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-enc") {
                std::cout << basefwx::filecodec::Pb512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-dec") {
                std::cout << basefwx::filecodec::Pb512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "fwxaes-enc" || command == "fwxaes-dec"
            || command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec"
            || command == "fwxaes-live-enc" || command == "fwxaes-live-dec") {
            FwxAesArgs opts = ParseFwxAesArgs(argc, argv, 2);
            if (opts.password.empty() && !opts.use_master) {
                throw std::runtime_error("Password required when master key usage is disabled");
            }
            if (opts.output.empty()) {
                if (command == "fwxaes-enc") {
                    if (!opts.ignore_media && LooksLikeMediaPath(std::filesystem::path(opts.input))) {
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
            if (command == "fwxaes-live-enc" || command == "fwxaes-live-dec") {
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
                return 0;
            }
            if (command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec") {
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
                if (command == "fwxaes-stream-enc") {
                    basefwx::fwxaes::EncryptStream(input, output, opts.password, stream_opts);
                } else {
                    basefwx::fwxaes::DecryptStream(input, output, opts.password, opts.use_master);
                }
                return 0;
            }
            if (command == "fwxaes-enc") {
                if (!opts.ignore_media && LooksLikeMediaPath(std::filesystem::path(opts.input))) {
                    try {
                        std::cout << basefwx::Jmge(
                            opts.input,
                            opts.password,
                            opts.output,
                            opts.keep_meta,
                            opts.keep_input,
                            opts.archive_original
                        ) << "\n";
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
                basefwx::fwxaes::EncryptFile(opts.input, opts.output, opts.password, fwxaes_opts, norm, pack_opts, opts.keep_input);
            } else {
                basefwx::fwxaes::DecryptFile(opts.input, opts.output, opts.password, opts.use_master);
            }
            return 0;
        }
        if (command == "jmge" || command == "jmgd") {
            ImageArgs opts = ParseImageArgs(argc, argv, 2);
            if (command == "jmge") {
                std::cout << basefwx::Jmge(
                    opts.input,
                    opts.password,
                    opts.output,
                    opts.keep_meta,
                    opts.keep_input,
                    opts.archive_original
                ) << "\n";
            } else {
                std::cout << basefwx::Jmgd(opts.input, opts.password, opts.output) << "\n";
            }
            return 0;
        }
        PrintUsage();
        return 2;
    } catch (const std::exception& exc) {
        bool plain = CliPlain();
        const char* red = "\033[31m";
        std::string msg = EmojiPrefix("❌", plain) + "Error: " + exc.what();
        std::cerr << StyleText(msg, red, plain) << "\n";
        return 1;
    }
}
