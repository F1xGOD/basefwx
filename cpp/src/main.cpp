#include "basefwx/basefwx.hpp"
#include "basefwx/env.hpp"

#include <chrono>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <condition_variable>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

std::string ToLower(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
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
    std::cout << "  basefwx_cpp info <file.fwx>\n";
    std::cout << "  basefwx_cpp b64-enc <text>\n";
    std::cout << "  basefwx_cpp b64-dec <text>\n";
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
    std::cout << "  basefwx_cpp fwxaes-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>] [--normalize] [--threshold <n>] [--cover-phrase <text>] [--compress] [--ignore-media] [--keep-meta] [--keep-input]\n";
    std::cout << "  basefwx_cpp fwxaes-dec <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp fwxaes-stream-enc <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp fwxaes-stream-dec <file> [-p <password>] [--master-pub <path>] [--no-master] [--out <path>]\n";
    std::cout << "  basefwx_cpp jmge <media> [-p <password>] [--master-pub <path>] [--out <path>] [--keep-meta] [--keep-input]\n";
    std::cout << "  basefwx_cpp jmgd <media> [-p <password>] [--master-pub <path>] [--out <path>]\n";
    std::cout << "  basefwx_cpp bench-text <method> <text-file> [-p <password>] [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-hash <method> <text-file>\n";
    std::cout << "  basefwx_cpp bench-fwxaes <file> <password> [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-fwxaes-par <file> <password> [--master-pub <path>] [--no-master]\n";
    std::cout << "  basefwx_cpp bench-b512file <file> <password> [--master-pub <path>] [--no-master] [--no-aead]\n";
    std::cout << "  basefwx_cpp bench-pb512file <file> <password> [--master-pub <path>] [--no-master] [--no-aead]\n";
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
};

struct ImageArgs {
    std::string input;
    std::string output;
    std::string password;
    bool keep_meta = false;
    bool keep_input = false;
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
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    std::string command(argv[1]);
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
            || command == "fwxaes-stream-enc" || command == "fwxaes-stream-dec") {
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
                } else if (opts.input.size() >= 4 && opts.input.rfind(".fwx") == opts.input.size() - 4) {
                    opts.output = opts.input.substr(0, opts.input.size() - 4);
                } else {
                    opts.output = opts.input + ".out";
                }
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
                        std::cout << basefwx::Jmge(opts.input, opts.password, opts.output, opts.keep_meta, opts.keep_input) << "\n";
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
                std::cout << basefwx::Jmge(opts.input, opts.password, opts.output, opts.keep_meta, opts.keep_input) << "\n";
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
