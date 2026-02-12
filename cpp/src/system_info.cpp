#include "basefwx/system_info.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <thread>

#if defined(_WIN32) || defined(_WIN64)
    #define BASEFWX_WINDOWS 1
    #include <windows.h>
    #include <sysinfoapi.h>
#elif defined(__APPLE__) && defined(__MACH__)
    #define BASEFWX_MACOS 1
    #include <sys/sysctl.h>
    #include <sys/types.h>
    #include <mach/mach.h>
    #include <mach/vm_statistics.h>
#elif defined(__linux__)
    #define BASEFWX_LINUX 1
    #include <sys/sysinfo.h>
    #include <unistd.h>
#endif

namespace basefwx::system {

namespace {

#if BASEFWX_LINUX
std::uint32_t ReadCpuMaxFrequency() {
    // Try reading from /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq
    std::ifstream freq_file("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
    if (freq_file.is_open()) {
        std::uint64_t khz = 0;
        freq_file >> khz;
        if (khz > 0) {
            return static_cast<std::uint32_t>(khz / 1000);  // Convert kHz to MHz
        }
    }
    
    // Fallback: try parsing /proc/cpuinfo
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo.is_open()) {
        return 0;
    }
    
    std::string line;
    double max_mhz = 0.0;
    while (std::getline(cpuinfo, line)) {
        if (line.find("cpu MHz") != std::string::npos) {
            std::size_t colon = line.find(':');
            if (colon != std::string::npos) {
                double mhz = std::stod(line.substr(colon + 1));
                max_mhz = std::max(max_mhz, mhz);
            }
        }
    }
    return static_cast<std::uint32_t>(max_mhz);
}

std::uint32_t ReadMemoryFrequency() {
    // Try reading from dmidecode (requires root, usually not available)
    // For now, return 0 (unknown)
    return 0;
}
#endif

#if BASEFWX_MACOS
std::uint32_t ReadCpuMaxFrequency() {
    std::uint64_t freq = 0;
    std::size_t size = sizeof(freq);
    if (sysctlbyname("hw.cpufrequency_max", &freq, &size, nullptr, 0) == 0) {
        return static_cast<std::uint32_t>(freq / 1000000);  // Convert Hz to MHz
    }
    // Fallback
    if (sysctlbyname("hw.cpufrequency", &freq, &size, nullptr, 0) == 0) {
        return static_cast<std::uint32_t>(freq / 1000000);
    }
    return 0;
}

std::uint32_t ReadMemoryFrequency() {
    return 0;  // macOS doesn't easily expose RAM frequency
}
#endif

#if BASEFWX_WINDOWS
std::uint32_t ReadCpuMaxFrequency() {
    // Try to read from registry: HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0
    HKEY hKey;
    DWORD mhz = 0;
    DWORD size = sizeof(mhz);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "~MHz", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(&mhz), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return static_cast<std::uint32_t>(mhz);
        }
        RegCloseKey(hKey);
    }
    return 0;
}

std::uint32_t ReadMemoryFrequency() {
    return 0;  // Windows doesn't easily expose RAM frequency without WMI
}
#endif

}  // namespace

CpuInfo DetectCpuInfo() {
    CpuInfo info;
    
    // Logical cores (threads)
    info.logical_cores = std::thread::hardware_concurrency();
    if (info.logical_cores == 0) {
        info.logical_cores = 1;  // Fallback
    }
    
    // Physical cores - approximate (logical / 2 for hyperthreading)
    // This is not accurate, but a reasonable estimate
    info.physical_cores = info.logical_cores;
    
#if BASEFWX_LINUX
    // Try to read physical core count from /sys
    std::ifstream core_file("/sys/devices/system/cpu/cpu0/topology/core_siblings_list");
    if (core_file.is_open()) {
        // This is complex to parse accurately; use logical for now
    }
#endif

#if BASEFWX_MACOS
    std::uint32_t physical = 0;
    std::size_t size = sizeof(physical);
    if (sysctlbyname("hw.physicalcpu", &physical, &size, nullptr, 0) == 0) {
        info.physical_cores = physical;
    }
#endif

#if BASEFWX_WINDOWS
    // Use GetLogicalProcessorInformation for accurate physical core count
    DWORD len = 0;
    GetLogicalProcessorInformation(nullptr, &len);
    if (len > 0) {
        auto buffer = std::make_unique<std::uint8_t[]>(len);
        if (GetLogicalProcessorInformation(
                reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION*>(buffer.get()), &len)) {
            std::uint32_t count = 0;
            std::size_t num = len / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
            auto ptr = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION*>(buffer.get());
            for (std::size_t i = 0; i < num; ++i) {
                if (ptr[i].Relationship == RelationProcessorCore) {
                    count++;
                }
            }
            if (count > 0) {
                info.physical_cores = count;
            }
        }
    }
#endif
    
    info.max_frequency_mhz = ReadCpuMaxFrequency();
    
    return info;
}

MemoryInfo DetectMemoryInfo() {
    MemoryInfo info;
    
#if BASEFWX_LINUX
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_bytes = static_cast<std::uint64_t>(si.totalram) * si.mem_unit;
        std::uint64_t free = static_cast<std::uint64_t>(si.freeram) * si.mem_unit;
        std::uint64_t buffers = static_cast<std::uint64_t>(si.bufferram) * si.mem_unit;
        
        // Available = free + buffers + cached
        // Try reading /proc/meminfo for more accurate "MemAvailable"
        std::ifstream meminfo("/proc/meminfo");
        if (meminfo.is_open()) {
            std::string line;
            while (std::getline(meminfo, line)) {
                if (line.find("MemAvailable:") == 0) {
                    std::istringstream iss(line.substr(13));
                    std::uint64_t kb = 0;
                    iss >> kb;
                    info.available_bytes = kb * 1024;
                    break;
                }
            }
        }
        
        if (info.available_bytes == 0) {
            // Fallback estimate
            info.available_bytes = free + buffers;
        }
        
        info.used_bytes = info.total_bytes - info.available_bytes;
    }
    info.frequency_mhz = ReadMemoryFrequency();
#endif

#if BASEFWX_MACOS
    std::uint64_t mem = 0;
    std::size_t size = sizeof(mem);
    if (sysctlbyname("hw.memsize", &mem, &size, nullptr, 0) == 0) {
        info.total_bytes = mem;
    }
    
    // Get available memory using vm_statistics
    mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
    vm_statistics_data_t vm_stat;
    if (host_statistics(mach_host_self(), HOST_VM_INFO,
                        reinterpret_cast<host_info_t>(&vm_stat), &count) == KERN_SUCCESS) {
        std::uint64_t page_size = 0;
        size = sizeof(page_size);
        sysctlbyname("hw.pagesize", &page_size, &size, nullptr, 0);
        if (page_size == 0) page_size = 4096;
        
        std::uint64_t free = static_cast<std::uint64_t>(vm_stat.free_count) * page_size;
        std::uint64_t inactive = static_cast<std::uint64_t>(vm_stat.inactive_count) * page_size;
        info.available_bytes = free + inactive;
        info.used_bytes = info.total_bytes - info.available_bytes;
    }
    info.frequency_mhz = ReadMemoryFrequency();
#endif

#if BASEFWX_WINDOWS
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        info.total_bytes = mem.ullTotalPhys;
        info.available_bytes = mem.ullAvailPhys;
        info.used_bytes = info.total_bytes - info.available_bytes;
    }
    info.frequency_mhz = ReadMemoryFrequency();
#endif
    
    return info;
}

SystemInfo DetectSystemInfo() {
    SystemInfo info;
    info.cpu = DetectCpuInfo();
    info.memory = DetectMemoryInfo();
    
#if BASEFWX_LINUX
    info.os_name = "Linux";
#elif BASEFWX_MACOS
    info.os_name = "macOS";
#elif BASEFWX_WINDOWS
    info.os_name = "Windows";
#else
    info.os_name = "Unknown";
#endif

#if defined(__x86_64__) || defined(_M_X64)
    info.arch = "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
    info.arch = "x86";
#elif defined(__aarch64__) || defined(_M_ARM64)
    info.arch = "arm64";
#elif defined(__arm__) || defined(_M_ARM)
    info.arch = "arm";
#else
    info.arch = "unknown";
#endif
    
    return info;
}

std::string FormatBytes(std::uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    std::size_t unit = 0;
    double value = static_cast<double>(bytes);
    
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }
    
    std::ostringstream oss;
    oss.precision(1);
    oss << std::fixed << value << " " << units[unit];
    return oss.str();
}

std::string FormatFrequency(std::uint32_t mhz) {
    if (mhz == 0) {
        return "Unknown";
    }
    if (mhz >= 1000) {
        double ghz = static_cast<double>(mhz) / 1000.0;
        std::ostringstream oss;
        oss.precision(2);
        oss << std::fixed << ghz << " GHz";
        return oss.str();
    }
    return std::to_string(mhz) + " MHz";
}

ChunkSizePolicy GetChunkSizePolicy(const MemoryInfo& mem) {
    std::uint64_t avail_mb = mem.available_bytes / (1024 * 1024);
    
    if (avail_mb < 512) return ChunkSizePolicy::MINIMAL;
    if (avail_mb < 1024) return ChunkSizePolicy::TINY;
    if (avail_mb < 2048) return ChunkSizePolicy::SMALL;
    if (avail_mb < 4096) return ChunkSizePolicy::MEDIUM;
    if (avail_mb < 8192) return ChunkSizePolicy::LARGE;
    if (avail_mb < 16384) return ChunkSizePolicy::XLARGE;
    return ChunkSizePolicy::HUGE_CHUNK;
}

std::size_t ChunkSizeFromPolicy(ChunkSizePolicy policy) {
    switch (policy) {
        case ChunkSizePolicy::MINIMAL: return 4 * 1024;        // 4KB
        case ChunkSizePolicy::TINY:    return 16 * 1024;       // 16KB
        case ChunkSizePolicy::SMALL:   return 64 * 1024;       // 64KB
        case ChunkSizePolicy::MEDIUM:  return 256 * 1024;      // 256KB
        case ChunkSizePolicy::LARGE:   return 1024 * 1024;     // 1MB
        case ChunkSizePolicy::XLARGE:  return 4 * 1024 * 1024; // 4MB
        case ChunkSizePolicy::HUGE_CHUNK: return 16 * 1024 * 1024; // 16MB
        default: return 64 * 1024;
    }
}

std::size_t AutoTuneChunkSize(std::uint64_t file_size, const MemoryInfo& mem) {
    // Strategy:
    // 1. Start with policy-based chunk size
    // 2. If file is small, use smaller chunks
    // 3. Ensure we don't use more than 10% of available memory for buffering
    // 4. For very large files, use larger chunks for better throughput
    
    ChunkSizePolicy policy = GetChunkSizePolicy(mem);
    std::size_t base_chunk = ChunkSizeFromPolicy(policy);
    
    // If file is very small (< 1MB), use tiny chunks
    if (file_size < 1024 * 1024) {
        return std::min<std::size_t>(base_chunk, 16 * 1024);
    }
    
    // Maximum chunk size: 10% of available memory
    std::uint64_t max_chunk = mem.available_bytes / 10;
    if (max_chunk < base_chunk) {
        return static_cast<std::size_t>(max_chunk);
    }
    
    // For very large files (> 1GB), consider using larger chunks
    if (file_size > 1024ULL * 1024 * 1024 && mem.available_bytes > 4ULL * 1024 * 1024 * 1024) {
        // If we have > 4GB available RAM and file is > 1GB, use larger chunks
        base_chunk = std::max(base_chunk, static_cast<std::size_t>(4 * 1024 * 1024)); // At least 4MB
    }
    
    // Clamp to max_chunk
    return std::min<std::size_t>(base_chunk, static_cast<std::size_t>(max_chunk));
}

}  // namespace basefwx::system
