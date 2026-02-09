#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace basefwx::system {

struct CpuInfo {
    std::uint32_t logical_cores = 0;
    std::uint32_t physical_cores = 0;
    std::uint32_t max_frequency_mhz = 0;  // 0 if unknown
    std::string vendor;
    std::string model;
};

struct MemoryInfo {
    std::uint64_t total_bytes = 0;
    std::uint64_t available_bytes = 0;
    std::uint64_t used_bytes = 0;
    std::uint32_t frequency_mhz = 0;  // 0 if unknown
};

struct SystemInfo {
    CpuInfo cpu;
    MemoryInfo memory;
    std::string os_name;
    std::string arch;
};

// Detect system information
SystemInfo DetectSystemInfo();
CpuInfo DetectCpuInfo();
MemoryInfo DetectMemoryInfo();

// Format bytes to human-readable string (e.g., "16.0 GB")
std::string FormatBytes(std::uint64_t bytes);

// Format frequency to human-readable string (e.g., "3.5 GHz")
std::string FormatFrequency(std::uint32_t mhz);

// Auto-tune chunk size based on:
// - Available memory
// - File size
// - System capabilities
// Returns optimal chunk size in bytes
std::size_t AutoTuneChunkSize(std::uint64_t file_size, const MemoryInfo& mem);

// Recommended chunk size categories
enum class ChunkSizePolicy {
    MINIMAL,      // 4KB - very limited memory (< 512MB available)
    TINY,         // 16KB - limited memory (< 1GB available)
    SMALL,        // 64KB - moderate memory (< 2GB available)
    MEDIUM,       // 256KB - good memory (< 4GB available)
    LARGE,        // 1MB - plenty of memory (< 8GB available)
    XLARGE,       // 4MB - lots of memory (< 16GB available)
    HUGE          // 16MB - massive memory (>= 16GB available)
};

ChunkSizePolicy GetChunkSizePolicy(const MemoryInfo& mem);
std::size_t ChunkSizeFromPolicy(ChunkSizePolicy policy);

}  // namespace basefwx::system
