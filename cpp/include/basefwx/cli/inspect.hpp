#pragma once

#include "basefwx/basefwx.hpp"
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace basefwx::cli {

struct FwxAesHeaderInfo {
    std::uint8_t algo = 0;
    std::uint8_t kdf = 0;
    std::uint8_t salt_len = 0;
    std::uint8_t iv_len = 0;
    std::uint32_t field0 = 0;
    std::uint32_t ct_len32 = 0;
    std::optional<std::uint64_t> ct_len64;
    std::uint64_t file_size = 0;
};

struct LightweightInspect {
    basefwx::InspectResult info;
    std::uint64_t file_size = 0;
};

struct UnknownFileAnalysis {
    std::uint64_t file_size = 0;
    std::size_t sample_size = 0;
    double entropy_bits = 0.0;
    double printable_ratio = 0.0;
    double zero_ratio = 0.0;
    bool high_entropy = false;
    bool looks_random = false;
    std::string format_hint;
    std::string note;
};

std::optional<LightweightInspect> InspectLengthPrefixedFile(const std::filesystem::path& path);
bool MetadataNeedsFullFallback(const basefwx::InspectResult& info);
std::uint64_t InspectFallbackMaxBytes();
std::optional<std::vector<std::uint8_t>> TryReadFullInspectSafe(const std::filesystem::path& path,
                                                                std::string* reason);
void MaybeWarnInspectFallback(const std::string& reason);
std::optional<FwxAesHeaderInfo> ParseFwxAesHeader(const std::filesystem::path& path);
bool PrintIdentifyLengthPrefixed(const std::string& file_path, const LightweightInspect& inspect);
bool PrintIdentifyFwxAes(const std::string& file_path, const FwxAesHeaderInfo& info);
bool PrintIdentifyKfmCarrier(const std::string& file_path, const basefwx::KfmCarrierInspectResult& info);
bool PrintIdentifyUnknown(const std::string& file_path, const UnknownFileAnalysis& analysis);
void PrintFwxAesInfo(const FwxAesHeaderInfo& info);
void PrintKfmCarrierInfo(const basefwx::KfmCarrierInspectResult& info);
void PrintInspectInfo(const basefwx::InspectResult& info);
void PrintUnknownInfo(const UnknownFileAnalysis& analysis);
std::optional<UnknownFileAnalysis> AnalyzeUnknownFile(const std::filesystem::path& path);
std::string StripAsciiWhitespace(std::string value);

}  // namespace basefwx::cli
