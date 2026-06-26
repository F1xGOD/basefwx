/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/cli/inspect.hpp"
#include "basefwx/cli/globals.hpp"
#include "basefwx/cli_colors.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/system_info.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <new>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace basefwx::cli {

namespace {

std::string ExtractJsonField(const std::string& json, const std::string& key) {
    if (json.empty() || key.empty()) {
        return {};
    }
    std::string needle = "\"" + key + "\":";
    std::size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return {};
    }
    pos += needle.size();
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
        ++pos;
    }
    if (pos >= json.size()) {
        return {};
    }
    if (json[pos] == '"') {
        ++pos;
        std::string out;
        out.reserve(32);
        bool escape = false;
        while (pos < json.size()) {
            char ch = json[pos++];
            if (escape) {
                out.push_back(ch);
                escape = false;
                continue;
            }
            if (ch == '\\') {
                escape = true;
                continue;
            }
            if (ch == '"') {
                break;
            }
            out.push_back(ch);
        }
        return out;
    }
    std::size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}') {
        ++end;
    }
    return StripAsciiWhitespace(json.substr(pos, end - pos));
}
std::string FormatSize(std::uint64_t bytes) {
    std::ostringstream out;
    out << bytes << " bytes (" << basefwx::system::FormatBytes(bytes) << ")";
    return out.str();
}

void PrintIdentifyField(const std::string& key, const std::string& value) {
    std::cout << basefwx::cli::Cyan(key) << ": " << value << "\n";
}

std::string FormatPercent(double ratio) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << (ratio * 100.0) << "%";
    return out.str();
}

std::string FormatEntropy(double bits_per_byte) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(2) << bits_per_byte << " bits/byte";
    return out.str();
}

std::string DescribeKfmMode(std::uint8_t mode) {
    if (mode == 1u) {
        return "image->audio";
    }
    if (mode == 2u) {
        return "audio->image";
    }
    return "unknown";
}

std::string DescribeKfmFlags(std::uint8_t flags) {
    if (flags == 0u) {
        return "none";
    }
    std::string out;
    if ((flags & 0x01u) != 0u) {
        out = "bw";
    }
    std::uint8_t remaining = static_cast<std::uint8_t>(flags & ~0x01u);
    if (remaining != 0u) {
        if (!out.empty()) {
            out += ", ";
        }
        std::ostringstream hex;
        hex << "0x" << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(remaining);
        out += hex.str();
    }
    return out;
}
std::vector<std::uint8_t> ReadSampleBytes(const std::filesystem::path& path, std::size_t max_bytes) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::vector<std::uint8_t> data(max_bytes);
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    data.resize(static_cast<std::size_t>(input.gcount()));
    return data;
}

std::string DetectFormatHint(const std::vector<std::uint8_t>& sample) {
    if (sample.empty()) {
        return "empty file";
    }
    if (sample.size() >= 8
        && sample[0] == 0x89u && sample[1] == 0x50u && sample[2] == 0x4Eu && sample[3] == 0x47u
        && sample[4] == 0x0Du && sample[5] == 0x0Au && sample[6] == 0x1Au && sample[7] == 0x0Au) {
        return "PNG image";
    }
    if (sample.size() >= 12
        && sample[0] == 'R' && sample[1] == 'I' && sample[2] == 'F' && sample[3] == 'F'
        && sample[8] == 'W' && sample[9] == 'A' && sample[10] == 'V' && sample[11] == 'E') {
        return "WAV audio";
    }
    if (sample.size() >= 3 && sample[0] == 0xFFu && sample[1] == 0xD8u && sample[2] == 0xFFu) {
        return "JPEG image";
    }
    if (sample.size() >= 4 && sample[0] == 'P' && sample[1] == 'K'
        && (sample[2] == 0x03u || sample[2] == 0x05u || sample[2] == 0x07u)
        && (sample[3] == 0x04u || sample[3] == 0x06u || sample[3] == 0x08u)) {
        return "ZIP archive";
    }
    if (sample.size() >= 2 && sample[0] == 0x1Fu && sample[1] == 0x8Bu) {
        return "gzip stream";
    }
    if (sample.size() >= 5
        && sample[0] == '%' && sample[1] == 'P' && sample[2] == 'D' && sample[3] == 'F' && sample[4] == '-') {
        return "PDF document";
    }
    if (sample.size() >= 4 && sample[0] == 0x7Fu && sample[1] == 'E' && sample[2] == 'L' && sample[3] == 'F') {
        return "ELF binary";
    }
    if (sample.size() >= 4 && sample[0] == 'O' && sample[1] == 'g' && sample[2] == 'g' && sample[3] == 'S') {
        return "Ogg container";
    }
    if (sample.size() >= 3 && sample[0] == 'I' && sample[1] == 'D' && sample[2] == '3') {
        return "MP3/ID3 audio";
    }
    return {};
}
bool ReadU32Be(std::istream& in, std::uint32_t* out) {
    std::array<std::uint8_t, 4> buf{};
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (in.gcount() != static_cast<std::streamsize>(buf.size())) {
        return false;
    }
    *out = (static_cast<std::uint32_t>(buf[0]) << 24)
           | (static_cast<std::uint32_t>(buf[1]) << 16)
           | (static_cast<std::uint32_t>(buf[2]) << 8)
           | static_cast<std::uint32_t>(buf[3]);
    return true;
}

}  // namespace

std::string StripAsciiWhitespace(std::string value) {
    value.erase(std::remove_if(value.begin(),
                               value.end(),
                               [](unsigned char ch) { return std::isspace(ch) != 0; }),
                value.end());
    return value;
}
std::optional<UnknownFileAnalysis> AnalyzeUnknownFile(const std::filesystem::path& path) {
    constexpr std::size_t kSampleLimit = 256u << 10;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        return std::nullopt;
    }

    UnknownFileAnalysis analysis;
    analysis.file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        analysis.file_size = 0;
    }

    std::vector<std::uint8_t> sample = ReadSampleBytes(path, kSampleLimit);
    analysis.sample_size = sample.size();
    analysis.format_hint = DetectFormatHint(sample);
    if (sample.empty()) {
        analysis.note = "File is empty; no BaseFWX container markers were found.";
        return analysis;
    }

    std::array<std::uint64_t, 256> counts{};
    std::size_t printable = 0;
    for (std::uint8_t byte : sample) {
        ++counts[byte];
        if ((byte >= 32u && byte <= 126u) || byte == '\n' || byte == '\r' || byte == '\t') {
            ++printable;
        }
    }

    double entropy = 0.0;
    for (std::uint64_t count : counts) {
        if (count == 0) {
            continue;
        }
        double p = static_cast<double>(count) / static_cast<double>(sample.size());
        entropy -= p * std::log2(p);
    }
    analysis.entropy_bits = entropy;
    analysis.printable_ratio = static_cast<double>(printable) / static_cast<double>(sample.size());
    analysis.zero_ratio = static_cast<double>(counts[0]) / static_cast<double>(sample.size());
    analysis.high_entropy = entropy >= 7.50;
    analysis.looks_random = analysis.format_hint.empty()
        && entropy >= 7.85
        && analysis.zero_ratio <= 0.02;

    if (!analysis.format_hint.empty()) {
        analysis.note = "File looks like " + analysis.format_hint
            + ", but no BaseFWX length-prefixed header, FWX1 header, or kFM carrier marker was found.";
    } else if (analysis.looks_random) {
        analysis.note =
            "Sample is high-entropy/random-like. It may be AN7 output, other encrypted data, or compressed data.";
    } else if (analysis.high_entropy) {
        analysis.note =
            "Sample has high entropy but does not match a known BaseFWX container. It may be encrypted or compressed.";
    } else {
        analysis.note = "File does not match a known BaseFWX container and does not look fully random.";
    }
    return analysis;
}
std::optional<LightweightInspect> InspectLengthPrefixedFile(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec || file_size < 12) {
        return std::nullopt;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }

    std::uint64_t offset = 0;
    std::uint32_t len_user = 0;
    if (!ReadU32Be(in, &len_user)) {
        return std::nullopt;
    }
    offset += 4;
    if (offset + len_user + 4 > file_size) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(len_user), std::ios::cur);
    if (!in) {
        return std::nullopt;
    }
    offset += len_user;

    std::uint32_t len_master = 0;
    if (!ReadU32Be(in, &len_master)) {
        return std::nullopt;
    }
    offset += 4;
    if (offset + len_master + 4 > file_size) {
        return std::nullopt;
    }
    in.seekg(static_cast<std::streamoff>(len_master), std::ios::cur);
    if (!in) {
        return std::nullopt;
    }
    offset += len_master;

    std::uint32_t len_payload_u32 = 0;
    if (!ReadU32Be(in, &len_payload_u32)) {
        return std::nullopt;
    }
    offset += 4;
    if (offset > file_size) {
        return std::nullopt;
    }
    std::uint64_t payload_available = file_size - offset;
    if (static_cast<std::uint32_t>(payload_available) != len_payload_u32) {
        return std::nullopt;
    }

    LightweightInspect result;
    result.file_size = file_size;
    result.info.user_blob_len = len_user;
    result.info.master_blob_len = len_master;
    result.info.payload_len = static_cast<std::size_t>(payload_available);

    if (payload_available < 4) {
        return result;
    }

    std::uint32_t metadata_len = 0;
    if (!ReadU32Be(in, &metadata_len)) {
        return std::nullopt;
    }
    if (metadata_len > payload_available - 4) {
        return std::nullopt;
    }

    result.info.has_metadata = true;
    result.info.metadata_len = metadata_len;
    if (metadata_len == 0) {
        return result;
    }

    constexpr std::uint32_t kMaxMetadataInspectBytes = 1u << 20;
    if (metadata_len > kMaxMetadataInspectBytes) {
        result.info.metadata_json = {};
        return result;
    }

    std::vector<std::uint8_t> metadata_blob(metadata_len);
    in.read(reinterpret_cast<char*>(metadata_blob.data()), static_cast<std::streamsize>(metadata_blob.size()));
    if (in.gcount() != static_cast<std::streamsize>(metadata_blob.size())) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> payload_prefix;
    payload_prefix.reserve(4u + metadata_blob.size());
    payload_prefix.push_back(static_cast<std::uint8_t>((metadata_len >> 24) & 0xFF));
    payload_prefix.push_back(static_cast<std::uint8_t>((metadata_len >> 16) & 0xFF));
    payload_prefix.push_back(static_cast<std::uint8_t>((metadata_len >> 8) & 0xFF));
    payload_prefix.push_back(static_cast<std::uint8_t>(metadata_len & 0xFF));
    payload_prefix.insert(payload_prefix.end(), metadata_blob.begin(), metadata_blob.end());

    auto preview = basefwx::format::TryDecodeMetadata(payload_prefix);
    if (preview.has_value()) {
        result.info.metadata_base64 = preview->metadata_base64;
        result.info.metadata_json = preview->metadata_json;
    } else {
        result.info.metadata_json = {};
    }
    return result;
}

bool MetadataNeedsFullFallback(const basefwx::InspectResult& info) {
    return info.has_metadata && info.metadata_len > 0 && info.metadata_json.empty();
}

std::uint64_t InspectFallbackMaxBytes() {
    constexpr std::uint64_t kDefault = 256ull << 20;  // 256 MiB
    std::string raw = basefwx::env::Get("BASEFWX_INSPECT_FALLBACK_MAX_BYTES");
    if (raw.empty()) {
        return kDefault;
    }
    try {
        std::uint64_t parsed = std::stoull(raw);
        if (parsed < (1ull << 20)) {
            return 1ull << 20;
        }
        return parsed;
    } catch (const std::exception&) {
        return kDefault;
    }
}

std::optional<std::vector<std::uint8_t>> TryReadFullInspectSafe(const std::filesystem::path& path,
                                                                std::string* reason) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        if (reason) {
            *reason = "file does not exist or is not a regular file";
        }
        return std::nullopt;
    }
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        if (reason) {
            *reason = "failed to stat file";
        }
        return std::nullopt;
    }

    bool unsafe = basefwx::env::IsEnabled("BASEFWX_INSPECT_FALLBACK_UNSAFE", false);
    std::uint64_t max_bytes = InspectFallbackMaxBytes();
    if (!unsafe && file_size > max_bytes) {
        if (reason) {
            std::ostringstream msg;
            msg << "full-read fallback skipped for safety (file="
                << basefwx::system::FormatBytes(file_size)
                << ", limit=" << basefwx::system::FormatBytes(max_bytes)
                << "; set BASEFWX_INSPECT_FALLBACK_UNSAFE=1 to force)";
            *reason = msg.str();
        }
        return std::nullopt;
    }

    try {
        return basefwx::ReadFile(path.string());
    } catch (const std::bad_alloc&) {
        if (reason) {
            *reason = "full-read fallback aborted: out of memory";
        }
        return std::nullopt;
    } catch (const std::exception& ex) {
        if (reason) {
            *reason = std::string("full-read fallback failed: ") + ex.what();
        }
        return std::nullopt;
    }
}

void MaybeWarnInspectFallback(const std::string& reason) {
    if (reason.empty() || !ShouldLog()) {
        return;
    }
    std::cerr << basefwx::cli::BoldYellow("[WARN] ") << reason << "\n";
}

std::optional<FwxAesHeaderInfo> ParseFwxAesHeader(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::uint64_t file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec || file_size < 16) {
        return std::nullopt;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::array<std::uint8_t, 16> head{};
    in.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
    if (in.gcount() != static_cast<std::streamsize>(head.size())) {
        return std::nullopt;
    }
    if (head[0] != 'F' || head[1] != 'W' || head[2] != 'X' || head[3] != '1') {
        return std::nullopt;
    }

    auto u32 = [&](std::size_t off) -> std::uint32_t {
        return (static_cast<std::uint32_t>(head[off]) << 24)
               | (static_cast<std::uint32_t>(head[off + 1]) << 16)
               | (static_cast<std::uint32_t>(head[off + 2]) << 8)
               | static_cast<std::uint32_t>(head[off + 3]);
    };

    FwxAesHeaderInfo out;
    out.algo = head[4];
    out.kdf = head[5];
    out.salt_len = head[6];
    out.iv_len = head[7];
    out.field0 = u32(8);
    out.ct_len32 = u32(12);
    out.file_size = file_size;

    std::uint64_t offset = 16;
    if (out.kdf == 0x01) {
        offset += static_cast<std::uint64_t>(out.salt_len) + static_cast<std::uint64_t>(out.iv_len);
    } else if (out.kdf == 0x02) {
        offset += static_cast<std::uint64_t>(out.field0) + static_cast<std::uint64_t>(out.iv_len);
    }

    if (out.algo == 0x02 && offset + 8 <= file_size) {
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        std::array<std::uint8_t, 8> buf{};
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (in.gcount() == static_cast<std::streamsize>(buf.size())) {
            std::uint64_t v = 0;
            for (std::uint8_t b : buf) {
                v = (v << 8) | b;
            }
            out.ct_len64 = v;
        }
    }
    return out;
}

bool PrintIdentifyLengthPrefixed(const std::string& file_path,
                                 const LightweightInspect& inspect) {
    const basefwx::InspectResult& info = inspect.info;
    std::string method = ExtractJsonField(info.metadata_json, "ENC-METHOD");
    std::string version = ExtractJsonField(info.metadata_json, "ENC-VERSION");
    std::string mode = ExtractJsonField(info.metadata_json, "ENC-MODE");
    std::string kdf = ExtractJsonField(info.metadata_json, "ENC-KDF");
    std::string aead = ExtractJsonField(info.metadata_json, "ENC-AEAD");
    std::string master = ExtractJsonField(info.metadata_json, "ENC-MASTER");
    std::string obf = ExtractJsonField(info.metadata_json, "ENC-OBF");
    std::string time = ExtractJsonField(info.metadata_json, "ENC-TIME");
    std::string kem = ExtractJsonField(info.metadata_json, "ENC-KEM");

    if (method.empty()) {
        method = "unknown";
    }
    if (version.empty()) {
        version = "unknown";
    }
    if (mode.empty()) {
        mode = "normal";
    }
    if (kdf.empty()) {
        kdf = "unknown";
    }
    if (aead.empty()) {
        aead = "unknown";
    }
    if (master.empty()) {
        master = "unknown";
    }
    if (obf.empty()) {
        obf = "unknown";
    }
    if (kem.empty()) {
        kem = "unknown";
    }
    if (time.empty()) {
        time = "unknown";
    }

    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", file_path);
    PrintIdentifyField("format", "basefwx length-prefixed container");
    PrintIdentifyField("integrity", basefwx::cli::BoldGreen("OK"));
    PrintIdentifyField("method", method);
    PrintIdentifyField("version", version);
    PrintIdentifyField("mode", mode);
    PrintIdentifyField("kdf", kdf);
    PrintIdentifyField("aead", aead);
    PrintIdentifyField("master", master);
    PrintIdentifyField("kem", kem);
    PrintIdentifyField("obfuscation", obf);
    PrintIdentifyField("encrypted_at", time);
    PrintIdentifyField("file_size", FormatSize(inspect.file_size));
    PrintIdentifyField("payload_size", FormatSize(static_cast<std::uint64_t>(info.payload_len)));
    PrintIdentifyField("user_blob", FormatSize(static_cast<std::uint64_t>(info.user_blob_len)));
    PrintIdentifyField("master_blob", FormatSize(static_cast<std::uint64_t>(info.master_blob_len)));
    if (info.has_metadata) {
        PrintIdentifyField("metadata_size", FormatSize(static_cast<std::uint64_t>(info.metadata_len)));
    } else {
        PrintIdentifyField("metadata_size", "unavailable");
    }
    return true;
}

bool PrintIdentifyFwxAes(const std::string& file_path, const FwxAesHeaderInfo& header) {
    std::string algo_name = "unknown";
    if (header.algo == 0x01) {
        algo_name = "fwxaes-v1";
    } else if (header.algo == 0x02) {
        algo_name = "fwxaes-stream-v2";
    }
    std::string kdf_name = "unknown";
    if (header.kdf == 0x01) {
        kdf_name = "pbkdf2";
    } else if (header.kdf == 0x02) {
        kdf_name = "wrapped";
    }

    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", file_path);
    PrintIdentifyField("format", "FWX1 header container");
    PrintIdentifyField("integrity", basefwx::cli::BoldGreen("OK"));
    PrintIdentifyField("algo", algo_name + " (" + std::to_string(static_cast<unsigned int>(header.algo)) + ")");
    PrintIdentifyField("kdf", kdf_name + " (" + std::to_string(static_cast<unsigned int>(header.kdf)) + ")");
    PrintIdentifyField("salt_len", std::to_string(static_cast<unsigned int>(header.salt_len)) + " bytes");
    PrintIdentifyField("iv_len", std::to_string(static_cast<unsigned int>(header.iv_len)) + " bytes");
    if (header.kdf == 0x01) {
        PrintIdentifyField("pbkdf2_iters", std::to_string(header.field0));
    } else if (header.kdf == 0x02) {
        PrintIdentifyField("key_header_len", std::to_string(header.field0) + " bytes");
    }
    if (header.ct_len64.has_value()) {
        PrintIdentifyField("ciphertext_len", FormatSize(*header.ct_len64));
    } else {
        PrintIdentifyField("ciphertext_len", FormatSize(header.ct_len32));
    }
    PrintIdentifyField("file_size", FormatSize(static_cast<std::uint64_t>(header.file_size)));
    return true;
}

bool PrintIdentifyKfmCarrier(const std::string& file_path, const basefwx::KfmCarrierInspectResult& info) {
    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", file_path);
    PrintIdentifyField("format", "basefwx kFM carrier");
    PrintIdentifyField("integrity", basefwx::cli::BoldGreen("OK"));
    PrintIdentifyField("carrier_kind", info.carrier_kind);
    PrintIdentifyField("mode", DescribeKfmMode(info.mode) + " (" + std::to_string(static_cast<unsigned int>(info.mode)) + ")");
    PrintIdentifyField("flags", DescribeKfmFlags(info.flags));
    PrintIdentifyField("payload_ext", info.payload_ext.empty() ? ".bin" : info.payload_ext);
    PrintIdentifyField("payload_size", FormatSize(static_cast<std::uint64_t>(info.payload_len)));
    PrintIdentifyField("file_size", FormatSize(info.file_size));
    return true;
}

bool PrintIdentifyUnknown(const std::string& file_path, const UnknownFileAnalysis& analysis) {
    std::cout << basefwx::cli::BoldBlue("basefwx identify") << "\n";
    PrintIdentifyField("file", file_path);
    PrintIdentifyField("format", "unknown");
    PrintIdentifyField("status", analysis.looks_random ? "unidentified high-entropy data" : "unidentified");
    if (!analysis.format_hint.empty()) {
        PrintIdentifyField("format_hint", analysis.format_hint);
    }
    PrintIdentifyField("entropy", FormatEntropy(analysis.entropy_bits));
    PrintIdentifyField("printable", FormatPercent(analysis.printable_ratio));
    PrintIdentifyField("zero_bytes", FormatPercent(analysis.zero_ratio));
    PrintIdentifyField("sample_size", FormatSize(static_cast<std::uint64_t>(analysis.sample_size)));
    PrintIdentifyField("file_size", FormatSize(analysis.file_size));
    PrintIdentifyField("note", analysis.note);
    return true;
}

void PrintFwxAesInfo(const FwxAesHeaderInfo& header) {

    std::string algo_name = "unknown";
    if (header.algo == 0x01) {
        algo_name = "fwxaes-v1";
    } else if (header.algo == 0x02) {
        algo_name = "fwxaes-stream-v2";
    }
    std::string kdf_name = "unknown";
    if (header.kdf == 0x01) {
        kdf_name = "pbkdf2";
    } else if (header.kdf == 0x02) {
        kdf_name = "wrapped";
    }

    std::cout << "format: fwxAES\n";
    std::cout << "algo: " << algo_name << " (" << static_cast<unsigned int>(header.algo) << ")\n";
    std::cout << "kdf: " << kdf_name << " (" << static_cast<unsigned int>(header.kdf) << ")\n";
    std::cout << "salt_len: " << static_cast<unsigned int>(header.salt_len) << " bytes\n";
    std::cout << "iv_len: " << static_cast<unsigned int>(header.iv_len) << " bytes\n";
    if (header.kdf == 0x01) {
        std::cout << "pbkdf2_iters: " << header.field0 << "\n";
    } else if (header.kdf == 0x02) {
        std::cout << "key_header_len: " << header.field0 << " bytes\n";
    }
    if (header.ct_len64.has_value()) {
        std::cout << "ciphertext_len: " << *header.ct_len64 << " bytes\n";
    } else {
        std::cout << "ciphertext_len: " << header.ct_len32 << " bytes\n";
    }
    std::cout << "file_size: " << header.file_size << " bytes\n";
}

void PrintKfmCarrierInfo(const basefwx::KfmCarrierInspectResult& info) {
    std::cout << "format: kFM carrier\n";
    std::cout << "carrier_kind: " << info.carrier_kind << "\n";
    std::cout << "mode: " << DescribeKfmMode(info.mode)
              << " (" << static_cast<unsigned int>(info.mode) << ")\n";
    std::cout << "flags: " << DescribeKfmFlags(info.flags) << "\n";
    std::cout << "payload_ext: " << (info.payload_ext.empty() ? ".bin" : info.payload_ext) << "\n";
    std::cout << "payload_len: " << info.payload_len << " bytes\n";
    std::cout << "file_size: " << info.file_size << " bytes\n";
}

void PrintInspectInfo(const basefwx::InspectResult& info) {
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
}

void PrintUnknownInfo(const UnknownFileAnalysis& analysis) {
    std::cout << "format: unknown\n";
    if (!analysis.format_hint.empty()) {
        std::cout << "format_hint: " << analysis.format_hint << "\n";
    }
    std::cout << "entropy: " << FormatEntropy(analysis.entropy_bits) << "\n";
    std::cout << "printable: " << FormatPercent(analysis.printable_ratio) << "\n";
    std::cout << "zero_bytes: " << FormatPercent(analysis.zero_ratio) << "\n";
    std::cout << "sample_size: " << analysis.sample_size << " bytes\n";
    std::cout << "file_size: " << analysis.file_size << " bytes\n";
    std::cout << "status: " << (analysis.looks_random ? "unidentified high-entropy data" : "unidentified") << "\n";
    std::cout << "note: " << analysis.note << "\n";
}

}  // namespace basefwx::cli
