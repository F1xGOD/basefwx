#include "basefwx/an7.hpp"

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/crypto_utils.hpp"
#include "basefwx/runtime.hpp"

#include <openssl/evp.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace basefwx {
namespace {

using Bytes = basefwx::crypto::Bytes;

constexpr std::size_t kAn7ChunkSize = 1u << 20;          // 1 MiB
constexpr std::size_t kAn7SuperblockChunks = 10;
constexpr std::size_t kAn7FlipStride = 10;
constexpr std::size_t kFooterSize = 64;
constexpr std::size_t kTailPlainLen = 20;
constexpr std::size_t kTailNonceLen = 12;
constexpr std::size_t kTailCipherLen = 20;
constexpr std::size_t kTailTagLen = 16;
constexpr std::size_t kSaltLen = 16;
constexpr std::size_t kTrailerNonceLen = 12;
constexpr std::size_t kSha256Len = 32;
constexpr std::size_t kDefaultCreatedLenLimit = 64;
constexpr std::uint32_t kArgon2TimeCost = 5;
constexpr std::uint32_t kArgon2MemoryKiB = 131072;
constexpr std::uint32_t kArgon2Parallelism = 4;
constexpr std::uint64_t kTenDigitsMod = 10000000000ULL;
constexpr std::string_view kTrailerVersion = "AN7v1";

class TempFileCleanup {
public:
    explicit TempFileCleanup(std::filesystem::path path)
        : path_(std::move(path)) {}

    TempFileCleanup(const TempFileCleanup&) = delete;
    TempFileCleanup& operator=(const TempFileCleanup&) = delete;

    ~TempFileCleanup() {
        if (!active_) {
            return;
        }
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    void Dismiss() noexcept {
        active_ = false;
    }

private:
    std::filesystem::path path_;
    bool active_ = true;
};

struct Sha256Hasher {
    Sha256Hasher() {
        ctx_ = basefwx::crypto::detail::UniqueMDCtx(EVP_MD_CTX_new());
        if (!ctx_) {
            throw std::runtime_error("SHA-256 context allocation failed");
        }
        if (EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("SHA-256 init failed");
        }
    }

    void Update(const std::uint8_t* data, std::size_t len) {
        if (len == 0) {
            return;
        }
        if (EVP_DigestUpdate(ctx_.get(), data, len) != 1) {
            throw std::runtime_error("SHA-256 update failed");
        }
    }

    std::array<std::uint8_t, kSha256Len> Final() {
        std::array<std::uint8_t, kSha256Len> out{};
        unsigned int out_len = 0;
        if (EVP_DigestFinal_ex(ctx_.get(), out.data(), &out_len) != 1 || out_len != kSha256Len) {
            throw std::runtime_error("SHA-256 final failed");
        }
        return out;
    }

private:
    basefwx::crypto::detail::UniqueMDCtx ctx_;
};

struct An7Keys {
    Bytes stream;
    Bytes perm;
    Bytes meta;
    Bytes tail;
};

struct TrailerInfo {
    std::string format_version;
    std::string original_basename;
    std::string original_extension;
    std::uint64_t original_size = 0;
    std::uint32_t chunk_size = static_cast<std::uint32_t>(kAn7ChunkSize);
    std::uint16_t superblock_chunks = static_cast<std::uint16_t>(kAn7SuperblockChunks);
    std::uint16_t flip_stride = static_cast<std::uint16_t>(kAn7FlipStride);
    Bytes stream_nonce;
    std::array<std::uint8_t, kSha256Len> sha256_original{};
    std::string created_utc;
};

struct FooterInfo {
    Bytes salt;
    Bytes tail_nonce;
    std::uint64_t trailer_len = 0;
    std::uint64_t payload_len = 0;
    std::uint32_t trailer_crc32 = 0;
};

struct FooterContext {
    An7Keys keys;
    FooterInfo footer;
};

void ThrowIfInterrupted() {
    if (basefwx::runtime::StopRequested()) {
        throw std::runtime_error("Interrupted");
    }
}

std::string ToLower(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

void RequireRegularFile(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        throw std::runtime_error("Input file not found: " + path.string());
    }
}

std::uint64_t FileSize(const std::filesystem::path& path) {
    std::error_code ec;
    std::uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        throw std::runtime_error("Failed to read file size: " + path.string());
    }
    return size;
}

void EnsureParentDir(const std::filesystem::path& path) {
    if (path.parent_path().empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        throw std::runtime_error("Failed to create output directory: " + path.parent_path().string());
    }
}

void ReadExact(std::ifstream& in, std::uint8_t* dst, std::size_t len, const std::string& err) {
    if (len == 0) {
        return;
    }
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(len));
    if (in.gcount() != static_cast<std::streamsize>(len)) {
        throw std::runtime_error(err);
    }
}

void WriteExact(std::ofstream& out, const std::uint8_t* src, std::size_t len, const std::string& err) {
    if (len == 0) {
        return;
    }
    out.write(reinterpret_cast<const char*>(src), static_cast<std::streamsize>(len));
    if (!out) {
        throw std::runtime_error(err);
    }
}

void PushU16Le(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void PushU32Le(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
}

void PushU64Le(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
    }
}

std::uint16_t ReadU16Le(const Bytes& data, std::size_t& offset) {
    if (offset + 2 > data.size()) {
        throw std::runtime_error("AN7 trailer is truncated (u16)");
    }
    std::uint16_t value = static_cast<std::uint16_t>(data[offset])
        | static_cast<std::uint16_t>(data[offset + 1] << 8);
    offset += 2;
    return value;
}

std::uint32_t ReadU32Le(const Bytes& data, std::size_t& offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("AN7 trailer is truncated (u32)");
    }
    std::uint32_t value = static_cast<std::uint32_t>(data[offset])
        | (static_cast<std::uint32_t>(data[offset + 1]) << 8)
        | (static_cast<std::uint32_t>(data[offset + 2]) << 16)
        | (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
}

std::uint64_t ReadU64Le(const Bytes& data, std::size_t& offset) {
    if (offset + 8 > data.size()) {
        throw std::runtime_error("AN7 trailer is truncated (u64)");
    }
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(data[offset + static_cast<std::size_t>(i)]) << (i * 8);
    }
    offset += 8;
    return value;
}

std::uint64_t ReadU64LeRaw(const std::uint8_t* ptr) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(ptr[static_cast<std::size_t>(i)]) << (i * 8);
    }
    return value;
}

std::uint32_t ReadU32LeRaw(const std::uint8_t* ptr) {
    return static_cast<std::uint32_t>(ptr[0])
        | (static_cast<std::uint32_t>(ptr[1]) << 8)
        | (static_cast<std::uint32_t>(ptr[2]) << 16)
        | (static_cast<std::uint32_t>(ptr[3]) << 24);
}

std::string HexEncode(const std::uint8_t* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        const std::uint8_t byte = data[i];
        out.push_back(kHex[(byte >> 4) & 0x0F]);
        out.push_back(kHex[byte & 0x0F]);
    }
    return out;
}

Bytes HexDecode(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid AN7 trailer hash encoding");
    }
    auto nibble = [](char ch) -> std::uint8_t {
        if (ch >= '0' && ch <= '9') {
            return static_cast<std::uint8_t>(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f') {
            return static_cast<std::uint8_t>(10 + (ch - 'a'));
        }
        if (ch >= 'A' && ch <= 'F') {
            return static_cast<std::uint8_t>(10 + (ch - 'A'));
        }
        throw std::runtime_error("Invalid AN7 trailer hash encoding");
    };
    Bytes out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]));
    }
    return out;
}

std::string UtcTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[32] = {};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        throw std::runtime_error("Failed to format UTC timestamp");
    }
    return std::string(buf);
}

std::string RandomDigits10() {
    Bytes rnd = basefwx::crypto::RandomBytes(8);
    std::uint64_t value = 0;
    for (std::uint8_t b : rnd) {
        value = (value << 8) | static_cast<std::uint64_t>(b);
    }
    value %= kTenDigitsMod;
    std::ostringstream oss;
    oss << std::setw(10) << std::setfill('0') << value;
    return oss.str();
}

std::filesystem::path EnsureCollisionSuffix(const std::filesystem::path& desired) {
    std::error_code ec;
    if (!std::filesystem::exists(desired, ec)) {
        return desired;
    }
    const std::string base = desired.string();
    for (std::uint64_t i = 1; i < std::numeric_limits<std::uint32_t>::max(); ++i) {
        std::filesystem::path candidate(base + "." + std::to_string(i));
        ec.clear();
        if (!std::filesystem::exists(candidate, ec)) {
            return candidate;
        }
    }
    throw std::runtime_error("Unable to resolve output path collision");
}

bool SameLogicalPath(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    std::error_code ec;
    if (std::filesystem::exists(lhs, ec) && std::filesystem::exists(rhs, ec)) {
        ec.clear();
        return std::filesystem::equivalent(lhs, rhs, ec) && !ec;
    }
    return lhs.lexically_normal() == rhs.lexically_normal();
}

std::filesystem::path MakeTempPath(const std::filesystem::path& final_path) {
    for (int tries = 0; tries < 128; ++tries) {
        std::filesystem::path candidate =
            final_path.parent_path() / (final_path.filename().string() + ".tmp." + RandomDigits10());
        std::error_code ec;
        if (!std::filesystem::exists(candidate, ec)) {
            return candidate;
        }
    }
    throw std::runtime_error("Failed to allocate temp output file path");
}

void CommitTempFile(const std::filesystem::path& temp_path, const std::filesystem::path& final_path) {
    std::error_code ec;
    std::filesystem::rename(temp_path, final_path, ec);
    if (!ec) {
        return;
    }

    ec.clear();
    std::filesystem::copy_file(temp_path, final_path, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        throw std::runtime_error("Failed to finalize AN7 output: " + final_path.string());
    }

    ec.clear();
    std::filesystem::remove(temp_path, ec);
    if (ec) {
        throw std::runtime_error("Failed to remove AN7 temp file: " + temp_path.string());
    }
}

std::string SanitizeBasename(std::string value) {
    for (char& ch : value) {
        unsigned char byte = static_cast<unsigned char>(ch);
        if (ch == '/' || ch == '\\' || byte < 32) {
            ch = '_';
        }
    }
    if (value.empty()) {
        value = "data";
    }
    return value;
}

std::string SanitizeExtension(std::string value) {
    if (value.empty()) {
        return {};
    }
    if (value.front() != '.') {
        value.insert(value.begin(), '.');
    }
    for (char& ch : value) {
        if (ch == '.') {
            continue;
        }
        unsigned char byte = static_cast<unsigned char>(ch);
        bool ok = (std::isalnum(byte) != 0) || ch == '_' || ch == '-';
        if (!ok) {
            ch = '_';
        }
    }
    return value;
}

Bytes BuildLabel(std::string_view prefix, const Bytes& nonce, std::uint64_t index) {
    Bytes out;
    out.reserve(prefix.size() + nonce.size() + 8);
    out.insert(out.end(), prefix.begin(), prefix.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    PushU64Le(out, index);
    return out;
}

std::array<std::uint8_t, 16> DeriveCtrIv(const Bytes& stream_key,
                                         const Bytes& stream_nonce,
                                         std::uint64_t chunk_index) {
    Bytes label = BuildLabel("ctr:", stream_nonce, chunk_index);
    Bytes digest = basefwx::crypto::HmacSha256(stream_key, label);
    if (digest.size() < 16) {
        throw std::runtime_error("Failed to derive AN7 stream IV");
    }
    std::array<std::uint8_t, 16> iv{};
    std::memcpy(iv.data(), digest.data(), iv.size());
    return iv;
}

void ApplyXorTransform(Bytes& chunk,
                       const Bytes& stream_key,
                       const Bytes& stream_nonce,
                       std::uint64_t chunk_index) {
    if (chunk.empty()) {
        return;
    }
    auto iv_arr = DeriveCtrIv(stream_key, stream_nonce, chunk_index);
    Bytes iv(iv_arr.begin(), iv_arr.end());
    Bytes out = basefwx::crypto::AesCtrTransform(stream_key, iv, chunk);
    chunk.swap(out);
}

std::uint64_t SplitMix64(std::uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = state;
    z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31U);
}

std::vector<std::size_t> BuildPermutation(const Bytes& perm_key,
                                          std::uint64_t superblock_index,
                                          std::size_t count) {
    std::vector<std::size_t> order(count);
    std::iota(order.begin(), order.end(), 0);
    if (count <= 1) {
        return order;
    }
    Bytes label;
    label.reserve(13);
    label.insert(label.end(), {'p', 'e', 'r', 'm', ':'});
    PushU64Le(label, superblock_index);
    Bytes digest = basefwx::crypto::HmacSha256(perm_key, label);
    if (digest.size() < 8) {
        throw std::runtime_error("Failed to derive AN7 permutation seed");
    }
    std::uint64_t rng_state = ReadU64LeRaw(digest.data());
    for (std::size_t i = count - 1; i > 0; --i) {
        const std::uint64_t r = SplitMix64(rng_state);
        const std::size_t j = static_cast<std::size_t>(r % static_cast<std::uint64_t>(i + 1));
        std::swap(order[i], order[j]);
    }
    return order;
}

std::size_t FlipStart(const Bytes& perm_key, std::uint64_t chunk_index, std::size_t stride) {
    if (stride == 0) {
        return 0;
    }
    Bytes label;
    label.reserve(13);
    label.insert(label.end(), {'f', 'l', 'i', 'p', ':'});
    PushU64Le(label, chunk_index);
    Bytes digest = basefwx::crypto::HmacSha256(perm_key, label);
    if (digest.size() < 8) {
        throw std::runtime_error("Failed to derive AN7 flip offset");
    }
    return static_cast<std::size_t>(ReadU64LeRaw(digest.data()) % static_cast<std::uint64_t>(stride));
}

void ApplySparseFlip(Bytes& chunk, std::size_t start, std::size_t stride) {
    if (chunk.empty() || stride == 0) {
        return;
    }
    for (std::size_t i = start; i < chunk.size(); i += stride) {
        chunk[i] ^= 0xFFu;
    }
}

std::size_t ChunkBytesAt(std::uint64_t payload_len,
                         std::size_t chunk_size,
                         std::uint64_t chunk_index) {
    if (payload_len == 0) {
        return 0;
    }
    const std::uint64_t offset = chunk_index * static_cast<std::uint64_t>(chunk_size);
    if (offset >= payload_len) {
        return 0;
    }
    const std::uint64_t remain = payload_len - offset;
    return static_cast<std::size_t>(
        std::min<std::uint64_t>(remain, static_cast<std::uint64_t>(chunk_size)));
}

std::uint64_t TotalChunks(std::uint64_t payload_len, std::size_t chunk_size) {
    if (payload_len == 0) {
        return 0;
    }
    return (payload_len + static_cast<std::uint64_t>(chunk_size) - 1ULL)
        / static_cast<std::uint64_t>(chunk_size);
}

An7Keys DeriveKeys(const std::string& password, const Bytes& salt) {
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    if (password.empty()) {
        throw std::runtime_error("Password is required for AN7");
    }
    Bytes root = basefwx::crypto::Argon2idHashRaw(
        password,
        salt,
        kArgon2TimeCost,
        kArgon2MemoryKiB,
        kArgon2Parallelism,
        64
    );
    An7Keys keys;
    keys.stream = basefwx::crypto::HkdfSha256(root, "an7-stream", 32);
    keys.perm = basefwx::crypto::HkdfSha256(root, "an7-perm", 32);
    keys.meta = basefwx::crypto::HkdfSha256(root, "an7-meta", 32);
    keys.tail = basefwx::crypto::HkdfSha256(root, "an7-tail", 32);
    basefwx::crypto::SecureClear(root);
    return keys;
#else
    (void)password;
    (void)salt;
    throw std::runtime_error("AN7 requires Argon2 support in this build");
#endif
}

Bytes SerializeTrailer(const TrailerInfo& info) {
    if (info.stream_nonce.size() != kTrailerNonceLen) {
        throw std::runtime_error("AN7 trailer has invalid stream nonce length");
    }
    if (info.original_basename.size() > std::numeric_limits<std::uint16_t>::max()
        || info.original_extension.size() > std::numeric_limits<std::uint16_t>::max()
        || info.created_utc.size() > kDefaultCreatedLenLimit) {
        throw std::runtime_error("AN7 trailer metadata is too large");
    }
    Bytes out;
    out.reserve(128 + info.original_basename.size() + info.original_extension.size());
    out.insert(out.end(), kTrailerVersion.begin(), kTrailerVersion.end());
    PushU32Le(out, info.chunk_size);
    PushU16Le(out, info.superblock_chunks);
    PushU16Le(out, info.flip_stride);
    PushU64Le(out, info.original_size);
    PushU16Le(out, static_cast<std::uint16_t>(info.created_utc.size()));
    out.insert(out.end(), info.created_utc.begin(), info.created_utc.end());
    out.insert(out.end(), info.stream_nonce.begin(), info.stream_nonce.end());
    out.insert(out.end(), info.sha256_original.begin(), info.sha256_original.end());
    PushU16Le(out, static_cast<std::uint16_t>(info.original_basename.size()));
    out.insert(out.end(), info.original_basename.begin(), info.original_basename.end());
    PushU16Le(out, static_cast<std::uint16_t>(info.original_extension.size()));
    out.insert(out.end(), info.original_extension.begin(), info.original_extension.end());
    return out;
}

TrailerInfo ParseTrailer(const Bytes& plain) {
    TrailerInfo info;
    if (plain.size() < kTrailerVersion.size() + 4 + 2 + 2 + 8 + 2 + kTrailerNonceLen + kSha256Len + 2 + 2) {
        throw std::runtime_error("AN7 trailer is too short");
    }
    std::size_t offset = 0;
    if (!std::equal(kTrailerVersion.begin(), kTrailerVersion.end(), plain.begin())) {
        throw std::runtime_error("AN7 trailer version mismatch");
    }
    info.format_version = std::string(kTrailerVersion);
    offset += kTrailerVersion.size();

    info.chunk_size = ReadU32Le(plain, offset);
    info.superblock_chunks = ReadU16Le(plain, offset);
    info.flip_stride = ReadU16Le(plain, offset);
    info.original_size = ReadU64Le(plain, offset);

    const std::uint16_t created_len = ReadU16Le(plain, offset);
    if (created_len > kDefaultCreatedLenLimit || offset + created_len > plain.size()) {
        throw std::runtime_error("AN7 trailer created timestamp is invalid");
    }
    info.created_utc.assign(reinterpret_cast<const char*>(plain.data() + offset), created_len);
    offset += created_len;

    if (offset + kTrailerNonceLen + kSha256Len > plain.size()) {
        throw std::runtime_error("AN7 trailer payload is truncated");
    }
    info.stream_nonce.assign(plain.begin() + static_cast<std::ptrdiff_t>(offset),
                             plain.begin() + static_cast<std::ptrdiff_t>(offset + kTrailerNonceLen));
    offset += kTrailerNonceLen;

    std::memcpy(info.sha256_original.data(), plain.data() + offset, info.sha256_original.size());
    offset += info.sha256_original.size();

    const std::uint16_t basename_len = ReadU16Le(plain, offset);
    if (offset + basename_len > plain.size()) {
        throw std::runtime_error("AN7 trailer basename is truncated");
    }
    info.original_basename.assign(reinterpret_cast<const char*>(plain.data() + offset), basename_len);
    offset += basename_len;

    const std::uint16_t ext_len = ReadU16Le(plain, offset);
    if (offset + ext_len > plain.size()) {
        throw std::runtime_error("AN7 trailer extension is truncated");
    }
    info.original_extension.assign(reinterpret_cast<const char*>(plain.data() + offset), ext_len);
    offset += ext_len;

    if (offset != plain.size()) {
        throw std::runtime_error("AN7 trailer has trailing bytes");
    }
    return info;
}

Bytes BuildTailPlain(std::uint64_t trailer_len,
                     std::uint64_t payload_len,
                     std::uint32_t trailer_crc32) {
    Bytes plain;
    plain.reserve(kTailPlainLen);
    PushU64Le(plain, trailer_len);
    PushU64Le(plain, payload_len);
    PushU32Le(plain, trailer_crc32);
    return plain;
}

FooterContext ParseFooterAndDerive(const std::array<std::uint8_t, kFooterSize>& footer,
                                   const std::string& password) {
    FooterInfo info;
    info.salt.assign(footer.begin(), footer.begin() + static_cast<std::ptrdiff_t>(kSaltLen));
    info.tail_nonce.assign(
        footer.begin() + static_cast<std::ptrdiff_t>(kSaltLen),
        footer.begin() + static_cast<std::ptrdiff_t>(kSaltLen + kTailNonceLen));

    Bytes tail_blob;
    tail_blob.reserve(kTailCipherLen + kTailTagLen);
    tail_blob.insert(
        tail_blob.end(),
        footer.begin() + static_cast<std::ptrdiff_t>(kSaltLen + kTailNonceLen),
        footer.begin() + static_cast<std::ptrdiff_t>(kSaltLen + kTailNonceLen + kTailCipherLen));
    tail_blob.insert(
        tail_blob.end(),
        footer.begin() + static_cast<std::ptrdiff_t>(kSaltLen + kTailNonceLen + kTailCipherLen),
        footer.end());

    FooterContext context;
    context.keys = DeriveKeys(password, info.salt);
    Bytes tail_plain = basefwx::crypto::AesGcmDecryptWithIv(context.keys.tail, info.tail_nonce, tail_blob, {});
    if (tail_plain.size() != kTailPlainLen) {
        throw std::runtime_error("AN7 footer tail length mismatch");
    }

    info.trailer_len = ReadU64LeRaw(tail_plain.data());
    info.payload_len = ReadU64LeRaw(tail_plain.data() + 8);
    info.trailer_crc32 = ReadU32LeRaw(tail_plain.data() + 16);
    context.footer = info;
    return context;
}

std::filesystem::path ResolveAn7OutputPath(const std::filesystem::path& input,
                                           const An7Options& opts) {
    std::filesystem::path desired;
    std::error_code ec;
    if (opts.out.has_value()) {
        desired = opts.out.value();
        if (std::filesystem::exists(desired, ec) && std::filesystem::is_directory(desired, ec)) {
            desired /= ("data" + RandomDigits10());
        }
    } else {
        desired = input.parent_path() / ("data" + RandomDigits10());
    }
    desired = EnsureCollisionSuffix(desired);
    EnsureParentDir(desired);
    return desired;
}

std::string ResolveRestoredFilename(const TrailerInfo& trailer) {
    std::string base = SanitizeBasename(trailer.original_basename);
    std::string ext = SanitizeExtension(trailer.original_extension);
    std::string name = base + ext;
    if (name.empty()) {
        return "dean7.out";
    }
    return name;
}

std::filesystem::path ResolveDean7OutputPath(const std::filesystem::path& input,
                                             const TrailerInfo& trailer,
                                             const Dean7Options& opts) {
    std::filesystem::path desired;
    const std::string restored = ResolveRestoredFilename(trailer);
    std::error_code ec;
    if (opts.out.has_value()) {
        desired = opts.out.value();
        if (std::filesystem::exists(desired, ec) && std::filesystem::is_directory(desired, ec)) {
            desired /= restored;
        }
    } else {
        desired = input.parent_path() / restored;
    }
    desired = EnsureCollisionSuffix(desired);
    EnsureParentDir(desired);
    return desired;
}

std::uint32_t Crc32Bytes(const Bytes& data) {
    return static_cast<std::uint32_t>(crc32(0L,
                                            reinterpret_cast<const Bytef*>(data.data()),
                                            static_cast<uInt>(data.size())));
}

}  // namespace

void an7_file(const std::filesystem::path& input,
              const std::string& password,
              const An7Options& opts) {
    RequireRegularFile(input);
    if (password.empty()) {
        throw std::runtime_error("Password is required for an7");
    }
    if (!opts.force_any) {
        std::string ext = ToLower(input.extension().string());
        if (ext != ".fwx") {
            throw std::runtime_error("an7 accepts only .fwx input by default (use --force-any to override)");
        }
    }

    const std::filesystem::path output = ResolveAn7OutputPath(input, opts);
    if (SameLogicalPath(input, output)) {
        throw std::runtime_error("Output path must differ from input path");
    }

    const std::filesystem::path temp_output = MakeTempPath(output);
    TempFileCleanup temp_cleanup(temp_output);

    std::ifstream in(input, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file: " + input.string());
    }
    std::ofstream out(temp_output, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to create output file: " + temp_output.string());
    }

    const std::uint64_t payload_len = FileSize(input);
    const std::uint64_t total_chunks = TotalChunks(payload_len, kAn7ChunkSize);

    Bytes salt = basefwx::crypto::RandomBytes(kSaltLen);
    An7Keys keys = DeriveKeys(password, salt);
    Bytes stream_nonce = basefwx::crypto::RandomBytes(kTrailerNonceLen);

    Sha256Hasher sha;

    for (std::uint64_t super_idx = 0; super_idx * kAn7SuperblockChunks < total_chunks; ++super_idx) {
        ThrowIfInterrupted();
        const std::uint64_t start_chunk = super_idx * kAn7SuperblockChunks;
        const std::size_t block_chunks = static_cast<std::size_t>(
            std::min<std::uint64_t>(kAn7SuperblockChunks, total_chunks - start_chunk));

        std::vector<Bytes> chunks(block_chunks);
        chunks.reserve(block_chunks);

        for (std::size_t local = 0; local < block_chunks; ++local) {
            ThrowIfInterrupted();
            const std::uint64_t global_chunk = start_chunk + static_cast<std::uint64_t>(local);
            const std::size_t chunk_len = ChunkBytesAt(payload_len, kAn7ChunkSize, global_chunk);

            Bytes chunk(chunk_len);
            ReadExact(in,
                      chunk.data(),
                      chunk_len,
                      "AN7 failed to read source payload chunk");
            sha.Update(chunk.data(), chunk.size());

            ApplyXorTransform(chunk, keys.stream, stream_nonce, global_chunk);
            if ((local % 2u) == 1u) {
                const std::size_t start = FlipStart(keys.perm, global_chunk, kAn7FlipStride);
                ApplySparseFlip(chunk, start, kAn7FlipStride);
            }
            chunks[local] = std::move(chunk);
        }

        const std::vector<std::size_t> order = BuildPermutation(keys.perm, super_idx, block_chunks);
        for (std::size_t pos = 0; pos < block_chunks; ++pos) {
            ThrowIfInterrupted();
            const Bytes& chunk = chunks[order[pos]];
            WriteExact(out,
                       chunk.data(),
                       chunk.size(),
                       "AN7 failed to write transformed payload");
        }
    }

    const auto digest = sha.Final();

    TrailerInfo trailer;
    trailer.format_version = std::string(kTrailerVersion);
    trailer.original_basename = input.stem().string();
    trailer.original_extension = input.extension().string();
    trailer.original_size = payload_len;
    trailer.chunk_size = static_cast<std::uint32_t>(kAn7ChunkSize);
    trailer.superblock_chunks = static_cast<std::uint16_t>(kAn7SuperblockChunks);
    trailer.flip_stride = static_cast<std::uint16_t>(kAn7FlipStride);
    trailer.stream_nonce = stream_nonce;
    trailer.sha256_original = digest;
    trailer.created_utc = UtcTimestamp();

    Bytes trailer_plain = SerializeTrailer(trailer);
    Bytes trailer_nonce = basefwx::crypto::RandomBytes(kTrailerNonceLen);
    Bytes trailer_cipher_and_tag = basefwx::crypto::AesGcmEncryptWithIv(keys.meta, trailer_nonce, trailer_plain, {});

    Bytes encrypted_trailer;
    encrypted_trailer.reserve(trailer_nonce.size() + trailer_cipher_and_tag.size());
    encrypted_trailer.insert(encrypted_trailer.end(), trailer_nonce.begin(), trailer_nonce.end());
    encrypted_trailer.insert(encrypted_trailer.end(), trailer_cipher_and_tag.begin(), trailer_cipher_and_tag.end());

    const std::uint64_t trailer_len = static_cast<std::uint64_t>(encrypted_trailer.size());
    const std::uint32_t trailer_crc32 = Crc32Bytes(encrypted_trailer);

    WriteExact(out,
               encrypted_trailer.data(),
               encrypted_trailer.size(),
               "AN7 failed to write encrypted trailer");

    const Bytes tail_plain = BuildTailPlain(trailer_len, payload_len, trailer_crc32);
    Bytes tail_nonce = basefwx::crypto::RandomBytes(kTailNonceLen);
    Bytes tail_cipher_and_tag = basefwx::crypto::AesGcmEncryptWithIv(keys.tail, tail_nonce, tail_plain, {});
    if (tail_cipher_and_tag.size() != kTailCipherLen + kTailTagLen) {
        throw std::runtime_error("AN7 tail encrypt produced unexpected length");
    }

    std::array<std::uint8_t, kFooterSize> footer{};
    std::memcpy(footer.data(), salt.data(), kSaltLen);
    std::memcpy(footer.data() + kSaltLen, tail_nonce.data(), kTailNonceLen);
    std::memcpy(footer.data() + kSaltLen + kTailNonceLen, tail_cipher_and_tag.data(), kTailCipherLen);
    std::memcpy(footer.data() + kSaltLen + kTailNonceLen + kTailCipherLen,
                tail_cipher_and_tag.data() + kTailCipherLen,
                kTailTagLen);

    WriteExact(out,
               footer.data(),
               footer.size(),
               "AN7 failed to write footer");
    out.flush();
    if (!out) {
        throw std::runtime_error("AN7 output flush failed");
    }

    CommitTempFile(temp_output, output);
    temp_cleanup.Dismiss();

    if (!opts.keep_input) {
        std::error_code ec;
        std::filesystem::remove(input, ec);
        if (ec) {
            throw std::runtime_error("AN7 failed to remove input file: " + input.string());
        }
    }
}

Dean7Result dean7_file(const std::filesystem::path& input,
                       const std::string& password,
                       const Dean7Options& opts) {
    RequireRegularFile(input);
    if (password.empty()) {
        throw std::runtime_error("Password is required for dean7");
    }

    const std::uint64_t file_size = FileSize(input);
    if (file_size < kFooterSize) {
        throw std::runtime_error("Input is too small to be an AN7 file");
    }

    std::ifstream in(input, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file: " + input.string());
    }

    in.seekg(static_cast<std::streamoff>(file_size - kFooterSize), std::ios::beg);
    std::array<std::uint8_t, kFooterSize> footer_buf{};
    ReadExact(in,
              footer_buf.data(),
              footer_buf.size(),
              "Failed to read AN7 footer");

    FooterContext context = ParseFooterAndDerive(footer_buf, password);
    const FooterInfo& footer = context.footer;

    if (footer.trailer_len < (kTrailerNonceLen + kTailTagLen)
        || footer.payload_len > file_size
        || footer.payload_len + footer.trailer_len + kFooterSize != file_size) {
        throw std::runtime_error("AN7 footer length fields are invalid");
    }

    in.seekg(static_cast<std::streamoff>(footer.payload_len), std::ios::beg);
    Bytes encrypted_trailer(static_cast<std::size_t>(footer.trailer_len));
    ReadExact(in,
              encrypted_trailer.data(),
              encrypted_trailer.size(),
              "Failed to read AN7 encrypted trailer");

    if (Crc32Bytes(encrypted_trailer) != footer.trailer_crc32) {
        throw std::runtime_error("AN7 trailer CRC mismatch");
    }

    Bytes trailer_nonce(encrypted_trailer.begin(),
                        encrypted_trailer.begin() + static_cast<std::ptrdiff_t>(kTrailerNonceLen));
    Bytes trailer_cipher_and_tag(encrypted_trailer.begin() + static_cast<std::ptrdiff_t>(kTrailerNonceLen),
                                 encrypted_trailer.end());

    Bytes trailer_plain = basefwx::crypto::AesGcmDecryptWithIv(
        context.keys.meta,
        trailer_nonce,
        trailer_cipher_and_tag,
        {}
    );

    TrailerInfo trailer = ParseTrailer(trailer_plain);
    if (trailer.chunk_size == 0
        || trailer.superblock_chunks == 0
        || trailer.flip_stride == 0
        || trailer.stream_nonce.size() != kTrailerNonceLen) {
        throw std::runtime_error("AN7 trailer contains invalid transform parameters");
    }

    if (trailer.original_size != footer.payload_len) {
        throw std::runtime_error("AN7 payload size mismatch");
    }

    const std::filesystem::path output = ResolveDean7OutputPath(input, trailer, opts);
    if (SameLogicalPath(input, output)) {
        throw std::runtime_error("Output path must differ from input path");
    }

    const std::filesystem::path temp_output = MakeTempPath(output);
    TempFileCleanup temp_cleanup(temp_output);

    std::ofstream out(temp_output, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to create output file: " + temp_output.string());
    }

    in.clear();
    in.seekg(0, std::ios::beg);

    Sha256Hasher sha;
    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_written = 0;

    const std::uint64_t total_chunks = TotalChunks(footer.payload_len, trailer.chunk_size);
    for (std::uint64_t super_idx = 0;
         super_idx * static_cast<std::uint64_t>(trailer.superblock_chunks) < total_chunks;
         ++super_idx) {
        ThrowIfInterrupted();

        const std::uint64_t start_chunk = super_idx * static_cast<std::uint64_t>(trailer.superblock_chunks);
        const std::size_t block_chunks = static_cast<std::size_t>(
            std::min<std::uint64_t>(
                trailer.superblock_chunks,
                total_chunks - start_chunk));

        std::vector<std::size_t> chunk_sizes(block_chunks, 0);
        for (std::size_t i = 0; i < block_chunks; ++i) {
            chunk_sizes[i] = ChunkBytesAt(footer.payload_len,
                                          trailer.chunk_size,
                                          start_chunk + static_cast<std::uint64_t>(i));
        }

        std::vector<Bytes> chunks(block_chunks);
        const std::vector<std::size_t> order = BuildPermutation(context.keys.perm, super_idx, block_chunks);

        for (std::size_t pos = 0; pos < block_chunks; ++pos) {
            ThrowIfInterrupted();
            const std::size_t original_slot = order[pos];
            const std::size_t len = chunk_sizes[original_slot];
            Bytes chunk(len);
            ReadExact(in,
                      chunk.data(),
                      chunk.size(),
                      "AN7 payload is truncated");
            bytes_read += static_cast<std::uint64_t>(chunk.size());
            chunks[original_slot] = std::move(chunk);
        }

        for (std::size_t local = 0; local < block_chunks; ++local) {
            ThrowIfInterrupted();
            const std::uint64_t global_chunk = start_chunk + static_cast<std::uint64_t>(local);
            Bytes& chunk = chunks[local];

            if ((local % 2u) == 1u) {
                const std::size_t start = FlipStart(
                    context.keys.perm,
                    global_chunk,
                    static_cast<std::size_t>(trailer.flip_stride));
                ApplySparseFlip(chunk, start, static_cast<std::size_t>(trailer.flip_stride));
            }
            ApplyXorTransform(chunk, context.keys.stream, trailer.stream_nonce, global_chunk);

            sha.Update(chunk.data(), chunk.size());
            WriteExact(out,
                       chunk.data(),
                       chunk.size(),
                       "Failed to write dean7 output payload");
            bytes_written += static_cast<std::uint64_t>(chunk.size());
        }
    }

    if (bytes_read != footer.payload_len || bytes_written != footer.payload_len) {
        throw std::runtime_error("AN7 payload length verification failed");
    }

    const auto digest = sha.Final();
    if (!std::equal(digest.begin(), digest.end(), trailer.sha256_original.begin())) {
        throw std::runtime_error("AN7 payload hash mismatch");
    }

    out.flush();
    if (!out) {
        throw std::runtime_error("Failed to flush dean7 output");
    }

    CommitTempFile(temp_output, output);
    temp_cleanup.Dismiss();

    if (!opts.keep_input) {
        std::error_code ec;
        std::filesystem::remove(input, ec);
        if (ec) {
            throw std::runtime_error("dean7 failed to remove input file: " + input.string());
        }
    }

    Dean7Result result;
    result.output_path = output;
    result.restored_name = output.filename().string();
    result.bytes_written = bytes_written;
    return result;
}

}  // namespace basefwx
