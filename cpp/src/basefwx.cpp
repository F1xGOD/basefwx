#include "basefwx/basefwx.hpp"

#include "basefwx/codec.hpp"
#include "basefwx/base64.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/crypto_utils.hpp"
#include "basefwx/format.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/imagecipher.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <openssl/evp.h>
#include <random>
#include <stdexcept>
#include <string_view>
#include <zlib.h>

#include "stb_image.h"
#include "stb_image_write.h"

namespace {

std::string HexEncode(const std::vector<std::uint8_t>& data) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t byte : data) {
        out.push_back(kHex[(byte >> 4) & 0x0F]);
        out.push_back(kHex[byte & 0x0F]);
    }
    return out;
}

std::string DigestHex(const std::string& input, const EVP_MD* md) {
    using basefwx::crypto::detail::UniqueMDCtx;
    UniqueMDCtx ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Digest context allocation failed");
    }
    // Use stack buffer for hash result (max 64 bytes for SHA-512)
    std::array<std::uint8_t, 64> out{};
    unsigned int out_len = 0;
    
    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        throw std::runtime_error("Digest init failed");
    }
    if (!input.empty()) {
        if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
            throw std::runtime_error("Digest update failed");
        }
    }
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) != 1) {
        throw std::runtime_error("Digest final failed");
    }
    
    std::vector<std::uint8_t> result(out.data(), out.data() + out_len);
    return HexEncode(result);
}

std::string MdCode(const std::string& input) {
    std::string out;
    out.reserve(input.size() * 3);
    for (unsigned char ch : input) {
        unsigned int val = ch;
        if (val < 10) {
            out.push_back('1');
            out.push_back('0' + val);
        } else if (val < 100) {
            out.push_back('2');
            out.push_back('0' + val / 10);
            out.push_back('0' + val % 10);
        } else {
            out.push_back('3');
            out.push_back('0' + val / 100);
            out.push_back('0' + (val / 10) % 10);
            out.push_back('0' + val % 10);
        }
    }
    return out;
}

std::string StripLeadingZeros(const std::string& input) {
    std::size_t idx = 0;
    while (idx < input.size() && input[idx] == '0') {
        ++idx;
    }
    if (idx == input.size()) {
        return "0";
    }
    return input.substr(idx);
}

int CompareMagnitude(const std::string& a, const std::string& b) {
    std::string aa = StripLeadingZeros(a);
    std::string bb = StripLeadingZeros(b);
    if (aa.size() != bb.size()) {
        return aa.size() < bb.size() ? -1 : 1;
    }
    if (aa == bb) {
        return 0;
    }
    return aa < bb ? -1 : 1;
}

std::string AddMagnitude(const std::string& a, const std::string& b) {
    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    int carry = 0;
    std::string out;
    while (i >= 0 || j >= 0 || carry > 0) {
        int da = (i >= 0) ? (a[static_cast<std::size_t>(i)] - '0') : 0;
        int db = (j >= 0) ? (b[static_cast<std::size_t>(j)] - '0') : 0;
        int sum = da + db + carry;
        out.push_back(static_cast<char>('0' + (sum % 10)));
        carry = sum / 10;
        --i;
        --j;
    }
    std::reverse(out.begin(), out.end());
    return StripLeadingZeros(out);
}

std::string SubtractMagnitude(const std::string& a, const std::string& b) {
    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    int borrow = 0;
    std::string out;
    while (i >= 0) {
        int da = (a[static_cast<std::size_t>(i)] - '0') - borrow;
        int db = (j >= 0) ? (b[static_cast<std::size_t>(j)] - '0') : 0;
        if (da < db) {
            da += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        int diff = da - db;
        out.push_back(static_cast<char>('0' + diff));
        --i;
        --j;
    }
    std::reverse(out.begin(), out.end());
    return StripLeadingZeros(out);
}

struct SignedNumber {
    bool negative = false;
    std::string digits = "0";
};

SignedNumber ParseSigned(const std::string& input) {
    SignedNumber result;
    if (input.empty()) {
        return result;
    }
    std::size_t start = 0;
    if (input[0] == '-') {
        result.negative = true;
        start = 1;
    }
    result.digits = StripLeadingZeros(input.substr(start));
    if (result.digits == "0") {
        result.negative = false;
    }
    return result;
}

std::string AddSigned(const std::string& a, const std::string& b) {
    SignedNumber sa = ParseSigned(a);
    SignedNumber sb = ParseSigned(b);
    if (sa.negative == sb.negative) {
        std::string sum = AddMagnitude(sa.digits, sb.digits);
        if (sum == "0") {
            return sum;
        }
        return (sa.negative ? "-" : "") + sum;
    }
    int cmp = CompareMagnitude(sa.digits, sb.digits);
    if (cmp == 0) {
        return "0";
    }
    if (cmp > 0) {
        std::string diff = SubtractMagnitude(sa.digits, sb.digits);
        return (sa.negative ? "-" : "") + diff;
    }
    std::string diff = SubtractMagnitude(sb.digits, sa.digits);
    return (sb.negative ? "-" : "") + diff;
}

std::string ReplaceAll(std::string input, const std::string& from, const std::string& to) {
    if (from.empty()) {
        return input;
    }
    std::size_t pos = 0;
    while ((pos = input.find(from, pos)) != std::string::npos) {
        input.replace(pos, from.size(), to);
        pos += to.size();
    }
    return input;
}

std::string MCode(const std::string& input) {
    std::string out;
    out.reserve(input.size() / 2);  // Rough estimate
    std::size_t idx = 0;
    while (idx < input.size()) {
        if (input[idx] < '0' || input[idx] > '9') {
            throw std::runtime_error("Invalid mcode input");
        }
        int len = input[idx] - '0';
        idx += 1;
        if (idx + static_cast<std::size_t>(len) > input.size()) {
            throw std::runtime_error("Invalid mcode length");
        }
        // Fast path for common lengths
        int val = 0;
        if (len == 1) {
            val = input[idx] - '0';
        } else if (len == 2) {
            val = (input[idx] - '0') * 10 + (input[idx + 1] - '0');
        } else if (len == 3) {
            val = (input[idx] - '0') * 100 + (input[idx + 1] - '0') * 10 + (input[idx + 2] - '0');
        } else {
            // Fallback for unexpected length
            std::string num = input.substr(idx, static_cast<std::size_t>(len));
            val = std::stoi(num);
        }
        idx += static_cast<std::size_t>(len);
        out.push_back(static_cast<char>(val));
    }
    return out;
}

constexpr std::uint64_t kN10Mod = 10000000000ULL;
constexpr std::uint64_t kN10Mul = 3816547291ULL;
constexpr std::uint64_t kN10Add = 7261940353ULL;
constexpr char kN10Magic[] = "927451";
constexpr char kN10Version[] = "01";
constexpr std::size_t kN10HeaderDigits = 28;

std::uint64_t ModSub(std::uint64_t value, std::uint64_t sub, std::uint64_t mod) {
    if (value >= sub) {
        return value - sub;
    }
    return mod - (sub - value);
}

std::uint64_t ModInverse(std::uint64_t value, std::uint64_t mod) {
    std::int64_t t = 0;
    std::int64_t new_t = 1;
    std::int64_t r = static_cast<std::int64_t>(mod);
    std::int64_t new_r = static_cast<std::int64_t>(value);
    while (new_r != 0) {
        std::int64_t q = r / new_r;
        std::int64_t temp_t = t - q * new_t;
        t = new_t;
        new_t = temp_t;
        std::int64_t temp_r = r - q * new_r;
        r = new_r;
        new_r = temp_r;
    }
    if (r != 1) {
        throw std::runtime_error("n10 internal inverse failure");
    }
    if (t < 0) {
        t += static_cast<std::int64_t>(mod);
    }
    return static_cast<std::uint64_t>(t);
}

std::uint64_t N10MulInverse() {
    static const std::uint64_t inverse = ModInverse(kN10Mul, kN10Mod);
    return inverse;
}

std::uint64_t Mix64(std::uint64_t value) {
    value += 0x9E3779B97F4A7C15ULL;
    value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31U);
}

std::uint64_t N10Offset(std::uint64_t index) {
    return Mix64(index ^ 0xA5A5F0F01234ABCDULL) % kN10Mod;
}

std::uint64_t MulMod10(std::uint64_t lhs, std::uint64_t rhs) {
#if defined(__SIZEOF_INT128__)
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(lhs) * static_cast<unsigned __int128>(rhs)) % kN10Mod
    );
#else
    lhs %= kN10Mod;
    rhs %= kN10Mod;
    std::uint64_t out = 0;
    while (rhs != 0) {
        if ((rhs & 1ULL) != 0ULL) {
            out += lhs;
            if (out >= kN10Mod) {
                out -= kN10Mod;
            }
        }
        rhs >>= 1U;
        lhs <<= 1U;
        if (lhs >= kN10Mod) {
            lhs -= kN10Mod;
        }
    }
    return out;
#endif
}

std::uint64_t N10Transform(std::uint64_t value, std::uint64_t index) {
    if (value >= kN10Mod) {
        throw std::runtime_error("n10 value too large");
    }
    std::uint64_t mixed = (value + N10Offset(index)) % kN10Mod;
    return (MulMod10(kN10Mul, mixed) + kN10Add) % kN10Mod;
}

std::uint64_t N10InverseTransform(std::uint64_t encoded, std::uint64_t index) {
    if (encoded >= kN10Mod) {
        throw std::runtime_error("n10 encoded value too large");
    }
    std::uint64_t step = ModSub(encoded, kN10Add, kN10Mod);
    std::uint64_t mixed = MulMod10(step, N10MulInverse());
    return ModSub(mixed, N10Offset(index), kN10Mod);
}

void AppendFixed10(std::string& out, std::uint64_t value) {
    if (value >= kN10Mod) {
        throw std::runtime_error("n10 fixed width overflow");
    }
    char digits[10];
    for (int idx = 9; idx >= 0; --idx) {
        digits[idx] = static_cast<char>('0' + (value % 10ULL));
        value /= 10ULL;
    }
    out.append(digits, sizeof(digits));
}

std::uint64_t ParseFixed10(std::string_view input, std::size_t offset) {
    if (offset + 10 > input.size()) {
        throw std::runtime_error("n10 payload truncated");
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 10; ++i) {
        char ch = input[offset + i];
        if (ch < '0' || ch > '9') {
            throw std::runtime_error("n10 payload must contain only digits");
        }
        value = value * 10ULL + static_cast<std::uint64_t>(ch - '0');
    }
    return value;
}

std::uint32_t Fnv1a32(std::string_view input) {
    std::uint32_t hash = 2166136261u;
    for (unsigned char byte : input) {
        hash ^= static_cast<std::uint32_t>(byte);
        hash *= 16777619u;
    }
    return hash;
}

constexpr std::array<char, 4> kKfmMagic = {'K', 'F', 'M', '!'};
constexpr std::uint8_t kKfmVersion = 1;
constexpr std::uint8_t kKfmModeImageAudio = 1;
constexpr std::uint8_t kKfmModeAudioImage = 2;
constexpr std::uint8_t kKfmFlagBw = 1;
constexpr std::size_t kKfmHeaderLen = 32;
constexpr std::size_t kKfmMaxPayload = 1u << 30;
constexpr std::uint32_t kKfmAudioRate = 24000;

void WriteU32BE(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void WriteU64BE(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
}

std::uint32_t ReadU32BE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("kFM header truncated");
    }
    return (static_cast<std::uint32_t>(data[offset]) << 24)
         | (static_cast<std::uint32_t>(data[offset + 1]) << 16)
         | (static_cast<std::uint32_t>(data[offset + 2]) << 8)
         | static_cast<std::uint32_t>(data[offset + 3]);
}

std::uint64_t ReadU64BE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 8 > data.size()) {
        throw std::runtime_error("kFM header truncated");
    }
    std::uint64_t out = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        out = (out << 8) | static_cast<std::uint64_t>(data[offset + i]);
    }
    return out;
}

std::uint32_t ReadU32LE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("kFM wav chunk truncated");
    }
    return static_cast<std::uint32_t>(data[offset])
         | (static_cast<std::uint32_t>(data[offset + 1]) << 8)
         | (static_cast<std::uint32_t>(data[offset + 2]) << 16)
         | (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint16_t ReadU16LE(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 2 > data.size()) {
        throw std::runtime_error("kFM wav chunk truncated");
    }
    return static_cast<std::uint16_t>(data[offset])
         | static_cast<std::uint16_t>(data[offset + 1] << 8);
}

void WriteU16LE(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void WriteU32LE(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
}

std::string CleanKfmExt(std::string ext) {
    if (ext.empty()) {
        return ".bin";
    }
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (ext.front() != '.') {
        ext.insert(ext.begin(), '.');
    }
    if (ext.size() > 24) {
        return ".bin";
    }
    for (char ch : ext) {
        bool ok = (ch == '.') || (ch == '_') || (ch == '-')
            || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (!ok) {
            return ".bin";
        }
    }
    return ext;
}

std::string KfmPathExt(const std::filesystem::path& path) {
    return CleanKfmExt(path.has_extension() ? path.extension().string() : "");
}

bool IsKnownKfmAudioExt(const std::string& ext) {
    static constexpr std::array<std::string_view, 16> kAudioExts = {
        ".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus",
        ".wma", ".amr", ".aiff", ".aif", ".alac", ".m4b", ".caf", ".mka",
    };
    for (std::string_view value : kAudioExts) {
        if (ext == value) {
            return true;
        }
    }
    return false;
}

bool IsKnownKfmImageExt(const std::string& ext) {
    static constexpr std::array<std::string_view, 13> kImageExts = {
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif",
        ".tiff", ".ico", ".heic", ".heif", ".ppm", ".pgm",
    };
    for (std::string_view value : kImageExts) {
        if (ext == value) {
            return true;
        }
    }
    return false;
}

void WarnKfmUsage(const std::string& message) {
    std::cerr << "WARN: " << message << "\n";
}

std::vector<std::uint8_t> KfmKeystream(std::uint64_t seed, std::size_t length) {
    std::vector<std::uint8_t> out(length);
    if (length == 0) {
        return out;
    }
    std::array<std::uint8_t, 16> seed_counter{};
    for (int i = 0; i < 8; ++i) {
        seed_counter[7 - i] = static_cast<std::uint8_t>((seed >> (i * 8)) & 0xFFu);
    }
    std::size_t offset = 0;
    std::uint64_t counter = 0;
    while (offset < length) {
        for (int i = 0; i < 8; ++i) {
            seed_counter[15 - i] = static_cast<std::uint8_t>((counter >> (i * 8)) & 0xFFu);
        }
        unsigned int digest_len = 0;
        std::array<std::uint8_t, 32> digest{};
        if (EVP_Digest(seed_counter.data(), seed_counter.size(), digest.data(), &digest_len, EVP_sha256(), nullptr) != 1
            || digest_len == 0) {
            throw std::runtime_error("kFM keystream digest failed");
        }
        std::size_t take = std::min<std::size_t>(digest_len, length - offset);
        std::memcpy(out.data() + offset, digest.data(), take);
        offset += take;
        ++counter;
    }
    return out;
}

void XorInPlace(std::vector<std::uint8_t>& target, const std::vector<std::uint8_t>& mask) {
    if (target.size() != mask.size()) {
        throw std::runtime_error("kFM mask length mismatch");
    }
    for (std::size_t i = 0; i < target.size(); ++i) {
        target[i] ^= mask[i];
    }
}

std::uint64_t RandomSeed64() {
    auto bytes = basefwx::crypto::RandomBytes(8);
    std::uint64_t seed = 0;
    for (std::uint8_t byte : bytes) {
        seed = (seed << 8) | static_cast<std::uint64_t>(byte);
    }
    return seed;
}

std::vector<std::uint8_t> BuildKfmContainer(std::uint8_t mode,
                                            const std::vector<std::uint8_t>& payload,
                                            const std::string& ext,
                                            std::uint8_t flags) {
    if (mode != kKfmModeImageAudio && mode != kKfmModeAudioImage) {
        throw std::runtime_error("kFM mode is invalid");
    }
    if (payload.size() > kKfmMaxPayload) {
        throw std::runtime_error("kFM payload is too large");
    }
    std::string cleaned_ext = CleanKfmExt(ext);
    std::vector<std::uint8_t> ext_bytes(cleaned_ext.begin(), cleaned_ext.end());
    if (ext_bytes.size() > 255) {
        ext_bytes.assign({'.', 'b', 'i', 'n'});
    }

    std::vector<std::uint8_t> body;
    body.reserve(ext_bytes.size() + payload.size());
    body.insert(body.end(), ext_bytes.begin(), ext_bytes.end());
    body.insert(body.end(), payload.begin(), payload.end());

    std::uint64_t seed = RandomSeed64();
    auto mask = KfmKeystream(seed, body.size());
    XorInPlace(body, mask);
    std::uint32_t crc = crc32(0L, payload.data(), static_cast<uInt>(payload.size()));

    std::vector<std::uint8_t> out;
    out.reserve(kKfmHeaderLen + body.size());
    out.insert(out.end(), kKfmMagic.begin(), kKfmMagic.end());
    out.push_back(kKfmVersion);
    out.push_back(mode);
    out.push_back(flags);
    out.push_back(static_cast<std::uint8_t>(ext_bytes.size()));
    WriteU64BE(out, static_cast<std::uint64_t>(payload.size()));
    WriteU32BE(out, crc);
    WriteU64BE(out, seed);
    WriteU32BE(out, 0u);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

struct KfmDecoded {
    std::uint8_t mode = 0;
    std::uint8_t flags = 0;
    std::string ext;
    std::vector<std::uint8_t> payload;
};

std::optional<KfmDecoded> ParseKfmContainer(const std::vector<std::uint8_t>& blob) {
    if (blob.size() < kKfmHeaderLen) {
        return std::nullopt;
    }
    if (!std::equal(kKfmMagic.begin(), kKfmMagic.end(), blob.begin())) {
        return std::nullopt;
    }
    std::uint8_t version = blob[4];
    std::uint8_t mode = blob[5];
    std::uint8_t flags = blob[6];
    std::uint8_t ext_len = blob[7];
    if (version != kKfmVersion || (mode != kKfmModeImageAudio && mode != kKfmModeAudioImage)) {
        return std::nullopt;
    }
    std::uint64_t payload_len = ReadU64BE(blob, 8);
    std::uint32_t crc_expected = ReadU32BE(blob, 16);
    std::uint64_t seed = ReadU64BE(blob, 20);
    if (payload_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() - ext_len)) {
        return std::nullopt;
    }
    std::size_t body_len = static_cast<std::size_t>(ext_len) + static_cast<std::size_t>(payload_len);
    if (body_len < ext_len) {
        return std::nullopt;
    }
    if (kKfmHeaderLen + body_len > blob.size()) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> body(blob.begin() + static_cast<std::ptrdiff_t>(kKfmHeaderLen),
                                   blob.begin() + static_cast<std::ptrdiff_t>(kKfmHeaderLen + body_len));
    auto mask = KfmKeystream(seed, body.size());
    XorInPlace(body, mask);
    std::vector<std::uint8_t> payload(body.begin() + static_cast<std::ptrdiff_t>(ext_len), body.end());
    std::uint32_t crc_actual = crc32(0L, payload.data(), static_cast<uInt>(payload.size()));
    if (crc_actual != crc_expected) {
        return std::nullopt;
    }
    std::string ext(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(ext_len));
    KfmDecoded decoded;
    decoded.mode = mode;
    decoded.flags = flags;
    decoded.ext = CleanKfmExt(ext);
    decoded.payload = std::move(payload);
    return decoded;
}

enum class KfmCarrierKind {
    Audio,
    Image,
};

std::vector<std::uint8_t> ReadAudioCarrierBytes(const std::filesystem::path& path);
std::vector<std::uint8_t> ReadPngCarrierBytes(const std::filesystem::path& path);

const char* KfmCarrierKindName(KfmCarrierKind kind) {
    return kind == KfmCarrierKind::Audio ? "audio" : "image";
}

std::vector<KfmCarrierKind> DetectKfmCarrierKinds(const std::filesystem::path& path, const std::string& ext) {
    if (IsKnownKfmAudioExt(ext)) {
        return {KfmCarrierKind::Audio};
    }
    if (IsKnownKfmImageExt(ext)) {
        return {KfmCarrierKind::Image};
    }
    std::array<std::uint8_t, 16> head{};
    std::size_t head_len = 0;
    std::ifstream input(path, std::ios::binary);
    if (input) {
        input.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
        head_len = static_cast<std::size_t>(input.gcount());
    }
    std::vector<KfmCarrierKind> kinds;
    static constexpr std::array<std::uint8_t, 8> kPngMagic = {
        0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au
    };
    if (head_len >= kPngMagic.size() && std::equal(kPngMagic.begin(), kPngMagic.end(), head.begin())) {
        kinds.push_back(KfmCarrierKind::Image);
    }
    if (head_len >= 12
        && head[0] == 'R' && head[1] == 'I' && head[2] == 'F' && head[3] == 'F'
        && head[8] == 'W' && head[9] == 'A' && head[10] == 'V' && head[11] == 'E') {
        kinds.push_back(KfmCarrierKind::Audio);
    }
    if (kinds.empty()) {
        kinds.push_back(KfmCarrierKind::Audio);
        kinds.push_back(KfmCarrierKind::Image);
    } else {
        if (std::find(kinds.begin(), kinds.end(), KfmCarrierKind::Audio) == kinds.end()) {
            kinds.push_back(KfmCarrierKind::Audio);
        }
        if (std::find(kinds.begin(), kinds.end(), KfmCarrierKind::Image) == kinds.end()) {
            kinds.push_back(KfmCarrierKind::Image);
        }
    }
    return kinds;
}

std::optional<KfmDecoded> DecodeKfmCarrierContainer(const std::filesystem::path& path,
                                                    const std::string& ext,
                                                    std::vector<std::string>* errors_out = nullptr) {
    auto kinds = DetectKfmCarrierKinds(path, ext);
    std::vector<std::string> errors;
    for (KfmCarrierKind kind : kinds) {
        std::vector<std::uint8_t> carrier;
        try {
            if (kind == KfmCarrierKind::Audio) {
                carrier = ReadAudioCarrierBytes(path);
            } else {
                carrier = ReadPngCarrierBytes(path);
            }
        } catch (const std::exception& exc) {
            if (kinds.size() == 1) {
                throw;
            }
            errors.push_back(std::string(KfmCarrierKindName(kind)) + ": " + exc.what());
            continue;
        }
        auto decoded = ParseKfmContainer(carrier);
        if (decoded) {
            if (errors_out) {
                *errors_out = std::move(errors);
            }
            return decoded;
        }
        errors.push_back(std::string(KfmCarrierKindName(kind)) + ": no BaseFWX header");
    }
    if (errors_out) {
        *errors_out = std::move(errors);
    }
    return std::nullopt;
}

void WriteBinaryFileRaw(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file: " + path.string());
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!out) {
        throw std::runtime_error("Failed to write output file: " + path.string());
    }
}

std::filesystem::path NormalizePathForCompare(const std::filesystem::path& path) {
    std::error_code ec;
    auto abs = std::filesystem::absolute(path, ec);
    if (ec) {
        return path.lexically_normal();
    }
    return abs.lexically_normal();
}

bool PathsEqual(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    return NormalizePathForCompare(lhs) == NormalizePathForCompare(rhs);
}

std::filesystem::path ResolveKfmOutputPath(const std::filesystem::path& src,
                                           const std::string& output,
                                           const std::string& ext,
                                           const std::string& tag) {
    if (!output.empty()) {
        std::filesystem::path out_path(output);
        if (PathsEqual(out_path, src)) {
            throw std::runtime_error("Refusing to overwrite input file; choose a different output path");
        }
        return out_path;
    }
    std::filesystem::path out_path = src;
    out_path.replace_extension(ext);
    if (PathsEqual(out_path, src)) {
        out_path = src.parent_path() / (src.stem().string() + "." + tag + ext);
    }
    return out_path;
}

std::vector<std::uint8_t> ReadWavCarrierBytes(const std::filesystem::path& path) {
    std::vector<std::uint8_t> file = basefwx::ReadFile(path.string());
    if (file.size() < 44) {
        throw std::runtime_error("kFM wav input is too short");
    }
    if (!std::equal(file.begin(), file.begin() + 4, "RIFF")
        || !std::equal(file.begin() + 8, file.begin() + 12, "WAVE")) {
        throw std::runtime_error("kFM wav input has invalid header");
    }

    bool has_fmt = false;
    bool has_data = false;
    std::uint16_t channels = 0;
    std::uint16_t bits_per_sample = 0;
    std::vector<std::uint8_t> data_chunk;

    std::size_t offset = 12;
    while (offset + 8 <= file.size()) {
        std::array<char, 4> chunk_id{};
        std::memcpy(chunk_id.data(), file.data() + offset, 4);
        std::uint32_t chunk_len = ReadU32LE(file, offset + 4);
        std::size_t data_offset = offset + 8;
        std::size_t next = data_offset + static_cast<std::size_t>(chunk_len);
        if (next > file.size()) {
            break;
        }
        if (std::equal(chunk_id.begin(), chunk_id.end(), "fmt ")) {
            if (chunk_len >= 16) {
                std::uint16_t format = ReadU16LE(file, data_offset);
                channels = ReadU16LE(file, data_offset + 2);
                bits_per_sample = ReadU16LE(file, data_offset + 14);
                has_fmt = (format == 1);
            }
        } else if (std::equal(chunk_id.begin(), chunk_id.end(), "data")) {
            data_chunk.assign(file.begin() + static_cast<std::ptrdiff_t>(data_offset),
                              file.begin() + static_cast<std::ptrdiff_t>(next));
            has_data = true;
        }
        offset = next + (chunk_len % 2u);
    }

    if (!has_data) {
        throw std::runtime_error("kFM wav input missing data chunk");
    }
    if (!(has_fmt && channels == 1 && bits_per_sample == 16)) {
        return data_chunk;
    }
    std::vector<std::uint8_t> pcm = std::move(data_chunk);
    if (pcm.size() % 2 != 0) {
        pcm.push_back(0);
    }
    std::vector<std::uint8_t> out(pcm.size());
    for (std::size_t i = 0; i < pcm.size(); i += 2) {
        std::int16_t sample = static_cast<std::int16_t>(
            static_cast<std::uint16_t>(pcm[i]) |
            static_cast<std::uint16_t>(pcm[i + 1] << 8));
        std::uint16_t value = static_cast<std::uint16_t>(sample + 32768);
        out[i] = static_cast<std::uint8_t>(value & 0xFFu);
        out[i + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    }
    return out;
}

std::vector<std::uint8_t> PCM16MonoToCarrierBytes(const std::vector<std::uint8_t>& pcm_input) {
    std::vector<std::uint8_t> pcm = pcm_input;
    if (pcm.size() % 2 != 0) {
        pcm.push_back(0);
    }
    std::vector<std::uint8_t> out(pcm.size());
    for (std::size_t i = 0; i < pcm.size(); i += 2) {
        std::int16_t sample = static_cast<std::int16_t>(
            static_cast<std::uint16_t>(pcm[i]) |
            static_cast<std::uint16_t>(pcm[i + 1] << 8));
        std::uint16_t value = static_cast<std::uint16_t>(sample + 32768);
        out[i] = static_cast<std::uint8_t>(value & 0xFFu);
        out[i + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    }
    return out;
}

std::string QuoteShellArg(const std::string& value) {
#ifdef _WIN32
    std::string out = "\"";
    for (char ch : value) {
        if (ch == '"') {
            out += "\\\"";
        } else {
            out.push_back(ch);
        }
    }
    out += "\"";
    return out;
#else
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\'') {
            out += "'\\''";
        } else {
            out.push_back(ch);
        }
    }
    out += "'";
    return out;
#endif
}

std::string KfmFfmpegHwAccelArgs() {
    std::string mode;
    if (const char* raw = std::getenv("BASEFWX_HWACCEL")) {
        mode = raw;
    }
    for (char& ch : mode) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (mode.empty()) {
        if (const char* visible = std::getenv("NVIDIA_VISIBLE_DEVICES")) {
            std::string v = visible;
            for (char& ch : v) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            if (!v.empty() && v != "none" && v != "void") {
                mode = "nvidia";
            }
        }
    }
    if (mode == "cuda" || mode == "nvenc" || mode == "nvidia") {
        return " -hwaccel cuda";
    }
    if (mode == "qsv" || mode == "intel") {
        return " -hwaccel qsv";
    }
    if (mode == "vaapi") {
        return " -hwaccel vaapi";
    }
    return "";
}

std::filesystem::path MakeKfmTempPath(const std::string& suffix) {
    const auto now = static_cast<std::uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for (std::uint32_t i = 0; i < 32; ++i) {
        auto candidate = std::filesystem::temp_directory_path() /
            ("basefwx_kfm_" + std::to_string(now) + "_" + std::to_string(i) + suffix);
        if (!std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    throw std::runtime_error("Failed to allocate temporary path for ffmpeg decode");
}

std::vector<std::uint8_t> DecodeAudioViaFfmpeg(const std::filesystem::path& path) {
    const char* ffmpeg_env = std::getenv("BASEFWX_FFMPEG_BIN");
    std::string ffmpeg_bin = (ffmpeg_env && *ffmpeg_env) ? ffmpeg_env : "ffmpeg";
    auto temp_raw = MakeKfmTempPath(".raw");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            if (!path.empty()) {
                std::error_code ec;
                std::filesystem::remove(path, ec);
            }
        }
    } cleanup{temp_raw};

    std::string command = QuoteShellArg(ffmpeg_bin)
        + " -v error -y"
        + KfmFfmpegHwAccelArgs()
        + " -i " + QuoteShellArg(path.string())
        + " -f s16le -ac 1 -ar " + std::to_string(kKfmAudioRate)
        + " " + QuoteShellArg(temp_raw.string());
#ifdef _WIN32
    command += " >NUL 2>&1";
#else
    command += " >/dev/null 2>&1";
#endif
    int rc = std::system(command.c_str());
    if (rc != 0) {
        throw std::runtime_error(
            "ffmpeg failed to decode audio carrier (install ffmpeg or use WAV input)");
    }
    std::vector<std::uint8_t> pcm = basefwx::ReadFile(temp_raw.string());
    if (pcm.empty()) {
        throw std::runtime_error("ffmpeg decode produced an empty PCM stream");
    }
    return PCM16MonoToCarrierBytes(pcm);
}

std::vector<std::uint8_t> ReadAudioCarrierBytes(const std::filesystem::path& path) {
    std::string wav_error;
    try {
        return ReadWavCarrierBytes(path);
    } catch (const std::exception& exc) {
        wav_error = exc.what();
    }
    try {
        return DecodeAudioViaFfmpeg(path);
    } catch (const std::exception& ff_exc) {
        throw std::runtime_error(
            "Failed to decode audio carrier '" + path.string() + "' (WAV parse: "
            + wav_error + "; ffmpeg: " + ff_exc.what() + ")");
    }
}

void WriteWavCarrierBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& carrier) {
    std::vector<std::uint8_t> raw = carrier;
    if (raw.size() % 2 != 0) {
        raw.push_back(0);
    }
    std::vector<std::uint8_t> pcm(raw.size());
    for (std::size_t i = 0; i < raw.size(); i += 2) {
        std::uint16_t value = static_cast<std::uint16_t>(raw[i]) |
            static_cast<std::uint16_t>(raw[i + 1] << 8);
        std::int32_t sample = static_cast<std::int32_t>(value) - 32768;
        std::uint16_t le = static_cast<std::uint16_t>(static_cast<std::int16_t>(sample));
        pcm[i] = static_cast<std::uint8_t>(le & 0xFFu);
        pcm[i + 1] = static_cast<std::uint8_t>((le >> 8) & 0xFFu);
    }

    std::vector<std::uint8_t> out;
    out.reserve(44 + pcm.size());
    out.insert(out.end(), {'R', 'I', 'F', 'F'});
    WriteU32LE(out, static_cast<std::uint32_t>(36 + pcm.size()));
    out.insert(out.end(), {'W', 'A', 'V', 'E'});
    out.insert(out.end(), {'f', 'm', 't', ' '});
    WriteU32LE(out, 16u);
    WriteU16LE(out, 1u);
    WriteU16LE(out, 1u);
    WriteU32LE(out, kKfmAudioRate);
    WriteU32LE(out, kKfmAudioRate * 2u);
    WriteU16LE(out, 2u);
    WriteU16LE(out, 16u);
    out.insert(out.end(), {'d', 'a', 't', 'a'});
    WriteU32LE(out, static_cast<std::uint32_t>(pcm.size()));
    out.insert(out.end(), pcm.begin(), pcm.end());
    WriteBinaryFileRaw(path, out);
}

std::vector<std::uint8_t> ReadPngCarrierBytes(const std::filesystem::path& path) {
    int width = 0;
    int height = 0;
    int channels = 0;
    stbi_uc* raw = stbi_load(path.string().c_str(), &width, &height, &channels, 0);
    if (!raw || width <= 0 || height <= 0 || channels <= 0) {
        std::string reason = stbi_failure_reason() ? stbi_failure_reason() : "unknown";
        throw std::runtime_error("Failed to load PNG carrier: " + reason);
    }

    std::vector<std::uint8_t> out;
    std::size_t pixels = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    if (channels == 1) {
        out.assign(raw, raw + static_cast<std::ptrdiff_t>(pixels));
    } else if (channels == 3) {
        out.assign(raw, raw + static_cast<std::ptrdiff_t>(pixels * 3));
    } else if (channels == 2) {
        out.resize(pixels * 3);
        for (std::size_t i = 0; i < pixels; ++i) {
            std::uint8_t l = raw[i * 2];
            out[i * 3] = l;
            out[i * 3 + 1] = l;
            out[i * 3 + 2] = l;
        }
    } else {
        out.resize(pixels * 3);
        for (std::size_t i = 0; i < pixels; ++i) {
            out[i * 3] = raw[i * channels];
            out[i * 3 + 1] = raw[i * channels + 1];
            out[i * 3 + 2] = raw[i * channels + 2];
        }
    }
    stbi_image_free(raw);
    return out;
}

void WritePngCarrierBytes(const std::filesystem::path& path,
                          const std::vector<std::uint8_t>& carrier,
                          bool bw_mode) {
    int channels = bw_mode ? 1 : 3;
    std::size_t pixels = std::max<std::size_t>(1, (carrier.size() + static_cast<std::size_t>(channels) - 1u) / static_cast<std::size_t>(channels));
    int width = static_cast<int>(std::ceil(std::sqrt(static_cast<double>(pixels))));
    if (width < 1) {
        width = 1;
    }
    int height = static_cast<int>((pixels + static_cast<std::size_t>(width) - 1u) / static_cast<std::size_t>(width));
    std::size_t capacity = static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * static_cast<std::size_t>(channels);

    std::vector<std::uint8_t> pixels_data = basefwx::crypto::RandomBytes(capacity);
    std::copy(carrier.begin(), carrier.end(), pixels_data.begin());

    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }
    int stride = width * channels;
    if (stbi_write_png(path.string().c_str(),
                       width,
                       height,
                       channels,
                       pixels_data.data(),
                       stride) == 0) {
        throw std::runtime_error("Failed to write PNG carrier");
    }
}

}  // namespace

namespace basefwx {

std::vector<std::uint8_t> ReadFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read file size: " + path);
    }
    input.seekg(0, std::ios::beg);
    
    std::vector<std::uint8_t> data;
    data.resize(static_cast<std::size_t>(size));
    
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!input) {
            throw std::runtime_error("Failed to read file: " + path);
        }
    }
    return data;
}

std::string ResolvePassword(const std::string& input) {
    if (input.empty()) {
        return input;
    }
    std::filesystem::path candidate(input);
    if (input.rfind("~/", 0) == 0 || input.rfind("~\\", 0) == 0) {
        std::string home = basefwx::env::HomeDir();
        if (!home.empty()) {
            candidate = std::filesystem::path(home) / input.substr(2);
        }
    }
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec) && std::filesystem::is_regular_file(candidate, ec)) {
        auto data = ReadFile(candidate.string());
        return std::string(reinterpret_cast<const char*>(data.data()), data.size());
    }
    return input;
}

InspectResult InspectBlob(const std::vector<std::uint8_t>& blob) {
    InspectResult result;
    auto parts = basefwx::format::UnpackLengthPrefixed(blob, 3);
    result.user_blob_len = parts[0].size();
    result.master_blob_len = parts[1].size();
    result.payload_len = parts[2].size();

    auto preview = basefwx::format::TryDecodeMetadata(parts[2]);
    if (preview) {
        result.has_metadata = true;
        result.metadata_len = preview->metadata_len;
        result.metadata_base64 = preview->metadata_base64;
        result.metadata_json = preview->metadata_json;
    }
    return result;
}

std::string B256Encode(const std::string& input) {
    return basefwx::codec::B256Encode(input);
}

std::string B256Decode(const std::string& input) {
    return basefwx::codec::B256Decode(input);
}

std::string B64Encode(const std::string& input) {
    return basefwx::base64::Encode(std::string_view(input));
}

std::string B64Decode(const std::string& input) {
    bool ok = false;
    std::string decoded = basefwx::base64::DecodeToString(input, &ok);
    if (!ok) {
        throw std::runtime_error("Invalid base64 payload");
    }
    return decoded;
}

std::string N10Encode(const std::string& input) {
    if (input.size() >= kN10Mod) {
        throw std::runtime_error("n10 input is too large");
    }

    std::size_t block_count = (input.size() + 3) / 4;
    if (block_count > (std::numeric_limits<std::size_t>::max() - kN10HeaderDigits) / 10) {
        throw std::runtime_error("n10 input is too large");
    }

    std::string out;
    out.reserve(kN10HeaderDigits + (block_count * 10));
    out.append(kN10Magic);
    out.append(kN10Version);
    AppendFixed10(out, N10Transform(static_cast<std::uint64_t>(input.size()), 0));
    AppendFixed10(out, N10Transform(static_cast<std::uint64_t>(Fnv1a32(input)), 1));

    const auto* bytes = reinterpret_cast<const unsigned char*>(input.data());
    std::size_t offset = 0;
    for (std::size_t block = 0; block < block_count; ++block) {
        std::uint32_t word = 0;
        std::size_t remaining = input.size() - offset;
        std::size_t chunk = remaining < 4 ? remaining : 4;
        for (std::size_t i = 0; i < chunk; ++i) {
            word |= static_cast<std::uint32_t>(bytes[offset + i]) << (24 - static_cast<int>(i) * 8);
        }
        offset += chunk;
        AppendFixed10(out, N10Transform(static_cast<std::uint64_t>(word), block + 2));
    }
    return out;
}

std::string N10Decode(const std::string& input) {
    std::string_view in(input);
    if (in.size() < kN10HeaderDigits) {
        throw std::runtime_error("n10 payload is too short");
    }
    if (in.substr(0, 6) != kN10Magic || in.substr(6, 2) != kN10Version) {
        throw std::runtime_error("n10 header mismatch");
    }

    std::uint64_t payload_len = N10InverseTransform(ParseFixed10(in, 8), 0);
    if (payload_len >= kN10Mod) {
        throw std::runtime_error("n10 decoded length is invalid");
    }
    if (payload_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("n10 decoded length is unsupported on this platform");
    }

    std::uint64_t checksum_expected = N10InverseTransform(ParseFixed10(in, 18), 1);
    if (checksum_expected > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw std::runtime_error("n10 checksum is invalid");
    }

    std::size_t out_len = static_cast<std::size_t>(payload_len);
    std::size_t block_count = (out_len + 3) / 4;
    if (block_count > (std::numeric_limits<std::size_t>::max() - kN10HeaderDigits) / 10) {
        throw std::runtime_error("n10 payload length overflow");
    }
    std::size_t expected_digits = kN10HeaderDigits + (block_count * 10);
    if (in.size() != expected_digits) {
        throw std::runtime_error("n10 payload length mismatch");
    }

    std::string out;
    out.resize(block_count * 4);
    std::size_t in_offset = kN10HeaderDigits;
    for (std::size_t block = 0; block < block_count; ++block) {
        std::uint64_t decoded = N10InverseTransform(ParseFixed10(in, in_offset), block + 2);
        in_offset += 10;
        if (decoded > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
            throw std::runtime_error("n10 block out of range");
        }
        std::uint32_t word = static_cast<std::uint32_t>(decoded);
        std::size_t out_offset = block * 4;
        out[out_offset] = static_cast<char>((word >> 24) & 0xFFu);
        out[out_offset + 1] = static_cast<char>((word >> 16) & 0xFFu);
        out[out_offset + 2] = static_cast<char>((word >> 8) & 0xFFu);
        out[out_offset + 3] = static_cast<char>(word & 0xFFu);
    }

    out.resize(out_len);
    std::uint32_t checksum_actual = Fnv1a32(out);
    if (checksum_actual != static_cast<std::uint32_t>(checksum_expected)) {
        throw std::runtime_error("n10 checksum mismatch");
    }
    return out;
}

std::string Hash512(const std::string& input) {
    return DigestHex(input, EVP_sha512());
}

std::string Uhash513(const std::string& input) {
    std::string h1 = DigestHex(input, EVP_sha256());
    std::string h2 = DigestHex(h1, EVP_sha1());
    std::string h3 = DigestHex(h2, EVP_sha512());
    std::string h4 = DigestHex(input, EVP_sha512());
    return DigestHex(h3 + h4, EVP_sha256());
}

std::string Bi512Encode(const std::string& input) {
    if (input.empty()) {
        throw std::runtime_error("bi512encode expects non-empty input");
    }
    std::string code;
    code.push_back(input.front());
    code.push_back(input.back());
    std::string md = MdCode(input);
    std::string md_code = MdCode(code);
    std::string diff;
    if (CompareMagnitude(md, md_code) >= 0) {
        diff = SubtractMagnitude(md, md_code);
    } else {
        diff = "0" + SubtractMagnitude(md_code, md);
    }
    std::string packed = basefwx::codec::B256Encode(diff);
    packed = ReplaceAll(packed, "=", "4G5tRA");
    return DigestHex(packed, EVP_sha256());
}

std::string A512Encode(const std::string& input) {
    std::string md = MdCode(input);
    std::string md_len = std::to_string(md.size());
    std::string prefix = std::to_string(md_len.size()) + md_len;
    std::size_t len_val = md.size();
    std::string code = std::to_string(len_val * len_val);
    std::string md_code = MdCode(code);
    std::string diff;
    if (CompareMagnitude(md, md_code) >= 0) {
        diff = SubtractMagnitude(md, md_code);
    } else {
        diff = "0" + SubtractMagnitude(md_code, md);
    }
    std::string packed = basefwx::codec::B256Encode(diff);
    packed = ReplaceAll(packed, "=", "4G5tRA");
    return prefix + packed;
}

std::string A512Decode(const std::string& input) {
    try {
        if (input.empty()) {
            throw std::runtime_error("Empty a512 payload");
        }
        if (input[0] < '0' || input[0] > '9') {
            throw std::runtime_error("Invalid a512 length marker");
        }
        int len_len = input[0] - '0';
        if (len_len <= 0 || input.size() < static_cast<std::size_t>(len_len) + 1) {
            throw std::runtime_error("Invalid a512 length encoding");
        }
        std::string len_str = input.substr(1, static_cast<std::size_t>(len_len));
        std::size_t md_len = static_cast<std::size_t>(std::stoul(len_str));
        std::string payload = input.substr(static_cast<std::size_t>(len_len) + 1);
        std::string code = std::to_string(md_len * md_len);
        std::string md_code = MdCode(code);
        std::string restored = basefwx::codec::B256Decode(ReplaceAll(payload, "4G5tRA", "="));
        if (!restored.empty() && restored[0] == '0') {
            restored = "-" + restored.substr(1);
        }
        std::string sum = AddSigned(restored, md_code);
        if (!sum.empty() && sum[0] == '-') {
            throw std::runtime_error("Negative a512 value");
        }
        return MCode(sum);
    } catch (...) {
        return "AN ERROR OCCURED!";
    }
}

std::string B1024Encode(const std::string& input) {
    return Bi512Encode(A512Encode(input));
}

std::string B512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    basefwx::pb512::KdfOptions opts;
    opts.label = kdf.label;
    opts.pbkdf2_iterations = kdf.pbkdf2_iterations;
    opts.argon2_time_cost = kdf.argon2_time_cost;
    opts.argon2_memory_cost = kdf.argon2_memory_cost;
    opts.argon2_parallelism = kdf.argon2_parallelism;
    opts.allow_pbkdf2_fallback = kdf.allow_pbkdf2_fallback;
    return basefwx::pb512::B512Encode(input, ResolvePassword(password), use_master, opts);
}

std::string B512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    basefwx::pb512::KdfOptions opts;
    opts.label = kdf.label;
    opts.pbkdf2_iterations = kdf.pbkdf2_iterations;
    opts.argon2_time_cost = kdf.argon2_time_cost;
    opts.argon2_memory_cost = kdf.argon2_memory_cost;
    opts.argon2_parallelism = kdf.argon2_parallelism;
    opts.allow_pbkdf2_fallback = kdf.allow_pbkdf2_fallback;
    return basefwx::pb512::B512Decode(input, ResolvePassword(password), use_master, opts);
}

std::string Pb512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    basefwx::pb512::KdfOptions opts;
    opts.label = kdf.label;
    opts.pbkdf2_iterations = kdf.pbkdf2_iterations;
    opts.argon2_time_cost = kdf.argon2_time_cost;
    opts.argon2_memory_cost = kdf.argon2_memory_cost;
    opts.argon2_parallelism = kdf.argon2_parallelism;
    opts.allow_pbkdf2_fallback = kdf.allow_pbkdf2_fallback;
    return basefwx::pb512::Pb512Encode(input, ResolvePassword(password), use_master, opts);
}

std::string Pb512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    basefwx::pb512::KdfOptions opts;
    opts.label = kdf.label;
    opts.pbkdf2_iterations = kdf.pbkdf2_iterations;
    opts.argon2_time_cost = kdf.argon2_time_cost;
    opts.argon2_memory_cost = kdf.argon2_memory_cost;
    opts.argon2_parallelism = kdf.argon2_parallelism;
    opts.allow_pbkdf2_fallback = kdf.allow_pbkdf2_fallback;
    return basefwx::pb512::Pb512Decode(input, ResolvePassword(password), use_master, opts);
}

std::string Jmge(const std::string& path,
                 const std::string& password,
                 const std::string& output,
                 bool keep_meta,
                 bool keep_input,
                 bool archive_original) {
    return basefwx::imagecipher::EncryptMedia(
        path,
        ResolvePassword(password),
        output,
        keep_meta,
        keep_input,
        archive_original
    );
}

std::string Jmgd(const std::string& path, const std::string& password, const std::string& output) {
    return basefwx::imagecipher::DecryptMedia(path, ResolvePassword(password), output);
}

std::string Kfme(const std::string& path, const std::string& output, bool bw_mode) {
    std::filesystem::path input_path(path);
    std::string input_ext = KfmPathExt(input_path);
    auto payload = ReadFile(path);
    if (IsKnownKfmAudioExt(input_ext)) {
        std::uint8_t flags = bw_mode ? kKfmFlagBw : 0u;
        auto container = BuildKfmContainer(kKfmModeAudioImage, payload, input_ext, flags);
        std::filesystem::path out_path = ResolveKfmOutputPath(input_path, output, ".png", "kfme");
        WritePngCarrierBytes(out_path, container, bw_mode);
        return out_path.string();
    }
    auto container = BuildKfmContainer(kKfmModeImageAudio, payload, input_ext, 0u);
    std::filesystem::path out_path = ResolveKfmOutputPath(input_path, output, ".wav", "kfme");
    WriteWavCarrierBytes(out_path, container);
    return out_path.string();
}

std::string Kfmd(const std::string& path, const std::string& output, bool bw_mode) {
    if (bw_mode) {
        WarnKfmUsage("kFMd --bw is deprecated and ignored in strict decode mode.");
    }
    std::filesystem::path input_path(path);
    std::string input_ext = KfmPathExt(input_path);
    std::vector<std::string> decode_errors;
    auto decoded = DecodeKfmCarrierContainer(input_path, input_ext, &decode_errors);
    if (!decoded) {
        std::string message =
            "kFMd refused input: file is not a BaseFWX kFM carrier. Use kFMe to encode first.";
        if (!decode_errors.empty()) {
            message += " (" + decode_errors.front() + ")";
        }
        throw std::runtime_error(message);
    }
    std::filesystem::path out_path = ResolveKfmOutputPath(input_path, output, decoded->ext, "kfmd");
    WriteBinaryFileRaw(out_path, decoded->payload);
    return out_path.string();
}

std::string Kfae(const std::string& path, const std::string& output, bool bw_mode) {
    WarnKfmUsage("kFAe is deprecated; using legacy PNG carrier mode. Prefer kFMe for auto mode.");
    std::filesystem::path input_path(path);
    std::string input_ext = KfmPathExt(input_path);
    auto payload = ReadFile(path);
    std::uint8_t flags = bw_mode ? kKfmFlagBw : 0u;
    auto container = BuildKfmContainer(kKfmModeAudioImage, payload, input_ext, flags);
    std::filesystem::path out_path = ResolveKfmOutputPath(input_path, output, ".png", "kfae");
    WritePngCarrierBytes(out_path, container, bw_mode);
    return out_path.string();
}

std::string Kfad(const std::string& path, const std::string& output) {
    WarnKfmUsage("kFAd is deprecated; use kFMd (auto-detect) instead.");
    return Kfmd(path, output, false);
}

std::uint64_t FwxAesLiveEncryptStream(std::istream& source,
                                      std::ostream& dest,
                                      const std::string& password,
                                      bool use_master,
                                      std::size_t chunk_size) {
    return basefwx::livecipher::EncryptStream(source, dest, password, use_master, chunk_size);
}

std::uint64_t FwxAesLiveDecryptStream(std::istream& source,
                                      std::ostream& dest,
                                      const std::string& password,
                                      bool use_master,
                                      std::size_t chunk_size) {
    return basefwx::livecipher::DecryptStream(source, dest, password, use_master, chunk_size);
}

}  // namespace basefwx
