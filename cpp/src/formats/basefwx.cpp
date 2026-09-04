/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/basefwx.hpp"

#include "basefwx/codec.hpp"
#include "basefwx/base64.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/crypto_utils.hpp"
#include "basefwx/format.hpp"
#include "basefwx/pb512.hpp"
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
#include <limits>
#include <optional>
#include <openssl/evp.h>
#include <random>
#include <stdexcept>
#include <string_view>


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

std::string MoveOutputPath(const std::string& current_path, const std::string& requested_path) {
    if (requested_path.empty() || current_path == requested_path) {
        return current_path;
    }
    std::filesystem::path src(current_path);
    std::filesystem::path dst(requested_path);
    std::error_code ec;
    if (std::filesystem::exists(dst, ec) && std::filesystem::is_directory(dst, ec)) {
        dst /= src.filename();
    }
    if (!dst.parent_path().empty()) {
        std::filesystem::create_directories(dst.parent_path(), ec);
        if (ec) {
            throw std::runtime_error("Failed to prepare output path: " + dst.string());
        }
    }
    std::filesystem::rename(src, dst, ec);
    if (ec) {
        ec.clear();
        std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            throw std::runtime_error("Failed to move output to: " + dst.string());
        }
        ec.clear();
        std::filesystem::remove(src, ec);
        if (ec) {
            throw std::runtime_error("Failed to finalize moved output: " + dst.string());
        }
    }
    return dst.string();
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


// True when `value` claims to be a password reference rather than a password.
// A resolved secret that still looks like one is refused, because that is the
// single condition under which resolving twice would yield two different keys.
bool LooksLikePasswordReference(const std::string& value) {
    return value.rfind("password://", 0) == 0 || value.rfind("file://", 0) == 0;
}

std::string ResolvePassword(const std::string& input) {
    if (input.empty()) {
        return input;
    }
    // 3.7.0: bare passwords are ALWAYS literal. Filesystem read is opt-in
    // via an explicit `file://` URI scheme. The old auto-detect behavior
    // (read input as a file if it happened to name an existing path)
    // could silently turn a user's password into a totally different
    // secret depending on filesystem state, and let an attacker who
    // controlled a file at a guessable path downgrade unrelated wraps
    // to a known key. `password://literal` is also recognized for
    // callers that want to force the literal-string interpretation even
    // when the string happens to contain `://`.
    constexpr std::string_view kFileScheme = "file://";
    constexpr std::string_view kPasswordScheme = "password://";
    if (input.rfind(kPasswordScheme, 0) == 0) {
        std::string literal = input.substr(kPasswordScheme.size());
        if (LooksLikePasswordReference(literal)) {
            basefwx::crypto::SecureClear(literal);
            throw std::runtime_error(
                "password:// value itself starts with a password:// or "
                "file:// scheme. Resolving it again would derive a different "
                "key than resolving it once, so it is refused as ambiguous. "
                "ResolvePassword is idempotent by contract: its result is "
                "never a reference.");
        }
        return literal;
    }
    if (input.rfind(kFileScheme, 0) == 0) {
        std::string path = input.substr(kFileScheme.size());
        if (path.rfind("~/", 0) == 0 || path.rfind("~\\", 0) == 0) {
            std::string home = basefwx::env::HomeDir();
            if (!home.empty()) {
                path = (std::filesystem::path(home) / path.substr(2)).string();
            }
        }
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
            throw std::runtime_error("Password file not found: " + path);
        }
        // lgtm[cpp/path-injection] - The `file://` scheme is the documented
        // way for a caller to point at a password file on their own machine
        // (see LICENSING.md / SECURITY.md). The "uncontrolled data" is the
        // caller's own argument, not an attacker-controlled value crossing
        // a trust boundary. is_regular_file() blocks the obvious
        // /dev/random etc. cases; the password itself is then hashed by
        // Argon2id/PBKDF2 before any cryptographic use.
        auto data = ReadFile(path);
        std::string secret(reinterpret_cast<const char*>(data.data()),
                           data.size());
        if (LooksLikePasswordReference(secret)) {
            basefwx::crypto::SecureClear(secret);
            throw std::runtime_error(
                "Password file " + path +
                " starts with a password:// or file:// scheme. Resolving it "
                "again would derive a different key than resolving it once, "
                "so the contents are refused as ambiguous rather than "
                "guessed. Store the literal secret bytes in the file.");
        }
        return secret;
    }
    return input;
}

void RequireStrongPasswordForEncryption(const std::string& password, std::string_view context) {
    if (password.empty()) {
        return;
    }
#if defined(BASEFWX_TESTING) && BASEFWX_TESTING
    if (!basefwx::env::TestKdfIters().empty()) {
        return;
    }
#endif
    if (basefwx::env::IsEnabled("BASEFWX_ALLOW_WEAK_PASSWORD", false)) {
        return;
    }
    std::size_t min_len = basefwx::constants::kMinimumPasswordLength;
    std::string raw_min = basefwx::env::Get("BASEFWX_MIN_PASSWORD_LEN");
    if (!raw_min.empty()) {
        raw_min.erase(
            raw_min.begin(),
            std::find_if(raw_min.begin(), raw_min.end(),
                         [](unsigned char ch) { return !std::isspace(ch); }));
        raw_min.erase(
            std::find_if(raw_min.rbegin(), raw_min.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); })
                .base(),
            raw_min.end());
        if (!raw_min.empty() && raw_min.front() != '-') {
            try {
                std::size_t consumed = 0;
                const unsigned long long parsed = std::stoull(raw_min, &consumed);
                if (consumed == raw_min.size() &&
                    parsed <= static_cast<unsigned long long>(
                        std::numeric_limits<std::size_t>::max())) {
                    min_len = static_cast<std::size_t>(parsed);
                }
            } catch (const std::exception&) {
            }
        }
    }
    if (min_len == 0 || password.size() >= min_len) {
        return;
    }
    std::string label = context.empty() ? "Encryption" : std::string(context);
    throw std::runtime_error(
        label + " requires a password of at least " + std::to_string(min_len)
        + " UTF-8 bytes (set BASEFWX_ALLOW_WEAK_PASSWORD=1 to override)");
}

InspectResult InspectBlob(const std::vector<std::uint8_t>& blob) {
    InspectResult result;
    auto read_u32 = [&](std::size_t offset) -> std::uint32_t {
        if (offset + 4 > blob.size()) {
            throw std::runtime_error("Malformed length-prefixed blob (missing length)");
        }
        return (static_cast<std::uint32_t>(blob[offset]) << 24)
               | (static_cast<std::uint32_t>(blob[offset + 1]) << 16)
               | (static_cast<std::uint32_t>(blob[offset + 2]) << 8)
               | static_cast<std::uint32_t>(blob[offset + 3]);
    };

    std::size_t offset = 0;
    std::uint32_t len_user = read_u32(offset);
    offset += 4;
    if (offset + len_user > blob.size()) {
        throw std::runtime_error("Malformed length-prefixed blob (truncated part)");
    }
    result.user_blob_len = len_user;
    offset += len_user;

    std::uint32_t len_master = read_u32(offset);
    offset += 4;
    if (offset + len_master > blob.size()) {
        throw std::runtime_error("Malformed length-prefixed blob (truncated part)");
    }
    result.master_blob_len = len_master;
    offset += len_master;

    std::uint32_t len_payload_u32 = read_u32(offset);
    offset += 4;
    if (offset > blob.size()) {
        throw std::runtime_error("Malformed length-prefixed blob (truncated part)");
    }
    std::size_t payload_available = blob.size() - offset;
    if (static_cast<std::uint32_t>(payload_available) != len_payload_u32) {
        throw std::runtime_error("Malformed length-prefixed blob (extra bytes)");
    }
    result.payload_len = payload_available;

    if (payload_available >= 4) {
        std::uint32_t meta_len = read_u32(offset);
        std::size_t meta_end = 4 + static_cast<std::size_t>(meta_len);
        if (meta_end <= payload_available) {
            std::vector<std::uint8_t> payload_prefix;
            payload_prefix.reserve(meta_end);
            payload_prefix.insert(payload_prefix.end(),
                                  blob.begin() + static_cast<std::ptrdiff_t>(offset),
                                  blob.begin() + static_cast<std::ptrdiff_t>(offset + meta_end));
            auto preview = basefwx::format::TryDecodeMetadata(payload_prefix);
            if (preview) {
                result.has_metadata = true;
                result.metadata_len = preview->metadata_len;
                result.metadata_base64 = preview->metadata_base64;
                result.metadata_json = preview->metadata_json;
            }
        }
    }
    return result;
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

std::string B512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    std::string resolved = ResolvePassword(password);
    RequireStrongPasswordForEncryption(resolved, "b512 encode");
    return basefwx::pb512::B512Encode(input, resolved, use_master, kdf);
}

std::string B512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    return basefwx::pb512::B512Decode(input, ResolvePassword(password), use_master, kdf);
}

std::string Pb512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    std::string resolved = ResolvePassword(password);
    RequireStrongPasswordForEncryption(resolved, "pb512 encode");
    return basefwx::pb512::Pb512Encode(input, resolved, use_master, kdf);
}

std::string Pb512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf) {
    return basefwx::pb512::Pb512Decode(input, ResolvePassword(password), use_master, kdf);
}

std::string FwxAesFile(const std::string& path,
                       const std::string& password,
                       const std::string& output,
                       bool use_master,
                       FwxAesProfile profile,
                       bool normalize,
                       std::size_t normalize_threshold,
                       const std::string& cover_phrase,
                       bool compress,
                       bool keep_input) {
    std::string resolved = ResolvePassword(password);
    std::filesystem::path input_path(path);
    std::string ext = input_path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    bool decrypt = (ext == ".fwx");
    if (!decrypt) {
        RequireStrongPasswordForEncryption(resolved, profile == FwxAesProfile::Heavy ? "fwxAES-heavy" : "fwxAES");
    }

    if (profile == FwxAesProfile::Heavy) {
        if (normalize || normalize_threshold != 8 * 1024 || cover_phrase != "low taper fade") {
            throw std::runtime_error("fwxAES heavy mode does not support normalize options");
        }
        basefwx::filecodec::FileOptions file_opts;
        file_opts.use_master = use_master;
        file_opts.compress = compress;
        file_opts.keep_input = keep_input;
        std::string produced = decrypt
            ? basefwx::filecodec::Pb512DecodeFile(path, resolved, file_opts)
            : basefwx::filecodec::Pb512EncodeFile(path, resolved, file_opts);
        return MoveOutputPath(produced, output);
    }

    std::string out = output;
    if (out.empty()) {
        if (!decrypt) {
            out = path + ".fwx";
        } else if (path.size() >= 4 && path.rfind(".fwx") == path.size() - 4) {
            out = path.substr(0, path.size() - 4);
        } else {
            out = path + ".out";
        }
    }

    if (decrypt) {
        basefwx::fwxaes::DecryptFile(path, out, resolved, use_master);
        return out;
    }

    basefwx::fwxaes::Options fwxaes_opts;
    fwxaes_opts.use_master = use_master;
    basefwx::fwxaes::NormalizeOptions norm;
    norm.enabled = normalize;
    norm.threshold = normalize_threshold;
    norm.cover_phrase = cover_phrase;
    basefwx::fwxaes::PackOptions pack_opts;
    pack_opts.compress = compress;
    basefwx::fwxaes::EncryptFile(path, out, resolved, fwxaes_opts, norm, pack_opts, keep_input);
    return out;
}

std::uint64_t FwxAesLiveEncryptStream(std::istream& source,
                                      std::ostream& dest,
                                      const std::string& password,
                                      bool use_master,
                                      std::size_t chunk_size) {
    std::string resolved = ResolvePassword(password);
    RequireStrongPasswordForEncryption(resolved, "fwxAES live");
    return basefwx::livecipher::EncryptStream(source, dest, resolved, use_master, chunk_size);
}

std::uint64_t FwxAesLiveDecryptStream(std::istream& source,
                                      std::ostream& dest,
                                      const std::string& password,
                                      bool use_master,
                                      std::size_t chunk_size) {
    return basefwx::livecipher::DecryptStream(source, dest, password, use_master, chunk_size);
}

}  // namespace basefwx
