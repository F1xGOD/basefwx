#include "basefwx/basefwx.hpp"

#include "basefwx/codec.hpp"
#include "basefwx/base64.hpp"
#include "basefwx/format.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/imagecipher.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <openssl/evp.h>
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
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Digest context allocation failed");
    }
    unsigned int out_len = 0;
    std::vector<std::uint8_t> out(EVP_MD_size(md));
    try {
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            throw std::runtime_error("Digest init failed");
        }
        if (!input.empty()) {
            if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
                throw std::runtime_error("Digest update failed");
            }
        }
        if (EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1) {
            throw std::runtime_error("Digest final failed");
        }
    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
    EVP_MD_CTX_free(ctx);
    out.resize(out_len);
    return HexEncode(out);
}

std::string MdCode(const std::string& input) {
    std::string out;
    out.reserve(input.size() * 3);
    for (unsigned char ch : input) {
        std::string digits = std::to_string(static_cast<unsigned int>(ch));
        out.append(std::to_string(digits.size()));
        out.append(digits);
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
        std::string num = input.substr(idx, static_cast<std::size_t>(len));
        idx += static_cast<std::size_t>(len);
        int val = std::stoi(num);
        out.push_back(static_cast<char>(val));
    }
    return out;
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
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
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
    std::vector<std::uint8_t> data(input.begin(), input.end());
    return basefwx::base64::Encode(data);
}

std::string B64Decode(const std::string& input) {
    bool ok = false;
    std::vector<std::uint8_t> decoded = basefwx::base64::Decode(input, &ok);
    if (!ok) {
        throw std::runtime_error("Invalid base64 payload");
    }
    return std::string(decoded.begin(), decoded.end());
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
                 bool keep_input) {
    return basefwx::imagecipher::EncryptMedia(path, ResolvePassword(password), output, keep_meta, keep_input);
}

std::string Jmgd(const std::string& path, const std::string& password, const std::string& output) {
    return basefwx::imagecipher::DecryptMedia(path, ResolvePassword(password), output);
}

}  // namespace basefwx
