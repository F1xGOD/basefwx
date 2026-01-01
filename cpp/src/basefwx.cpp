#include "basefwx/basefwx.hpp"

#include "basefwx/codec.hpp"
#include "basefwx/format.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/imagecipher.hpp"
#include "basefwx/env.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>

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
