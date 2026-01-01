#include "basefwx/pq.hpp"

#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#include <zlib.h>

#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
#include <oqs/oqs.h>
#endif

namespace basefwx::pq {

namespace {

Bytes ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open key file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read key size: " + path.string());
    }
    input.seekg(0, std::ios::beg);
    Bytes data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!input) {
            throw std::runtime_error("Failed to read key file: " + path.string());
        }
    }
    return data;
}

Bytes TrimBytes(const Bytes& raw) {
    if (raw.empty()) {
        return raw;
    }
    std::size_t start = 0;
    std::size_t end = raw.size();
    while (start < end && std::isspace(static_cast<unsigned char>(raw[start]))) {
        ++start;
    }
    while (end > start && std::isspace(static_cast<unsigned char>(raw[end - 1]))) {
        --end;
    }
    return Bytes(raw.begin() + static_cast<std::ptrdiff_t>(start),
                 raw.begin() + static_cast<std::ptrdiff_t>(end));
}

std::optional<Bytes> TryZlibDecompress(const Bytes& input) {
    if (input.empty()) {
        return Bytes{};
    }
    z_stream zs{};
    zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));
    zs.avail_in = static_cast<uInt>(input.size());
    if (inflateInit(&zs) != Z_OK) {
        return std::nullopt;
    }
    Bytes out;
    std::array<std::uint8_t, 8192> buffer{};
    int rc = Z_OK;
    while (rc == Z_OK) {
        zs.next_out = buffer.data();
        zs.avail_out = static_cast<uInt>(buffer.size());
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&zs);
            return std::nullopt;
        }
        std::size_t produced = buffer.size() - zs.avail_out;
        if (produced > 0) {
            out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(produced));
        }
    }
    inflateEnd(&zs);
    return out;
}

bool ContainsCandidate(const std::vector<Bytes>& candidates, const Bytes& value) {
    return std::any_of(candidates.begin(), candidates.end(),
                       [&value](const Bytes& candidate) { return candidate == value; });
}

std::filesystem::path ExpandUser(const std::string& path) {
    if (path.rfind("~/", 0) == 0 || path.rfind("~\\", 0) == 0) {
        std::string home = basefwx::env::HomeDir();
        if (!home.empty()) {
            return std::filesystem::path(home) / path.substr(2);
        }
    }
    return std::filesystem::path(path);
}

}  // namespace

Bytes DecodeKeyBytes(const Bytes& raw) {
    if (raw.empty()) {
        return raw;
    }
    std::vector<Bytes> candidates;
    candidates.push_back(raw);
    Bytes trimmed = TrimBytes(raw);
    if (!trimmed.empty() && trimmed != raw) {
        candidates.push_back(trimmed);
    }
    std::vector<Bytes> decoded_variants;
    for (const auto& candidate : candidates) {
        std::string text(candidate.begin(), candidate.end());
        bool ok = false;
        Bytes decoded = basefwx::base64::Decode(text, &ok);
        if (!ok) {
            continue;
        }
        if (!ContainsCandidate(candidates, decoded) && !ContainsCandidate(decoded_variants, decoded)) {
            decoded_variants.push_back(std::move(decoded));
        }
    }
    candidates.insert(candidates.end(), decoded_variants.begin(), decoded_variants.end());
    for (const auto& candidate : candidates) {
        std::optional<Bytes> inflated = TryZlibDecompress(candidate);
        if (inflated.has_value()) {
            return *inflated;
        }
    }
    return candidates.back();
}

std::optional<Bytes> LoadMasterPublicKey() {
    std::string env_path = basefwx::env::Get("BASEFWX_MASTER_PQ_PUB");
    if (!env_path.empty()) {
        std::filesystem::path candidate = ExpandUser(env_path);
        if (!std::filesystem::exists(candidate)) {
            throw std::runtime_error("Master PQ public key not found at " + candidate.string());
        }
        return DecodeKeyBytes(ReadFileBytes(candidate));
    }
    if (basefwx::env::IsEnabled("ALLOW_BAKED_PUB", false)) {
        Bytes baked(constants::kMasterPqPublicB64.begin(), constants::kMasterPqPublicB64.end());
        return DecodeKeyBytes(baked);
    }
    return std::nullopt;
}

Bytes LoadMasterPrivateKey() {
    std::vector<std::filesystem::path> candidates;
    std::string home = basefwx::env::HomeDir();
    if (!home.empty()) {
        candidates.emplace_back(std::filesystem::path(home) / "master_pq.sk");
    }
    candidates.emplace_back(std::filesystem::path("W:\\master_pq.sk"));

    for (const auto& path : candidates) {
        if (!path.empty() && std::filesystem::exists(path)) {
            return DecodeKeyBytes(ReadFileBytes(path));
        }
    }
    throw std::runtime_error("No master_pq.sk private key found");
}

KemResult KemEncrypt(const Bytes& public_key) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    OQS_KEM* kem = OQS_KEM_new(constants::kMasterPqAlg.data());
    if (!kem) {
        throw std::runtime_error("Failed to initialize ML-KEM-768");
    }
    KemResult result;
    if (public_key.size() != kem->length_public_key) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Invalid ML-KEM public key length");
    }
    result.ciphertext.resize(kem->length_ciphertext);
    result.shared.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, result.ciphertext.data(), result.shared.data(), public_key.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("ML-KEM encapsulation failed");
    }
    OQS_KEM_free(kem);
    return result;
#else
    (void)public_key;
    throw std::runtime_error("ML-KEM-768 support is not enabled in this build");
#endif
}

Bytes KemDecrypt(const Bytes& private_key, const Bytes& ciphertext) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    OQS_KEM* kem = OQS_KEM_new(constants::kMasterPqAlg.data());
    if (!kem) {
        throw std::runtime_error("Failed to initialize ML-KEM-768");
    }
    if (private_key.size() != kem->length_secret_key) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Invalid ML-KEM private key length");
    }
    if (ciphertext.size() != kem->length_ciphertext) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Invalid ML-KEM ciphertext length");
    }
    Bytes shared(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, shared.data(), ciphertext.data(), private_key.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("ML-KEM decapsulation failed");
    }
    OQS_KEM_free(kem);
    return shared;
#else
    (void)private_key;
    (void)ciphertext;
    throw std::runtime_error("ML-KEM-768 support is not enabled in this build");
#endif
}

}  // namespace basefwx::pq
