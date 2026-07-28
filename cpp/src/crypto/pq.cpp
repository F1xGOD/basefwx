/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/pq.hpp"

#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <utility>

#include <zlib.h>

#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
#include <oqs/oqs.h>
#endif

namespace basefwx::pq {

KemKeyPair& KemKeyPair::operator=(KemKeyPair&& other) noexcept {
    if (this != &other) {
        wipe_private();
        public_key = std::move(other.public_key);
        private_key = std::move(other.private_key);
    }
    return *this;
}

KemKeyPair::~KemKeyPair() {
    wipe_private();
}

void KemKeyPair::wipe_private() noexcept {
    basefwx::crypto::SecureClear(private_key);
}

KemResult& KemResult::operator=(KemResult&& other) noexcept {
    if (this != &other) {
        // Wipe the outgoing secret before letting the new content take over.
        wipe_shared();
        ciphertext = std::move(other.ciphertext);
        shared = std::move(other.shared);
    }
    return *this;
}

KemResult::~KemResult() {
    wipe_shared();
}

void KemResult::wipe_shared() noexcept {
    basefwx::crypto::SecureClear(shared);
}

namespace {

constexpr std::size_t kMaxKeyBytes = 4u * 1024u * 1024u;

std::string NormalizeAlg(std::string value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(),
        [](unsigned char ch) { return std::isspace(ch) != 0; });
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(),
        [](unsigned char ch) { return std::isspace(ch) != 0; }).base();
    if (first >= last) {
        return {};
    }
    value = std::string(first, last);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (value == "kyber768" || value == "kyber-768") {
        return std::string(constants::kMasterPqAlg);
    }
    if (value == "kyber1024" || value == "kyber-1024") {
        return std::string(constants::kMasterPqAlgHigh);
    }
    return value;
}

Bytes ReadFileBytes(const std::filesystem::path& path) {
    // ML-KEM-768 public/private keys are ~1.2 KiB / 2.4 KiB; ml-kem-1024 is
    // ~1.6 KiB / 3.2 KiB. Cap at 4 MiB so a malicious symlink (e.g.
    // BASEFWX_MASTER_PQ_PUB pointing at /dev/zero or a large file)
    // cannot OOM the process before the format check rejects the data.
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open key file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read key size: " + path.string());
    }
    if (size > static_cast<std::streamoff>(kMaxKeyBytes)) {
        throw std::runtime_error("Key file too large (>4 MiB): " + path.string());
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
            if (produced > kMaxKeyBytes - out.size()) {
                inflateEnd(&zs);
                throw std::runtime_error("Decoded key material too large (>4 MiB)");
            }
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

#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
struct OqsKemDeleter {
    void operator()(OQS_KEM* kem) const noexcept { OQS_KEM_free(kem); }
};

using OqsKemPtr = std::unique_ptr<OQS_KEM, OqsKemDeleter>;

OqsKemPtr NewKem(KemAlgorithm algorithm) {
    OqsKemPtr kem(OQS_KEM_new(std::string(KemAlgorithmName(algorithm)).c_str()));
    if (!kem) {
        throw std::runtime_error(
            "Failed to initialize " + std::string(KemAlgorithmName(algorithm)));
    }
    return kem;
}

KemAlgorithm InferKemFromPublicKeySize(std::size_t public_key_size) {
    for (const KemAlgorithm algorithm :
         {KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024}) {
        auto kem = NewKem(algorithm);
        if (public_key_size == kem->length_public_key) {
            return algorithm;
        }
    }
    throw std::runtime_error(
        "Invalid ML-KEM public key length; expected ML-KEM-768 or ML-KEM-1024");
}

KemAlgorithm InferKemFromDecapsulationSizes(std::size_t private_key_size,
                                            std::size_t ciphertext_size) {
    for (const KemAlgorithm algorithm :
         {KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024}) {
        auto kem = NewKem(algorithm);
        if (private_key_size == kem->length_secret_key &&
            ciphertext_size == kem->length_ciphertext) {
            return algorithm;
        }
    }
    throw std::runtime_error(
        "Invalid or mismatched ML-KEM private-key/ciphertext lengths");
}
#endif

}  // namespace

std::string_view KemAlgorithmName(KemAlgorithm algorithm) {
    switch (algorithm) {
        case KemAlgorithm::MlKem768:
            return constants::kMasterPqAlg;
        case KemAlgorithm::MlKem1024:
            return constants::kMasterPqAlgHigh;
    }
    throw std::runtime_error("Unknown ML-KEM algorithm");
}

bool IsSupportedKemAlgorithm(std::string_view algorithm) {
    const std::string normalized = NormalizeAlg(std::string(algorithm));
    return normalized == constants::kMasterPqAlg
        || normalized == constants::kMasterPqAlgHigh;
}

std::string CurrentKemAlgorithm() {
    std::string configured = NormalizeAlg(basefwx::env::Get("BASEFWX_MASTER_PQ_ALG"));
    if (configured.empty()) {
        if (basefwx::env::IsEnabled("BASEFWX_PQ_MAX", false)
            || basefwx::env::IsEnabled("BASEFWX_PQ_1024", false)) {
            return std::string(constants::kMasterPqAlgHigh);
        }
        return std::string(constants::kMasterPqAlg);
    }
    if (IsSupportedKemAlgorithm(configured)) {
        return configured;
    }
    throw std::runtime_error("Unsupported ML-KEM algorithm: " + configured);
}

KemAlgorithm InferKemAlgorithmFromPublicKey(const Bytes& public_key) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    return InferKemFromPublicKeySize(public_key.size());
#else
    (void)public_key;
    throw std::runtime_error(
        "ML-KEM public-key inference requires an OQS-enabled build");
#endif
}

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
    const std::string kem_alg = CurrentKemAlgorithm();

    // 1) Runtime path: explicit env-var pointing at a key file. Always wins.
    std::string env_path = basefwx::env::Get("BASEFWX_MASTER_PQ_PUB");
    if (!env_path.empty()) {
        std::filesystem::path candidate = ExpandUser(env_path);
        if (!std::filesystem::exists(candidate)) {
            throw std::runtime_error("Master PQ public key not found at " + candidate.string());
        }
        // lgtm[cpp/path-injection] - BASEFWX_MASTER_PQ_PUB is the documented
        // way for an operator to point at their own master key file on
        // their own machine; the env var is part of the public API contract
        // (see SECURITY.md). The "uncontrolled data" here is the operator's
        // own configuration. ReadFileBytes additionally caps the size at
        // 4 MiB to bound damage from a misconfigured symlink target.
        return DecodeKeyBytes(ReadFileBytes(candidate));
    }

    // 2) Build-time path: if this build baked a key via the
    // BASEFWX_MASTER_PQ_PUB_B64 CMake option, use it. Empty by default
    // for release artifacts — there is no maintainer-held escrow key in
    // upstream binaries. The 3.6.4 BASEFWX_MASTER_PQ_ALLOW_BAKED /
    // ALLOW_BAKED_PUB env-var path is removed; a self-baker just rebuilds
    // with -DBASEFWX_MASTER_PQ_PUB_B64=<their-key>.
    if (!constants::kMasterPqPublicB64.empty()) {
        if (kem_alg != constants::kMasterPqAlg) {
            throw std::runtime_error("Embedded PQ public key is available only for ml-kem-768");
        }
        Bytes baked(constants::kMasterPqPublicB64.begin(), constants::kMasterPqPublicB64.end());
        return DecodeKeyBytes(baked);
    }
    return std::nullopt;
}

Bytes LoadMasterPrivateKey() {
    // 3.7.0: the previous Windows-specific `W:\master_pq.sk` hardcoded
    // path is gone — it was a maintainer-machine artifact. Callers
    // configure their own location via BASEFWX_MASTER_PQ_SK, falling
    // back to ~/master_pq.sk.
    std::vector<std::filesystem::path> candidates;
    std::string env_path = basefwx::env::Get("BASEFWX_MASTER_PQ_SK");
    if (!env_path.empty()) {
        std::filesystem::path configured = ExpandUser(env_path);
        if (!std::filesystem::exists(configured)) {
            throw std::runtime_error(
                "Configured BASEFWX_MASTER_PQ_SK does not exist: "
                + configured.string());
        }
        return DecodeKeyBytes(ReadFileBytes(configured));
    }
    std::string home = basefwx::env::HomeDir();
    if (!home.empty()) {
        candidates.emplace_back(std::filesystem::path(home) / "master_pq.sk");
    }

    for (const auto& path : candidates) {
        if (!path.empty() && std::filesystem::exists(path)) {
            return DecodeKeyBytes(ReadFileBytes(path));
        }
    }
    throw std::runtime_error("No master_pq.sk private key found (set BASEFWX_MASTER_PQ_SK or place at ~/master_pq.sk)");
}

KemKeyPair GenerateKeyPair(KemAlgorithm algorithm) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    auto kem = NewKem(algorithm);
    KemKeyPair result;
    result.public_key.resize(kem->length_public_key);
    result.private_key.resize(kem->length_secret_key);
    if (OQS_KEM_keypair(kem.get(), result.public_key.data(), result.private_key.data()) !=
        OQS_SUCCESS) {
        throw std::runtime_error(
            std::string(KemAlgorithmName(algorithm)) + " key generation failed");
    }
    return result;
#else
    (void)algorithm;
    throw std::runtime_error("ML-KEM support is not enabled in this build");
#endif
}

KemResult KemEncrypt(KemAlgorithm algorithm, const Bytes& public_key) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    auto kem = NewKem(algorithm);
    KemResult result;
    if (public_key.size() != kem->length_public_key) {
        throw std::runtime_error("Invalid ML-KEM public key length");
    }
    result.ciphertext.resize(kem->length_ciphertext);
    result.shared.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem.get(), result.ciphertext.data(), result.shared.data(),
                       public_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error(
            std::string(KemAlgorithmName(algorithm)) + " encapsulation failed");
    }
    return result;
#else
    (void)algorithm;
    (void)public_key;
    throw std::runtime_error("ML-KEM support is not enabled in this build");
#endif
}

Bytes KemDecrypt(KemAlgorithm algorithm,
                 const Bytes& private_key,
                 const Bytes& ciphertext) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    auto kem = NewKem(algorithm);
    if (private_key.size() != kem->length_secret_key) {
        throw std::runtime_error("Invalid ML-KEM private key length");
    }
    if (ciphertext.size() != kem->length_ciphertext) {
        throw std::runtime_error("Invalid ML-KEM ciphertext length");
    }
    basefwx::crypto::SecureBytes shared{
        Bytes(kem->length_shared_secret)};
    if (OQS_KEM_decaps(kem.get(), shared.data(), ciphertext.data(),
                       private_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error(
            std::string(KemAlgorithmName(algorithm)) + " decapsulation failed");
    }
    return shared.Release();
#else
    (void)algorithm;
    (void)private_key;
    (void)ciphertext;
    throw std::runtime_error("ML-KEM support is not enabled in this build");
#endif
}

KemResult KemEncrypt(const Bytes& public_key) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    return KemEncrypt(InferKemFromPublicKeySize(public_key.size()), public_key);
#else
    (void)public_key;
    throw std::runtime_error("ML-KEM support is not enabled in this build");
#endif
}

Bytes KemDecrypt(const Bytes& private_key, const Bytes& ciphertext) {
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    return KemDecrypt(
        InferKemFromDecapsulationSizes(private_key.size(), ciphertext.size()),
        private_key, ciphertext);
#else
    (void)private_key;
    (void)ciphertext;
    throw std::runtime_error("ML-KEM support is not enabled in this build");
#endif
}

}  // namespace basefwx::pq
