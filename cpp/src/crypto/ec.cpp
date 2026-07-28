/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/ec.hpp"

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace basefwx::ec {

KemResult& KemResult::operator=(KemResult&& other) noexcept {
    if (this != &other) {
        wipe_shared();
        blob = std::move(other.blob);
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

using basefwx::constants::kMasterEcMagic;

struct BioDeleter {
    void operator()(BIO* bio) const noexcept {
        BIO_free(bio);
    }
};

struct EcKeyDeleter {
    void operator()(EC_KEY* key) const noexcept {
        EC_KEY_free(key);
    }
};

struct EcPointDeleter {
    void operator()(EC_POINT* point) const noexcept {
        EC_POINT_free(point);
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* context) const noexcept {
        EVP_PKEY_CTX_free(context);
    }
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EcKeyPtr = std::unique_ptr<EC_KEY, EcKeyDeleter>;
using EcPointPtr = std::unique_ptr<EC_POINT, EcPointDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr =
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

std::filesystem::path ExpandUser(const std::string& path) {
    if (path.rfind("~/", 0) == 0 || path.rfind("~\\", 0) == 0) {
        std::string home = basefwx::env::HomeDir();
        if (!home.empty()) {
            return std::filesystem::path(home) / path.substr(2);
        }
    }
    return std::filesystem::path(path);
}

std::filesystem::path DefaultPublicPath() {
    return ExpandUser("~/master_ec_public.pem");
}

std::filesystem::path DefaultPrivatePath() {
    return ExpandUser("~/master_ec_private.pem");
}

Bytes ReadFileBytes(const std::filesystem::path& path) {
    constexpr std::uintmax_t kMaxKeyBytes = 4u * 1024u * 1024u;
    std::error_code status_error;
    if (!std::filesystem::is_regular_file(path, status_error)
        || status_error) {
        throw std::runtime_error(
            "Key path is not a regular file: " + path.string());
    }
    const std::uintmax_t file_size =
        std::filesystem::file_size(path, status_error);
    if (status_error) {
        throw std::runtime_error(
            "Failed to inspect key file: " + path.string());
    }
    if (file_size > kMaxKeyBytes) {
        throw std::runtime_error(
            "Key file too large (>4 MiB): " + path.string());
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open key file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read key file: " + path.string());
    }
    if (static_cast<std::uintmax_t>(size) > kMaxKeyBytes) {
        throw std::runtime_error(
            "Key file too large (>4 MiB): " + path.string());
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

void WriteFileBytes(const std::filesystem::path& path, const Bytes& data) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to write key file: " + path.string());
    }
    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!output) {
            throw std::runtime_error("Failed to write key file: " + path.string());
        }
    }
}

void SetPublicPermissions(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
            | std::filesystem::perms::group_read | std::filesystem::perms::others_read,
        std::filesystem::perm_options::replace,
        ec
    );
}

Bytes BioToBytes(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (!mem || !mem->data || mem->length == 0) {
        return {};
    }
    return Bytes(reinterpret_cast<std::uint8_t*>(mem->data),
                 reinterpret_cast<std::uint8_t*>(mem->data) + mem->length);
}

EvpPkeyPtr LoadPublicKey(const Bytes& raw) {
    if (raw.empty()) {
        throw std::runtime_error("Empty EC public key data");
    }
    if (raw.size() > static_cast<std::size_t>(
                         std::numeric_limits<int>::max())) {
        throw std::runtime_error("EC public key data too large");
    }
    BioPtr bio(BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size())));
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    EvpPkeyPtr key(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if (key) {
        return key;
    }
    bio.reset(BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size())));
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    key.reset(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (key) {
        return key;
    }
    const unsigned char* ptr = raw.data();
    key.reset(d2i_PUBKEY(nullptr, &ptr, static_cast<long>(raw.size())));
    if (key) {
        return key;
    }
    ptr = raw.data();
    key.reset(
        d2i_AutoPrivateKey(nullptr, &ptr, static_cast<long>(raw.size())));
    if (key) {
        return key;
    }
    throw std::runtime_error("Unsupported EC public key format");
}

EvpPkeyPtr LoadPrivateKey(const Bytes& raw) {
    if (raw.empty()) {
        throw std::runtime_error("Empty EC private key data");
    }
    if (raw.size() > static_cast<std::size_t>(
                         std::numeric_limits<int>::max())) {
        throw std::runtime_error("EC private key data too large");
    }
    BioPtr bio(BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size())));
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    EvpPkeyPtr key(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (key) {
        return key;
    }
    const unsigned char* ptr = raw.data();
    key.reset(
        d2i_AutoPrivateKey(nullptr, &ptr, static_cast<long>(raw.size())));
    if (key) {
        return key;
    }
    throw std::runtime_error("Unsupported EC private key format");
}

EvpPkeyPtr GenerateKey() {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx) {
        throw std::runtime_error("Failed to initialize EC keygen");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw std::runtime_error("Failed to init EC keygen");
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
            ctx.get(), NID_secp521r1) != 1) {
        throw std::runtime_error("Failed to set EC curve");
    }
    if (EVP_PKEY_CTX_set_ec_param_enc(
            ctx.get(), OPENSSL_EC_NAMED_CURVE) != 1) {
        throw std::runtime_error("Failed to set EC params");
    }
    EVP_PKEY* raw_key = nullptr;
    const int result = EVP_PKEY_keygen(ctx.get(), &raw_key);
    EvpPkeyPtr pkey(raw_key);
    if (result != 1 || !pkey) {
        throw std::runtime_error("Failed to generate EC key");
    }
    return pkey;
}

Bytes PublicPemFromKey(EVP_PKEY* key) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    if (PEM_write_bio_PUBKEY(bio.get(), key) != 1) {
        throw std::runtime_error("Failed to write EC public key");
    }
    return BioToBytes(bio.get());
}

void EnsureCurve(EVP_PKEY* key) {
    EcKeyPtr ec_key(EVP_PKEY_get1_EC_KEY(key));
    if (!ec_key) {
        throw std::runtime_error("EC key expected");
    }
    const EC_GROUP* group = EC_KEY_get0_group(ec_key.get());
    if (!group) {
        throw std::runtime_error("EC key group missing");
    }
    int nid = EC_GROUP_get_curve_name(group);
    if (nid != NID_secp521r1) {
        throw std::runtime_error("EC key curve must be secp521r1");
    }
}

Bytes EncodePublicPoint(EVP_PKEY* key) {
    EcKeyPtr ec_key(EVP_PKEY_get1_EC_KEY(key));
    if (!ec_key) {
        throw std::runtime_error("EC key expected");
    }
    const EC_GROUP* group = EC_KEY_get0_group(ec_key.get());
    const EC_POINT* point = EC_KEY_get0_public_key(ec_key.get());
    if (!group || !point) {
        throw std::runtime_error("EC public key missing");
    }
    std::size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (len == 0) {
        throw std::runtime_error("Failed to encode EC public key");
    }
    Bytes out(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr) != len) {
        throw std::runtime_error("Failed to encode EC public key");
    }
    return out;
}

EvpPkeyPtr PublicKeyFromPoint(const Bytes& encoded) {
    EcKeyPtr ec_key(EC_KEY_new_by_curve_name(NID_secp521r1));
    if (!ec_key) {
        throw std::runtime_error("Failed to create EC key");
    }
    const EC_GROUP* group = EC_KEY_get0_group(ec_key.get());
    if (!group) {
        throw std::runtime_error("Failed to get EC group");
    }
    EcPointPtr point(EC_POINT_new(group));
    if (!point) {
        throw std::runtime_error("Failed to create EC point");
    }
    if (EC_POINT_oct2point(
            group,
            point.get(),
            encoded.data(),
            encoded.size(),
            nullptr) != 1) {
        throw std::runtime_error("Invalid EC public key encoding");
    }
    if (EC_KEY_set_public_key(ec_key.get(), point.get()) != 1) {
        throw std::runtime_error("Failed to set EC public key");
    }
    EvpPkeyPtr pkey(EVP_PKEY_new());
    if (!pkey) {
        throw std::runtime_error("Failed to allocate EVP_PKEY");
    }
    if (EVP_PKEY_set1_EC_KEY(pkey.get(), ec_key.get()) != 1) {
        throw std::runtime_error("Failed to assign EC key");
    }
    return pkey;
}

Bytes DeriveShared(EVP_PKEY* priv, EVP_PKEY* peer) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv, nullptr));
    if (!ctx) {
        throw std::runtime_error("Failed to init ECDH ctx");
    }
    if (EVP_PKEY_derive_init(ctx.get()) != 1) {
        throw std::runtime_error("Failed to init ECDH derive");
    }
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer) != 1) {
        throw std::runtime_error("Failed to set ECDH peer");
    }
    std::size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1 || len == 0) {
        throw std::runtime_error("Failed to size ECDH shared secret");
    }
    Bytes shared(len);
    if (EVP_PKEY_derive(ctx.get(), shared.data(), &len) != 1) {
        basefwx::crypto::SecureClear(shared);
        throw std::runtime_error("Failed to derive ECDH shared secret");
    }
    shared.resize(len);
    return shared;
}

}  // namespace

bool IsEcMasterBlob(const Bytes& blob) {
    constexpr std::size_t point_len =
        basefwx::constants::kMasterEcPointLen;
    constexpr std::size_t header_len = 2;
    if (blob.size() != kMasterEcMagic.size() + header_len + point_len) {
        return false;
    }
    const std::size_t length_offset = kMasterEcMagic.size();
    const std::uint16_t declared = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(blob[length_offset]) << 8)
        | blob[length_offset + 1]);
    return declared == point_len
        && blob[length_offset + header_len] == 0x04
        && std::equal(
            kMasterEcMagic.begin(), kMasterEcMagic.end(), blob.begin());
}

std::optional<Bytes> LoadMasterPublicKey(bool create_if_missing) {
    (void)create_if_missing;
    std::string env_pub = basefwx::env::Get("BASEFWX_MASTER_EC_PUB");
    if (!env_pub.empty()) {
        std::filesystem::path pub_path = ExpandUser(env_pub);
        if (std::filesystem::exists(pub_path)) {
            return ReadFileBytes(pub_path);
        }
        throw std::runtime_error(
            "Configured master EC public key not found: "
            + pub_path.string());
    }
    std::filesystem::path pub_path = DefaultPublicPath();
    std::filesystem::path priv_path = DefaultPrivatePath();
    if (std::filesystem::exists(pub_path)) {
        return ReadFileBytes(pub_path);
    }
    if (std::filesystem::exists(priv_path)) {
        basefwx::crypto::SecureBytes priv_bytes{
            ReadFileBytes(priv_path)};
        EvpPkeyPtr key = LoadPrivateKey(priv_bytes.bytes());
        Bytes pub_bytes = PublicPemFromKey(key.get());
        if (!std::filesystem::exists(pub_path)) {
            WriteFileBytes(pub_path, pub_bytes);
            SetPublicPermissions(pub_path);
        }
        return pub_bytes;
    }
    return std::nullopt;
}

Bytes LoadMasterPrivateKey() {
    std::vector<std::filesystem::path> candidates;
    std::string env_priv = basefwx::env::Get("BASEFWX_MASTER_EC_PRIV");
    if (!env_priv.empty()) {
        const auto configured = ExpandUser(env_priv);
        if (!std::filesystem::exists(configured)) {
            throw std::runtime_error(
                "Configured master EC private key not found: "
                + configured.string());
        }
        return ReadFileBytes(configured);
    }
    candidates.push_back(DefaultPrivatePath());
    for (const auto& path : candidates) {
        if (!path.empty() && std::filesystem::exists(path)) {
            return ReadFileBytes(path);
        }
    }
    throw std::runtime_error("No master EC private key found");
}

KemResult KemEncrypt(const Bytes& public_key) {
    EvpPkeyPtr peer = LoadPublicKey(public_key);
    EnsureCurve(peer.get());
    EvpPkeyPtr eph = GenerateKey();
    basefwx::crypto::SecureBytes shared{
        DeriveShared(eph.get(), peer.get())};
    Bytes epk = EncodePublicPoint(eph.get());
    if (epk.size() > 0xFFFFu) {
        throw std::runtime_error("EC public key encoding too large");
    }
    Bytes blob;
    blob.reserve(kMasterEcMagic.size() + 2 + epk.size());
    blob.insert(blob.end(), kMasterEcMagic.begin(), kMasterEcMagic.end());
    std::uint16_t len = static_cast<std::uint16_t>(epk.size());
    blob.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
    blob.push_back(static_cast<std::uint8_t>(len & 0xFF));
    blob.insert(blob.end(), epk.begin(), epk.end());
    return {std::move(blob), shared.Release()};
}

Bytes KemDecrypt(const Bytes& private_key, const Bytes& blob) {
    if (!IsEcMasterBlob(blob)) {
        throw std::runtime_error("Invalid EC master blob");
    }
    if (blob.size() < kMasterEcMagic.size() + 2) {
        throw std::runtime_error("Malformed EC master blob");
    }
    std::size_t offset = kMasterEcMagic.size();
    std::uint16_t len = static_cast<std::uint16_t>(blob[offset] << 8 | blob[offset + 1]);
    offset += 2;
    if (blob.size() < offset + len) {
        throw std::runtime_error("Truncated EC master blob");
    }
    Bytes epk(blob.begin() + static_cast<std::ptrdiff_t>(offset),
              blob.begin() + static_cast<std::ptrdiff_t>(offset + len));
    EvpPkeyPtr priv = LoadPrivateKey(private_key);
    EnsureCurve(priv.get());
    EvpPkeyPtr peer = PublicKeyFromPoint(epk);
    return DeriveShared(priv.get(), peer.get());
}

}  // namespace basefwx::ec
