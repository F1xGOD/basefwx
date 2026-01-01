#include "basefwx/ec.hpp"

#include "basefwx/constants.hpp"
#include "basefwx/env.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace basefwx::ec {

namespace {

using basefwx::constants::kMasterEcMagic;

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
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open key file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read key file: " + path.string());
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

void SetPrivatePermissions(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec
    );
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

EVP_PKEY* LoadPublicKey(const Bytes& raw) {
    if (raw.empty()) {
        throw std::runtime_error("Empty EC public key data");
    }
    BIO* bio = BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size()));
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key) {
        return key;
    }
    bio = BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size()));
    key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key) {
        return key;
    }
    const unsigned char* ptr = raw.data();
    key = d2i_PUBKEY(nullptr, &ptr, static_cast<long>(raw.size()));
    if (key) {
        return key;
    }
    ptr = raw.data();
    key = d2i_AutoPrivateKey(nullptr, &ptr, static_cast<long>(raw.size()));
    if (key) {
        return key;
    }
    throw std::runtime_error("Unsupported EC public key format");
}

EVP_PKEY* LoadPrivateKey(const Bytes& raw) {
    if (raw.empty()) {
        throw std::runtime_error("Empty EC private key data");
    }
    BIO* bio = BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size()));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key) {
        return key;
    }
    const unsigned char* ptr = raw.data();
    key = d2i_AutoPrivateKey(nullptr, &ptr, static_cast<long>(raw.size()));
    if (key) {
        return key;
    }
    throw std::runtime_error("Unsupported EC private key format");
}

EVP_PKEY* GenerateKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to initialize EC keygen");
    }
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to init EC keygen");
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp521r1) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set EC curve");
    }
    if (EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set EC params");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1 || !pkey) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate EC key");
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

Bytes PublicPemFromKey(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write EC public key");
    }
    Bytes out = BioToBytes(bio);
    BIO_free(bio);
    return out;
}

Bytes PrivatePemFromKey(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    if (PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write EC private key");
    }
    Bytes out = BioToBytes(bio);
    BIO_free(bio);
    return out;
}

void EnsureCurve(EVP_PKEY* key) {
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key);
    if (!ec_key) {
        throw std::runtime_error("EC key expected");
    }
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    int nid = EC_GROUP_get_curve_name(group);
    EC_KEY_free(ec_key);
    if (nid != NID_secp521r1) {
        throw std::runtime_error("EC key curve must be secp521r1");
    }
}

Bytes EncodePublicPoint(EVP_PKEY* key) {
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key);
    if (!ec_key) {
        throw std::runtime_error("EC key expected");
    }
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
    if (!group || !point) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("EC public key missing");
    }
    std::size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (len == 0) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Failed to encode EC public key");
    }
    Bytes out(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr) != len) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Failed to encode EC public key");
    }
    EC_KEY_free(ec_key);
    return out;
}

EVP_PKEY* PublicKeyFromPoint(const Bytes& encoded) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp521r1);
    if (!ec_key) {
        throw std::runtime_error("Failed to create EC key");
    }
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Failed to create EC point");
    }
    if (EC_POINT_oct2point(group, point, encoded.data(), encoded.size(), nullptr) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Invalid EC public key encoding");
    }
    if (EC_KEY_set_public_key(ec_key, point) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Failed to set EC public key");
    }
    EC_POINT_free(point);
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Failed to allocate EVP_PKEY");
    }
    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Failed to assign EC key");
    }
    EC_KEY_free(ec_key);
    return pkey;
}

Bytes DeriveShared(EVP_PKEY* priv, EVP_PKEY* peer) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to init ECDH ctx");
    }
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to init ECDH derive");
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set ECDH peer");
    }
    std::size_t len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &len) != 1 || len == 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to size ECDH shared secret");
    }
    Bytes shared(len);
    if (EVP_PKEY_derive(ctx, shared.data(), &len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to derive ECDH shared secret");
    }
    shared.resize(len);
    EVP_PKEY_CTX_free(ctx);
    return shared;
}

}  // namespace

bool IsEcMasterBlob(const Bytes& blob) {
    if (blob.size() < kMasterEcMagic.size()) {
        return false;
    }
    return std::equal(kMasterEcMagic.begin(), kMasterEcMagic.end(), blob.begin());
}

std::optional<Bytes> LoadMasterPublicKey(bool create_if_missing) {
    std::string env_pub = basefwx::env::Get("BASEFWX_MASTER_EC_PUB");
    std::string env_priv = basefwx::env::Get("BASEFWX_MASTER_EC_PRIV");
    if (!env_pub.empty()) {
        std::filesystem::path pub_path = ExpandUser(env_pub);
        if (std::filesystem::exists(pub_path)) {
            return ReadFileBytes(pub_path);
        }
        if (create_if_missing) {
            std::filesystem::path priv_path = env_priv.empty() ? DefaultPrivatePath() : ExpandUser(env_priv);
            EVP_PKEY* key = GenerateKey();
            Bytes priv_bytes = PrivatePemFromKey(key);
            Bytes pub_bytes = PublicPemFromKey(key);
            EVP_PKEY_free(key);
            WriteFileBytes(priv_path, priv_bytes);
            WriteFileBytes(pub_path, pub_bytes);
            SetPrivatePermissions(priv_path);
            SetPublicPermissions(pub_path);
            return pub_bytes;
        }
        return std::nullopt;
    }
    std::filesystem::path pub_path = DefaultPublicPath();
    std::filesystem::path priv_path = DefaultPrivatePath();
    if (std::filesystem::exists(pub_path)) {
        return ReadFileBytes(pub_path);
    }
    if (std::filesystem::exists(priv_path)) {
        Bytes priv_bytes = ReadFileBytes(priv_path);
        EVP_PKEY* key = LoadPrivateKey(priv_bytes);
        Bytes pub_bytes = PublicPemFromKey(key);
        EVP_PKEY_free(key);
        if (!std::filesystem::exists(pub_path)) {
            WriteFileBytes(pub_path, pub_bytes);
            SetPublicPermissions(pub_path);
        }
        return pub_bytes;
    }
    if (create_if_missing) {
        EVP_PKEY* key = GenerateKey();
        Bytes priv_bytes = PrivatePemFromKey(key);
        Bytes pub_bytes = PublicPemFromKey(key);
        EVP_PKEY_free(key);
        WriteFileBytes(priv_path, priv_bytes);
        WriteFileBytes(pub_path, pub_bytes);
        SetPrivatePermissions(priv_path);
        SetPublicPermissions(pub_path);
        return pub_bytes;
    }
    return std::nullopt;
}

Bytes LoadMasterPrivateKey() {
    std::vector<std::filesystem::path> candidates;
    std::string env_priv = basefwx::env::Get("BASEFWX_MASTER_EC_PRIV");
    if (!env_priv.empty()) {
        candidates.push_back(ExpandUser(env_priv));
    }
    candidates.push_back(DefaultPrivatePath());
    candidates.push_back(std::filesystem::path("W:\\master_ec_private.pem"));
    for (const auto& path : candidates) {
        if (!path.empty() && std::filesystem::exists(path)) {
            return ReadFileBytes(path);
        }
    }
    throw std::runtime_error("No master EC private key found");
}

KemResult KemEncrypt(const Bytes& public_key) {
    EVP_PKEY* peer = LoadPublicKey(public_key);
    EnsureCurve(peer);
    EVP_PKEY* eph = GenerateKey();
    Bytes shared = DeriveShared(eph, peer);
    Bytes epk = EncodePublicPoint(eph);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(eph);
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
    return {blob, shared};
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
    EVP_PKEY* priv = LoadPrivateKey(private_key);
    EnsureCurve(priv);
    EVP_PKEY* peer = PublicKeyFromPoint(epk);
    Bytes shared = DeriveShared(priv, peer);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return shared;
}

}  // namespace basefwx::ec
