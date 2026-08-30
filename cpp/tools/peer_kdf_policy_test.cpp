/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/ec.hpp"
#include "basefwx/filecodec.hpp"
#include "basefwx/format.hpp"
#include "basefwx/fwxaes.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/livecipher.hpp"
#include "basefwx/metadata.hpp"
#include "basefwx/obfuscation.hpp"
#include "basefwx/pq.hpp"
#include "basefwx/secure_temp.hpp"
#include "filecodec_internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

void WriteU32Be(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[3] = static_cast<std::uint8_t>(value & 0xFF);
}

void AppendU32Be(Bytes& out, std::uint32_t value) {
    const std::size_t offset = out.size();
    out.resize(offset + 4);
    WriteU32Be(out.data() + offset, value);
}

void AppendU64Be(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void AppendU16Be(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void ExpectReject(const std::function<void()>& action,
                  const std::string& label,
                  const std::string& message_part = {}) {
    try {
        action();
    } catch (const std::exception& exc) {
        if (message_part.empty()
            || std::string(exc.what()).find(message_part) != std::string::npos) {
            return;
        }
        throw std::runtime_error(
            label + " produced unexpected rejection: " + exc.what());
    }
    throw std::runtime_error(label + " was accepted");
}

Bytes MaliciousFwxAesHeader(std::uint32_t iterations) {
    Bytes blob(16, 0);
    std::memcpy(blob.data(), "FWX1", 4);
    blob[4] = basefwx::constants::kFwxAesAlgo;
    blob[5] = basefwx::constants::kFwxAesKdfPbkdf2;
    WriteU32Be(blob.data() + 8, iterations);
    WriteU32Be(
        blob.data() + 12,
        static_cast<std::uint32_t>(basefwx::constants::kAeadTagLen));
    return blob;
}

Bytes MaliciousLiveHeader(std::uint32_t iterations) {
    constexpr std::size_t body_len =
        basefwx::constants::kLiveHeaderFixedLen
        + 1
        + basefwx::constants::kLiveNoncePrefixLen;
    Bytes frame(basefwx::constants::kLiveFrameHeaderLen + body_len, 0);
    std::memcpy(
        frame.data(),
        basefwx::constants::kLiveFrameMagic.data(),
        basefwx::constants::kLiveFrameMagic.size());
    frame[4] = basefwx::constants::kLiveFrameVersion;
    frame[5] = basefwx::constants::kLiveFrameTypeHeader;
    WriteU32Be(
        frame.data() + 14,
        static_cast<std::uint32_t>(body_len));

    std::uint8_t* body =
        frame.data() + basefwx::constants::kLiveFrameHeaderLen;
    body[0] = basefwx::constants::kLiveKeyModePbkdf2;
    body[1] = 1;
    body[2] =
        static_cast<std::uint8_t>(basefwx::constants::kLiveNoncePrefixLen);
    WriteU32Be(body + 8, iterations);
    body[basefwx::constants::kLiveHeaderFixedLen] = 0xA5;
    return frame;
}

Bytes MaliciousLiveOuterHeader(std::uint32_t body_len) {
    Bytes frame(basefwx::constants::kLiveFrameHeaderLen, 0);
    std::memcpy(
        frame.data(),
        basefwx::constants::kLiveFrameMagic.data(),
        basefwx::constants::kLiveFrameMagic.size());
    frame[4] = basefwx::constants::kLiveFrameVersion;
    frame[5] = basefwx::constants::kLiveFrameTypeHeader;
    WriteU32Be(frame.data() + 14, body_len);
    return frame;
}

std::string MaliciousMetadata(
    std::uint32_t iterations,
    std::string_view mode = {}) {
    return basefwx::metadata::Build(
        "AES-HEAVY",
        false,
        false,
        "none",
        "AESGCM",
        "pbkdf2",
        mode,
        std::string_view{"no"},
        iterations);
}

Bytes MaliciousSimpleFileCodecBlob(std::uint32_t iterations) {
    const std::string metadata = MaliciousMetadata(iterations);
    Bytes payload;
    AppendU32Be(payload, static_cast<std::uint32_t>(metadata.size()));
    payload.insert(payload.end(), metadata.begin(), metadata.end());
    return basefwx::format::PackLengthPrefixed({{}, {}, payload});
}

Bytes MaliciousStreamingFileCodecBlob(std::uint32_t iterations) {
    const std::string metadata = MaliciousMetadata(iterations, "STREAM");
    const std::uint32_t payload_len =
        4u
        + static_cast<std::uint32_t>(metadata.size())
        + static_cast<std::uint32_t>(basefwx::constants::kAeadNonceLen)
        + static_cast<std::uint32_t>(basefwx::constants::kAeadTagLen);
    Bytes blob;
    AppendU32Be(blob, 0);
    AppendU32Be(blob, 0);
    AppendU32Be(blob, payload_len);
    AppendU32Be(blob, static_cast<std::uint32_t>(metadata.size()));
    blob.insert(blob.end(), metadata.begin(), metadata.end());
    blob.resize(blob.size()
        + basefwx::constants::kAeadNonceLen
        + basefwx::constants::kAeadTagLen);
    return blob;
}

Bytes AuthenticatedMalformedStreamingBlob(
    bool heavy,
    const std::string& password,
    const basefwx::pb512::KdfOptions& kdf) {
    const std::string metadata = heavy
        ? basefwx::metadata::Build(
              "AES-HEAVY", false, false, "none", "AESGCM", "pbkdf2",
              "STREAM", std::string_view{"no"}, 1u,
              std::nullopt, std::nullopt, std::nullopt, {}, "v1")
        : basefwx::metadata::Build(
              "FWX512R", false, false, "none", "AESGCM", "pbkdf2",
              "STREAM", std::string_view{"yes"});
    const Bytes metadata_bytes(metadata.begin(), metadata.end());

    Bytes plaintext = metadata_bytes;
    plaintext.insert(
        plaintext.end(),
        basefwx::constants::kMetaDelim.begin(),
        basefwx::constants::kMetaDelim.end());
    plaintext.insert(
        plaintext.end(),
        basefwx::constants::kStreamMagic.begin(),
        basefwx::constants::kStreamMagic.end());
    AppendU32Be(plaintext, 1024u);
    AppendU64Be(plaintext, 1u);
    plaintext.resize(
        plaintext.size()
            + basefwx::obf::StreamObfuscator::kSaltLen,
        0);
    constexpr std::string_view extension = ".bin";
    AppendU16Be(
        plaintext, static_cast<std::uint16_t>(extension.size()));
    plaintext.insert(
        plaintext.end(), extension.begin(), extension.end());
    // The authenticated header declares one data byte, but two follow. The
    // decoder must reject this only after tag verification and full parsing.
    plaintext.push_back(0x41);
    plaintext.push_back(0x42);

    Bytes user_blob;
    basefwx::crypto::SecureBytes aead_key;
    if (heavy) {
        basefwx::crypto::SecureBytes root_key{
            basefwx::crypto::RandomBytes(32)};
        const Bytes salt = basefwx::crypto::RandomBytes(
            basefwx::constants::kUserKdfSaltSize);
        basefwx::crypto::SecureBytes user_key{
            basefwx::keywrap::DeriveUserKeyWithLabel(
                password, salt, "pbkdf2", kdf)};
        const Bytes wrapped = basefwx::crypto::AeadEncrypt(
            user_key.bytes(), root_key.bytes(), metadata_bytes);
        user_blob = salt;
        user_blob.insert(user_blob.end(), wrapped.begin(), wrapped.end());
        auto payload_keys =
            basefwx::filecodec::internal::DerivePayloadKeys(
                root_key.bytes());
        aead_key.Reset(std::move(payload_keys.aead));
        basefwx::crypto::SecureClear(payload_keys.obf);
    } else {
        auto mask = basefwx::keywrap::PrepareMaskKey(
            password,
            false,
            basefwx::constants::kB512FileMaskInfo,
            true,
            basefwx::constants::kMaskAadB512File,
            kdf);
        user_blob = mask.user_blob;
        aead_key.Reset(basefwx::crypto::HkdfSha256(
            mask.mask_key, basefwx::constants::kB512AeadInfo, 32));
    }

    const Bytes nonce = basefwx::crypto::RandomBytes(
        basefwx::constants::kAeadNonceLen);
    const Bytes ciphertext = basefwx::crypto::AesGcmEncryptWithIv(
        aead_key.bytes(), nonce, plaintext, metadata_bytes);
    const std::uint32_t payload_len = static_cast<std::uint32_t>(
        4u + metadata_bytes.size() + nonce.size() + ciphertext.size());

    Bytes blob;
    AppendU32Be(blob, static_cast<std::uint32_t>(user_blob.size()));
    blob.insert(blob.end(), user_blob.begin(), user_blob.end());
    AppendU32Be(blob, 0u);
    AppendU32Be(blob, payload_len);
    AppendU32Be(blob, static_cast<std::uint32_t>(metadata_bytes.size()));
    blob.insert(blob.end(), metadata_bytes.begin(), metadata_bytes.end());
    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    return blob;
}

std::set<std::filesystem::path> DirectoryEntryNames(
    const std::filesystem::path& directory) {
    std::set<std::filesystem::path> entries;
    for (const auto& entry :
         std::filesystem::directory_iterator(directory)) {
        entries.insert(entry.path().filename());
    }
    return entries;
}

class ScopedTempDirectory {
  public:
    ScopedTempDirectory() {
        const auto seed =
            std::chrono::steady_clock::now().time_since_epoch().count();
        const auto root = std::filesystem::temp_directory_path();
        for (std::uint32_t attempt = 0; attempt < 100; ++attempt) {
            path_ = root / (
                "basefwx-peer-kdf-policy-"
                + std::to_string(seed)
                + "-"
                + std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create peer PBKDF2 policy test directory");
    }

    ~ScopedTempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    ScopedTempDirectory(const ScopedTempDirectory&) = delete;
    ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

    const std::filesystem::path& path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

class ScopedEnvironment {
  public:
    ScopedEnvironment(const char* name, const std::string& value)
        : name_(name) {
        if (const char* existing = std::getenv(name)) {
            previous_ = existing;
        }
#if defined(_WIN32)
        _putenv_s(name, value.c_str());
#else
        setenv(name, value.c_str(), 1);
#endif
    }

    ~ScopedEnvironment() {
#if defined(_WIN32)
        _putenv_s(name_.c_str(), previous_.value_or("").c_str());
#else
        if (previous_.has_value()) {
            setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            unsetenv(name_.c_str());
        }
#endif
    }

  private:
    std::string name_;
    std::optional<std::string> previous_;
};

}  // namespace

int main() {
    try {
        constexpr std::uint32_t max =
            basefwx::constants::kPeerPbkdf2IterationsMax;
        basefwx::keywrap::RequirePeerPbkdf2WithinLimits(max);
        if (basefwx::constants::kShortPasswordMin != 12
            || basefwx::constants::kShortPbkdf2Iterations != 1000000
            || basefwx::constants::kShortArgon2TimeCost != 5
            || basefwx::constants::kShortArgon2MemoryCost != (1u << 17)
            || basefwx::constants::kShortArgon2Parallelism != 4) {
            throw std::runtime_error(
                "implicit short-password KDF compatibility profile changed");
        }
        {
            basefwx::metadata::MetadataMap absent;
            if (basefwx::filecodec::internal::UsesDerivedPayloadKeys(
                    absent)) {
                throw std::runtime_error(
                    "absent payload key-separation marker was not legacy");
            }
            basefwx::metadata::MetadataMap v1{
                {"ENC-KSEP", "v1"}};
            if (!basefwx::filecodec::internal::UsesDerivedPayloadKeys(
                    v1)) {
                throw std::runtime_error(
                    "ENC-KSEP=v1 did not select derived payload keys");
            }
            basefwx::metadata::MetadataMap unknown{
                {"ENC-KSEP", "v2"}};
            ExpectReject(
                [&]() {
                    (void)basefwx::filecodec::internal::
                        UsesDerivedPayloadKeys(unknown);
                },
                "unknown payload key-separation marker",
                "Unsupported payload key-separation version");

            if (basefwx::filecodec::internal::
                    RequirePayloadObfuscationMode({}) != "yes"
                || basefwx::filecodec::internal::
                    RequirePayloadObfuscationMode("NO") != "no"
                || basefwx::filecodec::internal::
                    RequirePayloadObfuscationMode("fast") != "fast") {
                throw std::runtime_error(
                    "payload obfuscation mode normalization mismatch");
            }
            ExpectReject(
                [&]() {
                    (void)basefwx::filecodec::internal::
                        RequirePayloadObfuscationMode("future");
                },
                "unknown payload obfuscation mode",
                "Unsupported payload obfuscation mode");
        }
        auto parsed =
            basefwx::filecodec::internal::ParsePeerPbkdf2Iterations(
                std::to_string(max));
        if (!parsed.has_value() || parsed.value() != max) {
            throw std::runtime_error("exact PBKDF2 maximum did not parse");
        }

        for (const char* const value : {
                 "0",
                 "01",
                 "-1",
                 "4000000x",
                 "4000000 ",
                 "4000001",
                 "2147483648",
                 "4294967296",
                 "999999999999999999999999"}) {
            ExpectReject(
                [&]() {
                    (void)basefwx::filecodec::internal::
                        ParsePeerPbkdf2Iterations(value);
                },
                std::string("invalid ENC-KDF-ITER ") + value);
        }

        for (const char* const label : {
                 "pbkdf2", "argon2", "argon2id"}) {
            (void)basefwx::keywrap::ResolvePeerKdfLabel(label);
        }
        for (const char* const label : {
                 "", "auto", "argon2evil", "PBKDF2", " pbkdf2"}) {
            ExpectReject(
                [&]() {
                    (void)basefwx::keywrap::ResolvePeerKdfLabel(label);
                },
                std::string("invalid peer KDF label ") + label);
        }
        basefwx::pb512::KdfOptions unknown_producer_kdf;
        unknown_producer_kdf.label = "argon2evil";
        const basefwx::keywrap::MasterPublicKeys no_master_keys;
        ExpectReject(
            [&]() {
                (void)basefwx::keywrap::PrepareMaskKey(
                    "",
                    true,
                    basefwx::constants::kB512FileMaskInfo,
                    false,
                    basefwx::constants::kMaskAadB512File,
                    unknown_producer_kdf,
                    &no_master_keys);
            },
            "unknown master-only producer KDF",
            "Unsupported KDF");
        {
            ScopedEnvironment invalid_default_kdf(
                "BASEFWX_USER_KDF", "argon2evil");
            basefwx::pb512::KdfOptions default_producer_kdf;
            default_producer_kdf.label.clear();
            ExpectReject(
                [&]() {
                    (void)basefwx::keywrap::PrepareMaskKey(
                        "",
                        true,
                        basefwx::constants::kB512FileMaskInfo,
                        false,
                        basefwx::constants::kMaskAadB512File,
                        default_producer_kdf,
                        &no_master_keys);
                },
                "unknown env default master-only producer KDF",
                "Unsupported KDF");
        }
        {
            ScopedEnvironment automatic_default_kdf(
                "BASEFWX_USER_KDF", "auto");
            const std::string empty_resolved =
                basefwx::keywrap::ResolveKdfLabel("");
            const std::string auto_resolved =
                basefwx::keywrap::ResolveKdfLabel("auto");
            if (empty_resolved != auto_resolved
                || (empty_resolved != "pbkdf2"
                    && empty_resolved != "argon2id")) {
                throw std::runtime_error(
                    "env auto did not resolve to the compiled KDF default");
            }
        }

        Bytes valid_ec(
            basefwx::constants::kMasterEcMagic.size()
                + 2
                + basefwx::constants::kMasterEcPointLen,
            0);
        std::copy(
            basefwx::constants::kMasterEcMagic.begin(),
            basefwx::constants::kMasterEcMagic.end(),
            valid_ec.begin());
        const std::size_t ec_length_offset =
            basefwx::constants::kMasterEcMagic.size();
        valid_ec[ec_length_offset] = 0;
        valid_ec[ec_length_offset + 1] =
            static_cast<std::uint8_t>(
                basefwx::constants::kMasterEcPointLen);
        valid_ec[ec_length_offset + 2] = 0x04;
        if (!basefwx::ec::IsEcMasterBlob(valid_ec)) {
            throw std::runtime_error("exact EC frame was not recognized");
        }
        Bytes trailing_ec = valid_ec;
        trailing_ec.push_back(0);
        if (basefwx::ec::IsEcMasterBlob(trailing_ec)) {
            throw std::runtime_error("trailing EC frame byte was accepted");
        }
        Bytes kem_collision(1088, 0);
        std::copy(
            basefwx::constants::kMasterEcMagic.begin(),
            basefwx::constants::kMasterEcMagic.end(),
            kem_collision.begin());
        if (basefwx::ec::IsEcMasterBlob(kem_collision)) {
            throw std::runtime_error(
                "ML-KEM-sized EC1 prefix collision was classified as EC");
        }

        Bytes oversized_metadata_header(4, 0);
        WriteU32Be(
            oversized_metadata_header.data(),
            static_cast<std::uint32_t>(
                basefwx::constants::kMetadataMax + 1u));
        ExpectReject(
            [&]() {
                (void)basefwx::format::SplitPayload(
                    oversized_metadata_header);
            },
            "oversized in-memory metadata",
            "1 MiB");
        if (basefwx::format::TryDecodeMetadata(
                oversized_metadata_header).has_value()) {
            throw std::runtime_error(
                "oversized metadata preview was accepted");
        }

        ExpectReject(
            [&]() {
                basefwx::keywrap::RequirePeerPbkdf2WithinLimits(0);
            },
            "zero PBKDF2 iterations");
        ExpectReject(
            [&]() {
                basefwx::keywrap::RequirePeerPbkdf2WithinLimits(max + 1u);
            },
            "PBKDF2 maximum plus one");

        const Bytes raw = MaliciousFwxAesHeader(max + 1u);
        ExpectReject(
            [&]() {
                (void)basefwx::fwxaes::DecryptRaw(
                    raw, "correct-password", false);
            },
            "raw fwxAES PBKDF2 maximum plus one",
            "exceeds maximum");

        ExpectReject(
            [&]() {
                const std::string encoded(raw.begin(), raw.end());
                std::istringstream source(
                    encoded, std::ios::in | std::ios::binary);
                std::ostringstream dest(
                    std::ios::out | std::ios::binary);
                (void)basefwx::fwxaes::DecryptStream(
                    source, dest, "correct-password", false);
            },
            "stream fwxAES PBKDF2 maximum plus one",
            "exceeds maximum");

        ExpectReject(
            [&]() {
                basefwx::livecipher::LiveDecryptor decryptor(
                    "correct-password", false);
                (void)decryptor.Update(MaliciousLiveHeader(max + 1u));
            },
            "live fwxAES PBKDF2 maximum plus one",
            "exceeds maximum");

        ExpectReject(
            [&]() {
                basefwx::livecipher::LiveDecryptor decryptor(
                    "correct-password", false);
                (void)decryptor.Update(MaliciousLiveOuterHeader(
                    static_cast<std::uint32_t>(
                        basefwx::constants::kLiveMaxHeaderBody + 1u)));
            },
            "live oversized partial key header",
            "key header too large");

        {
            ScopedEnvironment stream_iters(
                "BASEFWX_FWXAES_PBKDF2_ITERS", "10000");
            const std::string plaintext(
                3u * 1024u * 1024u + 29u, 'P');
            std::istringstream source(
                plaintext, std::ios::in | std::ios::binary);
            std::ostringstream encrypted(
                std::ios::out | std::ios::binary);
            basefwx::fwxaes::Options options;
            options.pbkdf2_iters = 10000;
            (void)basefwx::fwxaes::EncryptStream(
                source,
                encrypted,
                "stream-auth-test-password",
                options);
            std::string tampered = encrypted.str();
            tampered.back() = static_cast<char>(
                static_cast<unsigned char>(tampered.back()) ^ 1u);
            std::istringstream ciphertext(
                tampered, std::ios::in | std::ios::binary);
            std::ostringstream destination(
                std::ios::out | std::ios::binary);
            destination << "existing authenticated stream destination";
            ExpectReject(
                [&]() {
                    (void)basefwx::fwxaes::DecryptStream(
                        ciphertext,
                        destination,
                        "stream-auth-test-password",
                        false);
                },
                "fwxAES stream bad tag publication",
                "auth failed");
            if (destination.str()
                != "existing authenticated stream destination") {
                throw std::runtime_error(
                    "fwxAES stream published unauthenticated plaintext");
            }
        }

        const Bytes simple_blob =
            MaliciousSimpleFileCodecBlob(max + 1u);
        ExpectReject(
            [&]() {
                basefwx::filecodec::FileOptions options;
                options.enable_obfuscation = false;
                (void)basefwx::filecodec::Pb512DecodeBytes(
                    simple_blob,
                    "correct-password",
                    options);
            },
            "simple file codec PBKDF2 maximum plus one",
            "exceeds maximum");

        ScopedTempDirectory temp_dir;
        {
            basefwx::pb512::KdfOptions kdf;
            kdf.label = "pbkdf2";
            kdf.pbkdf2_iterations = 1;
            for (const bool heavy : {false, true}) {
                const std::string label = heavy ? "pb512" : "b512";
                const auto source =
                    temp_dir.path() / ("invalid-" + label + "-chunk.bin");
                basefwx::filecodec::internal::WriteFileBytes(
                    source, Bytes{0x01});
                basefwx::filecodec::FileOptions options;
                options.keep_input = true;
                options.stream_threshold = 1;
                options.stream_chunk_size = 0;
                const auto encode = [&]() {
                    if (heavy) {
                        (void)basefwx::filecodec::Pb512EncodeFile(
                            source.string(),
                            "peer-stream-chunk-password",
                            options,
                            kdf);
                    } else {
                        (void)basefwx::filecodec::B512EncodeFile(
                            source.string(),
                            "peer-stream-chunk-password",
                            options,
                            kdf);
                    }
                };
                ExpectReject(
                    encode,
                    label + " zero streaming chunk size",
                    "chunk size");
                options.stream_chunk_size =
                    basefwx::constants::kStreamChunkSizeMax + 1u;
                ExpectReject(
                    encode,
                    label + " oversized streaming chunk size",
                    "chunk size");
                auto output = source;
                output.replace_extension(".fwx");
                if (std::filesystem::exists(output)) {
                    throw std::runtime_error(
                        "rejected streaming chunk size left output");
                }
            }
        }
        {
            ScopedEnvironment heavy_iterations(
                "BASEFWX_HEAVY_PBKDF2_ITERS", "1");
            basefwx::pb512::KdfOptions kdf;
            kdf.label = "pbkdf2";
            kdf.pbkdf2_iterations = 1;
            const Bytes expected(
                basefwx::constants::kStreamChunkSize + 29u,
                static_cast<std::uint8_t>(0x5c));
            for (const bool heavy : {false, true}) {
                const std::string label = heavy ? "pb512" : "b512";
                const auto source = temp_dir.path()
                    / (label + "-same-path.fwx");
                basefwx::filecodec::internal::WriteFileBytes(
                    source, expected);
                basefwx::filecodec::FileOptions options;
                options.keep_input = true;
                options.stream_threshold = 1;
                options.stream_chunk_size = 4096;
                const std::string encoded = heavy
                    ? basefwx::filecodec::Pb512EncodeFile(
                          source.string(),
                          "same-path-stream-password",
                          options,
                          kdf)
                    : basefwx::filecodec::B512EncodeFile(
                          source.string(),
                          "same-path-stream-password",
                          options,
                          kdf);
                if (std::filesystem::path(encoded) != source) {
                    throw std::runtime_error(
                        label + " same-path encode returned wrong path");
                }
                const std::string decoded = heavy
                    ? basefwx::filecodec::Pb512DecodeFile(
                          encoded,
                          "same-path-stream-password",
                          options,
                          kdf)
                    : basefwx::filecodec::B512DecodeFile(
                          encoded,
                          "same-path-stream-password",
                          options,
                          kdf);
                if (basefwx::filecodec::internal::ReadFileBytes(decoded)
                    != expected) {
                    throw std::runtime_error(
                        label + " same-path streaming roundtrip mismatch");
                }
            }
        }
        {
            constexpr std::string_view password =
                "peer-stream-publication-password";
            basefwx::pb512::KdfOptions kdf;
            kdf.label = "pbkdf2";
            kdf.pbkdf2_iterations = 1;
            const Bytes sentinel{
                'e', 'x', 'i', 's', 't', 'i', 'n', 'g'};
            for (const bool heavy : {false, true}) {
                const std::string label = heavy ? "pb512" : "b512";
                const auto candidate = temp_dir.path()
                    / (label + "-late-structure.bin.fwx");
                const auto target = temp_dir.path()
                    / (label + "-late-structure.bin");
                basefwx::filecodec::internal::WriteFileBytes(
                    candidate,
                    AuthenticatedMalformedStreamingBlob(
                        heavy, std::string(password), kdf));
                basefwx::filecodec::internal::WriteFileBytes(
                    target, sentinel);
                const auto before = DirectoryEntryNames(temp_dir.path());

                basefwx::filecodec::FileOptions options;
                options.keep_input = true;
                options.stream_chunk_size = 4096;
                ExpectReject(
                    [&]() {
                        if (heavy) {
                            (void)basefwx::filecodec::Pb512DecodeFile(
                                candidate.string(),
                                std::string(password),
                                options,
                                kdf);
                        } else {
                            (void)basefwx::filecodec::B512DecodeFile(
                                candidate.string(),
                                std::string(password),
                                options,
                                kdf);
                        }
                    },
                    label + " authenticated late structure publication",
                    "unexpected trailing data");
                if (basefwx::filecodec::internal::ReadFileBytes(target)
                    != sentinel) {
                    throw std::runtime_error(
                        label + " late structure failure clobbered target");
                }
                if (DirectoryEntryNames(temp_dir.path()) != before) {
                    throw std::runtime_error(
                        label + " late structure failure leaked temp data");
                }
            }
        }
        {
            const auto source = temp_dir.path() / "stripped-stream.bin";
            basefwx::filecodec::internal::WriteFileBytes(
                source, Bytes{0x01, 0x02, 0x03});
            basefwx::filecodec::FileOptions options;
            options.keep_input = true;
            options.strip_metadata = true;
            options.stream_threshold = 1;
            options.use_master = false;
            basefwx::pb512::KdfOptions kdf;
            kdf.label = "pbkdf2";
            kdf.pbkdf2_iterations = 1;
            ExpectReject(
                [&]() {
                    (void)basefwx::filecodec::B512EncodeFile(
                        source.string(), "correct-password", options, kdf);
                },
                "stripped b512 stream authoring",
                "requires metadata");
            ExpectReject(
                [&]() {
                    (void)basefwx::filecodec::Pb512EncodeFile(
                        source.string(), "correct-password", options, kdf);
                },
                "stripped pb512 stream authoring",
                "requires metadata");
            auto output = source;
            output.replace_extension(".fwx");
            if (std::filesystem::exists(output)) {
                throw std::runtime_error(
                    "rejected stripped stream left ciphertext output");
            }
        }
        {
            Bytes nonce_payload(
                4u
                    + basefwx::constants::kAeadNonceLen
                    + basefwx::constants::kAeadTagLen,
                0);
            std::fill_n(nonce_payload.begin(), 4, 0xff);
            const auto nonce_candidate =
                temp_dir.path() / "simple-nonce-candidate.fwx";
            basefwx::filecodec::internal::WriteFileBytes(
                nonce_candidate,
                basefwx::format::PackLengthPrefixed(
                    {{}, {}, nonce_payload}));
            if (basefwx::filecodec::internal::PeekMetadataBlob(
                    nonce_candidate).has_value()) {
                throw std::runtime_error(
                    "simple AEAD nonce was misclassified as stream metadata");
            }

            Bytes trailing = basefwx::filecodec::internal::ReadFileBytes(
                nonce_candidate);
            trailing.push_back(0x00);
            const auto trailing_candidate =
                temp_dir.path() / "trailing-container-data.fwx";
            basefwx::filecodec::internal::WriteFileBytes(
                trailing_candidate, trailing);
            ExpectReject(
                [&]() {
                    (void)basefwx::filecodec::internal::PeekMetadataBlob(
                        trailing_candidate);
                },
                "length-prefixed container with trailing bytes",
                "does not match remaining file");

            const auto non_stream_candidate =
                temp_dir.path() / "non-stream-metadata-candidate.fwx";
            basefwx::filecodec::internal::WriteFileBytes(
                non_stream_candidate,
                MaliciousSimpleFileCodecBlob(1));
            if (basefwx::filecodec::internal::PeekMetadataBlob(
                    non_stream_candidate).has_value()) {
                throw std::runtime_error(
                    "non-stream metadata was accepted as stream metadata");
            }

            const auto stream_candidate =
                temp_dir.path() / "stream-metadata-candidate.fwx";
            basefwx::filecodec::internal::WriteFileBytes(
                stream_candidate,
                MaliciousStreamingFileCodecBlob(1));
            if (!basefwx::filecodec::internal::PeekMetadataBlob(
                    stream_candidate).has_value()) {
                throw std::runtime_error(
                    "valid stream metadata was not detected");
            }
        }
        {
            const Bytes expected{
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
            basefwx::filecodec::FileOptions options;
            options.use_master = false;
            basefwx::pb512::KdfOptions kdf;
            kdf.label = "pbkdf2";
            kdf.pbkdf2_iterations = 1;
            Bytes encrypted;
            {
                ScopedEnvironment obf_env(
                    "BASEFWX_OBFUSCATE", "1");
                ScopedEnvironment heavy_env(
                    "BASEFWX_HEAVY_PBKDF2_ITERS", "1");
                encrypted =
                    basefwx::filecodec::Pb512EncodeBytes(
                        expected,
                        ".bin",
                        "correct-password",
                        options,
                        kdf);
            }
            basefwx::filecodec::DecodedBytes decoded;
            {
                ScopedEnvironment obf_env(
                    "BASEFWX_OBFUSCATE", "0");
                decoded =
                    basefwx::filecodec::Pb512DecodeBytes(
                        encrypted,
                        "correct-password",
                        options,
                        kdf);
            }
            if (decoded.data != expected) {
                throw std::runtime_error(
                    "PB512 simple decoder ignored authenticated "
                    "obfuscation metadata");
            }
        }
        {
            const Bytes expected(
                3u * 1024u * 1024u + 29u,
                static_cast<std::uint8_t>(0x5a));
            const auto source =
                temp_dir.path() / "pb512-obf-off.bin";
            {
                std::ofstream output(source, std::ios::binary);
                output.write(
                    reinterpret_cast<const char*>(expected.data()),
                    static_cast<std::streamsize>(expected.size()));
            }
            basefwx::filecodec::FileOptions options;
            options.use_master = false;
            options.stream_threshold = 1;
            options.stream_chunk_size = 1u << 20;
            basefwx::pb512::KdfOptions kdf;
            kdf.label = "pbkdf2";
            kdf.pbkdf2_iterations = 1;
            std::string encrypted;
            {
                ScopedEnvironment obf_env(
                    "BASEFWX_OBFUSCATE", "0");
                ScopedEnvironment heavy_env(
                    "BASEFWX_HEAVY_PBKDF2_ITERS", "1");
                encrypted =
                    basefwx::filecodec::Pb512EncodeFile(
                        source.string(),
                        "correct-password",
                        options,
                        kdf);
            }
            const auto metadata_blob =
                basefwx::filecodec::internal::PeekMetadataBlob(
                    encrypted);
            if (!metadata_blob.has_value()) {
                throw std::runtime_error(
                    "PB512 obfuscation-off stream omitted metadata");
            }
            const auto metadata =
                basefwx::metadata::Decode(*metadata_blob);
            if (basefwx::metadata::GetValue(
                    metadata, "ENC-KSEP") != "v1"
                || basefwx::metadata::GetValue(
                    metadata, "ENC-OBF") != "no") {
                throw std::runtime_error(
                    "PB512 obfuscation-off stream metadata mismatch");
            }
            std::string decoded;
            {
                ScopedEnvironment obf_env(
                    "BASEFWX_OBFUSCATE", "1");
                decoded =
                    basefwx::filecodec::Pb512DecodeFile(
                        encrypted,
                        "correct-password",
                        options,
                        kdf);
            }
            if (basefwx::filecodec::internal::ReadFileBytes(decoded)
                != expected) {
                throw std::runtime_error(
                    "PB512 obfuscation-off stream roundtrip mismatch");
            }
        }
        {
            const auto protected_input =
                temp_dir.path() / "protected-stream.fwx";
            const auto collision =
                temp_dir.path() / "protected-stream.fwx.plain.tmp";
            const auto sentinel =
                temp_dir.path() / "sentinel.txt";
            const auto legacy_symlink =
                temp_dir.path() / "protected-stream.fwx.plain.link";
            {
                std::ofstream(collision, std::ios::binary)
                    << "collision sentinel";
                std::ofstream(sentinel, std::ios::binary)
                    << "symlink sentinel";
            }
            std::error_code symlink_error;
            std::filesystem::create_symlink(
                sentinel, legacy_symlink, symlink_error);

            std::mutex temp_mutex;
            std::vector<basefwx::temp::SecureTempPath> temps;
            std::vector<std::filesystem::path> paths;
            std::vector<std::thread> creators;
            for (int index = 0; index < 16; ++index) {
                creators.emplace_back([&]() {
                    auto temp =
                        basefwx::temp::SecureTempPath::CreateSibling(
                            protected_input, "plain");
                    const auto path = temp.path();
                    const auto permissions =
                        std::filesystem::status(path).permissions();
                    const auto forbidden =
                        std::filesystem::perms::group_all
                        | std::filesystem::perms::others_all;
                    if ((permissions & forbidden)
                        != std::filesystem::perms::none) {
                        throw std::runtime_error(
                            "private temp permissions were too broad");
                    }
                    std::lock_guard<std::mutex> lock(temp_mutex);
                    paths.push_back(path);
                    temps.push_back(std::move(temp));
                });
            }
            for (auto& creator : creators) {
                creator.join();
            }
            if (std::set<std::filesystem::path>(
                    paths.begin(), paths.end()).size()
                != paths.size()) {
                throw std::runtime_error(
                    "concurrent private temp paths were not unique");
            }
            std::ifstream collision_input(
                collision, std::ios::binary);
            std::string collision_text(
                (std::istreambuf_iterator<char>(collision_input)),
                std::istreambuf_iterator<char>());
            if (collision_text != "collision sentinel") {
                throw std::runtime_error(
                    "legacy temp collision was overwritten");
            }
            if (!symlink_error) {
                std::ifstream sentinel_input(
                    sentinel, std::ios::binary);
                std::string sentinel_text(
                    (std::istreambuf_iterator<char>(sentinel_input)),
                    std::istreambuf_iterator<char>());
                if (sentinel_text != "symlink sentinel") {
                    throw std::runtime_error(
                        "legacy temp symlink target was overwritten");
                }
            }
        }
        {
            ScopedEnvironment stream_iters(
                "BASEFWX_FWXAES_PBKDF2_ITERS", "10000");
            const auto encrypted_path =
                temp_dir.path() / "fwxaes-bad-tag.fwx";
            const auto destination_path =
                temp_dir.path() / "fwxaes-destination.bin";
            {
                std::istringstream source(
                    std::string(2u * 1024u * 1024u + 17u, 'F'),
                    std::ios::in | std::ios::binary);
                std::ofstream encrypted(
                    encrypted_path, std::ios::binary);
                basefwx::fwxaes::Options options;
                options.pbkdf2_iters = 10000;
                (void)basefwx::fwxaes::EncryptStream(
                    source,
                    encrypted,
                    "stream-auth-test-password",
                    options);
            }
            {
                std::fstream encrypted(
                    encrypted_path,
                    std::ios::in | std::ios::out
                        | std::ios::binary);
                encrypted.seekg(-1, std::ios::end);
                char last = 0;
                encrypted.read(&last, 1);
                last = static_cast<char>(
                    static_cast<unsigned char>(last) ^ 1u);
                encrypted.seekp(-1, std::ios::end);
                encrypted.write(&last, 1);
            }
            {
                std::ofstream(destination_path, std::ios::binary)
                    << "existing authenticated destination";
            }
            std::set<std::filesystem::path> before;
            for (const auto& entry :
                 std::filesystem::directory_iterator(
                     temp_dir.path())) {
                before.insert(entry.path().filename());
            }
            ExpectReject(
                [&]() {
                    (void)basefwx::fwxaes::DecryptStreamFile(
                        encrypted_path,
                        destination_path,
                        "stream-auth-test-password",
                        false);
                },
                "fwxAES file bad tag publication",
                "auth failed");
            std::ifstream destination(
                destination_path, std::ios::binary);
            const std::string contents(
                (std::istreambuf_iterator<char>(destination)),
                std::istreambuf_iterator<char>());
            if (contents
                != "existing authenticated destination") {
                throw std::runtime_error(
                    "fwxAES file destination was clobbered");
            }
            std::set<std::filesystem::path> after;
            for (const auto& entry :
                 std::filesystem::directory_iterator(
                     temp_dir.path())) {
                after.insert(entry.path().filename());
            }
            if (before != after) {
                throw std::runtime_error(
                    "fwxAES file decrypt leaked a temp artifact");
            }
        }
        const std::filesystem::path stream_path =
            temp_dir.path() / "peer-pbkdf2-over-max.fwx";
        const Bytes stream_blob =
            MaliciousStreamingFileCodecBlob(max + 1u);
        {
            std::ofstream output(stream_path, std::ios::binary);
            if (!output) {
                throw std::runtime_error(
                    "failed to create malicious streaming file");
            }
            output.write(
                reinterpret_cast<const char*>(stream_blob.data()),
                static_cast<std::streamsize>(stream_blob.size()));
            if (!output) {
                throw std::runtime_error(
                    "failed to write malicious streaming file");
            }
        }
        ExpectReject(
            [&]() {
                basefwx::filecodec::FileOptions options;
                options.enable_obfuscation = false;
                options.keep_input = true;
                (void)basefwx::filecodec::Pb512DecodeFile(
                    stream_path.string(),
                    "correct-password",
                    options);
            },
            "direct-stream file codec PBKDF2 maximum plus one",
            "exceeds maximum");

        for (const char* const spelling : {
                 "ml-kem-768", " ML-KEM-768 ", "kyber768",
                 " Kyber-768 ", "ml-kem-1024", "kyber1024",
                 " kyber-1024 "}) {
            if (!basefwx::pq::IsSupportedKemAlgorithm(spelling)) {
                throw std::runtime_error(
                    std::string("supported KEM alias rejected: ")
                        + spelling);
            }
        }
        for (const char* const spelling : {
                 "", " ", "ml-kem-512"}) {
            if (basefwx::pq::IsSupportedKemAlgorithm(spelling)) {
                throw std::runtime_error(
                    std::string("unsupported KEM alias accepted: ")
                        + spelling);
            }
        }
        auto pair_768 = basefwx::pq::GenerateKeyPair(
            basefwx::pq::KemAlgorithm::MlKem768);
        auto pair_1024 = basefwx::pq::GenerateKeyPair(
            basefwx::pq::KemAlgorithm::MlKem1024);
        if (basefwx::pq::InferKemAlgorithmFromPublicKey(
                pair_768.public_key)
                != basefwx::pq::KemAlgorithm::MlKem768
            || basefwx::pq::InferKemAlgorithmFromPublicKey(
                pair_1024.public_key)
                != basefwx::pq::KemAlgorithm::MlKem1024) {
            throw std::runtime_error(
                "public-key-size KEM inference mismatch");
        }
        auto exercise_prepare_kem =
            [&](basefwx::pq::KemAlgorithm algorithm,
                const basefwx::pq::KemKeyPair& pair) {
                basefwx::keywrap::MasterPublicKeys selected;
                selected.pq = pair.public_key;
                basefwx::pb512::KdfOptions prepare_kdf;
                prepare_kdf.label = "pbkdf2";
                auto prepared =
                    basefwx::keywrap::PrepareMaskKey(
                        "",
                        true,
                        basefwx::constants::kB512FileMaskInfo,
                        false,
                        basefwx::constants::kMaskAadB512File,
                        prepare_kdf,
                        &selected);
                if (!prepared.used_master
                    || prepared.master_blob.empty()
                    || prepared.mask_key.size() != 32) {
                    throw std::runtime_error(
                        "PrepareMaskKey KEM path did not produce "
                        "a master-wrapped mask key");
                }
                basefwx::crypto::SecureBytes shared{
                    basefwx::pq::KemDecrypt(
                        algorithm,
                        pair.private_key,
                        prepared.master_blob)};
                basefwx::crypto::SecureBytes expected{
                    basefwx::crypto::HkdfSha256(
                        shared.bytes(),
                        basefwx::constants::kB512FileMaskInfo,
                        32)};
                if (prepared.mask_key != expected.bytes()) {
                    throw std::runtime_error(
                        "PrepareMaskKey KEM derivation mismatch");
                }
            };
        exercise_prepare_kem(
            basefwx::pq::KemAlgorithm::MlKem768, pair_768);
        exercise_prepare_kem(
            basefwx::pq::KemAlgorithm::MlKem1024, pair_1024);
        for (const char* const label : {
                 "ml-kem-768", "ml-kem-1024", "EC"}) {
            const std::string metadata = basefwx::metadata::Build(
                "TEST", false, true, label, "AESGCM", "pbkdf2");
            if (basefwx::metadata::GetValue(
                    basefwx::metadata::Decode(metadata),
                    "ENC-KEM") != label) {
                throw std::runtime_error(
                    "explicit ENC-KEM metadata mismatch");
            }
        }
        const std::string no_master_metadata =
            basefwx::metadata::Build(
                "TEST", false, false, "none", "AESGCM", "pbkdf2");
        if (basefwx::metadata::GetValue(
                basefwx::metadata::Decode(no_master_metadata),
                "ENC-KEM") != "none") {
            throw std::runtime_error("ENC-KEM=none mismatch");
        }

        basefwx::pb512::KdfOptions aad_kdf;
        aad_kdf.label = "pbkdf2";
        aad_kdf.pbkdf2_iterations = 1;
        const std::string legacy_label = "pbkdf2";
        const Bytes legacy_salt(
            basefwx::constants::kUserKdfSaltSize, 0x5A);
        const Bytes legacy_mask_key(32, 0xA5);
        const Bytes legacy_user_key =
            basefwx::keywrap::DeriveUserKeyWithLabel(
                "correct-password",
                legacy_salt,
                legacy_label,
                aad_kdf);
        const Bytes legacy_ciphertext =
            basefwx::crypto::AeadEncrypt(
                legacy_user_key,
                legacy_mask_key,
                Bytes(
                    basefwx::constants::kB512AeadInfo.begin(),
                    basefwx::constants::kB512AeadInfo.end()));
        Bytes legacy_user_blob;
        legacy_user_blob.push_back(
            static_cast<std::uint8_t>(legacy_label.size()));
        legacy_user_blob.insert(
            legacy_user_blob.end(),
            legacy_label.begin(),
            legacy_label.end());
        legacy_user_blob.insert(
            legacy_user_blob.end(),
            legacy_salt.begin(),
            legacy_salt.end());
        legacy_user_blob.insert(
            legacy_user_blob.end(),
            legacy_ciphertext.begin(),
            legacy_ciphertext.end());
        Bytes recovered_without_retry;
        try {
            recovered_without_retry =
                basefwx::keywrap::RecoverMaskKey(
                    legacy_user_blob,
                    {},
                    "correct-password",
                    false,
                    basefwx::constants::kB512FileMaskInfo,
                    basefwx::constants::kB512AeadInfo,
                    aad_kdf);
        } catch (const std::exception& exc) {
            throw std::runtime_error(
                std::string("canonical legacy fixture recovery failed: ")
                + exc.what());
        }
        if (recovered_without_retry != legacy_mask_key) {
            throw std::runtime_error(
                "direct legacy user-wrap recovery mismatch");
        }
        try {
            (void)basefwx::crypto::AeadDecrypt(
                legacy_user_key,
                legacy_ciphertext,
                Bytes(
                    basefwx::constants::kMaskAadB512File.begin(),
                    basefwx::constants::kMaskAadB512File.end()));
            throw std::runtime_error(
                "canonical AAD unexpectedly authenticated legacy fixture");
        } catch (const basefwx::crypto::AuthenticationError&) {
        }
        const Bytes direct_retry = basefwx::crypto::AeadDecrypt(
            legacy_user_key,
            legacy_ciphertext,
            Bytes(
                basefwx::constants::kB512AeadInfo.begin(),
                basefwx::constants::kB512AeadInfo.end()));
        if (direct_retry != legacy_mask_key) {
            throw std::runtime_error("direct legacy AAD retry mismatch");
        }
        Bytes recovered_legacy;
        try {
            recovered_legacy =
                basefwx::keywrap::RecoverMaskKey(
                    legacy_user_blob,
                    {},
                    "correct-password",
                    false,
                    basefwx::constants::kB512FileMaskInfo,
                    basefwx::constants::kMaskAadB512File,
                    aad_kdf,
                    basefwx::constants::kB512AeadInfo);
        } catch (const std::exception& exc) {
            throw std::runtime_error(
                std::string("legacy user-AAD retry failed: ")
                + exc.what());
        }
        if (recovered_legacy != legacy_mask_key) {
            throw std::runtime_error(
                "Java-3.7 b512 user-wrap AAD retry mismatch");
        }
        ExpectReject(
            [&]() {
                (void)basefwx::keywrap::RecoverMaskKey(
                    legacy_user_blob,
                    {},
                    "wrong-password",
                    false,
                    basefwx::constants::kB512FileMaskInfo,
                    basefwx::constants::kMaskAadB512File,
                    aad_kdf,
                    basefwx::constants::kB512AeadInfo);
            },
            "wrong password legacy user-AAD retry");

        basefwx::fwxaes::Options producer_options;
        producer_options.use_master = false;
        producer_options.force_legacy_pbkdf2 = true;
        producer_options.pbkdf2_iters =
            static_cast<std::uint32_t>(max + 1u);
        ExpectReject(
            [&]() {
                (void)basefwx::fwxaes::EncryptRaw(
                    Bytes{'x'},
                    "correct-password",
                    producer_options);
            },
            "raw producer PBKDF2 maximum plus one",
            "exceeds maximum");
        std::istringstream producer_source("payload");
        std::ostringstream producer_output;
        ExpectReject(
            [&]() {
                (void)basefwx::fwxaes::EncryptStream(
                    producer_source,
                    producer_output,
                    "correct-password",
                    producer_options);
            },
            "stream producer PBKDF2 maximum plus one",
            "exceeds maximum");
        if (!producer_output.str().empty()) {
            throw std::runtime_error(
                "stream producer wrote output before KDF-cap rejection");
        }
        {
            ScopedEnvironment iterations_env(
                "BASEFWX_FWXAES_PBKDF2_ITERS",
                std::to_string(max + 1u));
            basefwx::livecipher::LiveEncryptor live(
                "correct-password", false);
            ExpectReject(
                [&]() { (void)live.Start(); },
                "live producer PBKDF2 maximum plus one",
                "exceeds maximum");
        }

        const auto oversized_public =
            temp_dir.path() / "oversized-ec-public.pem";
        {
            std::ofstream output(oversized_public, std::ios::binary);
            output.seekp(4 * 1024 * 1024);
            output.put('x');
        }
        {
            ScopedEnvironment public_env(
                "BASEFWX_MASTER_EC_PUB",
                oversized_public.string());
            ExpectReject(
                [&]() {
                    (void)basefwx::ec::LoadMasterPublicKey(false);
                },
                "oversized EC public key",
                "4 MiB");
        }
        {
            ScopedEnvironment public_env(
                "BASEFWX_MASTER_EC_PUB",
                (temp_dir.path() / "missing-public.pem").string());
            ExpectReject(
                [&]() {
                    (void)basefwx::ec::LoadMasterPublicKey(false);
                },
                "missing explicit EC public key",
                "not found");
        }
        {
            ScopedEnvironment private_env(
                "BASEFWX_MASTER_EC_PRIV",
                (temp_dir.path() / "missing-private.pem").string());
            ExpectReject(
                [&]() {
                    (void)basefwx::ec::LoadMasterPrivateKey();
                },
                "missing explicit EC private key",
                "not found");
        }
        {
            const auto empty_home = temp_dir.path() / "empty-home";
            std::filesystem::create_directory(empty_home);
            ScopedEnvironment home_env("HOME", empty_home.string());
            ScopedEnvironment user_profile_env(
                "USERPROFILE", empty_home.string());
            ScopedEnvironment public_env("BASEFWX_MASTER_EC_PUB", "");
            const auto public_key =
                basefwx::ec::LoadMasterPublicKey(true);
            if (public_key.has_value()) {
                throw std::runtime_error(
                    "missing EC key unexpectedly produced a public key");
            }
            if (std::filesystem::exists(
                    empty_home / "master_ec_private.pem")
                || std::filesystem::exists(
                    empty_home / "master_ec_public.pem")) {
                throw std::runtime_error(
                    "EC public-key lookup created master key files");
            }
        }
    } catch (const std::exception& exc) {
        std::cerr << "peer_kdf_policy_test: " << exc.what() << '\n';
        return 1;
    }
    return 0;
}
