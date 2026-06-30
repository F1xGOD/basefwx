/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "filecodec_internal.hpp"

#include "basefwx/archive.hpp"
#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/crypto_utils.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/basefwx.hpp"
#include "basefwx/ec.hpp"
#include "basefwx/metadata.hpp"
#include "basefwx/obfuscation.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/pq.hpp"
#include "basefwx/runtime.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace basefwx::filecodec::internal {

std::string Pb512EncodeFileSimple(const std::filesystem::path& input,
                                  const std::string& password,
                                  const FileOptions& options,
                                  const basefwx::pb512::KdfOptions& kdf,
                                  std::string_view pack_flag) {
    std::string resolved = basefwx::ResolvePassword(password);
    Bytes data = ReadFileBytes(input);
    std::string b64_payload = basefwx::base64::Encode(data);
    std::string ext = input.extension().string();

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);
    bool obf_enabled = EnableObfuscation(options);
    bool fast_obf = obf_enabled && !options.strip_metadata && UseFastObfuscation(data.size());
    std::string obf_mode = ObfMode(obf_enabled, fast_obf);

    std::string ext_token = basefwx::pb512::Pb512Encode(ext, resolved, use_master_effective, kdf_opts);
    std::string data_token = basefwx::pb512::Pb512Encode(b64_payload, resolved, use_master_effective, kdf_opts);

    std::optional<std::uint32_t> argon_time;
    std::optional<std::uint32_t> argon_mem;
    std::optional<std::uint32_t> argon_par;
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    argon_time = basefwx::constants::kHeavyArgon2TimeCost;
    argon_mem = basefwx::constants::kHeavyArgon2MemoryCost;
    argon_par = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif

    std::string metadata_blob = basefwx::metadata::Build(
        "AES-HEAVY",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "",
        obf_mode,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        std::string(pack_flag),
        "v1"
    );

    std::string body = ext_token + std::string(constants::kFwxHeavyDelim) + data_token;
    std::string plaintext = metadata_blob.empty()
        ? body
        : metadata_blob + std::string(constants::kMetaDelim) + body;

    Bytes blob = EncryptAesPayload(
        plaintext,
        resolved,
        use_master_effective,
        metadata_blob,
        kdf_opts,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        obf_enabled,
        fast_obf
    );

    std::filesystem::path out_path = input;
    out_path.replace_extension(".fwx");
    WriteFileBytes(out_path, blob);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    return out_path.string();
}

std::string Pb512EncodeFileStream(const std::filesystem::path& input,
                                  const std::string& password,
                                  const FileOptions& options,
                                  const basefwx::pb512::KdfOptions& kdf,
                                  std::string_view pack_flag) {
    std::string resolved = basefwx::ResolvePassword(password);
    if (resolved.empty()) {
        throw std::runtime_error("Password required for AES-heavy streaming mode");
    }
    std::uint64_t input_size = FileSize(input);
    std::size_t chunk_size = options.stream_chunk_size;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);
    bool obf_enabled = EnableObfuscation(options);
    bool fast_obf = obf_enabled && !options.strip_metadata && UseFastObfuscation(input_size);
    std::string obf_mode = ObfMode(obf_enabled, fast_obf);

    std::optional<std::uint32_t> argon_time;
    std::optional<std::uint32_t> argon_mem;
    std::optional<std::uint32_t> argon_par;
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    argon_time = basefwx::constants::kHeavyArgon2TimeCost;
    argon_mem = basefwx::constants::kHeavyArgon2MemoryCost;
    argon_par = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif

    Bytes stream_salt = basefwx::obf::StreamObfuscator::GenerateSalt();
    std::string ext = input.extension().string();
    Bytes ext_bytes = ToBytes(ext);

    std::string metadata_blob = basefwx::metadata::Build(
        "AES-HEAVY",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "STREAM",
        obf_mode,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        std::string(pack_flag),
        "v1"
    );
    Bytes metadata_bytes = ToBytes(metadata_blob);
    Bytes prefix_bytes;
    if (!metadata_blob.empty()) {
        prefix_bytes = metadata_bytes;
        std::string delim(constants::kMetaDelim);
        prefix_bytes.insert(prefix_bytes.end(), delim.begin(), delim.end());
    }

    Bytes stream_header;
    stream_header.insert(stream_header.end(), constants::kStreamMagic.begin(), constants::kStreamMagic.end());
    Bytes chunk_bytes = Uint32Be(static_cast<std::uint32_t>(chunk_size));
    stream_header.insert(stream_header.end(), chunk_bytes.begin(), chunk_bytes.end());
    Bytes size_bytes = Uint64Be(input_size);
    stream_header.insert(stream_header.end(), size_bytes.begin(), size_bytes.end());
    stream_header.insert(stream_header.end(), stream_salt.begin(), stream_salt.end());
    Bytes ext_len = Uint16Be(static_cast<std::uint16_t>(ext_bytes.size()));
    stream_header.insert(stream_header.end(), ext_len.begin(), ext_len.end());
    stream_header.insert(stream_header.end(), ext_bytes.begin(), ext_bytes.end());

    std::uint64_t plaintext_len = static_cast<std::uint64_t>(prefix_bytes.size() + stream_header.size() + input_size);

    Bytes master_payload;
    Bytes ephemeral_key;
    PayloadKeys payload_keys;
    basefwx::crypto::SecretGuard secrets;
    secrets.Add(resolved);
    secrets.Add(ephemeral_key);
    secrets.Add(payload_keys.aead);
    secrets.Add(payload_keys.obf);
    if (use_master_effective) {
        if (pq_pub.has_value()) {
            basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(*pq_pub);
            master_payload = kem.ciphertext;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
            basefwx::crypto::SecureClear(kem.shared);
        } else if (ec_pub.has_value()) {
            basefwx::ec::KemResult kem = basefwx::ec::KemEncrypt(*ec_pub);
            master_payload = kem.blob;
            ephemeral_key = basefwx::crypto::HkdfSha256(kem.shared, constants::kKemInfo, 32);
            basefwx::crypto::SecureClear(kem.shared);
        } else {
            ephemeral_key = basefwx::crypto::RandomBytes(constants::kEphemeralKeyLen);
        }
    } else {
        ephemeral_key = basefwx::crypto::RandomBytes(constants::kEphemeralKeyLen);
    }

    Bytes user_blob;
    if (!resolved.empty()) {
        basefwx::pb512::KdfOptions kdf_wrap = kdf_opts;
        kdf_wrap.pbkdf2_iterations = basefwx::constants::HeavyPbkdf2Iterations();
        if (argon_time.has_value()) {
            kdf_wrap.argon2_time_cost = argon_time.value();
        }
        if (argon_mem.has_value()) {
            kdf_wrap.argon2_memory_cost = argon_mem.value();
        }
        if (argon_par.has_value()) {
            kdf_wrap.argon2_parallelism = argon_par.value();
        }
        kdf_wrap = HardenKdfOptionsForPassword(resolved, kdf_wrap);
        Bytes salt = basefwx::crypto::RandomBytes(constants::kUserKdfSaltSize);
        Bytes user_key = basefwx::keywrap::DeriveUserKeyWithLabel(resolved, salt, kdf_label, kdf_wrap);
        Bytes wrapped = basefwx::crypto::AeadEncrypt(user_key, ephemeral_key, metadata_bytes);
        basefwx::crypto::SecureClear(user_key);
        user_blob.reserve(salt.size() + wrapped.size());
        user_blob.insert(user_blob.end(), salt.begin(), salt.end());
        user_blob.insert(user_blob.end(), wrapped.begin(), wrapped.end());
    }
    payload_keys = DerivePayloadKeys(ephemeral_key);

    Bytes nonce = basefwx::crypto::RandomBytes(constants::kAeadNonceLen);
    std::uint64_t payload_len = 4 + metadata_bytes.size() + nonce.size() + plaintext_len + constants::kAeadTagLen;

    std::filesystem::path out_path = input;
    out_path.replace_extension(".fwx");
    std::ofstream output(out_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + out_path.string());
    }

    Bytes len_user = Uint32Be(static_cast<std::uint32_t>(user_blob.size()));
    Bytes len_master = Uint32Be(static_cast<std::uint32_t>(master_payload.size()));
    Bytes len_payload = Uint32Be(static_cast<std::uint32_t>(payload_len));
    output.write(reinterpret_cast<const char*>(len_user.data()), len_user.size());
    output.write(reinterpret_cast<const char*>(user_blob.data()), static_cast<std::streamsize>(user_blob.size()));
    output.write(reinterpret_cast<const char*>(len_master.data()), len_master.size());
    output.write(reinterpret_cast<const char*>(master_payload.data()), static_cast<std::streamsize>(master_payload.size()));
    output.write(reinterpret_cast<const char*>(len_payload.data()), len_payload.size());

    Bytes metadata_len = Uint32Be(static_cast<std::uint32_t>(metadata_bytes.size()));
    output.write(reinterpret_cast<const char*>(metadata_len.data()), metadata_len.size());
    if (!metadata_bytes.empty()) {
        output.write(reinterpret_cast<const char*>(metadata_bytes.data()),
                     static_cast<std::streamsize>(metadata_bytes.size()));
    }
    output.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));

    AesGcmEncryptor encryptor(payload_keys.aead, nonce, metadata_bytes);
    if (!prefix_bytes.empty()) {
        Bytes ct = encryptor.Update(prefix_bytes);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }
    if (!stream_header.empty()) {
        Bytes ct = encryptor.Update(stream_header);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }

    basefwx::obf::StreamObfuscator obfuscator = basefwx::obf::StreamObfuscator::ForKey(
        payload_keys.obf,
        stream_salt,
        fast_obf
    );
    std::ifstream input_stream(input, std::ios::binary);
    if (!input_stream) {
        throw std::runtime_error("Failed to open input file: " + input.string());
    }
    Bytes buffer(chunk_size);
    while (input_stream) {
        buffer.resize(chunk_size);
        input_stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = input_stream.gcount();
        if (got <= 0) {
            break;
        }
        buffer.resize(static_cast<std::size_t>(got));
        obfuscator.EncodeChunkInPlace(buffer);
        Bytes ct = encryptor.Update(buffer);
        output.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    }

    Bytes final_chunk = encryptor.Final();
    if (!final_chunk.empty()) {
        output.write(reinterpret_cast<const char*>(final_chunk.data()), static_cast<std::streamsize>(final_chunk.size()));
    }
    Bytes tag = encryptor.Tag();
    output.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));

    output.flush();
    if (!output) {
        throw std::runtime_error("Failed to write output file: " + out_path.string());
    }
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    return out_path.string();
}

std::string Pb512DecodeFileStream(const std::filesystem::path& input,
                                  const std::string& password,
                                  const FileOptions& options,
                                  const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::ifstream handle(input, std::ios::binary);
    if (!handle) {
        throw std::runtime_error("Failed to open file: " + input.string());
    }
    auto read_u32 = [&](std::uint32_t& out) {
        std::array<std::uint8_t, 4> buf{};
        handle.read(reinterpret_cast<char*>(buf.data()), buf.size());
        if (handle.gcount() != static_cast<std::streamsize>(buf.size())) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
        out = (static_cast<std::uint32_t>(buf[0]) << 24)
              | (static_cast<std::uint32_t>(buf[1]) << 16)
              | (static_cast<std::uint32_t>(buf[2]) << 8)
              | static_cast<std::uint32_t>(buf[3]);
    };

    std::uint32_t len_user = 0;
    read_u32(len_user);
    Bytes user_blob(len_user);
    if (len_user > 0) {
        handle.read(reinterpret_cast<char*>(user_blob.data()), len_user);
        if (handle.gcount() != static_cast<std::streamsize>(len_user)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    std::uint32_t len_master = 0;
    read_u32(len_master);
    Bytes master_blob(len_master);
    if (len_master > 0) {
        handle.read(reinterpret_cast<char*>(master_blob.data()), len_master);
        if (handle.gcount() != static_cast<std::streamsize>(len_master)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    std::uint32_t len_payload = 0;
    read_u32(len_payload);
    if (len_payload < 4 + constants::kAeadNonceLen + constants::kAeadTagLen) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    std::uint32_t metadata_len = 0;
    read_u32(metadata_len);
    Bytes metadata_bytes(metadata_len);
    if (metadata_len > 0) {
        handle.read(reinterpret_cast<char*>(metadata_bytes.data()), metadata_len);
        if (handle.gcount() != static_cast<std::streamsize>(metadata_len)) {
            throw std::runtime_error("Ciphertext payload truncated");
        }
    }
    Bytes nonce(constants::kAeadNonceLen);
    handle.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
    if (handle.gcount() != static_cast<std::streamsize>(nonce.size())) {
        throw std::runtime_error("Ciphertext payload truncated");
    }

    StreamCipherLayout layout = ResolveStreamCipherLayout(input, handle, len_payload, metadata_len);
    std::uint64_t cipher_body_len = layout.body_len;
    std::uint64_t cipher_body_start = layout.body_start;
    handle.seekg(static_cast<std::streamoff>(cipher_body_start + cipher_body_len), std::ios::beg);
    Bytes tag(constants::kAeadTagLen);
    handle.read(reinterpret_cast<char*>(tag.data()), tag.size());
    if (handle.gcount() != static_cast<std::streamsize>(tag.size())) {
        throw std::runtime_error("Ciphertext payload truncated");
    }
    handle.seekg(static_cast<std::streamoff>(cipher_body_start), std::ios::beg);

    bool use_master_effective = options.use_master && !options.strip_metadata;
    std::string metadata_blob = ToString(metadata_bytes);
    auto meta = basefwx::metadata::Decode(metadata_blob);
    if (basefwx::metadata::GetValue(meta, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }

    std::string kdf_label = basefwx::metadata::GetValue(meta, "ENC-KDF");
    kdf_label = basefwx::keywrap::ResolveKdfLabel(kdf_label.empty() ? kdf.label : kdf_label);
    auto kdf_iter = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-KDF-ITER"));
    auto argon2_time = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-TC"));
    auto argon2_mem = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-MEM"));
    auto argon2_par = ParseUint32(basefwx::metadata::GetValue(meta, "ENC-ARGON2-PAR"));
    bool use_derived_keys = basefwx::metadata::GetValue(meta, "ENC-KSEP") == "v1";

    Bytes ephemeral_key;
    PayloadKeys payload_keys;
    basefwx::crypto::SecretGuard secrets;
    secrets.Add(resolved);
    secrets.Add(ephemeral_key);
    secrets.Add(payload_keys.aead);
    secrets.Add(payload_keys.obf);
    if (!master_blob.empty()) {
        if (!use_master_effective) {
            throw std::runtime_error("Master key required to decrypt this payload");
        }
        if (basefwx::ec::IsEcMasterBlob(master_blob)) {
            if (StrictPqOnly()) {
                throw std::runtime_error("EC master blobs are disabled in PQ strict mode");
            }
            basefwx::crypto::SecureBytes private_key{basefwx::ec::LoadMasterPrivateKey()};
            basefwx::crypto::SecureBytes shared{
                basefwx::ec::KemDecrypt(private_key.bytes(), master_blob)};
            ephemeral_key = basefwx::crypto::HkdfSha256(shared.bytes(), constants::kKemInfo, 32);
        } else {
            basefwx::crypto::SecureBytes private_key{basefwx::pq::LoadMasterPrivateKey()};
            basefwx::crypto::SecureBytes shared{
                basefwx::pq::KemDecrypt(private_key.bytes(), master_blob)};
            ephemeral_key = basefwx::crypto::HkdfSha256(shared.bytes(), constants::kKemInfo, 32);
        }
    } else if (!user_blob.empty()) {
        if (resolved.empty()) {
            throw std::runtime_error("User password required to decrypt this payload");
        }
        if (user_blob.size() < constants::kUserKdfSaltSize + constants::kAeadNonceLen + constants::kAeadTagLen) {
            throw std::runtime_error("Corrupted user key blob: missing salt or AEAD data");
        }
        Bytes salt(user_blob.begin(), user_blob.begin() + static_cast<std::ptrdiff_t>(constants::kUserKdfSaltSize));
        Bytes wrapped(user_blob.begin() + static_cast<std::ptrdiff_t>(constants::kUserKdfSaltSize), user_blob.end());
        basefwx::pb512::KdfOptions kdf_opts = kdf;
        kdf_opts.label = kdf_label;
        if (kdf_iter.has_value()) {
            kdf_opts.pbkdf2_iterations = kdf_iter.value();
        } else {
            kdf_opts.pbkdf2_iterations = basefwx::constants::kUserKdfIterations;
        }
        if (argon2_time.has_value()) {
            kdf_opts.argon2_time_cost = argon2_time.value();
        }
        if (argon2_mem.has_value()) {
            kdf_opts.argon2_memory_cost = argon2_mem.value();
        }
        if (argon2_par.has_value()) {
            kdf_opts.argon2_parallelism = argon2_par.value();
        }
        kdf_opts = HardenKdfOptionsForPassword(resolved, kdf_opts);
        Bytes user_key = basefwx::keywrap::DeriveUserKeyWithLabel(resolved, salt, kdf_label, kdf_opts);
        ephemeral_key = basefwx::crypto::AeadDecrypt(user_key, wrapped, metadata_bytes);
        basefwx::crypto::SecureClear(user_key);
    } else {
        throw std::runtime_error("Ciphertext missing key transport data");
    }

    Bytes* aead_key = &ephemeral_key;
    Bytes* obf_key = nullptr;
    if (use_derived_keys) {
        payload_keys = DerivePayloadKeys(ephemeral_key);
        aead_key = &payload_keys.aead;
        obf_key = &payload_keys.obf;
    }

    AesGcmDecryptor decryptor(*aead_key, nonce, metadata_bytes);
    std::filesystem::path temp_plain = input;
    temp_plain += ".plain.tmp";
    TempFileCleanup temp_plain_cleanup(temp_plain);
    std::ofstream plain_out(temp_plain, std::ios::binary);
    if (!plain_out) {
        throw std::runtime_error("Failed to create temp file");
    }

    std::uint64_t remaining = cipher_body_len;
    Bytes buffer(options.stream_chunk_size);
    while (remaining > 0) {
        ThrowIfInterrupted();
        std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
        buffer.resize(take);
        handle.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(take));
        if (handle.gcount() != static_cast<std::streamsize>(take)) {
            throw std::runtime_error("Ciphertext truncated");
        }
        Bytes plain = decryptor.Update(buffer);
        if (!plain.empty()) {
            plain_out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
        }
        remaining -= take;
    }
    decryptor.Final(tag);
    plain_out.flush();
    if (!plain_out) {
        throw std::runtime_error("Failed to write plaintext temp file");
    }
    plain_out.close();
    ThrowIfInterrupted();

    std::ifstream plain_in(temp_plain, std::ios::binary);
    if (!plain_in) {
        throw std::runtime_error("Failed to open plaintext temp file");
    }
    if (!metadata_bytes.empty()) {
        Bytes prefix(metadata_bytes.size());
        plain_in.read(reinterpret_cast<char*>(prefix.data()), static_cast<std::streamsize>(prefix.size()));
        if (plain_in.gcount() != static_cast<std::streamsize>(prefix.size()) || prefix != metadata_bytes) {
            throw std::runtime_error("Metadata integrity mismatch detected");
        }
        Bytes delim(constants::kMetaDelim.begin(), constants::kMetaDelim.end());
        Bytes delim_buf(delim.size());
        plain_in.read(reinterpret_cast<char*>(delim_buf.data()), static_cast<std::streamsize>(delim_buf.size()));
        if (plain_in.gcount() != static_cast<std::streamsize>(delim_buf.size()) || delim_buf != delim) {
            throw std::runtime_error("Malformed streaming payload: missing metadata delimiter");
        }
    }

    Bytes magic(constants::kStreamMagic.begin(), constants::kStreamMagic.end());
    Bytes magic_buf(magic.size());
    plain_in.read(reinterpret_cast<char*>(magic_buf.data()), static_cast<std::streamsize>(magic_buf.size()));
    if (plain_in.gcount() != static_cast<std::streamsize>(magic_buf.size()) || magic_buf != magic) {
        throw std::runtime_error("Malformed streaming payload: magic mismatch");
    }
    std::array<std::uint8_t, 4> chunk_buf{};
    plain_in.read(reinterpret_cast<char*>(chunk_buf.data()), chunk_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(chunk_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing chunk size");
    }
    std::uint32_t chunk_size = (static_cast<std::uint32_t>(chunk_buf[0]) << 24)
                               | (static_cast<std::uint32_t>(chunk_buf[1]) << 16)
                               | (static_cast<std::uint32_t>(chunk_buf[2]) << 8)
                               | static_cast<std::uint32_t>(chunk_buf[3]);
    if (chunk_size == 0 || chunk_size > (16u << 20)) {
        chunk_size = static_cast<std::uint32_t>(options.stream_chunk_size);
    }
    std::array<std::uint8_t, 8> size_buf{};
    plain_in.read(reinterpret_cast<char*>(size_buf.data()), size_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(size_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing original size");
    }
    std::uint64_t original_size = 0;
    for (std::uint8_t b : size_buf) {
        original_size = (original_size << 8) | b;
    }
    Bytes salt(basefwx::obf::StreamObfuscator::kSaltLen);
    plain_in.read(reinterpret_cast<char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
    if (plain_in.gcount() != static_cast<std::streamsize>(salt.size())) {
        throw std::runtime_error("Malformed streaming payload: missing salt");
    }
    std::array<std::uint8_t, 2> ext_len_buf{};
    plain_in.read(reinterpret_cast<char*>(ext_len_buf.data()), ext_len_buf.size());
    if (plain_in.gcount() != static_cast<std::streamsize>(ext_len_buf.size())) {
        throw std::runtime_error("Malformed streaming payload: missing extension length");
    }
    std::uint16_t ext_len = static_cast<std::uint16_t>((ext_len_buf[0] << 8) | ext_len_buf[1]);
    Bytes ext_bytes(ext_len);
    if (ext_len > 0) {
        plain_in.read(reinterpret_cast<char*>(ext_bytes.data()), static_cast<std::streamsize>(ext_len));
        if (plain_in.gcount() != static_cast<std::streamsize>(ext_len)) {
            throw std::runtime_error("Malformed streaming payload: truncated extension");
        }
    }

    std::string obf_hint = basefwx::metadata::GetValue(meta, "ENC-OBF");
    if (obf_hint.empty()) {
        obf_hint = "yes";
    }
    bool fast_obf = obf_hint == "fast";
    std::optional<basefwx::obf::StreamObfuscator> decoder_v1;
    std::optional<basefwx::obf::StreamObfuscator> decoder_legacy;
    if (obf_key != nullptr) {
        decoder_v1.emplace(basefwx::obf::StreamObfuscator::ForKey(*obf_key, salt, fast_obf));
    } else {
        if (resolved.empty()) {
            throw std::runtime_error("Password required for AES-heavy streaming decode");
        }
        decoder_legacy.emplace(basefwx::obf::StreamObfuscator::ForPassword(resolved, salt, fast_obf));
    }
    std::filesystem::path target = input;
    target.replace_extension("");
    std::string ext;
    if (!ext_bytes.empty()) {
        ext = ToString(ext_bytes);
        target.replace_extension(ext);
    }
    auto pack_mode = ResolvePackMode(meta, ext);
    std::ofstream out(target, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file");
    }
    Bytes chunk_buf_bytes(chunk_size);
    std::uint64_t processed = 0;
    while (processed < original_size) {
        ThrowIfInterrupted();
        std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(chunk_size, original_size - processed));
        chunk_buf_bytes.resize(take);
        plain_in.read(reinterpret_cast<char*>(chunk_buf_bytes.data()), static_cast<std::streamsize>(take));
        if (plain_in.gcount() != static_cast<std::streamsize>(take)) {
            throw std::runtime_error("Streaming payload truncated");
        }
        if (decoder_v1.has_value()) {
            decoder_v1->DecodeChunkInPlace(chunk_buf_bytes);
        } else {
            decoder_legacy->DecodeChunkInPlace(chunk_buf_bytes);
        }
        out.write(reinterpret_cast<const char*>(chunk_buf_bytes.data()),
                  static_cast<std::streamsize>(chunk_buf_bytes.size()));
        processed += static_cast<std::uint64_t>(chunk_buf_bytes.size());
    }
    out.flush();
    if (!out) {
        throw std::runtime_error("Failed to write output file");
    }
    plain_in.close();
    std::error_code remove_ec;
    std::filesystem::remove(temp_plain, remove_ec);
    if (remove_ec) {
        throw std::runtime_error("Failed to remove temp file: " + remove_ec.message());
    }
    temp_plain_cleanup.Dismiss();
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    if (pack_mode != basefwx::archive::PackMode::None) {
        return basefwx::archive::UnpackArchive(target, pack_mode).string();
    }
    return target.string();
}

std::vector<std::uint8_t> Pb512EncodeBytes(const std::vector<std::uint8_t>& data,
                                           const std::string& extension,
                                           const std::string& password,
                                           const FileOptions& options,
                                           const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::uint64_t b64_len = ((data.size() + 2u) / 3u) * 4u;
    if (b64_len > basefwx::constants::kHkdfMaxLen) {
        throw std::runtime_error("pb512file bytes payload too large; use file-based streaming APIs");
    }
    std::string b64_payload = basefwx::base64::Encode(data);
    std::string ext = extension;

    std::optional<Bytes> pq_pub;
    std::optional<Bytes> ec_pub;
    if (options.use_master) {
        pq_pub = basefwx::pq::LoadMasterPublicKey();
        if (!pq_pub.has_value()) {
            ec_pub = TryLoadEcPublic(true);
        }
    }
    bool use_master_effective = options.use_master && !options.strip_metadata
        && (pq_pub.has_value() || ec_pub.has_value());
    basefwx::pb512::KdfOptions kdf_opts = kdf;
    std::string kdf_label = ResolveKdfLabel(kdf_opts);
    bool obf_enabled = EnableObfuscation(options);
    bool fast_obf = obf_enabled && !options.strip_metadata && UseFastObfuscation(data.size());
    std::string obf_mode = ObfMode(obf_enabled, fast_obf);

    std::string ext_token = basefwx::pb512::Pb512Encode(ext, resolved, use_master_effective, kdf_opts);
    std::string data_token = basefwx::pb512::Pb512Encode(b64_payload, resolved, use_master_effective, kdf_opts);

    std::optional<std::uint32_t> argon_time;
    std::optional<std::uint32_t> argon_mem;
    std::optional<std::uint32_t> argon_par;
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    argon_time = basefwx::constants::kHeavyArgon2TimeCost;
    argon_mem = basefwx::constants::kHeavyArgon2MemoryCost;
    argon_par = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif

    std::string metadata_blob = basefwx::metadata::Build(
        "AES-HEAVY",
        options.strip_metadata,
        use_master_effective,
        "AESGCM",
        kdf_label,
        "",
        obf_mode,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        std::string(),
        "v1"
    );

    std::string body = ext_token + std::string(constants::kFwxHeavyDelim) + data_token;
    std::string plaintext = metadata_blob.empty()
        ? body
        : metadata_blob + std::string(constants::kMetaDelim) + body;

    Bytes blob = EncryptAesPayload(
        plaintext,
        resolved,
        use_master_effective,
        metadata_blob,
        kdf_opts,
        basefwx::constants::HeavyPbkdf2Iterations(),
        argon_time,
        argon_mem,
        argon_par,
        obf_enabled,
        fast_obf
    );
    return blob;
}

DecodedBytes Pb512DecodeBytes(const std::vector<std::uint8_t>& blob,
                              const std::string& password,
                              const FileOptions& options,
                              const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    bool use_master_effective = options.use_master && !options.strip_metadata;
    bool obf_enabled = EnableObfuscation(options);
    std::string metadata_blob;
    std::string plaintext = DecryptAesPayload(blob, resolved, use_master_effective, kdf, obf_enabled, &metadata_blob);

    auto [meta_blob, payload] = SplitMetadata(plaintext);
    auto meta = basefwx::metadata::Decode(meta_blob);
    if (basefwx::metadata::GetValue(meta, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }
    auto split = SplitWithHeavyDelims(payload, "FWX heavy");
    std::string ext = basefwx::pb512::Pb512Decode(split.first, resolved, use_master_effective, kdf);
    std::string data_b64 = basefwx::pb512::Pb512Decode(split.second, resolved, use_master_effective, kdf);

    bool ok = false;
    Bytes decoded = basefwx::base64::Decode(data_b64, &ok);
    if (!ok) {
        throw std::runtime_error("Failed to decode base64 payload");
    }
    return DecodedBytes{decoded, ext};
}

std::string Pb512EncodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf) {
    std::filesystem::path input(path);
    if (!std::filesystem::exists(input)) {
        throw std::runtime_error("Input file not found: " + input.string());
    }
    auto pack = basefwx::archive::PackInput(input, options.compress);
    std::filesystem::path source = pack.used ? pack.source : input;
    std::string pack_flag = basefwx::archive::PackFlag(pack.mode);
    std::string output;
    try {
        std::uint64_t size = FileSize(source);
        std::uint64_t b64_len = ((size + 2u) / 3u) * 4u;
        bool force_stream = b64_len > basefwx::constants::kHkdfMaxLen;
        if (size >= options.stream_threshold || force_stream) {
            output = Pb512EncodeFileStream(source, password, options, kdf, pack_flag);
        } else {
            output = Pb512EncodeFileSimple(source, password, options, kdf, pack_flag);
        }
        if (pack.used) {
            std::filesystem::path final_out = input;
            final_out.replace_extension(".fwx");
            std::error_code ec;
            std::filesystem::remove(final_out, ec);
            std::filesystem::rename(output, final_out, ec);
            if (ec) {
                throw std::runtime_error("Failed to move output file: " + ec.message());
            }
            output = final_out.string();
            if (!options.keep_input) {
                if (std::filesystem::is_directory(input)) {
                    std::filesystem::remove_all(input, ec);
                } else {
                    std::filesystem::remove(input, ec);
                }
            }
        }
    } catch (...) {
        basefwx::archive::CleanupPack(pack);
        throw;
    }
    basefwx::archive::CleanupPack(pack);
    return output;
}

std::string Pb512DecodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::filesystem::path input(path);
    if (!std::filesystem::exists(input)) {
        throw std::runtime_error("Input file not found: " + input.string());
    }
    auto meta_preview = PeekMetadataBlob(input);
    if (meta_preview.has_value()) {
        auto meta = basefwx::metadata::Decode(meta_preview.value());
        std::string mode = basefwx::metadata::GetValue(meta, "ENC-MODE");
        if (!mode.empty() && mode == "STREAM") {
            return Pb512DecodeFileStream(input, password, options, kdf);
        }
    }

    Bytes blob = ReadFileBytes(input);
    bool use_master_effective = options.use_master && !options.strip_metadata;
    std::string metadata_blob;
    bool obf_enabled = EnableObfuscation(options);
    std::string plaintext = DecryptAesPayload(blob, resolved, use_master_effective, kdf, obf_enabled, &metadata_blob);

    auto [meta_blob, payload] = SplitMetadata(plaintext);
    auto meta = basefwx::metadata::Decode(meta_blob);
    if (basefwx::metadata::GetValue(meta, "ENC-MASTER") == "no") {
        use_master_effective = false;
    }
    auto split = SplitWithHeavyDelims(payload, "FWX heavy");
    std::string ext = basefwx::pb512::Pb512Decode(split.first, resolved, use_master_effective, kdf);
    std::string data_b64 = basefwx::pb512::Pb512Decode(split.second, resolved, use_master_effective, kdf);
    auto pack_mode = ResolvePackMode(meta, ext);

    bool ok = false;
    Bytes decoded = basefwx::base64::Decode(data_b64, &ok);
    if (!ok) {
        throw std::runtime_error("Failed to decode base64 payload");
    }
    std::filesystem::path target = input;
    target.replace_extension("");
    if (!ext.empty()) {
        target.replace_extension(ext);
    }
    WriteFileBytes(target, decoded);
    if (!options.keep_input) {
        std::filesystem::remove(input);
    }
    if (pack_mode != basefwx::archive::PackMode::None) {
        return basefwx::archive::UnpackArchive(target, pack_mode).string();
    }
    return target.string();
}

}  // namespace basefwx::filecodec::internal
