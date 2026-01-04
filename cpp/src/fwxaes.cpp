#include "basefwx/fwxaes.hpp"

#include "basefwx/archive.hpp"
#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

namespace basefwx::fwxaes {

namespace {

const std::uint8_t kMagic[4] = {'F', 'W', 'X', '1'};
const std::uint8_t kAlgo = 0x01;
const std::uint8_t kKdfPbkdf2 = 0x01;
const std::uint8_t kKdfWrap = 0x02;
const std::uint8_t kAadBytes[] = {'f', 'w', 'x', 'A', 'E', 'S'};
const std::uint8_t kPackMagic[] = {'F', 'W', 'X', 'P', 'K', '1'};
constexpr std::size_t kPackHeaderLen = sizeof(kPackMagic) + 1 + 8;
constexpr std::size_t kMaxKeyHeaderLen = 4 * 1024 * 1024;

std::uint32_t ResolveTestIters(std::uint32_t fallback) {
    std::string raw = basefwx::env::Get("BASEFWX_FWXAES_PBKDF2_ITERS");
    if (raw.empty()) {
        raw = basefwx::env::Get("BASEFWX_TEST_KDF_ITERS");
    }
    if (raw.empty()) {
        return fallback;
    }
    try {
        std::uint64_t parsed = static_cast<std::uint64_t>(std::stoul(raw));
        if (parsed == 0) {
            return fallback;
        }
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            return std::numeric_limits<std::uint32_t>::max();
        }
        return static_cast<std::uint32_t>(parsed);
    } catch (const std::exception&) {
        return fallback;
    }
}

std::uint32_t HardenPbkdf2Iterations(const std::string& password, std::uint32_t iters) {
    if (password.empty()) {
        return iters;
    }
    if (!basefwx::env::Get("BASEFWX_TEST_KDF_ITERS").empty()) {
        return iters;
    }
    if (password.size() < basefwx::constants::kShortPasswordMin) {
        if (iters < basefwx::constants::kShortPbkdf2Iterations) {
            iters = static_cast<std::uint32_t>(basefwx::constants::kShortPbkdf2Iterations);
        }
    }
    return iters;
}

bool IsSeekable(std::ostream& out) {
    auto pos = out.tellp();
    if (pos == std::streampos(-1)) {
        return false;
    }
    out.seekp(pos);
    return !out.fail();
}

void ReadExact(std::istream& in, std::uint8_t* data, std::size_t len, const char* label) {
    std::size_t total = 0;
    while (total < len && in) {
        in.read(reinterpret_cast<char*>(data + total), static_cast<std::streamsize>(len - total));
        std::streamsize got = in.gcount();
        if (got <= 0) {
            break;
        }
        total += static_cast<std::size_t>(got);
    }
    if (total != len) {
        throw std::runtime_error(label);
    }
}

void PutU32Be(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

std::uint32_t GetU32Be(const std::uint8_t* ptr) {
    return (static_cast<std::uint32_t>(ptr[0]) << 24)
           | (static_cast<std::uint32_t>(ptr[1]) << 16)
           | (static_cast<std::uint32_t>(ptr[2]) << 8)
           | static_cast<std::uint32_t>(ptr[3]);
}

Bytes WrapPackHeader(const Bytes& payload, basefwx::archive::PackMode mode) {
    if (mode == basefwx::archive::PackMode::None) {
        return payload;
    }
    std::string flag = basefwx::archive::PackFlag(mode);
    if (flag.empty()) {
        throw std::runtime_error("Unsupported pack mode");
    }
    Bytes out;
    out.reserve(kPackHeaderLen + payload.size());
    out.insert(out.end(), std::begin(kPackMagic), std::end(kPackMagic));
    out.push_back(static_cast<std::uint8_t>(flag[0]));
    std::uint64_t len = static_cast<std::uint64_t>(payload.size());
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((len >> (i * 8)) & 0xFF));
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool TryUnwrapPackHeader(const Bytes& data,
                         basefwx::archive::PackMode& mode_out,
                         Bytes& payload_out) {
    if (data.size() < kPackHeaderLen) {
        return false;
    }
    if (!std::equal(std::begin(kPackMagic), std::end(kPackMagic), data.begin())) {
        return false;
    }
    char flag_char = static_cast<char>(data[sizeof(kPackMagic)]);
    std::string flag(1, flag_char);
    mode_out = basefwx::archive::PackModeFromFlag(flag);
    if (mode_out == basefwx::archive::PackMode::None) {
        return false;
    }
    std::uint64_t length = 0;
    std::size_t length_start = sizeof(kPackMagic) + 1;
    for (std::size_t i = 0; i < 8; ++i) {
        length = (length << 8) | static_cast<std::uint64_t>(data[length_start + i]);
    }
    if (length != data.size() - kPackHeaderLen) {
        return false;
    }
    payload_out.assign(data.begin() + static_cast<std::ptrdiff_t>(kPackHeaderLen), data.end());
    return true;
}

std::vector<std::string> SplitWords(const std::string& phrase) {
    std::vector<std::string> words;
    std::string current;
    for (char ch : phrase) {
        if (ch == ' ') {
            if (!current.empty()) {
                words.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) {
        words.push_back(current);
    }
    return words;
}

std::string ReadText(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    // Use efficient seek-based reading instead of slow iterators
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read file size: " + path);
    }
    // Check for size overflow
    if (static_cast<std::uint64_t>(size) > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("File too large: " + path);
    }
    input.seekg(0, std::ios::beg);
    std::string data(static_cast<std::size_t>(size), '\0');
    if (!data.empty()) {
        input.read(&data[0], static_cast<std::streamsize>(data.size()));
        if (input.bad() || input.gcount() != static_cast<std::streamsize>(data.size())) {
            throw std::runtime_error("Failed to read file: " + path);
        }
    }
    return data;
}

void WriteBinary(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + path);
    }
    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
}

void WriteText(const std::string& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + path);
    }
    if (!text.empty()) {
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
    }
}

}  // namespace

Bytes EncryptRaw(const Bytes& plaintext, const std::string& password, const Options& options) {
    std::string resolved = basefwx::ResolvePassword(password);
    Options effective = options;
    effective.pbkdf2_iters = ResolveTestIters(options.pbkdf2_iters);
    effective.pbkdf2_iters = HardenPbkdf2Iterations(resolved, effective.pbkdf2_iters);
    if (!effective.use_master && resolved.empty()) {
        throw std::runtime_error("Password required when master key usage is disabled");
    }
    bool use_wrap = false;
    basefwx::keywrap::MaskKeyResult mask_key;
    Bytes key_header;
    if (effective.use_master) {
        basefwx::pb512::KdfOptions kdf;
        mask_key = basefwx::keywrap::PrepareMaskKey(
            resolved,
            true,
            basefwx::constants::kFwxAesMaskInfo,
            false,
            std::string_view(reinterpret_cast<const char*>(kAadBytes), sizeof(kAadBytes)),
            kdf
        );
        use_wrap = mask_key.used_master || resolved.empty();
        if (use_wrap) {
            std::vector<basefwx::format::Bytes> parts = {mask_key.user_blob, mask_key.master_blob};
            key_header = basefwx::format::PackLengthPrefixed(parts);
        }
    }

    Bytes iv = basefwx::crypto::RandomBytes(effective.iv_len);
    Bytes aad(kAadBytes, kAadBytes + sizeof(kAadBytes));
    Bytes key;
    if (use_wrap) {
        key = basefwx::crypto::HkdfSha256(mask_key.mask_key, basefwx::constants::kFwxAesKeyInfo, 32);
    } else {
        Bytes salt = basefwx::crypto::RandomBytes(effective.salt_len);
        key = basefwx::crypto::Pbkdf2HmacSha256(resolved, salt, effective.pbkdf2_iters, 32);
        Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(key, iv, plaintext, aad);

        Bytes blob;
        blob.reserve(16 + salt.size() + iv.size() + ct.size());
        blob.insert(blob.end(), kMagic, kMagic + 4);
        blob.push_back(kAlgo);
        blob.push_back(kKdfPbkdf2);
        blob.push_back(effective.salt_len);
        blob.push_back(effective.iv_len);
        PutU32Be(blob, effective.pbkdf2_iters);
        PutU32Be(blob, static_cast<std::uint32_t>(ct.size()));
        blob.insert(blob.end(), salt.begin(), salt.end());
        blob.insert(blob.end(), iv.begin(), iv.end());
        blob.insert(blob.end(), ct.begin(), ct.end());
        return blob;
    }

    Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(key, iv, plaintext, aad);
    if (key_header.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("fwxAES key header too large");
    }
    Bytes blob;
    blob.reserve(16 + key_header.size() + iv.size() + ct.size());
    blob.insert(blob.end(), kMagic, kMagic + 4);
    blob.push_back(kAlgo);
    blob.push_back(kKdfWrap);
    blob.push_back(0);
    blob.push_back(effective.iv_len);
    PutU32Be(blob, static_cast<std::uint32_t>(key_header.size()));
    PutU32Be(blob, static_cast<std::uint32_t>(ct.size()));
    blob.insert(blob.end(), key_header.begin(), key_header.end());
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), ct.begin(), ct.end());
    return blob;
}

Bytes DecryptRaw(const Bytes& blob, const std::string& password, bool use_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    const std::size_t header_len = 16;
    if (blob.size() < header_len) {
        throw std::runtime_error("fwxAES blob too short");
    }
    if (!std::equal(std::begin(kMagic), std::end(kMagic), blob.begin())) {
        throw std::runtime_error("fwxAES bad magic");
    }
    std::uint8_t algo = blob[4];
    std::uint8_t kdf = blob[5];
    std::uint8_t salt_len = blob[6];
    std::uint8_t iv_len = blob[7];
    if (algo != kAlgo || (kdf != kKdfPbkdf2 && kdf != kKdfWrap)) {
        throw std::runtime_error("fwxAES unsupported algo/kdf");
    }
    std::uint32_t iters = GetU32Be(&blob[8]);
    std::uint32_t ct_len = GetU32Be(&blob[12]);

    std::size_t offset = header_len;
    if (kdf == kKdfWrap) {
        std::size_t header_len_wrap = static_cast<std::size_t>(iters);
        if (header_len_wrap > kMaxKeyHeaderLen) {
            throw std::runtime_error("fwxAES key header too large");
        }
        if (header_len_wrap > blob.size() - offset) {
            throw std::runtime_error("fwxAES blob truncated");
        }
        std::size_t remaining = blob.size() - offset - header_len_wrap;
        if (remaining < iv_len || (remaining - iv_len) < ct_len) {
            throw std::runtime_error("fwxAES blob truncated");
        }
        Bytes header(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                     blob.begin() + static_cast<std::ptrdiff_t>(offset + header_len_wrap));
        offset += header_len_wrap;
        Bytes iv(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                 blob.begin() + static_cast<std::ptrdiff_t>(offset + iv_len));
        offset += iv_len;
        Bytes ct(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                 blob.begin() + static_cast<std::ptrdiff_t>(offset + ct_len));
        auto parts = basefwx::format::UnpackLengthPrefixed(header, 2);
        basefwx::pb512::KdfOptions kdf_opts;
        Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
            parts[0],
            parts[1],
            resolved,
            use_master,
            basefwx::constants::kFwxAesMaskInfo,
            std::string_view(reinterpret_cast<const char*>(kAadBytes), sizeof(kAadBytes)),
            kdf_opts
        );
        Bytes key = basefwx::crypto::HkdfSha256(mask_key, basefwx::constants::kFwxAesKeyInfo, 32);
        Bytes aad(kAadBytes, kAadBytes + sizeof(kAadBytes));
        return basefwx::crypto::AesGcmDecryptWithIv(key, iv, ct, aad);
    }
    if (blob.size() < offset + salt_len + iv_len + ct_len) {
        throw std::runtime_error("fwxAES blob truncated");
    }
    if (resolved.empty()) {
        throw std::runtime_error("fwxAES password required for PBKDF2 payload");
    }
    Bytes salt(blob.begin() + offset, blob.begin() + offset + salt_len);
    offset += salt_len;
    Bytes iv(blob.begin() + offset, blob.begin() + offset + iv_len);
    offset += iv_len;
    Bytes ct(blob.begin() + offset, blob.begin() + offset + ct_len);

    Bytes key = basefwx::crypto::Pbkdf2HmacSha256(resolved, salt, iters, 32);
    Bytes aad(kAadBytes, kAadBytes + sizeof(kAadBytes));
    return basefwx::crypto::AesGcmDecryptWithIv(key, iv, ct, aad);
}

std::uint64_t EncryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            const Options& options) {
    std::string resolved = basefwx::ResolvePassword(password);
    Options effective = options;
    effective.pbkdf2_iters = ResolveTestIters(options.pbkdf2_iters);
    effective.pbkdf2_iters = HardenPbkdf2Iterations(resolved, effective.pbkdf2_iters);
    if (!effective.use_master && resolved.empty()) {
        throw std::runtime_error("Password required when master key usage is disabled");
    }

    auto encrypt_to_seekable = [&](std::ostream& output) -> std::uint64_t {
        bool use_wrap = false;
        basefwx::keywrap::MaskKeyResult mask_key;
        Bytes key_header;
        if (effective.use_master) {
            basefwx::pb512::KdfOptions kdf;
            mask_key = basefwx::keywrap::PrepareMaskKey(
                resolved,
                true,
                basefwx::constants::kFwxAesMaskInfo,
                false,
                std::string_view(reinterpret_cast<const char*>(kAadBytes), sizeof(kAadBytes)),
                kdf
            );
            use_wrap = mask_key.used_master || resolved.empty();
            if (use_wrap) {
                std::vector<basefwx::format::Bytes> parts = {mask_key.user_blob, mask_key.master_blob};
                key_header = basefwx::format::PackLengthPrefixed(parts);
            }
        }

        Bytes iv = basefwx::crypto::RandomBytes(effective.iv_len);
        Bytes key;
        if (use_wrap) {
            key = basefwx::crypto::HkdfSha256(mask_key.mask_key, basefwx::constants::kFwxAesKeyInfo, 32);
        } else {
            if (resolved.empty()) {
                throw std::runtime_error("Password required when master key usage is disabled");
            }
            Bytes salt = basefwx::crypto::RandomBytes(effective.salt_len);
            key = basefwx::crypto::Pbkdf2HmacSha256(resolved, salt, effective.pbkdf2_iters, 32);

            Bytes header;
            header.reserve(16 + salt.size() + iv.size());
            header.insert(header.end(), kMagic, kMagic + 4);
            header.push_back(kAlgo);
            header.push_back(kKdfPbkdf2);
            header.push_back(effective.salt_len);
            header.push_back(effective.iv_len);
            PutU32Be(header, effective.pbkdf2_iters);
            PutU32Be(header, 0);
            output.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
            output.write(reinterpret_cast<const char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
            output.write(reinterpret_cast<const char*>(iv.data()), static_cast<std::streamsize>(iv.size()));
        }

        if (use_wrap) {
            if (key_header.size() > std::numeric_limits<std::uint32_t>::max()) {
                throw std::runtime_error("fwxAES key header too large");
            }
            Bytes header;
            header.reserve(16 + key_header.size() + iv.size());
            header.insert(header.end(), kMagic, kMagic + 4);
            header.push_back(kAlgo);
            header.push_back(kKdfWrap);
            header.push_back(0);
            header.push_back(effective.iv_len);
            PutU32Be(header, static_cast<std::uint32_t>(key_header.size()));
            PutU32Be(header, 0);
            output.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
            output.write(reinterpret_cast<const char*>(key_header.data()), static_cast<std::streamsize>(key_header.size()));
            output.write(reinterpret_cast<const char*>(iv.data()), static_cast<std::streamsize>(iv.size()));
        }

        struct CtxDeleter {
            void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
        };
        std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter> ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error("fwxAES encrypt ctx alloc failed");
        }
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("fwxAES encrypt init failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(iv.size()), nullptr) != 1) {
            throw std::runtime_error("fwxAES encrypt ivlen failed");
        }
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                               key.data(), iv.data()) != 1) {
            throw std::runtime_error("fwxAES encrypt key init failed");
        }
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_len,
                              kAadBytes, static_cast<int>(sizeof(kAadBytes))) != 1) {
            throw std::runtime_error("fwxAES encrypt aad failed");
        }

        std::uint64_t ct_len = 0;
        Bytes in_buf(basefwx::constants::kStreamChunkSize);
        Bytes out_buf(basefwx::constants::kStreamChunkSize + 16);
        while (source) {
            source.read(reinterpret_cast<char*>(in_buf.data()),
                        static_cast<std::streamsize>(in_buf.size()));
            std::streamsize got = source.gcount();
            if (got <= 0) {
                break;
            }
            if (EVP_EncryptUpdate(ctx.get(), out_buf.data(), &out_len,
                                  in_buf.data(), static_cast<int>(got)) != 1) {
                throw std::runtime_error("fwxAES encrypt update failed");
            }
            if (out_len > 0) {
                output.write(reinterpret_cast<const char*>(out_buf.data()),
                             static_cast<std::streamsize>(out_len));
                ct_len += static_cast<std::uint64_t>(out_len);
            }
        }

        if (EVP_EncryptFinal_ex(ctx.get(), out_buf.data(), &out_len) != 1) {
            throw std::runtime_error("fwxAES encrypt final failed");
        }
        if (out_len > 0) {
            output.write(reinterpret_cast<const char*>(out_buf.data()),
                         static_cast<std::streamsize>(out_len));
            ct_len += static_cast<std::uint64_t>(out_len);
        }

        std::array<std::uint8_t, 16> tag{};
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(tag.size()), tag.data()) != 1) {
            throw std::runtime_error("fwxAES encrypt tag failed");
        }
        output.write(reinterpret_cast<const char*>(tag.data()),
                     static_cast<std::streamsize>(tag.size()));
        ct_len += static_cast<std::uint64_t>(tag.size());

        if (ct_len > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("fwxAES ciphertext too large");
        }
        output.flush();
        std::streampos end_pos = output.tellp();
        output.seekp(12, std::ios::beg);
        std::uint32_t ct_len32 = static_cast<std::uint32_t>(ct_len);
        std::array<std::uint8_t, 4> ct_buf{
            static_cast<std::uint8_t>((ct_len32 >> 24) & 0xFF),
            static_cast<std::uint8_t>((ct_len32 >> 16) & 0xFF),
            static_cast<std::uint8_t>((ct_len32 >> 8) & 0xFF),
            static_cast<std::uint8_t>(ct_len32 & 0xFF)
        };
        output.write(reinterpret_cast<const char*>(ct_buf.data()),
                     static_cast<std::streamsize>(ct_buf.size()));
        output.seekp(end_pos);
        output.flush();
        return ct_len;
    };

    if (IsSeekable(dest)) {
        return encrypt_to_seekable(dest);
    }

    std::filesystem::path temp_path = std::filesystem::temp_directory_path()
        / ("basefwx-fwxaes-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".tmp");
    std::ofstream temp_out(temp_path, std::ios::binary);
    if (!temp_out) {
        throw std::runtime_error("Failed to open temp output for fwxaes stream");
    }
    std::uint64_t ct_len = encrypt_to_seekable(temp_out);
    temp_out.close();

    std::ifstream temp_in(temp_path, std::ios::binary);
    if (!temp_in) {
        throw std::runtime_error("Failed to open temp output for fwxaes stream");
    }
    dest << temp_in.rdbuf();
    temp_in.close();
    std::error_code ec;
    std::filesystem::remove(temp_path, ec);
    return ct_len;
}

std::uint64_t DecryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            bool use_master) {
    std::string resolved = basefwx::ResolvePassword(password);
    std::array<std::uint8_t, 16> header{};
    ReadExact(source, header.data(), header.size(), "fwxAES blob too short");
    if (!std::equal(std::begin(kMagic), std::end(kMagic), header.begin())) {
        throw std::runtime_error("fwxAES bad magic");
    }
    std::uint8_t algo = header[4];
    std::uint8_t kdf = header[5];
    std::uint8_t salt_len = header[6];
    std::uint8_t iv_len = header[7];
    if (algo != kAlgo || (kdf != kKdfPbkdf2 && kdf != kKdfWrap)) {
        throw std::runtime_error("fwxAES unsupported algo/kdf");
    }
    std::uint32_t iters = (static_cast<std::uint32_t>(header[8]) << 24)
                          | (static_cast<std::uint32_t>(header[9]) << 16)
                          | (static_cast<std::uint32_t>(header[10]) << 8)
                          | static_cast<std::uint32_t>(header[11]);
    std::uint32_t ct_len = (static_cast<std::uint32_t>(header[12]) << 24)
                           | (static_cast<std::uint32_t>(header[13]) << 16)
                           | (static_cast<std::uint32_t>(header[14]) << 8)
                           | static_cast<std::uint32_t>(header[15]);
    if (ct_len < 16) {
        throw std::runtime_error("fwxAES ciphertext too short");
    }

    Bytes iv;
    Bytes key;
    if (kdf == kKdfWrap) {
        std::size_t header_len = iters;
        if (header_len > kMaxKeyHeaderLen) {
            throw std::runtime_error("fwxAES key header too large");
        }
        Bytes key_header(header_len);
        if (header_len > 0) {
            ReadExact(source, key_header.data(), header_len, "fwxAES blob truncated");
        }
        iv.resize(iv_len);
        ReadExact(source, iv.data(), iv.size(), "fwxAES blob truncated");
        std::vector<basefwx::format::Bytes> parts = basefwx::format::UnpackLengthPrefixed(key_header, 2);
        Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
            parts[0],
            parts[1],
            resolved,
            use_master,
            basefwx::constants::kFwxAesMaskInfo,
            std::string_view(reinterpret_cast<const char*>(kAadBytes), sizeof(kAadBytes)),
            basefwx::pb512::KdfOptions{}
        );
        key = basefwx::crypto::HkdfSha256(mask_key, basefwx::constants::kFwxAesKeyInfo, 32);
    } else {
        Bytes salt(salt_len);
        ReadExact(source, salt.data(), salt.size(), "fwxAES blob truncated");
        iv.resize(iv_len);
        ReadExact(source, iv.data(), iv.size(), "fwxAES blob truncated");
        if (resolved.empty()) {
            throw std::runtime_error("fwxAES password required for PBKDF2 payload");
        }
        key = basefwx::crypto::Pbkdf2HmacSha256(resolved, salt, iters, 32);
    }

    struct CtxDeleter {
        void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
    };
    std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("fwxAES decrypt ctx alloc failed");
    }
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("fwxAES decrypt init failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1) {
        throw std::runtime_error("fwxAES decrypt ivlen failed");
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("fwxAES decrypt key init failed");
    }
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_len,
                          kAadBytes, static_cast<int>(sizeof(kAadBytes))) != 1) {
        throw std::runtime_error("fwxAES decrypt aad failed");
    }

    std::uint64_t cipher_len = static_cast<std::uint64_t>(ct_len - 16);
    std::uint64_t remaining = cipher_len;
    Bytes in_buf(basefwx::constants::kStreamChunkSize);
    Bytes out_buf(basefwx::constants::kStreamChunkSize + 16);
    std::uint64_t written = 0;
    while (remaining > 0) {
        std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, in_buf.size()));
        ReadExact(source, in_buf.data(), take, "fwxAES blob truncated");
        if (EVP_DecryptUpdate(ctx.get(), out_buf.data(), &out_len,
                              in_buf.data(), static_cast<int>(take)) != 1) {
            throw std::runtime_error("fwxAES decrypt update failed");
        }
        if (out_len > 0) {
            dest.write(reinterpret_cast<const char*>(out_buf.data()),
                       static_cast<std::streamsize>(out_len));
            written += static_cast<std::uint64_t>(out_len);
        }
        remaining -= take;
    }

    std::array<std::uint8_t, 16> tag{};
    ReadExact(source, tag.data(), tag.size(), "fwxAES blob truncated");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        throw std::runtime_error("fwxAES decrypt tag failed");
    }
    if (EVP_DecryptFinal_ex(ctx.get(), out_buf.data(), &out_len) != 1) {
        throw std::runtime_error("AES-GCM auth failed");
    }
    if (out_len > 0) {
        dest.write(reinterpret_cast<const char*>(out_buf.data()),
                   static_cast<std::streamsize>(out_len));
        written += static_cast<std::uint64_t>(out_len);
    }
    dest.flush();
    return written;
}

std::string NormalizeWrap(const Bytes& blob, const std::string& cover_phrase) {
    if (cover_phrase.empty()) {
        throw std::runtime_error("cover_phrase empty");
    }
    Bytes payload;
    payload.reserve(4 + blob.size());
    PutU32Be(payload, static_cast<std::uint32_t>(blob.size()));
    payload.insert(payload.end(), blob.begin(), blob.end());

    std::vector<std::uint8_t> bits;
    bits.reserve(payload.size() * 8);
    for (std::uint8_t byte : payload) {
        for (int i = 7; i >= 0; --i) {
            bits.push_back((byte >> i) & 0x01);
        }
    }

    const std::string zw0 = "\xE2\x80\x8B";
    const std::string zw1 = "\xE2\x80\x8C";

    std::vector<std::string> words = SplitWords(cover_phrase);
    if (words.empty()) {
        throw std::runtime_error("cover_phrase empty");
    }
    std::size_t token_count = bits.size() + 1;
    std::string out;
    out.reserve(token_count * 6);
    std::size_t bit_idx = 0;
    for (std::size_t t = 0; t < token_count; ++t) {
        out += words[t % words.size()];
        if (t + 1 < token_count) {
            out += " ";
            out += (bits[bit_idx++] ? zw1 : zw0);
        }
    }
    if (bit_idx != bits.size()) {
        throw std::runtime_error("failed to embed all bits");
    }
    return out;
}

Bytes NormalizeUnwrap(const std::string& text) {
    const std::string zw0 = "\xE2\x80\x8B";
    const std::string zw1 = "\xE2\x80\x8C";

    std::vector<std::uint8_t> bits;
    for (std::size_t i = 0; i < text.size();) {
        if (text.compare(i, zw0.size(), zw0) == 0) {
            bits.push_back(0);
            i += zw0.size();
        } else if (text.compare(i, zw1.size(), zw1) == 0) {
            bits.push_back(1);
            i += zw1.size();
        } else {
            i += 1;
        }
    }
    if (bits.size() < 32) {
        throw std::runtime_error("not enough hidden data");
    }

    std::uint32_t length = 0;
    for (int i = 0; i < 32; ++i) {
        length = (length << 1) | bits[i];
    }
    std::size_t needed = 32 + static_cast<std::size_t>(length) * 8;
    if (bits.size() < needed) {
        throw std::runtime_error("hidden data truncated");
    }

    Bytes blob;
    blob.reserve(length);
    for (std::size_t bi = 32; bi < needed; bi += 8) {
        std::uint8_t byte = 0;
        for (int j = 0; j < 8; ++j) {
            byte = static_cast<std::uint8_t>((byte << 1) | bits[bi + j]);
        }
        blob.push_back(byte);
    }
    return blob;
}

void EncryptFile(const std::string& path_in,
                 const std::string& path_out,
                 const std::string& password,
                 const Options& options,
                 const NormalizeOptions& normalize,
                 const PackOptions& pack,
                 bool keep_input) {
    std::filesystem::path input_path(path_in);
    auto pack_result = basefwx::archive::PackInput(input_path, pack.compress);
    Bytes plaintext;
    try {
        plaintext = basefwx::ReadFile(pack_result.source.string());
        if (pack_result.used) {
            plaintext = WrapPackHeader(plaintext, pack_result.mode);
        }
    } catch (...) {
        basefwx::archive::CleanupPack(pack_result);
        throw;
    }
    basefwx::archive::CleanupPack(pack_result);
    Bytes blob = EncryptRaw(plaintext, password, options);
    if (normalize.enabled && plaintext.size() <= normalize.threshold) {
        std::string text = NormalizeWrap(blob, normalize.cover_phrase);
        WriteText(path_out, text);
    } else {
        WriteBinary(path_out, blob);
    }
    if (!keep_input) {
        std::error_code ec;
        std::filesystem::path output_path(path_out);
        if (std::filesystem::equivalent(input_path, output_path, ec)) {
            return;
        }
        if (std::filesystem::is_directory(input_path, ec)) {
            std::filesystem::remove_all(input_path, ec);
        } else {
            std::filesystem::remove(input_path, ec);
        }
    }
}

void DecryptFile(const std::string& path_in,
                 const std::string& path_out,
                 const std::string& password,
                 bool use_master) {
    Bytes data = basefwx::ReadFile(path_in);
    Bytes blob;
    if (data.size() >= 4 && std::equal(std::begin(kMagic), std::end(kMagic), data.begin())) {
        blob = data;
    } else {
        std::string text(data.begin(), data.end());
        blob = NormalizeUnwrap(text);
    }
    Bytes plaintext = DecryptRaw(blob, password, use_master);
    basefwx::archive::PackMode pack_mode = basefwx::archive::PackMode::None;
    Bytes payload;
    if (TryUnwrapPackHeader(plaintext, pack_mode, payload)) {
        std::filesystem::path output_path(path_out);
        std::filesystem::path dest_dir = output_path;
        std::error_code ec;
        if (dest_dir.empty()) {
            dest_dir = std::filesystem::path(path_in).parent_path();
        } else if (!std::filesystem::is_directory(dest_dir, ec)) {
            dest_dir = output_path.parent_path();
        }
        auto temp_base = std::filesystem::temp_directory_path();
        auto temp_dir = temp_base / ("basefwx-pack-dec-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(temp_dir, ec);
        auto ext = (pack_mode == basefwx::archive::PackMode::Txz)
                       ? std::string(basefwx::constants::kPackTxzExt)
                       : std::string(basefwx::constants::kPackTgzExt);
        auto archive_path = temp_dir / (output_path.stem().string() + ext);
        WriteBinary(archive_path.string(), payload);
        basefwx::archive::UnpackArchive(archive_path, pack_mode, dest_dir);
        std::filesystem::remove_all(temp_dir, ec);
        return;
    }
    WriteBinary(path_out, plaintext);
}

}  // namespace basefwx::fwxaes
