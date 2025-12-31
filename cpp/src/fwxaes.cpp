#include "basefwx/fwxaes.hpp"

#include "basefwx/archive.hpp"
#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace basefwx::fwxaes {

namespace {

const std::uint8_t kMagic[4] = {'F', 'W', 'X', '1'};
const std::uint8_t kAlgo = 0x01;
const std::uint8_t kKdf = 0x01;
const std::uint8_t kAadBytes[] = {'f', 'w', 'x', 'A', 'E', 'S'};
const std::uint8_t kPackMagic[] = {'F', 'W', 'X', 'P', 'K', '1'};
constexpr std::size_t kPackHeaderLen = sizeof(kPackMagic) + 1 + 8;

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
    std::string data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
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
    Options effective = options;
    effective.pbkdf2_iters = ResolveTestIters(options.pbkdf2_iters);
    Bytes salt = basefwx::crypto::RandomBytes(effective.salt_len);
    Bytes iv = basefwx::crypto::RandomBytes(effective.iv_len);
    Bytes key = basefwx::crypto::Pbkdf2HmacSha256(password, salt, effective.pbkdf2_iters, 32);
    Bytes aad(kAadBytes, kAadBytes + sizeof(kAadBytes));
    Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(key, iv, plaintext, aad);

    Bytes blob;
    blob.reserve(16 + salt.size() + iv.size() + ct.size());
    blob.insert(blob.end(), kMagic, kMagic + 4);
    blob.push_back(kAlgo);
    blob.push_back(kKdf);
    blob.push_back(effective.salt_len);
    blob.push_back(effective.iv_len);
    PutU32Be(blob, effective.pbkdf2_iters);
    PutU32Be(blob, static_cast<std::uint32_t>(ct.size()));
    blob.insert(blob.end(), salt.begin(), salt.end());
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), ct.begin(), ct.end());
    return blob;
}

Bytes DecryptRaw(const Bytes& blob, const std::string& password) {
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
    if (algo != kAlgo || kdf != kKdf) {
        throw std::runtime_error("fwxAES unsupported algo/kdf");
    }
    std::uint32_t iters = GetU32Be(&blob[8]);
    std::uint32_t ct_len = GetU32Be(&blob[12]);

    std::size_t offset = header_len;
    if (blob.size() < offset + salt_len + iv_len + ct_len) {
        throw std::runtime_error("fwxAES blob truncated");
    }
    Bytes salt(blob.begin() + offset, blob.begin() + offset + salt_len);
    offset += salt_len;
    Bytes iv(blob.begin() + offset, blob.begin() + offset + iv_len);
    offset += iv_len;
    Bytes ct(blob.begin() + offset, blob.begin() + offset + ct_len);

    Bytes key = basefwx::crypto::Pbkdf2HmacSha256(password, salt, iters, 32);
    Bytes aad(kAadBytes, kAadBytes + sizeof(kAadBytes));
    return basefwx::crypto::AesGcmDecryptWithIv(key, iv, ct, aad);
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
                 const std::string& password) {
    Bytes data = basefwx::ReadFile(path_in);
    Bytes blob;
    if (data.size() >= 4 && std::equal(std::begin(kMagic), std::end(kMagic), data.begin())) {
        blob = data;
    } else {
        std::string text(data.begin(), data.end());
        blob = NormalizeUnwrap(text);
    }
    Bytes plaintext = DecryptRaw(blob, password);
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
