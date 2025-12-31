#include "basefwx/fwxaes.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/crypto.hpp"

#include <fstream>
#include <stdexcept>

namespace basefwx::fwxaes {

namespace {

const std::uint8_t kMagic[4] = {'F', 'W', 'X', '1'};
const std::uint8_t kAlgo = 0x01;
const std::uint8_t kKdf = 0x01;
const std::uint8_t kAadBytes[] = {'f', 'w', 'x', 'A', 'E', 'S'};

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
    Bytes salt = basefwx::crypto::RandomBytes(options.salt_len);
    Bytes iv = basefwx::crypto::RandomBytes(options.iv_len);
    Bytes key = basefwx::crypto::Pbkdf2HmacSha256(password, salt, options.pbkdf2_iters, 32);
    Bytes aad(kAadBytes, kAadBytes + sizeof(kAadBytes));
    Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(key, iv, plaintext, aad);

    Bytes blob;
    blob.reserve(16 + salt.size() + iv.size() + ct.size());
    blob.insert(blob.end(), kMagic, kMagic + 4);
    blob.push_back(kAlgo);
    blob.push_back(kKdf);
    blob.push_back(options.salt_len);
    blob.push_back(options.iv_len);
    PutU32Be(blob, options.pbkdf2_iters);
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
                 const NormalizeOptions& normalize) {
    Bytes plaintext = basefwx::ReadFile(path_in);
    Bytes blob = EncryptRaw(plaintext, password, options);
    if (normalize.enabled && plaintext.size() <= normalize.threshold) {
        std::string text = NormalizeWrap(blob, normalize.cover_phrase);
        WriteText(path_out, text);
    } else {
        WriteBinary(path_out, blob);
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
    WriteBinary(path_out, plaintext);
}

}  // namespace basefwx::fwxaes
