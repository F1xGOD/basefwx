#include "basefwx/livecipher.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <istream>
#include <iterator>
#include <limits>
#include <ostream>
#include <stdexcept>

namespace basefwx::livecipher {

namespace {

using basefwx::crypto::Bytes;

constexpr std::uint8_t kAadBytes[] = {'f', 'w', 'x', 'A', 'E', 'S'};
const Bytes kAadVec(kAadBytes, kAadBytes + sizeof(kAadBytes));

std::uint32_t ResolveFwxAesIterations(std::uint32_t fallback) {
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

std::uint32_t HardenFwxAesIterations(const std::string& password, std::uint32_t iters) {
    if (password.empty()) {
        return iters;
    }
    if (!basefwx::env::Get("BASEFWX_TEST_KDF_ITERS").empty()) {
        return iters;
    }
    if (password.size() < basefwx::constants::kShortPasswordMin
        && iters < basefwx::constants::kShortPbkdf2Iterations) {
        return static_cast<std::uint32_t>(basefwx::constants::kShortPbkdf2Iterations);
    }
    return iters;
}

void WriteU32Be(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[3] = static_cast<std::uint8_t>(value & 0xFF);
}

void WriteU64Be(std::uint8_t* out, std::uint64_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 56) & 0xFF);
    out[1] = static_cast<std::uint8_t>((value >> 48) & 0xFF);
    out[2] = static_cast<std::uint8_t>((value >> 40) & 0xFF);
    out[3] = static_cast<std::uint8_t>((value >> 32) & 0xFF);
    out[4] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    out[5] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[6] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[7] = static_cast<std::uint8_t>(value & 0xFF);
}

std::uint32_t ReadU32Be(const std::uint8_t* ptr) {
    return (static_cast<std::uint32_t>(ptr[0]) << 24)
        | (static_cast<std::uint32_t>(ptr[1]) << 16)
        | (static_cast<std::uint32_t>(ptr[2]) << 8)
        | static_cast<std::uint32_t>(ptr[3]);
}

std::uint64_t ReadU64Be(const std::uint8_t* ptr) {
    return (static_cast<std::uint64_t>(ptr[0]) << 56)
        | (static_cast<std::uint64_t>(ptr[1]) << 48)
        | (static_cast<std::uint64_t>(ptr[2]) << 40)
        | (static_cast<std::uint64_t>(ptr[3]) << 32)
        | (static_cast<std::uint64_t>(ptr[4]) << 24)
        | (static_cast<std::uint64_t>(ptr[5]) << 16)
        | (static_cast<std::uint64_t>(ptr[6]) << 8)
        | static_cast<std::uint64_t>(ptr[7]);
}

Bytes NonceForSequence(const Bytes& prefix, std::uint64_t sequence) {
    if (prefix.size() != basefwx::constants::kLiveNoncePrefixLen) {
        throw std::runtime_error("Invalid live nonce prefix");
    }
    Bytes nonce(basefwx::constants::kAeadNonceLen);
    std::memcpy(nonce.data(), prefix.data(), prefix.size());
    WriteU64Be(nonce.data() + prefix.size(), sequence);
    return nonce;
}

Bytes LiveAad(std::uint8_t frame_type, std::uint64_t sequence, std::uint32_t plain_len) {
    Bytes aad(basefwx::constants::kLiveFrameHeaderLen);
    std::memcpy(aad.data(), basefwx::constants::kLiveFrameMagic.data(), basefwx::constants::kLiveFrameMagic.size());
    aad[4] = basefwx::constants::kLiveFrameVersion;
    aad[5] = frame_type;
    WriteU64Be(aad.data() + 6, sequence);
    WriteU32Be(aad.data() + 14, plain_len);
    return aad;
}

Bytes PackFrame(std::uint8_t frame_type, std::uint64_t sequence, const Bytes& body) {
    if (body.size() > basefwx::constants::kLiveMaxBody) {
        throw std::runtime_error("Live frame body too large");
    }
    Bytes frame(basefwx::constants::kLiveFrameHeaderLen + body.size());
    std::memcpy(frame.data(), basefwx::constants::kLiveFrameMagic.data(), basefwx::constants::kLiveFrameMagic.size());
    frame[4] = basefwx::constants::kLiveFrameVersion;
    frame[5] = frame_type;
    WriteU64Be(frame.data() + 6, sequence);
    WriteU32Be(frame.data() + 14, static_cast<std::uint32_t>(body.size()));
    if (!body.empty()) {
        std::memcpy(frame.data() + basefwx::constants::kLiveFrameHeaderLen, body.data(), body.size());
    }
    return frame;
}

Bytes BuildSessionHeader(std::uint8_t key_mode,
                         const Bytes& key_header,
                         const Bytes& salt,
                         const Bytes& nonce_prefix,
                         std::uint32_t iters) {
    if (salt.size() > 0xFF || nonce_prefix.size() > 0xFF) {
        throw std::runtime_error("Live header field too large");
    }
    if (key_header.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("Live key header too large");
    }
    Bytes body(basefwx::constants::kLiveHeaderFixedLen + key_header.size() + salt.size() + nonce_prefix.size());
    body[0] = key_mode;
    body[1] = static_cast<std::uint8_t>(salt.size());
    body[2] = static_cast<std::uint8_t>(nonce_prefix.size());
    body[3] = 0;
    WriteU32Be(body.data() + 4, static_cast<std::uint32_t>(key_header.size()));
    WriteU32Be(body.data() + 8, iters);
    std::size_t offset = basefwx::constants::kLiveHeaderFixedLen;
    if (!key_header.empty()) {
        std::memcpy(body.data() + offset, key_header.data(), key_header.size());
        offset += key_header.size();
    }
    if (!salt.empty()) {
        std::memcpy(body.data() + offset, salt.data(), salt.size());
        offset += salt.size();
    }
    if (!nonce_prefix.empty()) {
        std::memcpy(body.data() + offset, nonce_prefix.data(), nonce_prefix.size());
    }
    return body;
}

void AppendBytes(Bytes& dst, const std::uint8_t* data, std::size_t len) {
    if (data == nullptr || len == 0) {
        return;
    }
    dst.insert(dst.end(), data, data + len);
}

}  // namespace

LiveEncryptor::LiveEncryptor(const std::string& password, bool use_master)
    : password_(basefwx::ResolvePassword(password)),
      use_master_(use_master) {}

Bytes LiveEncryptor::InitSession() {
    bool has_password = !password_.empty();
    std::uint8_t key_mode = basefwx::constants::kLiveKeyModePbkdf2;
    Bytes key_header;
    Bytes salt;
    std::uint32_t iters = 0;
    bool use_wrap = false;

    if (use_master_) {
        try {
            basefwx::pb512::KdfOptions kdf;
            auto mask_key = basefwx::keywrap::PrepareMaskKey(
                password_,
                true,
                basefwx::constants::kFwxAesMaskInfo,
                false,
                std::string_view(reinterpret_cast<const char*>(kAadBytes), sizeof(kAadBytes)),
                kdf
            );
            use_wrap = mask_key.used_master || !has_password;
            if (use_wrap) {
                key_mode = basefwx::constants::kLiveKeyModeWrap;
                std::vector<basefwx::format::Bytes> parts = {mask_key.user_blob, mask_key.master_blob};
                key_header = basefwx::format::PackLengthPrefixed(parts);
                key_ = basefwx::crypto::HkdfSha256(mask_key.mask_key, basefwx::constants::kFwxAesKeyInfo, 32);
            }
        } catch (const std::exception&) {
            if (!has_password) {
                throw;
            }
            use_wrap = false;
        }
    }

    if (!use_wrap) {
        if (!has_password) {
            throw std::runtime_error("Password required when live stream master key wrapping is disabled");
        }
        salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
        iters = HardenFwxAesIterations(password_, ResolveFwxAesIterations(200000));
        key_ = basefwx::crypto::Pbkdf2HmacSha256(password_, salt, iters, 32);
    }

    nonce_prefix_ = basefwx::crypto::RandomBytes(basefwx::constants::kLiveNoncePrefixLen);
    Bytes body = BuildSessionHeader(key_mode, key_header, salt, nonce_prefix_, iters);
    return PackFrame(basefwx::constants::kLiveFrameTypeHeader, 0, body);
}

Bytes LiveEncryptor::Start() {
    if (started_) {
        throw std::runtime_error("LiveEncryptor already started");
    }
    if (finalized_) {
        throw std::runtime_error("LiveEncryptor already finalized");
    }
    Bytes frame = InitSession();
    started_ = true;
    return frame;
}

Bytes LiveEncryptor::Update(const Bytes& chunk) {
    return Update(chunk.data(), chunk.size());
}

Bytes LiveEncryptor::Update(const std::uint8_t* data, std::size_t len) {
    if (!started_) {
        throw std::runtime_error("LiveEncryptor.start() must be called before update()");
    }
    if (finalized_) {
        throw std::runtime_error("LiveEncryptor already finalized");
    }
    if (data == nullptr || len == 0) {
        return {};
    }
    if (len > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("Live frame plaintext too large");
    }
    Bytes payload(data, data + len);
    Bytes nonce = NonceForSequence(nonce_prefix_, sequence_);
    Bytes aad = LiveAad(basefwx::constants::kLiveFrameTypeData, sequence_, static_cast<std::uint32_t>(len));
    Bytes ct = basefwx::crypto::AesGcmEncryptWithIv(key_, nonce, payload, aad);
    Bytes body(4 + ct.size());
    WriteU32Be(body.data(), static_cast<std::uint32_t>(len));
    std::memcpy(body.data() + 4, ct.data(), ct.size());
    Bytes frame = PackFrame(basefwx::constants::kLiveFrameTypeData, sequence_, body);
    sequence_ += 1;
    return frame;
}

Bytes LiveEncryptor::Finalize() {
    if (!started_) {
        throw std::runtime_error("LiveEncryptor.start() must be called before finalize()");
    }
    if (finalized_) {
        throw std::runtime_error("LiveEncryptor already finalized");
    }
    Bytes nonce = NonceForSequence(nonce_prefix_, sequence_);
    Bytes aad = LiveAad(basefwx::constants::kLiveFrameTypeFin, sequence_, 0);
    Bytes fin_blob = basefwx::crypto::AesGcmEncryptWithIv(key_, nonce, {}, aad);
    Bytes frame = PackFrame(basefwx::constants::kLiveFrameTypeFin, sequence_, fin_blob);
    sequence_ += 1;
    finalized_ = true;
    return frame;
}

LiveDecryptor::LiveDecryptor(const std::string& password, bool use_master)
    : password_(basefwx::ResolvePassword(password)),
      use_master_(use_master) {}

void LiveDecryptor::ParseHeader(const Bytes& body) {
    if (body.size() < basefwx::constants::kLiveHeaderFixedLen) {
        throw std::runtime_error("Truncated live stream header");
    }
    std::uint8_t key_mode = body[0];
    std::uint8_t salt_len = body[1];
    std::uint8_t nonce_len = body[2];
    std::uint32_t key_header_len = ReadU32Be(body.data() + 4);
    std::uint32_t iters = ReadU32Be(body.data() + 8);

    std::size_t needed = basefwx::constants::kLiveHeaderFixedLen
        + static_cast<std::size_t>(key_header_len)
        + static_cast<std::size_t>(salt_len)
        + static_cast<std::size_t>(nonce_len);
    if (body.size() != needed) {
        throw std::runtime_error("Invalid live stream header length");
    }

    std::size_t offset = basefwx::constants::kLiveHeaderFixedLen;
    Bytes key_header;
    if (key_header_len > 0) {
        key_header.assign(body.begin() + static_cast<std::ptrdiff_t>(offset),
                          body.begin() + static_cast<std::ptrdiff_t>(offset + key_header_len));
        offset += key_header_len;
    }
    Bytes salt;
    if (salt_len > 0) {
        salt.assign(body.begin() + static_cast<std::ptrdiff_t>(offset),
                    body.begin() + static_cast<std::ptrdiff_t>(offset + salt_len));
        offset += salt_len;
    }
    Bytes nonce_prefix;
    if (nonce_len > 0) {
        nonce_prefix.assign(body.begin() + static_cast<std::ptrdiff_t>(offset),
                            body.begin() + static_cast<std::ptrdiff_t>(offset + nonce_len));
    }
    if (nonce_prefix.size() != basefwx::constants::kLiveNoncePrefixLen) {
        throw std::runtime_error("Invalid live stream nonce prefix");
    }

    if (key_mode == basefwx::constants::kLiveKeyModeWrap) {
        if (key_header.empty()) {
            throw std::runtime_error("Missing live key header");
        }
        auto parts = basefwx::format::UnpackLengthPrefixed(key_header, 2);
        basefwx::pb512::KdfOptions kdf;
        Bytes mask_key = basefwx::keywrap::RecoverMaskKey(
            parts[0],
            parts[1],
            password_,
            use_master_,
            basefwx::constants::kFwxAesMaskInfo,
            std::string_view(reinterpret_cast<const char*>(kAadBytes), sizeof(kAadBytes)),
            kdf
        );
        key_ = basefwx::crypto::HkdfSha256(mask_key, basefwx::constants::kFwxAesKeyInfo, 32);
    } else if (key_mode == basefwx::constants::kLiveKeyModePbkdf2) {
        if (password_.empty()) {
            throw std::runtime_error("Password required for PBKDF2 live stream");
        }
        if (salt.empty()) {
            throw std::runtime_error("Missing live stream PBKDF2 salt");
        }
        if (iters == 0) {
            throw std::runtime_error("Invalid live stream PBKDF2 iterations");
        }
        key_ = basefwx::crypto::Pbkdf2HmacSha256(password_, salt, iters, 32);
    } else {
        throw std::runtime_error("Unsupported live key mode");
    }

    nonce_prefix_ = std::move(nonce_prefix);
    started_ = true;
    expected_sequence_ = 1;
}

Bytes LiveDecryptor::DecryptDataFrame(std::uint64_t sequence, const Bytes& body) const {
    if (body.size() < 4 + basefwx::constants::kAeadTagLen) {
        throw std::runtime_error("Truncated live data frame");
    }
    std::uint32_t plain_len = ReadU32Be(body.data());
    Bytes ct(body.begin() + 4, body.end());
    Bytes nonce = NonceForSequence(nonce_prefix_, sequence);
    Bytes aad = LiveAad(basefwx::constants::kLiveFrameTypeData, sequence, plain_len);
    Bytes plain;
    try {
        plain = basefwx::crypto::AesGcmDecryptWithIv(key_, nonce, ct, aad);
    } catch (const std::exception&) {
        throw std::runtime_error("Live frame authentication failed");
    }
    if (plain.size() != plain_len) {
        throw std::runtime_error("Live frame length mismatch");
    }
    return plain;
}

void LiveDecryptor::DecryptFinFrame(std::uint64_t sequence, const Bytes& body) {
    if (body.size() < basefwx::constants::kAeadTagLen) {
        throw std::runtime_error("Truncated live FIN frame");
    }
    Bytes nonce = NonceForSequence(nonce_prefix_, sequence);
    Bytes aad = LiveAad(basefwx::constants::kLiveFrameTypeFin, sequence, 0);
    Bytes plain;
    try {
        plain = basefwx::crypto::AesGcmDecryptWithIv(key_, nonce, body, aad);
    } catch (const std::exception&) {
        throw std::runtime_error("Live FIN authentication failed");
    }
    if (!plain.empty()) {
        throw std::runtime_error("Live FIN frame carries unexpected payload");
    }
    finished_ = true;
}

std::vector<Bytes> LiveDecryptor::Update(const Bytes& data) {
    return Update(data.data(), data.size());
}

std::vector<Bytes> LiveDecryptor::Update(const std::uint8_t* data, std::size_t len) {
    if (finished_ && len > 0) {
        throw std::runtime_error("Live stream already finalized");
    }
    AppendBytes(buffer_, data, len);

    std::vector<Bytes> outputs;
    while (buffer_.size() >= basefwx::constants::kLiveFrameHeaderLen) {
        const std::uint8_t* head = buffer_.data();
        if (std::memcmp(head,
                        basefwx::constants::kLiveFrameMagic.data(),
                        basefwx::constants::kLiveFrameMagic.size()) != 0) {
            throw std::runtime_error("Invalid live frame magic");
        }
        std::uint8_t version = head[4];
        if (version != basefwx::constants::kLiveFrameVersion) {
            throw std::runtime_error("Unsupported live frame version");
        }
        std::uint8_t frame_type = head[5];
        std::uint64_t sequence = ReadU64Be(head + 6);
        std::uint32_t body_len = ReadU32Be(head + 14);
        if (body_len > basefwx::constants::kLiveMaxBody) {
            throw std::runtime_error("Live frame too large");
        }
        std::size_t frame_len = basefwx::constants::kLiveFrameHeaderLen + static_cast<std::size_t>(body_len);
        if (buffer_.size() < frame_len) {
            break;
        }
        Bytes body;
        if (body_len > 0) {
            body.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(basefwx::constants::kLiveFrameHeaderLen),
                        buffer_.begin() + static_cast<std::ptrdiff_t>(frame_len));
        }
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(frame_len));

        if (!started_) {
            if (frame_type != basefwx::constants::kLiveFrameTypeHeader || sequence != 0) {
                throw std::runtime_error("Live stream must start with header frame");
            }
            ParseHeader(body);
            continue;
        }
        if (sequence != expected_sequence_) {
            throw std::runtime_error("Live frame sequence mismatch");
        }
        if (frame_type == basefwx::constants::kLiveFrameTypeData) {
            Bytes plain = DecryptDataFrame(sequence, body);
            if (!plain.empty()) {
                outputs.push_back(std::move(plain));
            }
        } else if (frame_type == basefwx::constants::kLiveFrameTypeFin) {
            DecryptFinFrame(sequence, body);
        } else {
            throw std::runtime_error("Unexpected live frame type");
        }
        expected_sequence_ += 1;
    }
    return outputs;
}

void LiveDecryptor::Finalize() {
    if (!started_) {
        throw std::runtime_error("Missing live stream header frame");
    }
    if (!finished_) {
        throw std::runtime_error("Live stream ended without FIN frame");
    }
    if (!buffer_.empty()) {
        throw std::runtime_error("Trailing bytes after live stream FIN");
    }
}

std::vector<Bytes> EncryptChunks(const std::vector<Bytes>& chunks,
                                 const std::string& password,
                                 bool use_master) {
    LiveEncryptor encryptor(password, use_master);
    std::vector<Bytes> frames;
    frames.push_back(encryptor.Start());
    for (const auto& chunk : chunks) {
        Bytes frame = encryptor.Update(chunk);
        if (!frame.empty()) {
            frames.push_back(std::move(frame));
        }
    }
    frames.push_back(encryptor.Finalize());
    return frames;
}

std::vector<Bytes> DecryptChunks(const std::vector<Bytes>& chunks,
                                 const std::string& password,
                                 bool use_master) {
    LiveDecryptor decryptor(password, use_master);
    std::vector<Bytes> plain_chunks;
    for (const auto& chunk : chunks) {
        auto out = decryptor.Update(chunk);
        plain_chunks.insert(plain_chunks.end(),
                            std::make_move_iterator(out.begin()),
                            std::make_move_iterator(out.end()));
    }
    decryptor.Finalize();
    return plain_chunks;
}

std::uint64_t EncryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            bool use_master,
                            std::size_t chunk_size) {
    std::size_t chunk = chunk_size > 0 ? chunk_size : basefwx::constants::kStreamChunkSize;
    LiveEncryptor encryptor(password, use_master);
    std::uint64_t total = 0;

    Bytes header = encryptor.Start();
    dest.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
    total += static_cast<std::uint64_t>(header.size());

    std::vector<std::uint8_t> buffer(chunk);
    while (source) {
        source.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = source.gcount();
        if (got <= 0) {
            break;
        }
        Bytes frame = encryptor.Update(buffer.data(), static_cast<std::size_t>(got));
        if (!frame.empty()) {
            dest.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
            total += static_cast<std::uint64_t>(frame.size());
        }
    }

    Bytes fin = encryptor.Finalize();
    dest.write(reinterpret_cast<const char*>(fin.data()), static_cast<std::streamsize>(fin.size()));
    total += static_cast<std::uint64_t>(fin.size());
    dest.flush();
    return total;
}

std::uint64_t DecryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            bool use_master,
                            std::size_t chunk_size) {
    std::size_t chunk = chunk_size > 0 ? chunk_size : basefwx::constants::kStreamChunkSize;
    LiveDecryptor decryptor(password, use_master);
    std::uint64_t written = 0;

    std::vector<std::uint8_t> buffer(chunk);
    while (source) {
        source.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = source.gcount();
        if (got <= 0) {
            break;
        }
        auto plain_chunks = decryptor.Update(buffer.data(), static_cast<std::size_t>(got));
        for (const auto& plain : plain_chunks) {
            if (plain.empty()) {
                continue;
            }
            dest.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
            written += static_cast<std::uint64_t>(plain.size());
        }
    }
    decryptor.Finalize();
    dest.flush();
    return written;
}

}  // namespace basefwx::livecipher
