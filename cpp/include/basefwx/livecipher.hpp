#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace basefwx::livecipher {

using Bytes = std::vector<std::uint8_t>;

class LiveEncryptor {
public:
    explicit LiveEncryptor(const std::string& password, bool use_master = false);

    Bytes Start();
    Bytes Update(const Bytes& chunk);
    Bytes Update(const std::uint8_t* data, std::size_t len);
    Bytes Finalize();

private:
    Bytes InitSession();

    std::string password_;
    bool use_master_ = false;
    bool started_ = false;
    bool finalized_ = false;
    std::uint64_t sequence_ = 1;
    Bytes key_;
    Bytes nonce_prefix_;
};

class LiveDecryptor {
public:
    explicit LiveDecryptor(const std::string& password, bool use_master = false);

    std::vector<Bytes> Update(const Bytes& data);
    std::vector<Bytes> Update(const std::uint8_t* data, std::size_t len);
    void Finalize();

private:
    void ParseHeader(const std::uint8_t* body, std::size_t body_len);
    Bytes DecryptDataFrame(std::uint64_t sequence, const std::uint8_t* body, std::size_t body_len) const;
    void DecryptFinFrame(std::uint64_t sequence, const std::uint8_t* body, std::size_t body_len);
    void CompactBufferIfNeeded(std::size_t incoming_len = 0);

    std::string password_;
    bool use_master_ = false;
    bool started_ = false;
    bool finished_ = false;
    std::uint64_t expected_sequence_ = 0;
    Bytes key_;
    Bytes nonce_prefix_;
    Bytes buffer_;
    std::size_t buffer_offset_ = 0;
};

std::vector<Bytes> EncryptChunks(const std::vector<Bytes>& chunks,
                                 const std::string& password,
                                 bool use_master = false);

std::vector<Bytes> DecryptChunks(const std::vector<Bytes>& chunks,
                                 const std::string& password,
                                 bool use_master = false);

std::uint64_t EncryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            bool use_master = false,
                            std::size_t chunk_size = 0);

std::uint64_t DecryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            bool use_master = false,
                            std::size_t chunk_size = 0);

}  // namespace basefwx::livecipher
