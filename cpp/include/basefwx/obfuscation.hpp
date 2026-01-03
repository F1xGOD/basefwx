#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace basefwx::obf {

using Bytes = std::vector<std::uint8_t>;

Bytes ObfuscateBytes(const Bytes& data, const Bytes& key, bool fast = false);
Bytes DeobfuscateBytes(const Bytes& data, const Bytes& key, bool fast = false);

class StreamObfuscator {
public:
    static constexpr std::size_t kSaltLen = 16;

    static Bytes GenerateSalt();
    static StreamObfuscator ForPassword(const std::string& password, const Bytes& salt, bool fast = false);

    StreamObfuscator(StreamObfuscator&& other) noexcept;
    StreamObfuscator& operator=(StreamObfuscator&& other) noexcept;
    ~StreamObfuscator();

    Bytes EncodeChunk(const Bytes& chunk);
    Bytes DecodeChunk(const Bytes& chunk);
    void EncodeChunkInPlace(Bytes& buffer);
    void DecodeChunkInPlace(Bytes& buffer);

private:
    StreamObfuscator(Bytes perm_material, void* ctx, bool fast);
    StreamObfuscator(const StreamObfuscator&) = delete;
    StreamObfuscator& operator=(const StreamObfuscator&) = delete;

    Bytes perm_material_;
    std::size_t chunk_index_ = 0;
    bool fast_ = false;
    void* ctx_ = nullptr;
};

}  // namespace basefwx::obf
