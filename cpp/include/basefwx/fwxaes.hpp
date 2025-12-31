#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace basefwx::fwxaes {

using Bytes = std::vector<std::uint8_t>;

struct Options {
    std::uint32_t pbkdf2_iters = 200000;
    std::uint8_t salt_len = 16;
    std::uint8_t iv_len = 12;
};

struct NormalizeOptions {
    bool enabled = false;
    std::size_t threshold = 8 * 1024;
    std::string cover_phrase = "low taper fade";
};

struct PackOptions {
    bool compress = false;
};

Bytes EncryptRaw(const Bytes& plaintext, const std::string& password, const Options& options = {});
Bytes DecryptRaw(const Bytes& blob, const std::string& password);

std::string NormalizeWrap(const Bytes& blob, const std::string& cover_phrase = "low taper fade");
Bytes NormalizeUnwrap(const std::string& text);

void EncryptFile(const std::string& path_in,
                 const std::string& path_out,
                 const std::string& password,
                 const Options& options = {},
                 const NormalizeOptions& normalize = {},
                 const PackOptions& pack = {},
                 bool keep_input = false);

void DecryptFile(const std::string& path_in,
                 const std::string& path_out,
                 const std::string& password);

}  // namespace basefwx::fwxaes
