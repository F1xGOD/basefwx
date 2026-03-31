#pragma once

#include "basefwx/archive.hpp"

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include "basefwx/pb512.hpp"

namespace basefwx::fwxaes {

using Bytes = std::vector<std::uint8_t>;

struct Options {
    std::uint32_t pbkdf2_iters = static_cast<std::uint32_t>(constants::kUserKdfIterations);
    std::uint8_t salt_len = 16;
    std::uint8_t iv_len = 12;
    bool use_master = false;
    bool force_legacy_pbkdf2 = false;
    basefwx::pb512::KdfOptions user_kdf{};
};

struct NormalizeOptions {
    bool enabled = false;
    std::size_t threshold = 8 * 1024;
    std::string cover_phrase = "low taper fade";
};

struct PackOptions {
    bool compress = false;
    basefwx::archive::CompressionPreset compression = basefwx::archive::CompressionPreset::Auto;
};

Bytes EncryptRaw(const Bytes& plaintext, const std::string& password, const Options& options = {});
Bytes DecryptRaw(const Bytes& blob, const std::string& password, bool use_master = false);
std::uint64_t EncryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            const Options& options = {});
std::uint64_t DecryptStream(std::istream& source,
                            std::ostream& dest,
                            const std::string& password,
                            bool use_master = false);

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
                 const std::string& password,
                 bool use_master = false);

}  // namespace basefwx::fwxaes
