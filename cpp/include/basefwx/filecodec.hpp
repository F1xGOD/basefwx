#pragma once

#include "basefwx/constants.hpp"
#include "basefwx/pb512.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace basefwx::filecodec {

struct FileOptions {
    bool strip_metadata = false;
    bool use_master = true;
    bool enable_aead = true;
    bool enable_obfuscation = true;
    bool compress = false;
    bool keep_input = false;
    std::size_t stream_threshold = basefwx::constants::kStreamThreshold;
    std::size_t stream_chunk_size = basefwx::constants::kStreamChunkSize;
};

struct DecodedBytes {
    std::vector<std::uint8_t> data;
    std::string extension;
};

std::string B512EncodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options = {},
                           const basefwx::pb512::KdfOptions& kdf = {});

std::string B512DecodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options = {},
                           const basefwx::pb512::KdfOptions& kdf = {});

std::vector<std::uint8_t> B512EncodeBytes(const std::vector<std::uint8_t>& data,
                                          const std::string& extension,
                                          const std::string& password,
                                          const FileOptions& options = {},
                                          const basefwx::pb512::KdfOptions& kdf = {});

DecodedBytes B512DecodeBytes(const std::vector<std::uint8_t>& blob,
                             const std::string& password,
                             const FileOptions& options = {},
                             const basefwx::pb512::KdfOptions& kdf = {});

std::vector<std::uint8_t> Pb512EncodeBytes(const std::vector<std::uint8_t>& data,
                                           const std::string& extension,
                                           const std::string& password,
                                           const FileOptions& options = {},
                                           const basefwx::pb512::KdfOptions& kdf = {});

DecodedBytes Pb512DecodeBytes(const std::vector<std::uint8_t>& blob,
                              const std::string& password,
                              const FileOptions& options = {},
                              const basefwx::pb512::KdfOptions& kdf = {});

std::string Pb512EncodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options = {},
                            const basefwx::pb512::KdfOptions& kdf = {});

std::string Pb512DecodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options = {},
                            const basefwx::pb512::KdfOptions& kdf = {});


}  // namespace basefwx::filecodec
