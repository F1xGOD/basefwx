#pragma once

#include "basefwx/constants.hpp"
#include "basefwx/pb512.hpp"

#include <cstddef>
#include <string>

namespace basefwx::filecodec {

struct FileOptions {
    bool strip_metadata = false;
    bool use_master = true;
    bool enable_aead = true;
    bool enable_obfuscation = true;
    std::size_t stream_threshold = basefwx::constants::kStreamThreshold;
    std::size_t stream_chunk_size = basefwx::constants::kStreamChunkSize;
};

std::string B512EncodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options = {},
                           const basefwx::pb512::KdfOptions& kdf = {});

std::string B512DecodeFile(const std::string& path,
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
