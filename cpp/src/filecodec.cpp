/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/filecodec.hpp"

#include "filecodec_internal.hpp"

namespace basefwx::filecodec {

std::string B512EncodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf) {
    return internal::B512EncodeFile(path, password, options, kdf);
}

std::string B512DecodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf) {
    return internal::B512DecodeFile(path, password, options, kdf);
}

std::vector<std::uint8_t> B512EncodeBytes(const std::vector<std::uint8_t>& data,
                                          const std::string& extension,
                                          const std::string& password,
                                          const FileOptions& options,
                                          const basefwx::pb512::KdfOptions& kdf) {
    return internal::B512EncodeBytes(data, extension, password, options, kdf);
}

DecodedBytes B512DecodeBytes(const std::vector<std::uint8_t>& blob,
                             const std::string& password,
                             const FileOptions& options,
                             const basefwx::pb512::KdfOptions& kdf) {
    return internal::B512DecodeBytes(blob, password, options, kdf);
}

std::vector<std::uint8_t> Pb512EncodeBytes(const std::vector<std::uint8_t>& data,
                                           const std::string& extension,
                                           const std::string& password,
                                           const FileOptions& options,
                                           const basefwx::pb512::KdfOptions& kdf) {
    return internal::Pb512EncodeBytes(data, extension, password, options, kdf);
}

DecodedBytes Pb512DecodeBytes(const std::vector<std::uint8_t>& blob,
                              const std::string& password,
                              const FileOptions& options,
                              const basefwx::pb512::KdfOptions& kdf) {
    return internal::Pb512DecodeBytes(blob, password, options, kdf);
}

std::string Pb512EncodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf) {
    return internal::Pb512EncodeFile(path, password, options, kdf);
}

std::string Pb512DecodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf) {
    return internal::Pb512DecodeFile(path, password, options, kdf);
}

}  // namespace basefwx::filecodec
