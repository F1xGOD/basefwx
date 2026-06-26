/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include "basefwx/filecodec.hpp"

namespace basefwx::filecodec::internal {

std::string B512EncodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf);

std::string B512DecodeFile(const std::string& path,
                           const std::string& password,
                           const FileOptions& options,
                           const basefwx::pb512::KdfOptions& kdf);

std::vector<std::uint8_t> B512EncodeBytes(const std::vector<std::uint8_t>& data,
                                          const std::string& extension,
                                          const std::string& password,
                                          const FileOptions& options,
                                          const basefwx::pb512::KdfOptions& kdf);

DecodedBytes B512DecodeBytes(const std::vector<std::uint8_t>& blob,
                             const std::string& password,
                             const FileOptions& options,
                             const basefwx::pb512::KdfOptions& kdf);

std::vector<std::uint8_t> Pb512EncodeBytes(const std::vector<std::uint8_t>& data,
                                           const std::string& extension,
                                           const std::string& password,
                                           const FileOptions& options,
                                           const basefwx::pb512::KdfOptions& kdf);

DecodedBytes Pb512DecodeBytes(const std::vector<std::uint8_t>& blob,
                              const std::string& password,
                              const FileOptions& options,
                              const basefwx::pb512::KdfOptions& kdf);

std::string Pb512EncodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf);

std::string Pb512DecodeFile(const std::string& path,
                            const std::string& password,
                            const FileOptions& options,
                            const basefwx::pb512::KdfOptions& kdf);

}  // namespace basefwx::filecodec::internal
