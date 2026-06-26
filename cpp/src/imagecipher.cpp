/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/imagecipher.hpp"

#include "imagecipher_internal.hpp"

namespace basefwx::imagecipher {

std::string EncryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool include_trailer,
                            bool archive_original,
                            bool use_master) {
    return internal::EncryptImageInv(path, password, output, include_trailer, archive_original, use_master);
}

std::string DecryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output,
                            bool use_master) {
    return internal::DecryptImageInv(path, password, output, use_master);
}

std::string EncryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool keep_meta,
                         bool keep_input,
                         bool archive_original,
                         bool use_master) {
    return internal::EncryptMedia(path, password, output, keep_meta, keep_input, archive_original, use_master);
}

std::string DecryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool use_master) {
    return internal::DecryptMedia(path, password, output, use_master);
}

}  // namespace basefwx::imagecipher
