/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/basefwx.hpp"
#include "basefwx/imagecipher.hpp"

namespace basefwx {

std::string Jmge(const std::string& path,
                 const std::string& password,
                 const std::string& output,
                 bool keep_meta,
                 bool keep_input,
                 bool archive_original,
                 bool use_master) {
    std::string resolved = ResolvePassword(password);
    RequireStrongPasswordForEncryption(resolved, "jMG");
    return basefwx::imagecipher::EncryptMedia(
        path,
        resolved,
        output,
        keep_meta,
        keep_input,
        archive_original,
        use_master
    );
}

std::string Jmgd(const std::string& path,
                 const std::string& password,
                 const std::string& output,
                 bool use_master) {
    return basefwx::imagecipher::DecryptMedia(
        path, ResolvePassword(password), output, use_master);
}

}  // namespace basefwx
