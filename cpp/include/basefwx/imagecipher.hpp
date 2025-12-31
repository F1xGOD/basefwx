#pragma once

#include <string>

namespace basefwx::imagecipher {

std::string EncryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output = {},
                            bool include_trailer = true);

std::string DecryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output = {});

std::string EncryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output = {},
                         bool keep_meta = false,
                         bool keep_input = false);

std::string DecryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output = {});

}  // namespace basefwx::imagecipher
