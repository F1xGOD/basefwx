/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <utility>
#include <string_view>

namespace basefwx::temp {

class SecureTempPath {
public:
    static SecureTempPath CreateSibling(
        const std::filesystem::path& target,
        std::string_view purpose);

    SecureTempPath(const SecureTempPath&) = delete;
    SecureTempPath& operator=(const SecureTempPath&) = delete;
    SecureTempPath(SecureTempPath&& other) noexcept;
    SecureTempPath& operator=(SecureTempPath&& other) noexcept;
    ~SecureTempPath();

    const std::filesystem::path& path() const noexcept {
        return path_;
    }

    void CommitReplace(const std::filesystem::path& target);

private:
    SecureTempPath(
        std::filesystem::path directory,
        std::filesystem::path path)
        : directory_(std::move(directory)),
          path_(std::move(path)) {}

    void Cleanup() noexcept;

    std::filesystem::path directory_;
    std::filesystem::path path_;
    bool active_ = true;
};

}  // namespace basefwx::temp
