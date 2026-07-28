/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/secure_temp.hpp"

#include "basefwx/crypto.hpp"

#include <cerrno>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <accctrl.h>
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace basefwx::temp {
namespace {

#if defined(_WIN32)
class ScopedWinHandle {
public:
    explicit ScopedWinHandle(HANDLE handle) noexcept
        : handle_(handle) {}

    ~ScopedWinHandle() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;

private:
    HANDLE handle_;
};

class ScopedLocalMemory {
public:
    explicit ScopedLocalMemory(HLOCAL memory = nullptr) noexcept
        : memory_(memory) {}

    ~ScopedLocalMemory() {
        if (memory_ != nullptr) {
            LocalFree(memory_);
        }
    }

    ScopedLocalMemory(const ScopedLocalMemory&) = delete;
    ScopedLocalMemory& operator=(const ScopedLocalMemory&) = delete;

private:
    HLOCAL memory_;
};

[[noreturn]] void ThrowWindowsError(
    DWORD error,
    const char* message) {
    throw std::system_error(
        static_cast<int>(error),
        std::system_category(),
        message);
}
#endif

std::string HexToken() {
    const auto random = basefwx::crypto::RandomBytes(16);
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(random.size() * 2);
    for (const std::uint8_t byte : random) {
        out.push_back(digits[(byte >> 4) & 0x0F]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

bool CreateExclusivePrivate(const std::filesystem::path& path) {
#if defined(_WIN32)
    const int fd = _wopen(
        path.c_str(),
        _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY | _O_NOINHERIT,
        _S_IREAD | _S_IWRITE);
    if (fd >= 0) {
        _close(fd);
        return true;
    }
#else
    int flags = O_CREAT | O_EXCL | O_RDWR;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int fd = ::open(path.c_str(), flags, 0600);
    if (fd >= 0) {
        ::close(fd);
        return true;
    }
#endif
    if (errno == EEXIST || errno == ELOOP) {
        return false;
    }
    throw std::system_error(
        errno,
        std::generic_category(),
        "Failed to create private sibling temp file");
}

bool CreatePrivateDirectory(const std::filesystem::path& path) {
#if defined(_WIN32)
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &raw_token)) {
        ThrowWindowsError(
            GetLastError(),
            "Failed to open process token for private temp directory");
    }
    ScopedWinHandle token(raw_token);

    DWORD token_user_size = 0;
    if (GetTokenInformation(
            raw_token,
            TokenUser,
            nullptr,
            0,
            &token_user_size)
        || GetLastError() != ERROR_INSUFFICIENT_BUFFER
        || token_user_size == 0) {
        ThrowWindowsError(
            GetLastError(),
            "Failed to size current user SID for private temp directory");
    }
    std::vector<unsigned char> token_user_buffer(token_user_size);
    if (!GetTokenInformation(
            raw_token,
            TokenUser,
            token_user_buffer.data(),
            token_user_size,
            &token_user_size)) {
        ThrowWindowsError(
            GetLastError(),
            "Failed to read current user SID for private temp directory");
    }
    auto* token_user =
        reinterpret_cast<TOKEN_USER*>(token_user_buffer.data());

    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = FILE_ALL_ACCESS;
    access.grfAccessMode = SET_ACCESS;
    access.grfInheritance =
        SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName =
        static_cast<LPWSTR>(token_user->User.Sid);

    PACL raw_acl = nullptr;
    const DWORD acl_error =
        SetEntriesInAclW(1, &access, nullptr, &raw_acl);
    if (acl_error != ERROR_SUCCESS) {
        ThrowWindowsError(
            acl_error,
            "Failed to create owner-only ACL for private temp directory");
    }
    ScopedLocalMemory acl(raw_acl);

    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(
            &descriptor,
            SECURITY_DESCRIPTOR_REVISION)
        || !SetSecurityDescriptorDacl(
            &descriptor,
            TRUE,
            raw_acl,
            FALSE)
        || !SetSecurityDescriptorControl(
            &descriptor,
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED)) {
        ThrowWindowsError(
            GetLastError(),
            "Failed to protect private temp directory ACL");
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = &descriptor;
    attributes.bInheritHandle = FALSE;

    if (CreateDirectoryW(path.c_str(), &attributes)) {
        return true;
    }
    const DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS
        || error == ERROR_FILE_EXISTS) {
        return false;
    }
    throw std::system_error(
        static_cast<int>(error),
        std::system_category(),
        "Failed to create private sibling temp directory");
#else
    if (::mkdir(path.c_str(), 0700) == 0) {
        return true;
    }
    if (errno == EEXIST || errno == ELOOP) {
        return false;
    }
    throw std::system_error(
        errno,
        std::generic_category(),
        "Failed to create private sibling temp directory");
#endif
}

}  // namespace

SecureTempPath SecureTempPath::CreateSibling(
    const std::filesystem::path& target,
    std::string_view purpose) {
    std::filesystem::path parent = target.parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    const std::string base = target.filename().string();
    for (int attempt = 0; attempt < 128; ++attempt) {
        const std::filesystem::path directory =
            parent
            / ("." + base + ".basefwx-" + std::string(purpose)
               + "-" + HexToken() + ".tmp.d");
        if (!CreatePrivateDirectory(directory)) {
            continue;
        }
        const std::filesystem::path candidate =
            directory / "payload.tmp";
        try {
            if (CreateExclusivePrivate(candidate)) {
                return SecureTempPath(directory, candidate);
            }
        } catch (...) {
            std::error_code cleanup_error;
            std::filesystem::remove_all(
                directory, cleanup_error);
            throw;
        }
        std::error_code cleanup_error;
        std::filesystem::remove_all(directory, cleanup_error);
    }
    throw std::runtime_error(
        "Failed to allocate unique private sibling temp file");
}

SecureTempPath::SecureTempPath(SecureTempPath&& other) noexcept
    : directory_(std::move(other.directory_)),
      path_(std::move(other.path_)),
      active_(other.active_) {
    other.active_ = false;
}

SecureTempPath& SecureTempPath::operator=(
    SecureTempPath&& other) noexcept {
    if (this != &other) {
        Cleanup();
        directory_ = std::move(other.directory_);
        path_ = std::move(other.path_);
        active_ = other.active_;
        other.active_ = false;
    }
    return *this;
}

SecureTempPath::~SecureTempPath() {
    Cleanup();
}

void SecureTempPath::Cleanup() noexcept {
    if (!active_ || path_.empty()) {
        return;
    }
    std::error_code error;
    std::filesystem::remove(path_, error);
    error.clear();
    std::filesystem::remove(directory_, error);
    active_ = false;
}

void SecureTempPath::CommitReplace(
    const std::filesystem::path& target) {
#if defined(_WIN32)
    if (!MoveFileExW(
            path_.c_str(),
            target.c_str(),
            MOVEFILE_REPLACE_EXISTING
                | MOVEFILE_WRITE_THROUGH)) {
        throw std::system_error(
            static_cast<int>(GetLastError()),
            std::system_category(),
            "Failed to publish authenticated temp file");
    }
#else
    std::filesystem::rename(path_, target);
#endif
    std::error_code cleanup_error;
    std::filesystem::remove(directory_, cleanup_error);
    active_ = false;
}

}  // namespace basefwx::temp
