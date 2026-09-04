/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

// Two properties that keep a written blob openable and a resolved secret
// unambiguous:
//
//  - ResolvePassword is idempotent. Some entry points resolve at the public
//    boundary and again further in. If resolving twice could yield a
//    different secret, the same input would derive two different keys
//    depending on which path was taken.
//  - fwxAES wrap mode refuses a KDF cost it cannot record. The wrap header
//    stores the KDF label but not its cost, so a blob written with any other
//    cost could never be opened again.

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/fwxaes.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

namespace {

int failures = 0;

void expect(bool condition, std::string_view what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << '\n';
        ++failures;
    }
}

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
    } catch (...) {
        return true;
    }
    return false;
}

std::filesystem::path WriteTemp(std::string_view name,
                                std::string_view contents) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    out.close();
    return path;
}

void TestResolvePasswordIsIdempotent() {
    const std::string literal = basefwx::ResolvePassword("plain-secret");
    expect(literal == "plain-secret", "a bare password stays literal");
    expect(basefwx::ResolvePassword(literal) == literal,
           "resolving a literal again is identity");

    const std::string scheme = basefwx::ResolvePassword("password://hunter2");
    expect(scheme == "hunter2", "password:// yields its literal");
    expect(basefwx::ResolvePassword(scheme) == scheme,
           "a stripped literal does not resolve further");

    const auto file = WriteTemp("basefwx-resolve-literal.txt", "from-a-file");
    const std::string from_file =
        basefwx::ResolvePassword("file://" + file.string());
    expect(from_file == "from-a-file", "file:// yields the file contents");
    expect(basefwx::ResolvePassword(from_file) == from_file,
           "file contents do not resolve further");
    std::filesystem::remove(file);

    // The only inputs where resolving twice could disagree are the ones whose
    // result is itself a reference. Those are refused, not guessed.
    expect(Throws([] {
               (void)basefwx::ResolvePassword("password://file:///etc/passwd");
           }),
           "a password:// value naming a file:// reference is refused");
    expect(Throws([] {
               (void)basefwx::ResolvePassword("password://password://x");
           }),
           "a doubly-schemed password:// value is refused");

    const auto nested =
        WriteTemp("basefwx-resolve-nested.txt", "password://inner");
    expect(Throws([&] {
               (void)basefwx::ResolvePassword("file://" + nested.string());
           }),
           "a password file whose contents are a reference is refused");
    std::filesystem::remove(nested);
}

void TestWrapRefusesUnrecordableKdfCost() {
    const basefwx::fwxaes::Bytes plaintext{'c', 'o', 'v', 'e', 'r'};
    const std::string password = "a-sufficiently-long-password";

    basefwx::fwxaes::Options defaults;
    const basefwx::fwxaes::Bytes blob =
        basefwx::fwxaes::EncryptRaw(plaintext, password, defaults);
    expect(!blob.empty(), "the default wrap cost still encrypts");
    const basefwx::fwxaes::Bytes round_trip =
        basefwx::fwxaes::DecryptRaw(blob, password, false);
    expect(round_trip == plaintext, "the default wrap cost round-trips");

    basefwx::fwxaes::Options custom_pbkdf2;
    custom_pbkdf2.pbkdf2_iters =
        static_cast<std::uint32_t>(basefwx::constants::kUserKdfIterations) + 1;
    expect(Throws([&] {
               (void)basefwx::fwxaes::EncryptRaw(plaintext, password,
                                                 custom_pbkdf2);
           }),
           "wrap mode refuses a PBKDF2 cost it cannot record");

    basefwx::fwxaes::Options custom_argon2;
    custom_argon2.user_kdf.argon2_time_cost =
        basefwx::constants::kArgon2TimeCost + 1;
    expect(Throws([&] {
               (void)basefwx::fwxaes::EncryptRaw(plaintext, password,
                                                 custom_argon2);
           }),
           "wrap mode refuses an Argon2 time cost it cannot record");
}

}  // namespace

int main() {
    TestResolvePasswordIsIdempotent();
    TestWrapRefusesUnrecordableKdfCost();
    if (failures == 0) {
        std::cout << "secret_resolution_policy_test: ok\n";
    }
    return failures == 0 ? 0 : 1;
}
