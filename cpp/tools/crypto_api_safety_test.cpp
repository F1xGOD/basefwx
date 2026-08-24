/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace {

template <typename Exception, typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
    } catch (const Exception&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

int Fail(std::string_view message) {
    std::cerr << "FAIL: " << message << '\n';
    return 1;
}

}  // namespace

int main() {
    using basefwx::crypto::Bytes;

    const Bytes key(32, 0x2a);
    const Bytes iv(basefwx::constants::kAeadNonceLen, 0x19);
    const Bytes aad{0x61, 0x61, 0x64};
    const Bytes plaintext{0x70, 0x6c, 0x61, 0x69, 0x6e};
    Bytes ciphertext = basefwx::crypto::AesGcmEncryptWithIv(
        key, iv, plaintext, aad);

    Bytes restored(plaintext.size(), 0);
    const std::size_t written = basefwx::crypto::AesGcmDecryptWithIvInto(
        key, iv, ciphertext.data(), ciphertext.size(), aad,
        restored.data(), restored.size());
    if (written != plaintext.size() || restored != plaintext) {
        return Fail("valid decrypt-into did not round-trip");
    }

    Bytes framed{0xff};
    framed.insert(framed.end(), ciphertext.begin(), ciphertext.end());
    const Bytes owned = basefwx::crypto::AesGcmDecryptWithIvOwned(
        key, iv, framed.data() + 1, ciphertext.size(), aad);
    if (owned != plaintext) {
        return Fail("owned ciphertext-slice decrypt did not round-trip");
    }

    const Bytes empty_ciphertext = basefwx::crypto::AesGcmEncryptWithIv(
        key, iv, {}, aad);
    if (!basefwx::crypto::AesGcmDecryptWithIv(
             key, iv, empty_ciphertext, aad).empty()) {
        return Fail("empty plaintext did not round-trip");
    }

    ciphertext.back() ^= 0x01;
    Bytes sentinel(plaintext.size(), 0xa5);
    const Bytes before = sentinel;
    if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
            basefwx::crypto::AesGcmDecryptWithIvInto(
                key, iv, ciphertext.data(), ciphertext.size(), aad,
                sentinel.data(), sentinel.size());
        })) {
        return Fail("tampered ciphertext was not rejected");
    }
    if (sentinel != before) {
        return Fail("authentication failure modified caller output");
    }

    std::uint8_t byte = 0;
    if (!Throws<std::invalid_argument>([&]() {
            basefwx::crypto::AesGcmEncryptWithIvInto(
                key, iv, nullptr, 1, aad, &byte,
                basefwx::constants::kAeadTagLen + 1);
        })) {
        return Fail("null plaintext buffer was not rejected");
    }
    if (!Throws<std::length_error>([&]() {
            basefwx::crypto::AesGcmEncryptWithIvInto(
                key, iv, &byte,
                static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1,
                aad, &byte, std::numeric_limits<std::size_t>::max());
        })) {
        return Fail("EVP int-length overflow was not rejected");
    }
    if (!Throws<std::length_error>([&]() {
            basefwx::crypto::AesGcmEncryptWithIvInto(
                key, iv, &byte, std::numeric_limits<std::size_t>::max(),
                aad, &byte, std::numeric_limits<std::size_t>::max());
        })) {
        return Fail("output size overflow was not rejected");
    }
    if (!Throws<std::invalid_argument>([&]() {
            basefwx::crypto::AesGcmDecryptWithIvInto(
                key, iv, nullptr, basefwx::constants::kAeadTagLen,
                aad, nullptr, 0);
        })) {
        return Fail("null ciphertext buffer was not rejected");
    }
    if (!Throws<std::length_error>([&]() {
            basefwx::crypto::AesGcmDecryptWithIvInto(
                key, iv, &byte,
                static_cast<std::size_t>(std::numeric_limits<int>::max())
                    + basefwx::constants::kAeadTagLen + 1,
                aad, &byte, std::numeric_limits<std::size_t>::max());
        })) {
        return Fail("ciphertext EVP int-length overflow was not rejected");
    }

    return 0;
}
