/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

// AeadContext keeps an AES-256-GCM key schedule alive across records. The
// value of that is only real if it stays byte-compatible with the one-shot
// AesGcmEncryptWithIv/DecryptWithIv pair callers already use, so every
// assertion here is anchored to those functions rather than to a fixture
// this file made up.

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using basefwx::crypto::AeadContext;
using basefwx::crypto::AuthenticationError;
using basefwx::crypto::Bytes;

int failures = 0;

void Check(bool ok, std::string_view what) {
    if (!ok) {
        std::cerr << "FAIL: " << what << '\n';
        ++failures;
    }
}

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

Bytes Pattern(std::size_t length, std::uint8_t seed) {
    Bytes out(length);
    for (std::size_t i = 0; i < length; ++i) {
        out[i] = static_cast<std::uint8_t>((i * 31u + seed) & 0xffu);
    }
    return out;
}

Bytes NonceForSequence(std::uint64_t sequence, std::size_t length) {
    Bytes nonce(length, 0);
    for (std::size_t i = 0; i < 8 && i < length; ++i) {
        nonce[length - 1 - i] =
            static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xffu);
    }
    return nonce;
}

void ExpectMatchesOneShot(AeadContext& ctx,
                          const Bytes& key,
                          const Bytes& nonce,
                          const Bytes& plaintext,
                          const Bytes& aad,
                          std::string_view what) {
    const Bytes expected =
        basefwx::crypto::AesGcmEncryptWithIv(key, nonce, plaintext, aad);
    Bytes sealed(plaintext.size() + AeadContext::OverheadBytes());
    const std::size_t written = ctx.Seal(nonce, plaintext.data(),
                                         plaintext.size(), aad, sealed.data(),
                                         sealed.size());
    Check(written == sealed.size(), std::string(what) + ": sealed length");
    Check(sealed == expected, std::string(what) + ": byte parity with one-shot");

    Bytes opened(plaintext.size());
    const std::size_t produced =
        ctx.Open(nonce, sealed.data(), sealed.size(), aad,
                 opened.data(), opened.size());
    Check(produced == plaintext.size(), std::string(what) + ": opened length");
    Check(opened == plaintext, std::string(what) + ": round trip");

    // The one-shot decrypt must also accept what the context produced.
    const Bytes cross =
        basefwx::crypto::AesGcmDecryptWithIv(key, nonce, sealed, aad);
    Check(cross == plaintext, std::string(what) + ": one-shot opens context output");
}

void TestParityAndRoundTrip() {
    const Bytes key = Pattern(32, 7);
    AeadContext ctx(key);
    Check(ctx.nonce_length() == basefwx::constants::kAeadNonceLen,
          "default nonce length matches the wire constant");

    ExpectMatchesOneShot(ctx, key, NonceForSequence(1, 12), Pattern(64, 1),
                         Pattern(19, 2), "small record");
    ExpectMatchesOneShot(ctx, key, NonceForSequence(2, 12), Bytes{},
                         Pattern(19, 3), "empty plaintext");
    ExpectMatchesOneShot(ctx, key, NonceForSequence(3, 12), Pattern(64, 4),
                         Bytes{}, "empty aad");
    ExpectMatchesOneShot(ctx, key, NonceForSequence(4, 12), Bytes{}, Bytes{},
                         "empty plaintext and aad");
    ExpectMatchesOneShot(ctx, key, NonceForSequence(5, 12),
                         Pattern(65536, 5), Pattern(37, 6), "64 KiB record");
    // Back to a small record after a large one, to prove the reused staging
    // buffer does not leak the previous length into the next result.
    ExpectMatchesOneShot(ctx, key, NonceForSequence(6, 12), Pattern(9, 7),
                         Pattern(3, 8), "small record after large record");
}

void TestManyRecordsUnderOneSchedule() {
    const Bytes key = Pattern(32, 11);
    AeadContext ctx(key);
    const Bytes aad = Pattern(16, 12);
    bool all_ok = true;
    for (std::uint64_t sequence = 1; sequence <= 512; ++sequence) {
        const Bytes nonce = NonceForSequence(sequence, 12);
        const Bytes plaintext =
            Pattern(1 + (sequence % 97), static_cast<std::uint8_t>(sequence));
        Bytes sealed(plaintext.size() + AeadContext::OverheadBytes());
        ctx.Seal(nonce, plaintext.data(), plaintext.size(), aad,
                 sealed.data(), sealed.size());
        if (sealed != basefwx::crypto::AesGcmEncryptWithIv(key, nonce,
                                                           plaintext, aad)) {
            all_ok = false;
            break;
        }
        Bytes opened(plaintext.size());
        ctx.Open(nonce, sealed.data(), sealed.size(), aad, opened.data(),
                 opened.size());
        if (opened != plaintext) {
            all_ok = false;
            break;
        }
    }
    Check(all_ok, "512 consecutive records stay parity-correct");
}

void TestRekey() {
    const Bytes first = Pattern(32, 21);
    const Bytes second = Pattern(32, 22);
    AeadContext ctx(first);
    const Bytes nonce = NonceForSequence(1, 12);
    const Bytes plaintext = Pattern(48, 23);
    const Bytes aad = Pattern(8, 24);

    ExpectMatchesOneShot(ctx, first, nonce, plaintext, aad, "before rekey");
    ctx.Rekey(second);
    // The same nonce is legitimate under a new key, so the repeat guard must
    // not have survived the rekey.
    ExpectMatchesOneShot(ctx, second, nonce, plaintext, aad, "after rekey");

    Check(Throws<std::runtime_error>([&] { ctx.Rekey(Bytes(31, 0)); }),
          "rekey rejects a short key");
}

void TestAuthenticationFailureLeavesOutputUntouched() {
    const Bytes key = Pattern(32, 31);
    AeadContext ctx(key);
    const Bytes nonce = NonceForSequence(1, 12);
    const Bytes plaintext = Pattern(128, 32);
    const Bytes aad = Pattern(11, 33);

    Bytes sealed(plaintext.size() + AeadContext::OverheadBytes());
    ctx.Seal(nonce, plaintext.data(), plaintext.size(), aad, sealed.data(),
             sealed.size());

    const std::uint8_t sentinel = 0xa5;
    const auto expect_untouched = [&](Bytes corrupted, const Bytes& used_aad,
                                      std::string_view what) {
        Bytes out(plaintext.size(), sentinel);
        const bool threw = Throws<AuthenticationError>([&] {
            ctx.Open(nonce, corrupted.data(), corrupted.size(), used_aad,
                     out.data(), out.size());
        });
        Check(threw, std::string(what) + ": throws AuthenticationError");
        Check(out == Bytes(plaintext.size(), sentinel),
              std::string(what) + ": output buffer untouched");
    };

    Bytes flipped_ciphertext = sealed;
    flipped_ciphertext[0] ^= 0x01u;
    expect_untouched(flipped_ciphertext, aad, "flipped ciphertext byte");

    Bytes flipped_tag = sealed;
    flipped_tag[flipped_tag.size() - 1] ^= 0x01u;
    expect_untouched(flipped_tag, aad, "flipped tag byte");

    Bytes wrong_aad = aad;
    wrong_aad[0] ^= 0x01u;
    expect_untouched(sealed, wrong_aad, "wrong aad");

    // A truncated blob is a length error rather than an auth failure, but it
    // must still publish nothing.
    Bytes out(plaintext.size(), sentinel);
    Check(Throws<std::runtime_error>([&] {
              ctx.Open(nonce, sealed.data(), basefwx::constants::kAeadTagLen - 1,
                       aad, out.data(), out.size());
          }),
          "blob shorter than the tag is rejected");
    Check(out == Bytes(plaintext.size(), sentinel),
          "short blob leaves the output buffer untouched");

    // The context must still work after a rejected record.
    ExpectMatchesOneShot(ctx, key, NonceForSequence(2, 12), plaintext, aad,
                         "record after an authentication failure");
}

void TestNonceDiscipline() {
    const Bytes key = Pattern(32, 41);
    AeadContext ctx(key);
    const Bytes nonce = NonceForSequence(1, 12);
    const Bytes plaintext = Pattern(32, 42);
    Bytes sealed(plaintext.size() + AeadContext::OverheadBytes());
    ctx.Seal(nonce, plaintext.data(), plaintext.size(), {}, sealed.data(),
             sealed.size());

    Check(Throws<std::runtime_error>([&] {
              ctx.Seal(nonce, plaintext.data(), plaintext.size(), {},
                       sealed.data(), sealed.size());
          }),
          "consecutive seal under the same nonce is rejected");

    // Opening the same nonce twice is legitimate, so no guard applies there.
    Bytes opened(plaintext.size());
    ctx.Open(nonce, sealed.data(), sealed.size(), {}, opened.data(),
             opened.size());
    ctx.Open(nonce, sealed.data(), sealed.size(), {}, opened.data(),
             opened.size());
    Check(opened == plaintext, "repeated open under one nonce is allowed");

    const Bytes wrong_length = NonceForSequence(2, 13);
    Check(Throws<std::runtime_error>([&] {
              ctx.Seal(wrong_length, plaintext.data(), plaintext.size(), {},
                       sealed.data(), sealed.size());
          }),
          "seal rejects a nonce of the wrong length");
    Check(Throws<std::runtime_error>([&] {
              ctx.Open(wrong_length, sealed.data(), sealed.size(), {},
                       opened.data(), opened.size());
          }),
          "open rejects a nonce of the wrong length");
}

void TestConstructionAndBufferValidation() {
    Check(Throws<std::runtime_error>([] { AeadContext ctx(Bytes(31, 0)); }),
          "31-byte key is rejected");
    Check(Throws<std::runtime_error>([] { AeadContext ctx(Bytes(33, 0)); }),
          "33-byte key is rejected");
    Check(Throws<std::runtime_error>([] { AeadContext ctx(Bytes(32, 0), 0); }),
          "zero-length nonce is rejected");
    Check(Throws<std::runtime_error>([] { AeadContext ctx(Bytes(32, 0), 4); }),
          "4-byte nonce is rejected");

    const Bytes key = Pattern(32, 51);
    AeadContext ctx(key);
    const Bytes nonce = NonceForSequence(1, 12);
    const Bytes plaintext = Pattern(40, 52);
    Bytes too_small(plaintext.size() + AeadContext::OverheadBytes() - 1);
    Check(Throws<std::runtime_error>([&] {
              ctx.Seal(nonce, plaintext.data(), plaintext.size(), {},
                       too_small.data(), too_small.size());
          }),
          "seal rejects an output buffer with no room for the tag");

    Bytes sealed(plaintext.size() + AeadContext::OverheadBytes());
    ctx.Seal(nonce, plaintext.data(), plaintext.size(), {}, sealed.data(),
             sealed.size());
    Bytes short_out(plaintext.size() - 1);
    Check(Throws<std::runtime_error>([&] {
              ctx.Open(NonceForSequence(2, 12), sealed.data(), sealed.size(),
                       {}, short_out.data(), short_out.size());
          }),
          "open rejects an output buffer smaller than the plaintext");
}

void TestNonDefaultNonceLength() {
    const Bytes key = Pattern(32, 61);
    AeadContext ctx(key, 16);
    Check(ctx.nonce_length() == 16, "context reports its nonce length");
    ExpectMatchesOneShot(ctx, key, NonceForSequence(1, 16), Pattern(72, 62),
                         Pattern(5, 63), "16-byte nonce");
}

void TestMoveLeavesAUsableContext() {
    const Bytes key = Pattern(32, 71);
    AeadContext source(key);
    AeadContext moved(std::move(source));
    ExpectMatchesOneShot(moved, key, NonceForSequence(1, 12), Pattern(24, 72),
                         Pattern(4, 73), "moved-to context");
}

}  // namespace

int main() {
    try {
        TestParityAndRoundTrip();
        TestManyRecordsUnderOneSchedule();
        TestRekey();
        TestAuthenticationFailureLeavesOutputUntouched();
        TestNonceDiscipline();
        TestConstructionAndBufferValidation();
        TestNonDefaultNonceLength();
        TestMoveLeavesAUsableContext();
    } catch (const std::exception& error) {
        std::cerr << "FAIL: unexpected exception: " << error.what() << '\n';
        return 1;
    }
    if (failures != 0) {
        std::cerr << failures << " AeadContext check(s) failed\n";
        return 1;
    }
    std::cout << "AeadContext checks passed\n";
    return 0;
}
