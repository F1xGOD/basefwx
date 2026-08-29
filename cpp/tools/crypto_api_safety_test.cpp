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

basefwx::crypto::Bytes FromHex(std::string_view hex) {
    // A silently truncated fixture would weaken every assertion built on it,
    // so an odd-length literal is a hard error rather than a dropped nibble.
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("odd-length hex fixture");
    }
    basefwx::crypto::Bytes out;
    out.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("bad hex digit in test fixture");
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(
            (nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
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

    // --- ChaCha20-Poly1305 (RFC 8439) explicit-nonce one-shot ---

    // RFC 8439 section 2.8.2 known-answer vector. This pins the primitive to
    // the standard IETF construction rather than merely proving that our own
    // encrypt and decrypt agree with each other.
    {
        const Bytes kat_key = FromHex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        const Bytes kat_iv = FromHex("070000004041424344454647");
        const Bytes kat_aad = FromHex("50515253c0c1c2c3c4c5c6c7");
        const std::string_view kat_text =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        const Bytes kat_plaintext(kat_text.begin(), kat_text.end());
        const Bytes kat_expected = FromHex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
            "1ae10b594f09e26a7e902ecbd0600691");

        const Bytes produced = basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
            kat_key, kat_iv, kat_plaintext, kat_aad);
        if (produced != kat_expected) {
            return Fail("RFC 8439 2.8.2 encrypt vector mismatch");
        }
        const Bytes recovered =
            basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                kat_key, kat_iv, kat_expected.data(), kat_expected.size(),
                kat_aad);
        if (recovered != kat_plaintext) {
            return Fail("RFC 8439 2.8.2 decrypt vector mismatch");
        }
    }

    // Empty-AAD byte identity. YUME's at-rest relay-history helper calls
    // ChaCha20-Poly1305 without ever issuing an AAD update; RFC 8439 absorbs
    // zero AAD bytes with len(AAD)=0, so an explicitly empty AAD must
    // reproduce those records exactly. This fixture was generated by an
    // independent implementation and is the compatibility gate for a future
    // migration of that caller -- a round trip against ourselves would not
    // prove it.
    const Bytes cc_key(32, 0x2a);
    const Bytes cc_iv(basefwx::constants::kAeadNonceLen, 0x19);
    {
        const std::string_view record_text = "yume relay history record";
        const Bytes record(record_text.begin(), record_text.end());
        const Bytes expected_blob = FromHex(
            "7d2f5037e54628bb740a597621203cc4f639a2ce0584401f9ab315dd0f"
            "c4c635c1589234ff3c5b4f02");
        if (basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
                cc_key, cc_iv, record, {}) != expected_blob) {
            return Fail("empty-AAD ciphertext is not byte-identical");
        }
        if (basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                cc_key, cc_iv, expected_blob.data(), expected_blob.size(),
                {}) != record) {
            return Fail("empty-AAD fixture did not decrypt");
        }
        // A tag-only blob is the empty-plaintext boundary of that same shape.
        const Bytes empty_blob = FromHex("fed2368d2fbef85955334eb4d1425419");
        if (basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
                cc_key, cc_iv, {}, {}) != empty_blob) {
            return Fail("empty plaintext with empty AAD is not byte-identical");
        }
        if (!basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                 cc_key, cc_iv, empty_blob.data(), empty_blob.size(),
                 {}).empty()) {
            return Fail("tag-only blob did not decrypt to empty plaintext");
        }
    }

    const Bytes cc_plain{0x70, 0x6c, 0x61, 0x69, 0x6e};
    const Bytes cc_blob = basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
        cc_key, cc_iv, cc_plain, aad);
    if (cc_blob.size() != cc_plain.size() + basefwx::constants::kAeadTagLen) {
        return Fail("ChaCha20-Poly1305 blob is not ciphertext||tag sized");
    }

    // Decrypting a slice proves the API never assumes it owns a whole buffer.
    Bytes cc_framed{0xff};
    cc_framed.insert(cc_framed.end(), cc_blob.begin(), cc_blob.end());
    if (basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
            cc_key, cc_iv, cc_framed.data() + 1, cc_blob.size(), aad)
        != cc_plain) {
        return Fail("ChaCha20-Poly1305 slice decrypt did not round-trip");
    }

    // Every authentication input must be bound: ciphertext, tag, AAD, key,
    // and nonce each independently reject.
    {
        Bytes tampered_ct = cc_blob;
        tampered_ct.front() ^= 0x01;
        if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, cc_iv, tampered_ct.data(), tampered_ct.size(),
                    aad);
            })) {
            return Fail("tampered ChaCha20-Poly1305 ciphertext was accepted");
        }

        Bytes tampered_tag = cc_blob;
        tampered_tag.back() ^= 0x01;
        if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, cc_iv, tampered_tag.data(), tampered_tag.size(),
                    aad);
            })) {
            return Fail("tampered ChaCha20-Poly1305 tag was accepted");
        }

        Bytes tampered_aad = aad;
        tampered_aad.front() ^= 0x01;
        if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, cc_iv, cc_blob.data(), cc_blob.size(),
                    tampered_aad);
            })) {
            return Fail("tampered ChaCha20-Poly1305 AAD was accepted");
        }
        if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, cc_iv, cc_blob.data(), cc_blob.size(), {});
            })) {
            return Fail("dropping the AAD entirely was accepted");
        }

        Bytes wrong_key = cc_key;
        wrong_key.front() ^= 0x01;
        if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    wrong_key, cc_iv, cc_blob.data(), cc_blob.size(), aad);
            })) {
            return Fail("wrong ChaCha20-Poly1305 key was accepted");
        }

        Bytes wrong_iv = cc_iv;
        wrong_iv.front() ^= 0x01;
        if (!Throws<basefwx::crypto::AuthenticationError>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, wrong_iv, cc_blob.data(), cc_blob.size(), aad);
            })) {
            return Fail("wrong ChaCha20-Poly1305 nonce was accepted");
        }
    }

    // Unlike AES-GCM, this construction has exactly one legal nonce size, so
    // a merely non-empty IV must not be admitted.
    for (std::size_t bad_iv_len : {std::size_t{0}, std::size_t{8},
                                   std::size_t{11}, std::size_t{13}}) {
        const Bytes bad_iv(bad_iv_len, 0x19);
        if (!Throws<std::runtime_error>([&]() {
                basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
                    cc_key, bad_iv, cc_plain, aad);
            })) {
            return Fail("encrypt accepted a non-12-byte ChaCha nonce");
        }
        if (!Throws<std::runtime_error>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, bad_iv, cc_blob.data(), cc_blob.size(), aad);
            })) {
            return Fail("decrypt accepted a non-12-byte ChaCha nonce");
        }
    }

    for (std::size_t bad_key_len : {std::size_t{0}, std::size_t{16},
                                    std::size_t{31}, std::size_t{33}}) {
        const Bytes bad_key(bad_key_len, 0x2a);
        if (!Throws<std::runtime_error>([&]() {
                basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
                    bad_key, cc_iv, cc_plain, aad);
            })) {
            return Fail("encrypt accepted a non-32-byte ChaCha key");
        }
        if (!Throws<std::runtime_error>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    bad_key, cc_iv, cc_blob.data(), cc_blob.size(), aad);
            })) {
            return Fail("decrypt accepted a non-32-byte ChaCha key");
        }
    }

    // A blob shorter than the tag is a structural error, not a forgery, so it
    // must report as such rather than as AuthenticationError.
    for (std::size_t short_len = 0;
         short_len < basefwx::constants::kAeadTagLen; ++short_len) {
        if (!Throws<std::runtime_error>([&]() {
                basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                    cc_key, cc_iv, cc_blob.data(), short_len, aad);
            })) {
            return Fail("under-length ChaCha20-Poly1305 blob was accepted");
        }
    }
    if (Throws<basefwx::crypto::AuthenticationError>([&]() {
            basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                cc_key, cc_iv, cc_blob.data(), 0, aad);
        })) {
        return Fail("short blob reported as an authentication failure");
    }

    if (!Throws<std::invalid_argument>([&]() {
            basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                cc_key, cc_iv, nullptr, basefwx::constants::kAeadTagLen + 1,
                aad);
        })) {
        return Fail("null ChaCha20-Poly1305 blob was not rejected");
    }
    if (!Throws<std::length_error>([&]() {
            basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                cc_key, cc_iv, &byte,
                static_cast<std::size_t>(std::numeric_limits<int>::max())
                    + basefwx::constants::kAeadTagLen + 1,
                aad);
        })) {
        return Fail("ChaCha20-Poly1305 int-length overflow was not rejected");
    }

    // Output-length arithmetic across block boundaries. The encrypt path
    // accumulates offsets in size_t and bounds each advance against the
    // output buffer; this sweep exercises that logic either side of the
    // 64-byte ChaCha block and the 16-byte tag. The INT_MAX overflow edge
    // itself is deliberately NOT tested here -- reaching it needs a ~2 GiB
    // plaintext plus its ciphertext buffer, so the code is instead written
    // so the overflow cannot be expressed.
    for (std::size_t len : {std::size_t{0}, std::size_t{1}, std::size_t{15},
                            std::size_t{16}, std::size_t{17}, std::size_t{63},
                            std::size_t{64}, std::size_t{65},
                            std::size_t{4096}}) {
        const Bytes sweep_plain(len, 0x5c);
        const Bytes sweep_blob = basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
            cc_key, cc_iv, sweep_plain, aad);
        if (sweep_blob.size() != len + basefwx::constants::kAeadTagLen) {
            return Fail("ChaCha20-Poly1305 blob size is wrong for some length");
        }
        if (basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
                cc_key, cc_iv, sweep_blob.data(), sweep_blob.size(), aad)
            != sweep_plain) {
            return Fail("ChaCha20-Poly1305 length sweep did not round-trip");
        }
    }

    // The fixtures above are only as good as the decoder that reads them.
    if (!Throws<std::invalid_argument>([&]() { FromHex("abc"); })) {
        return Fail("odd-length hex fixture was silently truncated");
    }
    if (!Throws<std::invalid_argument>([&]() { FromHex("zz"); })) {
        return Fail("invalid hex digit was accepted");
    }

    return 0;
}
