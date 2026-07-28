/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 *
 * Emits randomized vector snapshots for multi-runtime parity tests.
 * Usage: protocol_kat_gen > testdata/protocol_kats/vectors.json
 */

#include "basefwx/crypto.hpp"
#include "basefwx/pq.hpp"
#include "basefwx/x25519.hpp"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string Hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t b : bytes) {
        out << std::setw(2) << static_cast<unsigned>(b);
    }
    return out.str();
}

std::vector<std::uint8_t> FromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("odd hex length");
    }
    std::vector<std::uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

void EmitString(const char* key, const std::string& value, bool trailing_comma) {
    std::cout << "    \"" << key << "\": \"" << value << "\""
              << (trailing_comma ? ",\n" : "\n");
}

}  // namespace

int main() {
    try {
        std::cout << "{\n";
        std::cout << "  \"comment\": \"C++/liboqs/OpenSSL generated KATs for BaseFWX multi-runtime parity. Do not hand-edit outputs.\",\n";
        std::cout << "  \"generator\": \"cpp/tools/protocol_kat_gen.cpp\",\n";

        // --- HKDF salted ---
        {
            auto ikm = FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            auto salt = FromHex("000102030405060708090a0b0c");
            std::string info_hex = "f0f1f2f3f4f5f6f7f8f9";
            auto info = FromHex(info_hex);
            auto out = basefwx::crypto::HkdfSha256(
                ikm, salt, std::string(reinterpret_cast<const char*>(info.data()), info.size()), 42);
            std::cout << "  \"hkdf_sha256_salted\": {\n";
            EmitString("ikm_hex", Hex(ikm), true);
            EmitString("salt_hex", Hex(salt), true);
            EmitString("info_hex", info_hex, true);
            std::cout << "    \"length\": 42,\n";
            EmitString("okm_hex", Hex(out), false);
            std::cout << "  },\n";
        }

        // --- HKDF empty salt (matches 3-arg overload / Java zero-salt extract) ---
        {
            auto ikm = FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            const std::string info = "basefwx.kat.v1";
            auto out = basefwx::crypto::HkdfSha256(ikm, {}, info, 32);
            std::cout << "  \"hkdf_sha256_empty_salt\": {\n";
            EmitString("ikm_hex", Hex(ikm), true);
            EmitString("salt_hex", "", true);
            EmitString("info_utf8", info, true);
            std::cout << "    \"length\": 32,\n";
            EmitString("okm_hex", Hex(out), false);
            std::cout << "  },\n";
        }

        // --- X25519 ---
        {
            auto alice = basefwx::x25519::GenerateKeyPair();
            auto bob = basefwx::x25519::GenerateKeyPair();
            auto shared_a = basefwx::x25519::DeriveSharedSecret(alice.private_key, bob.public_key);
            auto shared_b = basefwx::x25519::DeriveSharedSecret(bob.private_key, alice.public_key);
            if (shared_a != shared_b) {
                throw std::runtime_error("X25519 shared secret mismatch");
            }
            std::cout << "  \"x25519\": {\n";
            EmitString("alice_private_hex", Hex(alice.private_key), true);
            EmitString("alice_public_hex", Hex(alice.public_key), true);
            EmitString("bob_private_hex", Hex(bob.private_key), true);
            EmitString("bob_public_hex", Hex(bob.public_key), true);
            EmitString("shared_hex", Hex(shared_a), true);
            std::cout << "    \"all_zero_shared_must_reject\": true\n";
            std::cout << "  },\n";
            basefwx::crypto::SecureClear(shared_a);
            basefwx::crypto::SecureClear(shared_b);
        }

        // --- ML-KEM ---
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
        auto emit_kem = [](const char* section, basefwx::pq::KemAlgorithm alg) {
            auto kp = basefwx::pq::GenerateKeyPair(alg);
            auto enc = basefwx::pq::KemEncrypt(kp.public_key);
            auto shared2 = basefwx::pq::KemDecrypt(kp.private_key, enc.ciphertext);
            if (shared2 != enc.shared) {
                throw std::runtime_error(std::string(section) + " decaps mismatch");
            }
            std::cout << "  \"" << section << "\": {\n";
            EmitString("algorithm", std::string(basefwx::pq::KemAlgorithmName(alg)), true);
            EmitString("public_key_hex", Hex(kp.public_key), true);
            EmitString("private_key_hex", Hex(kp.private_key), true);
            EmitString("ciphertext_hex", Hex(enc.ciphertext), true);
            EmitString("shared_hex", Hex(enc.shared), false);
            std::cout << "  },\n";
            basefwx::crypto::SecureClear(shared2);
        };
        emit_kem("ml_kem_768", basefwx::pq::KemAlgorithm::MlKem768);
        emit_kem("ml_kem_1024", basefwx::pq::KemAlgorithm::MlKem1024);
        std::cout << "  \"ml_kem_1024_available\": true\n";
#else
        std::cout << "  \"ml_kem_768\": null,\n";
        std::cout << "  \"ml_kem_1024\": null,\n";
        std::cout << "  \"ml_kem_1024_available\": false\n";
#endif
        std::cout << "}\n";
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "protocol_kat_gen failed: " << exc.what() << "\n";
        return 1;
    }
}
