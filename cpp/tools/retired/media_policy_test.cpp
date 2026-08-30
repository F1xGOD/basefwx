/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/constants.hpp"
#include "basefwx/imagecipher.hpp"
#include "basefwx/retired/codecs.hpp"
#include "retired/media/imagecipher_internal.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

void AppendU32Be(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void ExpectReject(const std::function<void()>& action,
                  const std::string& label,
                  const std::string& message_part) {
    try {
        action();
    } catch (const std::exception& exc) {
        if (std::string(exc.what()).find(message_part) != std::string::npos) {
            return;
        }
        throw std::runtime_error(
            label + " produced unexpected rejection: " + exc.what());
    }
    throw std::runtime_error(label + " was accepted");
}

class ScopedTempDirectory {
  public:
    ScopedTempDirectory() {
        const auto seed =
            std::chrono::steady_clock::now().time_since_epoch().count();
        const auto root = std::filesystem::temp_directory_path();
        for (std::uint32_t attempt = 0; attempt < 100; ++attempt) {
            path_ = root / (
                "basefwx-retired-media-policy-"
                + std::to_string(seed)
                + "-"
                + std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create retired-media policy test directory");
    }

    ~ScopedTempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    ScopedTempDirectory(const ScopedTempDirectory&) = delete;
    ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

    const std::filesystem::path& path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

void TestProfiledHeader() {
    const Bytes user_blob{0x01, 0x02, 0x03};
    const Bytes master_blob{0x04, 0x05};
    const Bytes header =
        basefwx::imagecipher::internal::BuildJmgHeader(
            user_blob,
            master_blob,
            basefwx::constants::kJmgSecurityProfileMax);
    std::size_t header_len = 0;
    Bytes parsed_user;
    Bytes parsed_master;
    std::uint8_t parsed_profile = 0;
    if (!basefwx::imagecipher::internal::ParseJmgHeader(
            header,
            header_len,
            parsed_user,
            parsed_master,
            &parsed_profile)
        || header_len != header.size()
        || parsed_user != user_blob
        || parsed_master != master_blob
        || parsed_profile != basefwx::constants::kJmgSecurityProfileMax) {
        throw std::runtime_error(
            "JMG profiled key header did not roundtrip");
    }

    Bytes missing_profile(
        basefwx::constants::kJmgKeyMagic.begin(),
        basefwx::constants::kJmgKeyMagic.end());
    missing_profile.push_back(basefwx::constants::kJmgKeyVersion);
    AppendU32Be(missing_profile, 0);
    ExpectReject(
        [&]() {
            (void)basefwx::imagecipher::internal::ParseJmgHeader(
                missing_profile,
                header_len,
                parsed_user,
                parsed_master,
                &parsed_profile);
        },
        "JMG missing profile byte",
        "Truncated JMG key header profile");
}

void TestRetiredCodecVectors() {
    constexpr const char* kInput = "basefwx";
    const std::string b256 =
        "4PK6OP9A65TJISRC9CQM2UP85944EG984PF4CAI7AOK2KI3JDDBG4";
    const std::string a512 =
        "22659442R15AKJ4EAI3593KGGI159442R15AKJ4EAI35154GAI7BSKKKI2JFLR7QTH"
        "8593KCH2V5554GKRTEOK4GK216TUNCNP999456A28A10JEL968SL46L968SL46A2A90"
        "L4EIAL50J5CL968SL46NP999456A2A90L4EAI791142IAL50J5CIAL50J5C3";
    if (basefwx::codec::B256Encode(kInput) != b256
        || basefwx::codec::B256Decode(b256) != kInput
        || basefwx::B256Encode(kInput) != b256
        || basefwx::B256Decode(b256) != kInput
        || basefwx::A512Encode(kInput) != a512
        || basefwx::A512Decode(a512) != kInput
        || basefwx::Bi512Encode(kInput)
            != "47d28c46896d43b415dde8a79eed97da6ac6686127f595fa28bce0a0492df42d"
        || basefwx::Uhash513(kInput)
            != "a2a622418b25e4ec8c9a08f61b979fe8bb17272d34983bbbed44740fffd3c4b4") {
        throw std::runtime_error("retired codec compatibility vector mismatch");
    }
}

void TestHostileInnerHeader() {
    ScopedTempDirectory temp_dir;
    const auto carrier = temp_dir.path() / "hostile-jmg.bin";
    const auto destination = temp_dir.path() / "hostile-jmg-output.bin";
    Bytes key_header(
        basefwx::constants::kJmgKeyMagic.begin(),
        basefwx::constants::kJmgKeyMagic.end());
    key_header.push_back(basefwx::constants::kJmgKeyVersion);
    AppendU32Be(
        key_header,
        std::numeric_limits<std::int32_t>::max());
    Bytes length;
    AppendU32Be(
        length,
        static_cast<std::uint32_t>(key_header.size()));
    {
        std::ofstream output(carrier, std::ios::binary);
        output << "carrier";
        output.write(
            basefwx::constants::kImageCipherTrailerMagic.data(),
            static_cast<std::streamsize>(
                basefwx::constants::kImageCipherTrailerMagic.size()));
        output.write(
            reinterpret_cast<const char*>(length.data()),
            static_cast<std::streamsize>(length.size()));
        output.write(
            reinterpret_cast<const char*>(key_header.data()),
            static_cast<std::streamsize>(key_header.size()));
        output.write(
            basefwx::constants::kImageCipherTrailerMagic.data(),
            static_cast<std::streamsize>(
                basefwx::constants::kImageCipherTrailerMagic.size()));
        output.write(
            reinterpret_cast<const char*>(length.data()),
            static_cast<std::streamsize>(length.size()));
    }
    {
        std::ofstream(destination, std::ios::binary)
            << "existing authenticated destination";
    }
    std::set<std::filesystem::path> before;
    for (const auto& entry :
         std::filesystem::directory_iterator(temp_dir.path())) {
        before.insert(entry.path().filename());
    }
    ExpectReject(
        [&]() {
            (void)basefwx::imagecipher::DecryptMedia(
                carrier.string(),
                "media-trailer-test-password",
                destination.string(),
                false);
        },
        "JMG inner key header allocation cap",
        "Invalid JMG key header length");
    std::ifstream restored(destination, std::ios::binary);
    const std::string restored_text(
        (std::istreambuf_iterator<char>(restored)),
        std::istreambuf_iterator<char>());
    if (restored_text != "existing authenticated destination") {
        throw std::runtime_error(
            "hostile JMG header clobbered destination");
    }
    std::set<std::filesystem::path> after;
    for (const auto& entry :
         std::filesystem::directory_iterator(temp_dir.path())) {
        after.insert(entry.path().filename());
    }
    if (before != after) {
        throw std::runtime_error("hostile JMG header leaked temp output");
    }
}

}  // namespace

int main() {
    try {
        TestRetiredCodecVectors();
        TestProfiledHeader();
        TestHostileInnerHeader();
    } catch (const std::exception& exc) {
        std::cerr << "retired_media_policy_test: " << exc.what() << '\n';
        return 1;
    }
    return 0;
}
