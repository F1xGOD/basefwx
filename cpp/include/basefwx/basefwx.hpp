/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include "basefwx/constants.hpp"
#include "basefwx/filecodec.hpp"
#include "basefwx/features.hpp"
#include "basefwx/fwxaes.hpp"
#include "basefwx/livecipher.hpp"
#include "basefwx/an7.hpp"
#if BASEFWX_HAS_RETIRED_MEDIA
#include "basefwx/retired/codecs.hpp"
#include "basefwx/retired/media.hpp"
#endif

namespace basefwx {

struct InspectResult {
    std::size_t user_blob_len = 0;
    std::size_t master_blob_len = 0;
    std::size_t payload_len = 0;
    bool has_metadata = false;
    std::uint32_t metadata_len = 0;
    std::string metadata_base64;
    std::string metadata_json;
};

std::vector<std::uint8_t> ReadFile(const std::string& path);
InspectResult InspectBlob(const std::vector<std::uint8_t>& blob);
std::string ResolvePassword(const std::string& input);
void RequireStrongPasswordForEncryption(const std::string& password, std::string_view context = {});

std::string B64Encode(const std::string& input);
std::string B64Decode(const std::string& input);
std::string N10Encode(const std::string& input);
std::string N10Decode(const std::string& input);
std::string Hash512(const std::string& input);
struct KdfOptions {
    std::string label = "auto";
    std::size_t pbkdf2_iterations = constants::kUserKdfIterations;
    std::uint32_t argon2_time_cost = constants::kArgon2TimeCost;
    std::uint32_t argon2_memory_cost = constants::kArgon2MemoryCost;
    std::uint32_t argon2_parallelism = constants::DefaultArgon2Parallelism();
    bool allow_pbkdf2_fallback = true;
};

std::string B512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);
std::string B512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);
std::string Pb512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);
std::string Pb512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);

enum class FwxAesProfile {
    Light,
    Heavy,
};

std::string FwxAesFile(const std::string& path,
                       const std::string& password,
                       const std::string& output = {},
                       bool use_master = false,
                       FwxAesProfile profile = FwxAesProfile::Light,
                       bool normalize = false,
                       std::size_t normalize_threshold = 8 * 1024,
                       const std::string& cover_phrase = "low taper fade",
                       bool compress = false,
                       bool keep_input = false);

std::uint64_t FwxAesLiveEncryptStream(std::istream& source,
                                      std::ostream& dest,
                                      const std::string& password,
                                      bool use_master = false,
                                      std::size_t chunk_size = constants::kStreamChunkSize);

std::uint64_t FwxAesLiveDecryptStream(std::istream& source,
                                      std::ostream& dest,
                                      const std::string& password,
                                      bool use_master = false,
                                      std::size_t chunk_size = constants::kStreamChunkSize);

}  // namespace basefwx
