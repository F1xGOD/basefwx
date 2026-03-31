#pragma once

#include "basefwx/constants.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace basefwx::pb512 {

using Bytes = std::vector<std::uint8_t>;

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

}  // namespace basefwx::pb512
