#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "basefwx/constants.hpp"
#include "basefwx/filecodec.hpp"
#include "basefwx/fwxaes.hpp"

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

std::string B256Encode(const std::string& input);
std::string B256Decode(const std::string& input);
std::string B64Encode(const std::string& input);
std::string B64Decode(const std::string& input);
std::string N10Encode(const std::string& input);
std::string N10Decode(const std::string& input);
std::string Hash512(const std::string& input);
std::string Uhash513(const std::string& input);
std::string Bi512Encode(const std::string& input);
std::string A512Encode(const std::string& input);
std::string A512Decode(const std::string& input);
std::string B1024Encode(const std::string& input);

struct KdfOptions {
    std::string label = "auto";
    std::size_t pbkdf2_iterations = 200000;
    std::uint32_t argon2_time_cost = 3;
    std::uint32_t argon2_memory_cost = 1u << 15;
    std::uint32_t argon2_parallelism = constants::DefaultArgon2Parallelism();
    bool allow_pbkdf2_fallback = true;
};

std::string B512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);
std::string B512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);
std::string Pb512Encode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);
std::string Pb512Decode(const std::string& input, const std::string& password, bool use_master, const KdfOptions& kdf);

std::string Jmge(const std::string& path,
                 const std::string& password,
                 const std::string& output = {},
                 bool keep_meta = false,
                 bool keep_input = false);
std::string Jmgd(const std::string& path, const std::string& password, const std::string& output = {});
std::string Kfme(const std::string& path, const std::string& output = {}, bool bw_mode = false);
std::string Kfmd(const std::string& path, const std::string& output = {}, bool bw_mode = false);
std::string Kfae(const std::string& path, const std::string& output = {}, bool bw_mode = false);
std::string Kfad(const std::string& path, const std::string& output = {});

}  // namespace basefwx
