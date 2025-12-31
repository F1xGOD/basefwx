#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace basefwx::metadata {

using MetadataMap = std::unordered_map<std::string, std::string>;

std::string Build(const std::string& method,
                  bool strip,
                  bool use_master,
                  std::string_view aead,
                  std::string_view kdf_label,
                  std::string_view mode = {},
                  std::optional<bool> obfuscation = std::nullopt,
                  std::optional<std::uint32_t> kdf_iters = std::nullopt,
                  std::optional<std::uint32_t> argon2_time = std::nullopt,
                  std::optional<std::uint32_t> argon2_mem = std::nullopt,
                  std::optional<std::uint32_t> argon2_par = std::nullopt,
                  std::string_view pack = {});

MetadataMap Decode(const std::string& blob);
std::string GetValue(const MetadataMap& meta, std::string_view key);

}  // namespace basefwx::metadata
