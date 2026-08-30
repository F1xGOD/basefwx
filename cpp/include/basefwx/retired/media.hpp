/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace basefwx {

struct KfmCarrierInspectResult {
    std::uint64_t file_size = 0;
    std::size_t payload_len = 0;
    std::uint8_t mode = 0;
    std::uint8_t flags = 0;
    std::string carrier_kind;
    std::string payload_ext;
};

std::optional<KfmCarrierInspectResult> InspectKfmCarrierFile(
    const std::string& path);

std::string Jmge(const std::string& path,
                 const std::string& password,
                 const std::string& output = {},
                 bool keep_meta = false,
                 bool keep_input = false,
                 bool archive_original = false,
                 bool use_master = false);
std::string Jmgd(const std::string& path,
                 const std::string& password,
                 const std::string& output = {},
                 bool use_master = false);
std::string Kfme(const std::string& path,
                 const std::string& output = {},
                 bool bw_mode = false);
std::string Kfmd(const std::string& path,
                 const std::string& output = {},
                 bool bw_mode = false);
std::string Kfae(const std::string& path,
                 const std::string& output = {},
                 bool bw_mode = false);
std::string Kfad(const std::string& path,
                 const std::string& output = {});

}  // namespace basefwx
