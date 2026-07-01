/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include "basefwx/plugin.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace basefwx::plugin {

struct PluginTag {
    std::array<std::uint8_t, BASEFWX_PLUGIN_ID_LEN> plugin_id{};
    std::uint8_t position = 0;
    std::vector<std::uint8_t> config;
};

class PluginHandle {
public:
    PluginHandle() = default;
    PluginHandle(PluginHandle&& other) noexcept;
    PluginHandle& operator=(PluginHandle&& other) noexcept;
    ~PluginHandle();

    PluginHandle(const PluginHandle&) = delete;
    PluginHandle& operator=(const PluginHandle&) = delete;

    const std::uint8_t* plugin_id() const noexcept;
    std::uint32_t capabilities() const noexcept { return capabilities_; }
    std::uint32_t supported_positions() const noexcept;

    std::vector<std::uint8_t> TransformForward(const std::vector<std::uint8_t>& input,
                                               std::uint32_t position) const;
    std::vector<std::uint8_t> TransformInverse(const std::vector<std::uint8_t>& input,
                                                 std::uint32_t position) const;

    bool IsValid() const noexcept { return ctx_ != nullptr; }

private:
    friend PluginHandle LoadPluginByPath(const std::string& path,
                                         const std::vector<std::uint8_t>& config);
    friend PluginHandle LoadPluginById(const std::uint8_t id[BASEFWX_PLUGIN_ID_LEN],
                                       const std::string& path,
                                       const std::vector<std::uint8_t>& config);
    friend PluginHandle LoadPluginForTag(const PluginTag& tag,
                                         const std::string& path,
                                         const std::string& id_hex_override);

    PluginHandle(const basefwx_plugin_vtable* vtable,
                 basefwx_plugin_ctx* ctx,
                 std::uint32_t capabilities,
                 void* dl_handle);

    void Reset() noexcept;

    const basefwx_plugin_vtable* vtable_ = nullptr;
    basefwx_plugin_ctx* ctx_ = nullptr;
    std::uint32_t capabilities_ = 0;
    void* dl_handle_ = nullptr;
};

PluginHandle LoadPluginByPath(const std::string& path,
                              const std::vector<std::uint8_t>& config = {});

PluginHandle LoadPluginById(const std::uint8_t id[BASEFWX_PLUGIN_ID_LEN],
                            const std::string& path = {},
                            const std::vector<std::uint8_t>& config = {});

PluginHandle LoadPluginForTag(const PluginTag& tag,
                              const std::string& path = {},
                              const std::string& id_hex_override = {});

std::array<std::uint8_t, BASEFWX_PLUGIN_ID_LEN> ParsePluginIdHex(const std::string& hex);

std::uint8_t ParsePluginPosition(const std::string& pos);

void ValidatePluginPosition(std::uint32_t position, std::uint32_t supported_positions);

std::vector<std::uint8_t> SerializePluginTag(const PluginTag& tag);

PluginTag ParsePluginTag(const std::uint8_t* data, std::size_t len);

bool PluginConfigured(const std::string& path,
                      const std::string& id_hex,
                      std::uint8_t position);

}  // namespace basefwx::plugin
