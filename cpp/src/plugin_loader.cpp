/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/plugin_loader.hpp"

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/plugin_static.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>

#if defined(_WIN32) || defined(__CYGWIN__)
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

namespace basefwx::plugin {

namespace {

constexpr std::size_t kPluginTagFixedLen =
    basefwx::constants::kFwxAesPluginIdLen + 1 + basefwx::constants::kFwxAesPluginConfigLenBytes;

std::uint32_t ReadCapabilities(const basefwx_plugin_vtable* vtable, basefwx_plugin_ctx* ctx) {
    if (vtable == nullptr || vtable->capabilities == nullptr) {
        return 0;
    }
    return vtable->capabilities(ctx);
}

void CheckApiVersion(const basefwx_plugin_vtable* vtable) {
    if (vtable == nullptr) {
        throw std::runtime_error("plugin vtable is null");
    }
    if (vtable->api_version != BASEFWX_PLUGIN_API_VERSION) {
        throw std::runtime_error("plugin ABI version mismatch");
    }
    if (vtable->init == nullptr || vtable->destroy == nullptr
        || vtable->forward == nullptr || vtable->inverse == nullptr
        || vtable->max_output_for_input == nullptr) {
        throw std::runtime_error("plugin vtable missing required slots");
    }
}

void CloseDlHandle(void* handle) noexcept {
    if (handle == nullptr) {
        return;
    }
#if defined(_WIN32) || defined(__CYGWIN__)
    FreeLibrary(static_cast<HMODULE>(handle));
#else
    dlclose(handle);
#endif
}

void* OpenLibrary(const std::string& path) {
#if defined(_WIN32) || defined(__CYGWIN__)
    HMODULE handle = LoadLibraryA(path.c_str());
    if (handle == nullptr) {
        throw std::runtime_error("dlopen failed: " + path);
    }
    return static_cast<void*>(handle);
#else
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
        const char* err = dlerror();
        throw std::runtime_error(std::string("dlopen failed: ") + (err != nullptr ? err : path));
    }
    return handle;
#endif
}

const basefwx_plugin_vtable* ResolveEntry(void* handle) {
#if defined(_WIN32) || defined(__CYGWIN__)
    using EntryFn = const basefwx_plugin_vtable* (*)();
    auto entry = reinterpret_cast<EntryFn>(GetProcAddress(static_cast<HMODULE>(handle), "basefwx_plugin_entry"));
    if (entry == nullptr) {
        throw std::runtime_error("dlsym basefwx_plugin_entry failed");
    }
    return entry();
#else
    dlerror();
    using EntryFn = const basefwx_plugin_vtable* (*)();
    auto entry = reinterpret_cast<EntryFn>(dlsym(handle, "basefwx_plugin_entry"));
    const char* err = dlerror();
    if (err != nullptr || entry == nullptr) {
        throw std::runtime_error(std::string("dlsym basefwx_plugin_entry failed: ")
                                 + (err != nullptr ? err : "null entry"));
    }
    return entry();
#endif
}

const basefwx_plugin_vtable* LoadVtableFromPath(const std::string& path, void** dl_out) {
    void* handle = OpenLibrary(path);
    try {
        const basefwx_plugin_vtable* vtable = ResolveEntry(handle);
        CheckApiVersion(vtable);
        *dl_out = handle;
        return vtable;
    } catch (...) {
        CloseDlHandle(handle);
        throw;
    }
}

basefwx_plugin_ctx* InitPlugin(const basefwx_plugin_vtable* vtable,
                               const std::vector<std::uint8_t>& config) {
    basefwx_plugin_ctx* ctx = nullptr;
    const std::uint8_t* cfg_ptr = config.empty() ? nullptr : config.data();
    int rc = vtable->init(&ctx, cfg_ptr, config.size());
    if (rc != BASEFWX_PLUGIN_OK || ctx == nullptr) {
        throw std::runtime_error("plugin init failed");
    }
    return ctx;
}

void EnsurePositionAllowed(std::uint32_t position, std::uint32_t supported, std::uint32_t caps) {
    if (position == BASEFWX_PLUGIN_POS_RAW) {
        if ((caps & BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE) == 0) {
            throw std::runtime_error("plugin does not declare CAP_SAFE_RAW_MODE for POS_RAW");
        }
    }
    if ((supported & position) == 0) {
        throw std::runtime_error("plugin does not support requested position");
    }
}

std::vector<std::uint8_t> DispatchTransform(const basefwx_plugin_vtable* vtable,
                                            basefwx_plugin_ctx* ctx,
                                            const std::vector<std::uint8_t>& input,
                                            bool inverse) {
    size_t cap = vtable->max_output_for_input(ctx, input.size());
    std::vector<std::uint8_t> out(cap);
    size_t out_len = 0;
    const std::uint8_t* in_ptr = input.empty() ? nullptr : input.data();
    int rc = inverse
                 ? vtable->inverse(ctx, in_ptr, input.size(), out.data(), out.size(), &out_len)
                 : vtable->forward(ctx, in_ptr, input.size(), out.data(), out.size(), &out_len);
    if (rc != BASEFWX_PLUGIN_OK) {
        throw std::runtime_error(inverse ? "plugin inverse failed" : "plugin forward failed");
    }
    out.resize(out_len);
    return out;
}

bool IdMatches(const std::uint8_t* a, const std::uint8_t* b) {
    return std::memcmp(a, b, BASEFWX_PLUGIN_ID_LEN) == 0;
}

}  // namespace

PluginHandle::PluginHandle(PluginHandle&& other) noexcept
    : vtable_(other.vtable_),
      ctx_(other.ctx_),
      capabilities_(other.capabilities_),
      dl_handle_(other.dl_handle_) {
    other.vtable_ = nullptr;
    other.ctx_ = nullptr;
    other.capabilities_ = 0;
    other.dl_handle_ = nullptr;
}

PluginHandle& PluginHandle::operator=(PluginHandle&& other) noexcept {
    if (this != &other) {
        Reset();
        vtable_ = other.vtable_;
        ctx_ = other.ctx_;
        capabilities_ = other.capabilities_;
        dl_handle_ = other.dl_handle_;
        other.vtable_ = nullptr;
        other.ctx_ = nullptr;
        other.capabilities_ = 0;
        other.dl_handle_ = nullptr;
    }
    return *this;
}

PluginHandle::~PluginHandle() {
    Reset();
}

PluginHandle::PluginHandle(const basefwx_plugin_vtable* vtable,
                           basefwx_plugin_ctx* ctx,
                           std::uint32_t capabilities,
                           void* dl_handle)
    : vtable_(vtable), ctx_(ctx), capabilities_(capabilities), dl_handle_(dl_handle) {}

void PluginHandle::Reset() noexcept {
    if (vtable_ != nullptr && ctx_ != nullptr && vtable_->destroy != nullptr) {
        vtable_->destroy(ctx_);
    }
    ctx_ = nullptr;
    vtable_ = nullptr;
    capabilities_ = 0;
    CloseDlHandle(dl_handle_);
    dl_handle_ = nullptr;
}

const std::uint8_t* PluginHandle::plugin_id() const noexcept {
    if (vtable_ == nullptr) {
        return nullptr;
    }
    return vtable_->plugin_id;
}

std::uint32_t PluginHandle::supported_positions() const noexcept {
    if (vtable_ == nullptr) {
        return 0;
    }
    return vtable_->supported_positions;
}

std::vector<std::uint8_t> PluginHandle::TransformForward(const std::vector<std::uint8_t>& input,
                                                         std::uint32_t position) const {
    if (ctx_ == nullptr || vtable_ == nullptr) {
        throw std::runtime_error("plugin handle not loaded");
    }
    EnsurePositionAllowed(position, vtable_->supported_positions, capabilities_);
    return DispatchTransform(vtable_, ctx_, input, false);
}

std::vector<std::uint8_t> PluginHandle::TransformInverse(const std::vector<std::uint8_t>& input,
                                                         std::uint32_t position) const {
    if (ctx_ == nullptr || vtable_ == nullptr) {
        throw std::runtime_error("plugin handle not loaded");
    }
    EnsurePositionAllowed(position, vtable_->supported_positions, capabilities_);
    return DispatchTransform(vtable_, ctx_, input, true);
}

PluginHandle LoadPluginByPath(const std::string& path, const std::vector<std::uint8_t>& config) {
    if (path.empty()) {
        throw std::runtime_error("plugin path required");
    }
    void* dl_handle = nullptr;
    const basefwx_plugin_vtable* vtable = LoadVtableFromPath(path, &dl_handle);
    basefwx_plugin_ctx* ctx = InitPlugin(vtable, config);
    std::uint32_t caps = ReadCapabilities(vtable, ctx);
    return PluginHandle(vtable, ctx, caps, dl_handle);
}

PluginHandle LoadPluginById(const std::uint8_t id[BASEFWX_PLUGIN_ID_LEN],
                            const std::string& path,
                            const std::vector<std::uint8_t>& config) {
    if (id == nullptr) {
        throw std::runtime_error("plugin id required");
    }
    const basefwx_plugin_vtable* embedded = Registry::Instance().Find(id);
    if (embedded != nullptr) {
        CheckApiVersion(embedded);
        basefwx_plugin_ctx* ctx = InitPlugin(embedded, config);
        std::uint32_t caps = ReadCapabilities(embedded, ctx);
        return PluginHandle(embedded, ctx, caps, nullptr);
    }
    if (path.empty()) {
        throw std::runtime_error("plugin not found in registry and no path provided");
    }
    void* dl_handle = nullptr;
    const basefwx_plugin_vtable* vtable = LoadVtableFromPath(path, &dl_handle);
    if (!IdMatches(vtable->plugin_id, id)) {
        CloseDlHandle(dl_handle);
        throw std::runtime_error("plugin id mismatch");
    }
    basefwx_plugin_ctx* ctx = InitPlugin(vtable, config);
    std::uint32_t caps = ReadCapabilities(vtable, ctx);
    return PluginHandle(vtable, ctx, caps, dl_handle);
}

PluginHandle LoadPluginForTag(const PluginTag& tag,
                              const std::string& path,
                              const std::string& id_hex_override) {
    if (!id_hex_override.empty()) {
        auto override_id = ParsePluginIdHex(id_hex_override);
        if (!IdMatches(override_id.data(), tag.plugin_id.data())) {
            throw std::runtime_error("plugin id override does not match blob tag");
        }
    }
    std::vector<std::uint8_t> config = tag.config;
    if (!path.empty()) {
        void* dl_handle = nullptr;
        const basefwx_plugin_vtable* vtable = LoadVtableFromPath(path, &dl_handle);
        if (!IdMatches(vtable->plugin_id, tag.plugin_id.data())) {
            CloseDlHandle(dl_handle);
            throw std::runtime_error("loaded plugin id does not match blob tag");
        }
        basefwx_plugin_ctx* ctx = InitPlugin(vtable, config);
        std::uint32_t caps = ReadCapabilities(vtable, ctx);
        return PluginHandle(vtable, ctx, caps, dl_handle);
    }
    return LoadPluginById(tag.plugin_id.data(), {}, config);
}

std::array<std::uint8_t, BASEFWX_PLUGIN_ID_LEN> ParsePluginIdHex(const std::string& hex) {
    std::string cleaned;
    cleaned.reserve(hex.size());
    for (char ch : hex) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            cleaned.push_back(ch);
        }
    }
    if (cleaned.size() != BASEFWX_PLUGIN_ID_LEN * 2) {
        throw std::runtime_error("plugin id hex must be 32 characters");
    }
    std::array<std::uint8_t, BASEFWX_PLUGIN_ID_LEN> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        char buf[3] = {cleaned[i * 2], cleaned[i * 2 + 1], '\0'};
        char* end = nullptr;
        unsigned long value = std::strtoul(buf, &end, 16);
        if (end == buf || value > 0xFF) {
            throw std::runtime_error("invalid plugin id hex");
        }
        out[i] = static_cast<std::uint8_t>(value);
    }
    return out;
}

std::uint8_t ParsePluginPosition(const std::string& pos) {
    if (pos == "pre") {
        return static_cast<std::uint8_t>(BASEFWX_PLUGIN_POS_PRE_AEAD);
    }
    if (pos == "post") {
        return static_cast<std::uint8_t>(BASEFWX_PLUGIN_POS_POST_AEAD);
    }
    throw std::runtime_error("plugin position must be pre or post");
}

void ValidatePluginPosition(std::uint32_t position, std::uint32_t supported_positions) {
    if (position != BASEFWX_PLUGIN_POS_PRE_AEAD && position != BASEFWX_PLUGIN_POS_POST_AEAD) {
        throw std::runtime_error("unsupported plugin position");
    }
    if ((supported_positions & position) == 0) {
        throw std::runtime_error("plugin does not support requested position");
    }
}

std::vector<std::uint8_t> SerializePluginTag(const PluginTag& tag) {
    if (tag.config.size() > 0xFFFF) {
        throw std::runtime_error("plugin config too large");
    }
    if (tag.config.size() > basefwx::constants::kFwxAesPluginMaxConfigLen) {
        throw std::runtime_error("plugin config exceeds maximum");
    }
    std::vector<std::uint8_t> out;
    out.reserve(kPluginTagFixedLen + tag.config.size());
    out.insert(out.end(), tag.plugin_id.begin(), tag.plugin_id.end());
    out.push_back(tag.position);
    std::uint16_t cfg_len = static_cast<std::uint16_t>(tag.config.size());
    out.push_back(static_cast<std::uint8_t>((cfg_len >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(cfg_len & 0xFF));
    out.insert(out.end(), tag.config.begin(), tag.config.end());
    return out;
}

PluginTag ParsePluginTag(const std::uint8_t* data, std::size_t len) {
    if (data == nullptr || len < kPluginTagFixedLen) {
        throw std::runtime_error("plugin tag truncated");
    }
    PluginTag tag;
    std::memcpy(tag.plugin_id.data(), data, tag.plugin_id.size());
    tag.position = data[tag.plugin_id.size()];
    std::uint16_t cfg_len = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[tag.plugin_id.size() + 1]) << 8)
        | static_cast<std::uint16_t>(data[tag.plugin_id.size() + 2]));
    if (cfg_len > basefwx::constants::kFwxAesPluginMaxConfigLen) {
        throw std::runtime_error("plugin config length exceeds maximum");
    }
    if (len < kPluginTagFixedLen + cfg_len) {
        throw std::runtime_error("plugin tag truncated");
    }
    tag.config.assign(data + kPluginTagFixedLen, data + kPluginTagFixedLen + cfg_len);
    return tag;
}

bool PluginConfigured(const std::string& path,
                      const std::string& id_hex,
                      std::uint8_t position) {
    return !path.empty() || !id_hex.empty() || position != 0;
}

}  // namespace basefwx::plugin
