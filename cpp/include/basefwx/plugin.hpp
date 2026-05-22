/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#ifndef BASEFWX_PLUGIN_HPP
#define BASEFWX_PLUGIN_HPP

#include "basefwx/plugin.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace basefwx::plugin {

/* ---------- views over caller buffers ------------------------------ */

/* Read-only view of an immutable byte sequence. Cheap to copy. */
class BytesView {
public:
    constexpr BytesView() noexcept = default;
    constexpr BytesView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

    constexpr const std::uint8_t* data() const noexcept { return data_; }
    constexpr std::size_t size() const noexcept { return size_; }
    constexpr bool empty() const noexcept { return size_ == 0; }

    constexpr const std::uint8_t* begin() const noexcept { return data_; }
    constexpr const std::uint8_t* end() const noexcept {
        return data_ != nullptr ? data_ + size_ : nullptr;
    }

    std::uint8_t operator[](std::size_t i) const {
        if (i >= size_) throw std::out_of_range("BytesView index");
        return data_[i];
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

/* Writable view into a caller-provided output buffer. The plugin
 * writes into `data()` up to `capacity()` bytes and reports the
 * actual length via the wrapper's return value. */
class BytesSpan {
public:
    constexpr BytesSpan() noexcept = default;
    constexpr BytesSpan(std::uint8_t* data, std::size_t capacity) noexcept
        : data_(data), capacity_(capacity) {}

    constexpr std::uint8_t* data() const noexcept { return data_; }
    constexpr std::size_t capacity() const noexcept { return capacity_; }

    /* Copy `src` into the span starting at `offset`. Throws
     * `std::out_of_range` if the write would overflow capacity — the
     * macro layer converts that to BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL. */
    void write(std::size_t offset, BytesView src) {
        if (offset > capacity_ || src.size() > capacity_ - offset) {
            throw std::out_of_range("BytesSpan write overflows capacity");
        }
        if (src.size() > 0 && src.data() != nullptr) {
            std::memcpy(data_ + offset, src.data(), src.size());
        }
    }

private:
    std::uint8_t* data_ = nullptr;
    std::size_t capacity_ = 0;
};

/* Read-only view of the opaque config blob passed to init(). */
class ConfigView : public BytesView {
public:
    using BytesView::BytesView;

    /* Convenience helper for the common case: the plugin wants the
     * config as a `std::string_view` (e.g. a JSON snippet). Returns
     * an empty string-view when the config is empty. */
    const char* as_text() const noexcept {
        return reinterpret_cast<const char*>(data());
    }
};

/* ---------- zero-on-destroy secret-bearing buffer ----------------- */

/* A thin std::vector<uint8_t> wrapper that calls `OPENSSL_cleanse`-
 * style zeroization on destruction. Use this for any per-instance
 * key material the plugin holds. The compiler is NOT allowed to elide
 * the wipe because the helper hides it behind a function call. */
class SecretBuffer {
public:
    SecretBuffer() = default;
    explicit SecretBuffer(std::size_t n) : buf_(n) {}
    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;
    SecretBuffer(SecretBuffer&& other) noexcept : buf_(std::move(other.buf_)) {
        other.buf_.clear();
    }
    SecretBuffer& operator=(SecretBuffer&& other) noexcept {
        if (this != &other) {
            wipe();
            buf_ = std::move(other.buf_);
            other.buf_.clear();
        }
        return *this;
    }
    ~SecretBuffer() { wipe(); }

    void resize(std::size_t n) { buf_.resize(n); }
    void assign(BytesView v) {
        buf_.assign(v.data(), v.data() + v.size());
    }

    std::uint8_t* data() noexcept { return buf_.data(); }
    const std::uint8_t* data() const noexcept { return buf_.data(); }
    std::size_t size() const noexcept { return buf_.size(); }
    BytesView view() const noexcept { return BytesView(buf_.data(), buf_.size()); }

private:
    void wipe() noexcept {
        if (buf_.empty()) return;
        /* `volatile` keeps the optimizer from removing the store. */
        volatile std::uint8_t* p = buf_.data();
        for (std::size_t i = 0; i < buf_.size(); ++i) p[i] = 0;
        buf_.clear();
    }
    std::vector<std::uint8_t> buf_;
};

/* ---------- exception-to-error-code mapper ------------------------ */

inline int translate_exception(const std::exception_ptr& ep) noexcept {
    if (!ep) return BASEFWX_PLUGIN_ERR_GENERIC;
    try {
        std::rethrow_exception(ep);
    } catch (const std::out_of_range&) {
        return BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL;
    } catch (const std::overflow_error&) {
        return BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL;
    } catch (const std::invalid_argument&) {
        return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    } catch (const std::logic_error&) {
        return BASEFWX_PLUGIN_ERR_BAD_STATE;
    } catch (...) {
        return BASEFWX_PLUGIN_ERR_GENERIC;
    }
}

/* ---------- ABI conformance check at compile time ---------------- */

/* If a plugin gets recompiled against an upgraded header that bumped
 * the ABI version while the source still expects the old one, this
 * catches it before any byte hits a .so. */
static_assert(BASEFWX_PLUGIN_API_VERSION == 1u,
              "basefwx/plugin.hpp expected BASEFWX_PLUGIN_API_VERSION 1; "
              "regenerate this wrapper for the new ABI.");

}  // namespace basefwx::plugin

/* ---------- BASEFWX_PLUGIN_DEFINE(...) ---------------------------- */

/* Hidden-namespace shims that the macro expands into. Authors don't
 * touch these directly. */
namespace basefwx::plugin::detail {

template <typename PluginT>
int generic_init(::basefwx_plugin_ctx** ctx_out,
                 const std::uint8_t* config, std::size_t config_len) noexcept
{
    if (ctx_out == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    try {
        ConfigView cfg(config, config_len);
        PluginT* p = new PluginT(cfg);
        *ctx_out = reinterpret_cast<::basefwx_plugin_ctx*>(p);
        return BASEFWX_PLUGIN_OK;
    } catch (...) {
        return translate_exception(std::current_exception());
    }
}

template <typename PluginT>
void generic_destroy(::basefwx_plugin_ctx* ctx) noexcept {
    if (ctx == nullptr) return;
    delete reinterpret_cast<PluginT*>(ctx);
}

template <typename PluginT, bool IsInverse>
int generic_transform(::basefwx_plugin_ctx* ctx,
                      const std::uint8_t* in, std::size_t in_len,
                      std::uint8_t* out, std::size_t out_cap,
                      std::size_t* out_len) noexcept
{
    if (ctx == nullptr) return BASEFWX_PLUGIN_ERR_BAD_STATE;
    if (out_len == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (out_cap > 0 && out == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (in_len > 0 && in == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    try {
        PluginT* p = reinterpret_cast<PluginT*>(ctx);
        BytesView in_view(in, in_len);
        BytesSpan out_span(out, out_cap);
        std::size_t written = 0;
        if constexpr (IsInverse) {
            written = p->Inverse(in_view, out_span);
        } else {
            written = p->Forward(in_view, out_span);
        }
        if (written > out_cap) return BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL;
        *out_len = written;
        return BASEFWX_PLUGIN_OK;
    } catch (...) {
        return translate_exception(std::current_exception());
    }
}

template <typename PluginT>
std::size_t generic_max_output(::basefwx_plugin_ctx* ctx, std::size_t in_len) noexcept
{
    if (ctx == nullptr) return in_len;
    try {
        return reinterpret_cast<const PluginT*>(ctx)->MaxOutput(in_len);
    } catch (...) {
        return in_len;
    }
}

template <typename PluginT>
std::uint32_t generic_capabilities(const ::basefwx_plugin_ctx* ctx) noexcept {
    if (ctx == nullptr) return 0u;
    try {
        return reinterpret_cast<const PluginT*>(ctx)->Capabilities();
    } catch (...) {
        return 0u;
    }
}

template <typename PluginT, bool IsInverse>
int generic_transform_keyed(::basefwx_plugin_ctx* ctx,
                            const std::uint8_t* in, std::size_t in_len,
                            const std::uint8_t* tweak, std::size_t tweak_len,
                            const std::uint8_t* host_secret, std::size_t host_secret_len,
                            std::uint8_t* out, std::size_t out_cap,
                            std::size_t* out_len) noexcept
{
    if (ctx == nullptr) return BASEFWX_PLUGIN_ERR_BAD_STATE;
    if (out_len == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (out_cap > 0 && out == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (in_len > 0 && in == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (tweak_len > 0 && tweak == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    if (host_secret_len > 0 && host_secret == nullptr) return BASEFWX_PLUGIN_ERR_BAD_INPUT;
    try {
        PluginT* p = reinterpret_cast<PluginT*>(ctx);
        BytesView in_view(in, in_len);
        BytesView tweak_view(tweak, tweak_len);
        BytesView secret_view(host_secret, host_secret_len);
        BytesSpan out_span(out, out_cap);
        std::size_t written = 0;
        if constexpr (IsInverse) {
            written = p->InverseKeyed(in_view, tweak_view, secret_view, out_span);
        } else {
            written = p->ForwardKeyed(in_view, tweak_view, secret_view, out_span);
        }
        if (written > out_cap) return BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL;
        *out_len = written;
        return BASEFWX_PLUGIN_OK;
    } catch (...) {
        return translate_exception(std::current_exception());
    }
}

template <typename PluginT>
int generic_selftest(::basefwx_plugin_ctx* ctx) noexcept {
    /* Default selftest: round-trip a fixed 32-byte vector through
     * Forward → Inverse and compare. Plugin authors can override by
     * adding their own `bool SelfTest()` method and using the
     * `BASEFWX_PLUGIN_DEFINE_WITH_SELFTEST` macro variant. */
    if (ctx == nullptr) return BASEFWX_PLUGIN_ERR_BAD_STATE;
    PluginT* p = reinterpret_cast<PluginT*>(ctx);
    static const std::uint8_t kVec[32] = {
        0xde,0xad,0xbe,0xef,0x00,0xff,0x10,0x20,
        0xa5,0xa5,0x5a,0x5a,0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,
        0xdd,0xee,0xff,0x00,0x12,0x34,0x56,0x78,
    };
    try {
        const std::size_t cap = p->MaxOutput(sizeof(kVec));
        std::vector<std::uint8_t> mid(cap);
        std::vector<std::uint8_t> back(cap);
        BytesView in_view(kVec, sizeof(kVec));
        BytesSpan mid_span(mid.data(), mid.size());
        const std::size_t mid_len = p->Forward(in_view, mid_span);
        if (mid_len > cap) return BASEFWX_PLUGIN_ERR_GENERIC;
        BytesView mid_view(mid.data(), mid_len);
        BytesSpan back_span(back.data(), back.size());
        const std::size_t back_len = p->Inverse(mid_view, back_span);
        if (back_len != sizeof(kVec)) return BASEFWX_PLUGIN_ERR_GENERIC;
        if (std::memcmp(kVec, back.data(), sizeof(kVec)) != 0)
            return BASEFWX_PLUGIN_ERR_GENERIC;
        return BASEFWX_PLUGIN_OK;
    } catch (...) {
        return translate_exception(std::current_exception());
    }
}

}  // namespace basefwx::plugin::detail

/*
 * BASEFWX_PLUGIN_DEFINE — drop this in your translation unit ONCE.
 *
 *   plugin_cls   — your C++ class. Must define:
 *                    - ctor (basefwx::plugin::ConfigView)
 *                    - std::size_t MaxOutput(std::size_t in_len) const noexcept
 *                    - std::size_t Forward(BytesView in, BytesSpan out)
 *                    - std::size_t Inverse(BytesView in, BytesSpan out)
 *   16 plugin_id bytes — 16 comma-separated hex values.
 *   name         — string literal, ≤64 chars.
 *   version      — string literal, ≤64 chars.
 *   positions    — bitwise OR of BASEFWX_PLUGIN_POS_* values.
 */
#define BASEFWX_PLUGIN_DEFINE(plugin_cls, \
                              id0,id1,id2,id3,id4,id5,id6,id7, \
                              id8,id9,id10,id11,id12,id13,id14,id15, \
                              name_literal, version_literal, positions_mask) \
    static const ::basefwx_plugin_vtable kBasefwxPluginVtable = { \
        BASEFWX_PLUGIN_API_VERSION, \
        { id0,id1,id2,id3,id4,id5,id6,id7, \
          id8,id9,id10,id11,id12,id13,id14,id15 }, \
        name_literal, \
        version_literal, \
        (positions_mask), \
        &basefwx::plugin::detail::generic_init<plugin_cls>, \
        &basefwx::plugin::detail::generic_destroy<plugin_cls>, \
        &basefwx::plugin::detail::generic_transform<plugin_cls, /*IsInverse=*/false>, \
        &basefwx::plugin::detail::generic_transform<plugin_cls, /*IsInverse=*/true>, \
        &basefwx::plugin::detail::generic_max_output<plugin_cls>, \
        &basefwx::plugin::detail::generic_selftest<plugin_cls>, \
        /* capabilities, forward_keyed, inverse_keyed: not implemented \
         * by this v1-style plugin. Host will refuse POS_RAW and run \
         * only the deterministic forward/inverse. */ \
        nullptr, nullptr, nullptr, \
        nullptr, \
    }; \
    extern "C" BASEFWX_PLUGIN_EXPORT \
    const ::basefwx_plugin_vtable* basefwx_plugin_entry(void) { \
        return &kBasefwxPluginVtable; \
    } \
    /* eat trailing semicolon */ \
    struct BASEFWX_PLUGIN_DEFINE_force_semicolon_##plugin_cls {}

/*
 * BASEFWX_PLUGIN_DEFINE_KEYED — drop this in your translation unit
 * ONCE when your plugin supports the keyed forward / inverse path.
 * In addition to the v1 requirements (ctor, MaxOutput, Forward,
 * Inverse), the plugin class must also define:
 *
 *   std::uint32_t Capabilities() const noexcept
 *   std::size_t ForwardKeyed(BytesView in,
 *                            BytesView tweak,
 *                            BytesView host_secret,
 *                            BytesSpan out)
 *   std::size_t InverseKeyed(BytesView in,
 *                            BytesView tweak,
 *                            BytesView host_secret,
 *                            BytesSpan out)
 *
 * The non-keyed Forward / Inverse are still required: hosts that
 * choose to wrap the plugin between AEAD layers may opt to call the
 * cheaper deterministic path. For raw-mode safety, return a
 * capabilities mask containing BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE.
 */
#define BASEFWX_PLUGIN_DEFINE_KEYED(plugin_cls, \
                                    id0,id1,id2,id3,id4,id5,id6,id7, \
                                    id8,id9,id10,id11,id12,id13,id14,id15, \
                                    name_literal, version_literal, positions_mask) \
    static const ::basefwx_plugin_vtable kBasefwxPluginVtable = { \
        BASEFWX_PLUGIN_API_VERSION, \
        { id0,id1,id2,id3,id4,id5,id6,id7, \
          id8,id9,id10,id11,id12,id13,id14,id15 }, \
        name_literal, \
        version_literal, \
        (positions_mask), \
        &basefwx::plugin::detail::generic_init<plugin_cls>, \
        &basefwx::plugin::detail::generic_destroy<plugin_cls>, \
        &basefwx::plugin::detail::generic_transform<plugin_cls, /*IsInverse=*/false>, \
        &basefwx::plugin::detail::generic_transform<plugin_cls, /*IsInverse=*/true>, \
        &basefwx::plugin::detail::generic_max_output<plugin_cls>, \
        &basefwx::plugin::detail::generic_selftest<plugin_cls>, \
        &basefwx::plugin::detail::generic_capabilities<plugin_cls>, \
        &basefwx::plugin::detail::generic_transform_keyed<plugin_cls, /*IsInverse=*/false>, \
        &basefwx::plugin::detail::generic_transform_keyed<plugin_cls, /*IsInverse=*/true>, \
        nullptr, \
    }; \
    extern "C" BASEFWX_PLUGIN_EXPORT \
    const ::basefwx_plugin_vtable* basefwx_plugin_entry(void) { \
        return &kBasefwxPluginVtable; \
    } \
    /* eat trailing semicolon */ \
    struct BASEFWX_PLUGIN_DEFINE_KEYED_force_semicolon_##plugin_cls {}

#endif  /* BASEFWX_PLUGIN_HPP */
