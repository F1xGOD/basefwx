/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * --- Commercial-license-only API surface ----------------------------
 *
 * Statically linking BaseFWX into a closed-source binary is OUTSIDE
 * the Plugin Exception (which requires a separately shipped .so/.dll
 * /.jar). See LICENSING.md. Using this header to register an
 * in-process plugin against a statically-linked BaseFWX requires a
 * commercial license from FixCraft Inc. (`admin@fixcraft.jp`).
 *
 * GPL-3.0 users with a dynamically-loaded BaseFWX library may still
 * call this header to register additional in-process plugins
 * alongside dlopen'd ones — that combination stays inside the free
 * track. The license boundary is on how BaseFWX itself is linked
 * into the host, not on whether plugins are registered statically.
 */

#ifndef BASEFWX_PLUGIN_STATIC_HPP
#define BASEFWX_PLUGIN_STATIC_HPP

#include "basefwx/plugin.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace basefwx::plugin {

/*
 * In-process plugin registry. Lets the host code-link a plugin's
 * `basefwx_plugin_entry()` symbol (or any pointer to a static
 * basefwx_plugin_vtable) at build time and resolve it by plugin_id
 * at runtime, with NO .so / .dll on disk.
 *
 * Threat-model implication: a statically embedded plugin is harder
 * to extract from the host binary than a separate .so, BUT extraction
 * cost is NOT cryptographic security. A determined attacker with
 * the binary will eventually recover the transform. The actual
 * protection against oracle attacks comes from making the plugin
 * KEYED — see forward_keyed / inverse_keyed in plugin.h and
 * examples/plugins/THREAT_MODEL.md.
 *
 * Static embedding without keyed semantics raises the bar against
 * casual reverse engineering. It does NOT raise the bar against
 * adversaries with debugger access or willingness to write a
 * disassembler script.
 */
class Registry {
public:
    static constexpr std::size_t kPluginIdLen = BASEFWX_PLUGIN_ID_LEN;
    using PluginId = std::array<std::uint8_t, kPluginIdLen>;

    /* Process-wide singleton. */
    static Registry& Instance() noexcept {
        static Registry r;
        return r;
    }

    /*
     * Register an in-process plugin. The vtable pointer must remain
     * valid for the lifetime of the process (typical: it's a
     * `static const basefwx_plugin_vtable` from the plugin source
     * compiled into the host binary).
     *
     * Returns false if:
     *   - vtable is nullptr
     *   - vtable->api_version != BASEFWX_PLUGIN_API_VERSION
     *   - a plugin with the same plugin_id is already registered
     *
     * Idempotent under retry with the SAME pointer — a re-register
     * of an already-registered vtable returns true (helps with
     * libraries that may be loaded multiple times in odd build
     * configurations).
     */
    bool Register(const ::basefwx_plugin_vtable* vtable) noexcept {
        if (vtable == nullptr) return false;
        if (vtable->api_version != BASEFWX_PLUGIN_API_VERSION) return false;
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& e : entries_) {
            if (std::memcmp(e.id.data(), vtable->plugin_id, kPluginIdLen) == 0) {
                return e.vtable == vtable;  // idempotent for identical re-register
            }
        }
        Entry e;
        std::memcpy(e.id.data(), vtable->plugin_id, kPluginIdLen);
        e.vtable = vtable;
        entries_.push_back(e);
        return true;
    }

    /*
     * Resolve a plugin by its 16-byte ID. Returns nullptr if no
     * matching plugin is registered.
     *
     * Host loaders should call this BEFORE falling back to dlopen()
     * so that an embedded plugin always wins over a same-ID plugin
     * file on disk (avoids the substitution attack where an
     * attacker drops a malicious .so with a known plugin ID into
     * the search path).
     */
    const ::basefwx_plugin_vtable* Find(const std::uint8_t id[kPluginIdLen]) const noexcept {
        if (id == nullptr) return nullptr;
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& e : entries_) {
            if (std::memcmp(e.id.data(), id, kPluginIdLen) == 0) {
                return e.vtable;
            }
        }
        return nullptr;
    }

    const ::basefwx_plugin_vtable* Find(const PluginId& id) const noexcept {
        return Find(id.data());
    }

    /* Diagnostic accessor — returns a snapshot of registered IDs.
     * Order is registration order. */
    std::vector<PluginId> RegisteredIds() const {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<PluginId> out;
        out.reserve(entries_.size());
        for (const auto& e : entries_) out.push_back(e.id);
        return out;
    }

    std::size_t Count() const noexcept {
        std::lock_guard<std::mutex> lock(mu_);
        return entries_.size();
    }

private:
    struct Entry {
        PluginId id{};
        const ::basefwx_plugin_vtable* vtable = nullptr;
    };

    Registry() = default;
    Registry(const Registry&) = delete;
    Registry& operator=(const Registry&) = delete;

    mutable std::mutex mu_;
    std::vector<Entry> entries_;
};

/*
 * BASEFWX_PLUGIN_REGISTER_STATIC(vtable_expr)
 *
 * Drop this at file scope in your host binary (or in the plugin
 * source you're compiling into your host) to register the vtable at
 * program startup. `vtable_expr` is any expression that evaluates
 * to a `const basefwx_plugin_vtable*`, typically
 * `basefwx_plugin_entry()` of the plugin TU.
 *
 * Example:
 *
 *   extern "C" const basefwx_plugin_vtable* basefwx_plugin_entry(void);
 *   BASEFWX_PLUGIN_REGISTER_STATIC(basefwx_plugin_entry());
 *
 * Failure to register (e.g. duplicate plugin_id, ABI mismatch)
 * leaves the registry unchanged; the host loader will then fail to
 * resolve the plugin and surface a clear error at first use rather
 * than silently dispatching to the wrong vtable.
 */
#define BASEFWX_PLUGIN_REGISTER_STATIC(vtable_expr) \
    namespace { \
        const bool basefwx_plugin_static_registered_ ## __LINE__ = \
            ::basefwx::plugin::Registry::Instance().Register(vtable_expr); \
    } \
    struct BASEFWX_PLUGIN_REGISTER_STATIC_force_semicolon_ ## __LINE__ {}

}  // namespace basefwx::plugin

#endif  /* BASEFWX_PLUGIN_STATIC_HPP */
