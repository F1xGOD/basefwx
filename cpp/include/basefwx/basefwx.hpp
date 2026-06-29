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
#include "basefwx/fwxaes.hpp"
#include "basefwx/livecipher.hpp"
#include "basefwx/an7.hpp"

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

struct KfmCarrierInspectResult {
    std::uint64_t file_size = 0;
    std::size_t payload_len = 0;
    std::uint8_t mode = 0;
    std::uint8_t flags = 0;
    std::string carrier_kind;
    std::string payload_ext;
};

std::vector<std::uint8_t> ReadFile(const std::string& path);
InspectResult InspectBlob(const std::vector<std::uint8_t>& blob);
std::optional<KfmCarrierInspectResult> InspectKfmCarrierFile(const std::string& path);
std::string ResolvePassword(const std::string& input);
void RequireStrongPasswordForEncryption(const std::string& password, std::string_view context = {});

// Deprecated since 3.7.0. b256 was the very first encoding method in
// BaseFWX — born in V1, back when this was a proof of concept and not
// a project. It served from day one. Existing b256-encoded blobs still
// decode; use base64 (stdlib) or Hash512 for new code.
// Retired but loved. 🫡 ❤️  See CHANGELOG for the full retirement note.
[[deprecated("Retired since 3.7.0 — b256 was the first BaseFWX encoding (V1, PoC era). Use base64 / Hash512. Existing blobs still decode.")]]
std::string B256Encode(const std::string& input);
[[deprecated("Retired since 3.7.0 — see B256Encode. Existing blobs still decode.")]]
std::string B256Decode(const std::string& input);
std::string B64Encode(const std::string& input);
std::string B64Decode(const std::string& input);
std::string N10Encode(const std::string& input);
std::string N10Decode(const std::string& input);
std::string Hash512(const std::string& input);
// Deprecated since 3.7.0. `Uhash513` is a non-standard chained hash
// (SHA-256 → SHA-1 → SHA-512 → SHA-256 over the concatenation). The
// embedded SHA-1 step adds no security and uses a hash with known
// collision weaknesses; the overall collision resistance is bounded
// by the outer SHA-256 anyway. The "513" in the name is marketing —
// the output is a 256-bit SHA-256 hex string. Use `Hash512` (SHA-512)
// or SHA3-512 for new code. Existing call sites continue to work.
[[deprecated("Use Hash512 (SHA-512) or SHA3-512 — Uhash513 is a non-standard chain with a SHA-1 hop and a misleading name")]]
std::string Uhash513(const std::string& input);
// Deprecated since 3.7.0. `Bi512Encode` is "SHA-256 with a custom prefilter"
// — the prefilter adds no security beyond SHA-256 itself. Use `Hash512`
// (SHA-512) for new code. The function stays so existing blobs / call
// sites continue to work; expect removal in a future major bump.
[[deprecated("Use Hash512 (SHA-512) — Bi512Encode is SHA-256 with no added security; Uhash513 is also deprecated")]]
std::string Bi512Encode(const std::string& input);

// Deprecated since 3.7.0. `A512Encode` / `A512Decode` are a reversible
// obfuscation codec with no security goal (no key, no AEAD). Slower than
// base64 for the same output. Use base64 for new reversible-encoding
// needs. (Their internal b256 building block is also deprecated as of
// 3.7.0 — see B256Encode.)
[[deprecated("Use base64 — A512 has no security goal and is slower")]]
std::string A512Encode(const std::string& input);
[[deprecated("Use base64 — A512 has no security goal and is slower")]]
std::string A512Decode(const std::string& input);
// B1024Encode removed in 3.7.0 — it was a one-line alias for
// Bi512Encode(A512Encode(input)) that added no security or functionality
// and was a significant chunk of the cross-runtime test-suite runtime.
// Callers that want the same byte-for-byte output should chain the two
// primitives directly.

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
std::string Kfme(const std::string& path, const std::string& output = {}, bool bw_mode = false);
std::string Kfmd(const std::string& path, const std::string& output = {}, bool bw_mode = false);
std::string Kfae(const std::string& path, const std::string& output = {}, bool bw_mode = false);
std::string Kfad(const std::string& path, const std::string& output = {});

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
