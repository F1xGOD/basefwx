/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "basefwx/env.hpp"

namespace basefwx::constants {

#ifndef BASEFWX_VERSION_STRING
#error "BASEFWX_VERSION_STRING must be provided by the build system"
#endif

inline constexpr std::size_t kUserKdfSaltSize = 16;
inline constexpr std::size_t kUserKdfIterations = 600000;
inline constexpr std::size_t kUserKdfIterationsFallback = 32768;
inline constexpr std::uint32_t kArgon2TimeCost = 4;
inline constexpr std::uint32_t kArgon2MemoryCost = 1u << 16;
inline constexpr std::uint32_t kArgon2Parallelism = 4;
inline constexpr std::size_t kMinimumPasswordLength = 10;
inline constexpr std::size_t kShortPasswordMin = 12;
inline constexpr std::size_t kShortPbkdf2Iterations = 1000000;
inline constexpr std::uint32_t kShortArgon2TimeCost = 5;
inline constexpr std::uint32_t kShortArgon2MemoryCost = 1u << 17;

inline constexpr std::uint32_t kHeavyPbkdf2Iterations = 2000000;
inline constexpr std::uint32_t kHeavyArgon2TimeCost = 6;
inline constexpr std::uint32_t kHeavyArgon2MemoryCost = 1u << 18;
inline constexpr std::uint32_t kHeavyArgon2Parallelism = 4;

inline std::uint32_t HeavyPbkdf2Iterations() {
    std::string raw = basefwx::env::Get("BASEFWX_HEAVY_PBKDF2_ITERS");
    if (raw.empty()) {
        raw = basefwx::env::TestKdfIters();
    }
    if (raw.empty()) {
        return kHeavyPbkdf2Iterations;
    }
    try {
        std::uint64_t parsed = static_cast<std::uint64_t>(std::stoul(raw));
        if (parsed == 0) {
            return kHeavyPbkdf2Iterations;
        }
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            return std::numeric_limits<std::uint32_t>::max();
        }
        return static_cast<std::uint32_t>(parsed);
    } catch (const std::exception&) {
        return kHeavyPbkdf2Iterations;
    }
}

// 3.7.0: parallelism is fixed at the compile-time constant (4 / 4) so
// blobs are portable across hosts. The wire format carries the salt
// and KDF label, but NOT the Argon2 parallelism lane count; previously
// every runtime resolved it from std::thread::hardware_concurrency()
// at decrypt time, so a blob encrypted on a 16-core machine could not
// be decrypted on a 4-core machine without the caller explicitly
// pinning argon2_parallelism via KdfOptions. Callers who deliberately
// want host-tuned parallelism can still set it on KdfOptions before
// the encrypt — the default now just stops silently varying.
inline std::uint32_t DefaultArgon2Parallelism() {
    return kArgon2Parallelism;
}

inline std::uint32_t DefaultHeavyArgon2Parallelism() {
    return kHeavyArgon2Parallelism;
}

inline constexpr std::size_t kAeadNonceLen = 12;
inline constexpr std::size_t kAeadTagLen = 16;
inline constexpr std::size_t kEphemeralKeyLen = 32;
inline constexpr std::size_t kUserWrapFixedLen = kUserKdfSaltSize + kAeadNonceLen + kAeadTagLen + kEphemeralKeyLen;

inline constexpr std::size_t kStreamChunkSize = 1u << 20;
inline constexpr std::size_t kStreamThreshold = 250u * 1024u;
inline constexpr std::size_t kPerfObfuscationThreshold = 1u << 20;
inline constexpr std::size_t kHkdfMaxLen = 255u * 32u;
inline constexpr std::size_t kOfbFastMin = 64u * 1024u;
inline constexpr std::size_t kPermFastMin = 4u * 1024u;

inline constexpr std::string_view kFwxDelim = "\x1f\x1e";
inline constexpr std::string_view kFwxHeavyDelim = "\x1f\x1d";
inline constexpr std::string_view kLegacyFwxDelim = "A8igTOmG";
inline constexpr std::string_view kLegacyFwxHeavyDelim = "673827837628292873";
inline constexpr std::string_view kMetaDelim = "::FWX-META::";
inline constexpr std::string_view kPackMetaKey = "ENC-P";
inline constexpr std::string_view kPackTgzExt = ".tgz";
inline constexpr std::string_view kPackTxzExt = ".txz";
inline constexpr std::string_view kEngineVersion = BASEFWX_VERSION_STRING;

inline constexpr std::string_view kMasterPqAlg = "ml-kem-768";
inline constexpr std::string_view kMasterPqAlgHigh = "ml-kem-1024";
// 3.7.0: master public key is no longer baked into release artifacts. Each
// deployment configures its own master key via BASEFWX_MASTER_PQ_PUB=<path>
// (runtime) or, for fleet builds that want a baked-in key, the
// BASEFWX_MASTER_PQ_PUB_B64 CMake option (build-time). Empty by default.
#ifndef BASEFWX_MASTER_PQ_PUB_B64
#define BASEFWX_MASTER_PQ_PUB_B64 ""
#endif
inline constexpr std::string_view kMasterPqPublicB64 = BASEFWX_MASTER_PQ_PUB_B64;
inline constexpr std::string_view kMasterEcMagic = "EC1";

inline constexpr std::string_view kStreamMagic = "STRMOBF1";

inline constexpr std::string_view kImageCipherStreamInfo = "basefwx.imagecipher.stream.v1";
inline constexpr std::string_view kImageCipherArchiveInfo = "basefwx.imagecipher.archive.v1";
inline constexpr std::string_view kImageCipherTrailerMagic = "JMG0";
inline constexpr std::string_view kImageCipherKeyTrailerMagic = "JMG1";
inline constexpr std::string_view kJmgKeyMagic = "JMGK";
inline constexpr std::uint8_t kJmgKeyVersionLegacy = 1;
inline constexpr std::uint8_t kJmgKeyVersion = 2;
inline constexpr std::uint8_t kJmgSecurityProfileLegacy = 0;
inline constexpr std::uint8_t kJmgSecurityProfileMax = 1;
inline constexpr std::uint8_t kJmgSecurityProfileDefault = kJmgSecurityProfileMax;
inline constexpr std::string_view kJmgMaskInfo = "basefwx.jmg.mask.v1";
inline constexpr std::string_view kFwxAesAad = "fwxAES";
inline constexpr std::string_view kFwxAesMaskInfo = "basefwx.fwxaes.mask.v1";
inline constexpr std::string_view kFwxAesKeyInfo = "basefwx.fwxaes.key.v1";
inline constexpr std::string_view kFwxAesPayloadAeadInfo = "basefwx.fwxaes.payload.aead.v1";
inline constexpr std::string_view kFwxAesPayloadObfInfo = "basefwx.fwxaes.payload.obf.v1";

inline constexpr std::string_view kLiveFrameMagic = "LIVE";
inline constexpr std::uint8_t kLiveFrameVersion = 1;
inline constexpr std::uint8_t kLiveFrameTypeHeader = 1;
inline constexpr std::uint8_t kLiveFrameTypeData = 2;
inline constexpr std::uint8_t kLiveFrameTypeFin = 3;
inline constexpr std::uint8_t kLiveKeyModePbkdf2 = 1;
inline constexpr std::uint8_t kLiveKeyModeWrap = 2;
inline constexpr std::size_t kLiveNoncePrefixLen = 4;
inline constexpr std::size_t kLiveFrameHeaderLen = 18;
inline constexpr std::size_t kLiveHeaderFixedLen = 12;
inline constexpr std::size_t kLiveMaxBody = 1u << 30;

inline constexpr std::string_view kB512MaskInfo = "basefwx.b512.mask.v1";
inline constexpr std::string_view kPb512MaskInfo = "basefwx.pb512.mask.v1";
inline constexpr std::string_view kB512StreamInfo = "basefwx.b512.stream.v1";
inline constexpr std::string_view kPb512StreamInfo = "basefwx.pb512.stream.v1";
inline constexpr std::string_view kB512FileMaskInfo = "basefwx.b512file.mask.v1";
inline constexpr std::string_view kB512AeadInfo = "basefwx.b512file.v1";

inline constexpr std::string_view kObfInfoMask = "basefwx.obf.mask.v1";
inline constexpr std::string_view kObfInfoPerm = "basefwx.obf.perm.v1";
inline constexpr std::string_view kKemInfo = "basefwx.kem.v1";

inline constexpr std::string_view kStreamInfoKey = "basefwx.stream.obf.key.v1";
inline constexpr std::string_view kStreamInfoIv = "basefwx.stream.obf.iv.v1";
inline constexpr std::string_view kStreamInfoPerm = "basefwx.stream.obf.perm.v1";

inline constexpr std::string_view kMaskAadB512 = "b512";
inline constexpr std::string_view kMaskAadPb512 = "pb512";
inline constexpr std::string_view kMaskAadB512File = "b512file";
inline constexpr std::string_view kMaskAadJmg = "jmg";

}  // namespace basefwx::constants
