#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <thread>

#include "basefwx/env.hpp"

namespace basefwx::constants {

inline constexpr std::size_t kUserKdfSaltSize = 16;
inline constexpr std::size_t kUserKdfIterations = 200000;
inline constexpr std::size_t kUserKdfIterationsFallback = 32768;
inline constexpr std::uint32_t kArgon2TimeCost = 3;
inline constexpr std::uint32_t kArgon2MemoryCost = 1u << 15;
inline constexpr std::uint32_t kArgon2Parallelism = 4;
inline constexpr std::size_t kShortPasswordMin = 12;
inline constexpr std::size_t kShortPbkdf2Iterations = 400000;
inline constexpr std::uint32_t kShortArgon2TimeCost = 4;
inline constexpr std::uint32_t kShortArgon2MemoryCost = 1u << 16;

inline constexpr std::uint32_t kHeavyPbkdf2Iterations = 1000000;
inline constexpr std::uint32_t kHeavyArgon2TimeCost = 5;
inline constexpr std::uint32_t kHeavyArgon2MemoryCost = 1u << 17;
inline constexpr std::uint32_t kHeavyArgon2Parallelism = 4;

inline std::uint32_t HeavyPbkdf2Iterations() {
    std::string raw = basefwx::env::Get("BASEFWX_HEAVY_PBKDF2_ITERS");
    if (raw.empty()) {
        raw = basefwx::env::Get("BASEFWX_TEST_KDF_ITERS");
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

inline std::uint32_t DefaultArgon2Parallelism() {
    auto count = std::thread::hardware_concurrency();
    return count > 0 ? count : kArgon2Parallelism;
}

inline std::uint32_t DefaultHeavyArgon2Parallelism() {
    auto count = std::thread::hardware_concurrency();
    return count > 0 ? count : kHeavyArgon2Parallelism;
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
inline constexpr std::string_view kEngineVersion = "3.6.2";

inline constexpr std::string_view kMasterPqAlg = "ml-kem-768";
inline constexpr std::string_view kMasterPqPublicB64 = R"(eJwBoARf+/rkrYxhXn0CNFqTkzQUrIYloydzGrqpIuWXi+qnLO/XRnspzQBDwwTKLW3Ku6Zwii1AfriFM5t8PtugqMNFt/5HoHxIZLGkytTWKP3IKoP7EH2HFu14b5bagh+KIFTWoW12qZqLRNjJLBHZmzxasEIsN7AnsOiokMHxt4XwoLk5fscIhXSANBZpHUVEO+NkBhg5UnvzWkzAqPm6rEvCfE+CHxgFg1SjBJeFfVMyzpKpsUi6iCGXSl6nZuTkr10btfi8RHCEfxDrfhcJk0bsKMWEI6wVY23KQXXlmcJ4VydGZ/ZbjWhVbX6bo0DKqG5IlwpTDPJIwlumRpxbBog8JG10p8PTaRJEAKfiVo7jiD1Aki7hYqmyyBn2Q0RFy03Bm/Rpy1zlK3DahaaoMj1mJrJ5ff2FYYVsBQbrywcDUcdHUkIpUqwrrRyqdEIHq1T6AiKHmf2KHTXQnLuZpJ3Ih59bkH1GC2UzbEIWzFSImvQDkswCBW9cF0tFYCNnReiReb57XAjaW3smdOg1o9oyk2IbyptJtNe1teHoPsMJkBGin/ugUeFmEOa0f8lTEmK4u1/GxHrQxD65kxm2IHT4NPM8Z5oqQ9z0WthUE5MouNrZLK8EltZQzAcZJ/g7CesRi40qFecyD14hDPBcr6cEV6yqOXXrcDRQVCUhuYRyUNqrFe4JPks2kZlxXjABHMD1PHVzfJpsAtsTDJa2EdpoAkKRvfg2QOK6CpYix6zIyB1yGwdCG8L2QS9DQefDQntXDlwSIieqRrwmiWcba4mSgwfxsoH2SIbQPZKbtEA4XNGqen1CcldAw1w2mnO3otspreJEBZJjVSihGcoyVjWap9dWc0pLffeDC5mUyOTzWUQ3XBAxX817G9rIbFyMQ+4AdeP2zL/nk9s2wYuZT2MEbwTHW/6UJQXbRf+svg9Kq//ryl/YRiaxdK2xRkP7oaBBVbyyXxYUJEhXOD7cUar8HsGZlXmiDSxzCBZSJG+4ooAgOKfEx6liOvqHBQKrsG4ylg3JQqmKBUdXcf6cMImRqS4MFM23vQkSPqIckxGgkrJGDKLGg8DKsuOqUvkzexAWviAIJQZsJsqjUl2stBgnltsyysE2cdI5Poh7KgOFV27bfi4iCpFSXc46Aa2jjN0WFYAgfhcRXgvIanJ3L8/sPrR7QKvpTtPFSfdcBipqp8vRdYImF5HceU1TU+QwtOcmCKDmaDTBGtJLZDXYJ3/2VQAEr8Mhk1WxGQsWUikZBi9pHTTbh93gvl9gLaGlxlRCjwzSqcJVXF80UiVMA06hfDnzi9MFpIGZL0czax+1zwdLFsnnHLGLzm/YpgrUBIk0gTgMVhqiu0+JyagxwrXCsDmGbhj8PzJGUeR8xhoxzOtTMgtaFwekbEAss+JGzuZJeakDxhMJEvvbKabIFDeQLsImO4eaAslqXyNoSg7AtnDlHfzTTFvwk2/UppeXNmcEC9n1UyfyWNW6qAZRJe5zQkijzLfkGKWsR/ksjmUQwMHwOOWVQ8qqUapYxsmbZkosPBXRDNBhY6PNjfciD2hRoIqrd/pnkJ6cZd1FQyxge6FA3PMpHw==)";
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
inline constexpr std::string_view kFwxAesMaskInfo = "basefwx.fwxaes.mask.v1";
inline constexpr std::string_view kFwxAesKeyInfo = "basefwx.fwxaes.key.v1";

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
