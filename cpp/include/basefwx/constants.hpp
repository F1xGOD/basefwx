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
inline constexpr std::string_view kEngineVersion = "3.5.2";

inline constexpr std::string_view kMasterPqAlg = "ml-kem-768";
inline constexpr std::string_view kMasterPqPublicB64 = R"(eJwBoARf+9Kzz6BzXHi8fntsVzKBAxCzV6VTNfbCvfAqh+jMdEfccE7UR4Nnbl+roH3ML55Adeabfs6kZ3CgSZijRTWJDbaUXj+LX391QXOnTa7rNEg1qTaxSa1DKmFZwY+kCRlyjP8BWUY0P9c2NLHDiHlBObDRjUyWrbb1YdiJXfITJz3bvBlnRLTQIRSpH042LZy1CwpQT+C0ISO5tc9qkDocWZ3Jx8+Avd0KcY2TP8rcCY4kY/7JR4xWiRV6e1wnz3BnQxdivx4jPusMo8VnlInHhYlSJvEIHDgqo5WjScSIKkT0UNXknxWgb5mpoB/poD4gtyCWA57iGarFM6k3oZZnRjMilMAwvQ8bGCRxnDLsnJPCEpTkDP2Ek7LDSGv6KaG3ManmIaAoZH4mpxAmePaRkTSKYuE7vMeVqeyxl394QUZrfi/YirIhfom6SYIChFzlAgHAZCPMx+9FVzmVxicnvlKRPCWITkFRnkVraxZ8x9S4OR9HzT4G0BEsj/sKOY5VeAi6c82ricH6HnaJB+eEvhjiTssSoxnBX9vUbftnLjFqTMPctY1DgmTabWz1U23rffPSqo0zeDxIlR0FD1foxs9gc9JSR/MChL2ZzFLAUqq7QBPWxHsrjN8VO86FyG64VncSQvtwEPR5kRQgEgoBkqsHHnOVBov3le/mB9oBbPDzCTw7rPchTzNWVvwDOS/bfkmQIlOKKENZLvMInF6ktaLGiAzhy0eob5g7dMFwLCnDU/iQjQqZbyIMVCqMuBlgTFHhPWgKErNwcnIMPEoYg+mstgJIq272I7VCX9usoSjWXZX6SViIpg8FrS2RFCzmXPEpbCQHcg9arbxCD+cZIWfxVmxFx1y4Od2Eb/FkZTt6Maq4zMNalRfBjX/0C0C1aetQWiJ8HCvkZufLlYwAwovRJE+7wkXDgQLMe6dwzzo6ydEJM32kJBuzhjxjMGd4BY8JGKzKVBeJhsMLaViBGw5SEiXWgZhUbECktcJDrfc6r8PBgcQwV1TpU3pTcNNHFt1YoAMCpO9XdO7cDfnbaqRbBUY0hr3sI3P0x962F7rkR45xEGzFZp9XfmsRmG5qHfSTk4EGyS0cdFoDZ51Rvw/4e738wo4QRJGkDBGagROXzbwnmpSpV+cxXvK0Su5FIaGhJQHJqTQTv94Gy710eE43GffqEuT6D4X6mRclSBNGTepgGq6laanzJSp3UcVwFZwCNjdbCB+ycdkqR77muhUgnxHAcZvRf4oXx0pnkGx2Px/gvvAaZGLmqv16jFFZj3pocKlIrVBiSduoYy/CBkehUQDoeykgZs73zhGklAi1NBTBkXjgasYySO2UuS8bSINJfKLqUHOsfbB6sEOLilCaPfCcRtqafMqYJwdXW+KwgpmXqbV0I+nyqAVMIpRmwMYjpBxEkV5CMRgHyEnMr2cBXuv8RcjZfLmMbCATfNcJdEuQUXDjfE4nr94DHERSk8y3IkE7paIUbGV4jgGnFtEYUiZ6ADewLTFDDTmFpRA7jCjytuukSqmmdchYYLIgQnRmTRk3AZbnMbwxkgwy86skVNZZYldaxFdWvulRMd1FgnQn5Q==)";

inline constexpr std::string_view kStreamMagic = "STRMOBF1";

inline constexpr std::string_view kImageCipherStreamInfo = "basefwx.imagecipher.stream.v1";
inline constexpr std::string_view kImageCipherArchiveInfo = "basefwx.imagecipher.archive.v1";
inline constexpr std::string_view kImageCipherTrailerMagic = "JMG0";

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

}  // namespace basefwx::constants
