#include "basefwx/obfuscation.hpp"

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif

#include <openssl/evp.h>

namespace basefwx::obf {

namespace {

using basefwx::constants::kPermFastMin;

constexpr std::uint64_t kSplitMix64Increment = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t kSplitMix64Mul1 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t kSplitMix64Mul2 = 0x94D049BB133111EBULL;

constexpr std::uint32_t kInitA = 0x43b0d7e5U;
constexpr std::uint32_t kInitB = 0x8b51f9ddU;
constexpr std::uint32_t kMultA = 0x931e8875U;
constexpr std::uint32_t kMultB = 0x58f38dedU;
constexpr std::uint32_t kMixMultL = 0xca01f9ddU;
constexpr std::uint32_t kMixMultR = 0x4973f715U;
constexpr std::uint32_t kXShift = 16U;

constexpr std::uint64_t kPcgMultiplierHigh = 2549297995355413924ULL;
constexpr std::uint64_t kPcgMultiplierLow = 4865540595714422341ULL;

#if defined(_MSC_VER) && !defined(__clang__)
struct UInt128 {
    std::uint64_t hi;
    std::uint64_t lo;
};

UInt128 MakeUInt128(std::uint64_t hi, std::uint64_t lo) {
    return {hi, lo};
}

UInt128 Add128(UInt128 a, UInt128 b) {
    UInt128 out;
    out.lo = a.lo + b.lo;
    out.hi = a.hi + b.hi + (out.lo < a.lo ? 1ULL : 0ULL);
    return out;
}

UInt128 ShiftLeft1(UInt128 value) {
    UInt128 out;
    out.hi = (value.hi << 1) | (value.lo >> 63);
    out.lo = value.lo << 1;
    return out;
}

UInt128 Mul128(UInt128 a, UInt128 b) {
    std::uint64_t hi0 = 0;
    std::uint64_t lo0 = _umul128(a.lo, b.lo, &hi0);
    std::uint64_t hi_dummy = 0;
    std::uint64_t lo1 = _umul128(a.lo, b.hi, &hi_dummy);
    std::uint64_t lo2 = _umul128(a.hi, b.lo, &hi_dummy);
    UInt128 out;
    out.lo = lo0;
    out.hi = hi0 + lo1 + lo2;
    return out;
}
#endif

std::uint64_t SplitMix64(std::uint64_t& state) {
    std::uint64_t z = state + kSplitMix64Increment;
    state = z;
    std::uint64_t x = z;
    x = (x ^ (x >> 30)) * kSplitMix64Mul1;
    x = (x ^ (x >> 27)) * kSplitMix64Mul2;
    x ^= x >> 31;
    return x;
}

std::uint64_t Rotr64(std::uint64_t x, std::uint64_t r) {
    return (x >> r) | (x << ((64 - r) & 63));
}

std::uint32_t HashMix(std::uint32_t value, std::uint32_t& hash_const) {
    value ^= hash_const;
    hash_const = static_cast<std::uint32_t>(static_cast<std::uint64_t>(hash_const) * kMultA);
    value = static_cast<std::uint32_t>(static_cast<std::uint64_t>(value) * hash_const);
    value ^= value >> kXShift;
    return value;
}

std::uint32_t Mix32(std::uint32_t x, std::uint32_t y) {
    std::uint32_t result = static_cast<std::uint32_t>(
        static_cast<std::uint64_t>(kMixMultL) * x -
        static_cast<std::uint64_t>(kMixMultR) * y
    );
    result ^= result >> kXShift;
    return result;
}

std::vector<std::uint32_t> IntToUint32Array(std::uint64_t n) {
    std::vector<std::uint32_t> out;
    if (n == 0) {
        out.push_back(0);
        return out;
    }
    while (n > 0) {
        out.push_back(static_cast<std::uint32_t>(n & 0xFFFFFFFFULL));
        n >>= 32;
    }
    return out;
}

std::array<std::uint32_t, 4> SeedPool(std::uint64_t entropy) {
    std::array<std::uint32_t, 4> pool{};
    std::vector<std::uint32_t> entropy_array = IntToUint32Array(entropy);
    std::uint32_t hash_const = kInitA;

    for (std::size_t i = 0; i < pool.size(); ++i) {
        if (i < entropy_array.size()) {
            pool[i] = HashMix(entropy_array[i], hash_const);
        } else {
            pool[i] = HashMix(0, hash_const);
        }
    }

    for (std::size_t i_src = 0; i_src < pool.size(); ++i_src) {
        for (std::size_t i_dst = 0; i_dst < pool.size(); ++i_dst) {
            if (i_src == i_dst) {
                continue;
            }
            pool[i_dst] = Mix32(pool[i_dst], HashMix(pool[i_src], hash_const));
        }
    }

    for (std::size_t i_src = pool.size(); i_src < entropy_array.size(); ++i_src) {
        for (std::size_t i_dst = 0; i_dst < pool.size(); ++i_dst) {
            pool[i_dst] = Mix32(pool[i_dst], HashMix(entropy_array[i_src], hash_const));
        }
    }
    return pool;
}

std::string_view AsStringView(const Bytes& data) {
    if (data.empty()) {
        return {};
    }
    return std::string_view(reinterpret_cast<const char*>(data.data()), data.size());
}

std::array<std::uint64_t, 4> SeedSequenceState(std::uint64_t entropy) {
    std::array<std::uint32_t, 4> pool = SeedPool(entropy);
    std::array<std::uint32_t, 8> state32{};
    std::uint32_t hash_const = kInitB;
    for (std::size_t i = 0; i < state32.size(); ++i) {
        std::uint32_t data_val = pool[i % pool.size()];
        data_val ^= hash_const;
        hash_const = static_cast<std::uint32_t>(static_cast<std::uint64_t>(hash_const) * kMultB);
        data_val = static_cast<std::uint32_t>(static_cast<std::uint64_t>(data_val) * hash_const);
        data_val ^= data_val >> kXShift;
        state32[i] = data_val;
    }
    std::array<std::uint64_t, 4> state64{};
    for (std::size_t i = 0; i < state64.size(); ++i) {
        state64[i] = static_cast<std::uint64_t>(state32[i * 2])
                     | (static_cast<std::uint64_t>(state32[i * 2 + 1]) << 32);
    }
    return state64;
}

class Pcg64Rng {
public:
    explicit Pcg64Rng(std::uint64_t seed) {
        std::array<std::uint64_t, 4> state = SeedSequenceState(seed);
        Seed(state[0], state[1], state[2], state[3]);
        has_uint32_ = false;
        uinteger_ = 0;
        Next64();  // Align with NumPy PCG64 output sequence.
    }

    std::uint64_t Next64() {
#if defined(_MSC_VER) && !defined(__clang__)
        UInt128 old_state = state_;
        Step();
        std::uint64_t high = old_state.hi;
        std::uint64_t low = old_state.lo;
#else
        __uint128_t old_state = state_;
        Step();
        std::uint64_t high = static_cast<std::uint64_t>(old_state >> 64);
        std::uint64_t low = static_cast<std::uint64_t>(old_state);
#endif
        std::uint64_t xorshifted = high ^ low;
        std::uint64_t rot = high >> 58u;
        return Rotr64(xorshifted, rot);
    }

    std::uint32_t Next32() {
        if (has_uint32_) {
            has_uint32_ = false;
            return uinteger_;
        }
        std::uint64_t next = Next64();
        has_uint32_ = true;
        uinteger_ = static_cast<std::uint32_t>(next >> 32);
        return static_cast<std::uint32_t>(next & 0xFFFFFFFFu);
    }

    std::uint64_t RandomInterval(std::uint64_t max) {
        if (max == 0) {
            return 0;
        }
        std::uint64_t mask = max;
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;
        mask |= mask >> 32;
        if (max <= 0xFFFFFFFFu) {
            std::uint64_t value = 0;
            do {
                value = static_cast<std::uint64_t>(Next32()) & mask;
            } while (value > max);
            return value;
        }
        std::uint64_t value = 0;
        do {
            value = Next64() & mask;
        } while (value > max);
        return value;
    }

private:
    void Seed(std::uint64_t seed_high,
              std::uint64_t seed_low,
              std::uint64_t inc_high,
              std::uint64_t inc_low) {
#if defined(_MSC_VER) && !defined(__clang__)
        UInt128 initstate = MakeUInt128(seed_high, seed_low);
        UInt128 initseq = MakeUInt128(inc_high, inc_low);
        state_ = {0, 0};
        inc_ = ShiftLeft1(initseq);
        inc_.lo |= 1ULL;
        Step();
        state_ = Add128(state_, initstate);
        Step();
#else
        __uint128_t initstate = (static_cast<__uint128_t>(seed_high) << 64) | seed_low;
        __uint128_t initseq = (static_cast<__uint128_t>(inc_high) << 64) | inc_low;
        state_ = 0;
        inc_ = (initseq << 1) | 1;
        Step();
        state_ += initstate;
        Step();
#endif
    }

    void Step() {
#if defined(_MSC_VER) && !defined(__clang__)
        UInt128 multiplier = MakeUInt128(kPcgMultiplierHigh, kPcgMultiplierLow);
        state_ = Add128(Mul128(state_, multiplier), inc_);
#else
        const __uint128_t multiplier =
            (static_cast<__uint128_t>(kPcgMultiplierHigh) << 64) | kPcgMultiplierLow;
        state_ = state_ * multiplier + inc_;
#endif
    }

#if defined(_MSC_VER) && !defined(__clang__)
    UInt128 state_{0, 0};
    UInt128 inc_{0, 0};
#else
    __uint128_t state_{0};
    __uint128_t inc_{0};
#endif
    bool has_uint32_{false};
    std::uint32_t uinteger_{0};
};

std::uint64_t Seed64FromBytes(const Bytes& seed_bytes) {
    if (seed_bytes.size() < 8) {
        return 0;
    }
    std::uint64_t out = 0;
    std::size_t start = seed_bytes.size() - 8;
    for (std::size_t i = 0; i < 8; ++i) {
        out = (out << 8) | seed_bytes[start + i];
    }
    return out;
}

void RotateLeftInPlace(Bytes& data, std::uint8_t rotation) {
    if (rotation == 0) {
        return;
    }
    for (auto& byte : data) {
        byte = static_cast<std::uint8_t>((byte << rotation) | (byte >> (8 - rotation)));
    }
}

void RotateRightInPlace(Bytes& data, std::uint8_t rotation) {
    if (rotation == 0) {
        return;
    }
    for (auto& byte : data) {
        byte = static_cast<std::uint8_t>((byte >> rotation) | (byte << (8 - rotation)));
    }
}

void SwapNibblesInPlace(Bytes& data) {
    for (auto& byte : data) {
        byte = static_cast<std::uint8_t>((byte >> 4) | ((byte & 0x0F) << 4));
    }
}

void PermuteInPlace(Bytes& data, std::uint64_t seed) {
    std::size_t n = data.size();
    if (n < 2) {
        return;
    }
    if (n >= kPermFastMin) {
        Pcg64Rng rng(seed);
        for (std::size_t i = n - 1; i > 0; --i) {
            std::size_t j = static_cast<std::size_t>(rng.RandomInterval(i));
            if (j != i) {
                std::swap(data[i], data[j]);
            }
        }
        return;
    }
    std::uint64_t state = seed;
    for (std::size_t i = n - 1; i > 0; --i) {
        std::uint64_t rnd = SplitMix64(state);
        std::size_t j = static_cast<std::size_t>(rnd % (i + 1));
        if (j != i) {
            std::swap(data[i], data[j]);
        }
    }
}

void UnpermuteInPlace(Bytes& data, std::uint64_t seed) {
    std::size_t n = data.size();
    if (n < 2) {
        return;
    }
    if (n >= kPermFastMin) {
        Pcg64Rng rng(seed);
        std::vector<std::size_t> swaps(n);
        for (std::size_t i = n - 1; i > 0; --i) {
            std::size_t j = static_cast<std::size_t>(rng.RandomInterval(i));
            swaps[i] = j;
        }
        for (std::size_t i = 1; i < n; ++i) {
            std::size_t j = swaps[i];
            if (j != i) {
                std::swap(data[i], data[j]);
            }
        }
        return;
    }
    std::vector<std::pair<std::size_t, std::size_t>> swaps;
    std::uint64_t state = seed;
    for (std::size_t i = n - 1; i > 0; --i) {
        std::uint64_t rnd = SplitMix64(state);
        std::size_t j = static_cast<std::size_t>(rnd % (i + 1));
        swaps.emplace_back(i, j);
    }
    for (auto it = swaps.rbegin(); it != swaps.rend(); ++it) {
        if (it->first != it->second) {
            std::swap(data[it->first], data[it->second]);
        }
    }
}

Bytes BuildInfoWithLength(std::string_view prefix, std::size_t length) {
    Bytes info(prefix.begin(), prefix.end());
    std::array<std::uint8_t, 8> len_bytes{};
    std::uint64_t len = static_cast<std::uint64_t>(length);
    for (int i = 7; i >= 0; --i) {
        len_bytes[i] = static_cast<std::uint8_t>(len & 0xFF);
        len >>= 8;
    }
    info.insert(info.end(), len_bytes.begin(), len_bytes.end());
    return info;
}

void XorKeystreamInPlace(Bytes& buf, const Bytes& key, std::string_view info) {
    if (buf.empty()) {
        return;
    }
    Bytes block_key = basefwx::crypto::HkdfSha256(key, info, 32);
    std::array<std::uint8_t, 8> len_bytes{};
    std::uint64_t len = static_cast<std::uint64_t>(buf.size());
    for (int i = 7; i >= 0; --i) {
        len_bytes[i] = static_cast<std::uint8_t>(len & 0xFF);
        len >>= 8;
    }
    std::size_t offset = 0;
    std::uint64_t ctr = 0;
    while (offset < buf.size()) {
        std::array<std::uint8_t, 8> ctr_bytes{};
        std::uint64_t ctr_value = ctr;
        for (int i = 7; i >= 0; --i) {
            ctr_bytes[i] = static_cast<std::uint8_t>(ctr_value & 0xFF);
            ctr_value >>= 8;
        }
        Bytes data(info.begin(), info.end());
        data.insert(data.end(), len_bytes.begin(), len_bytes.end());
        data.insert(data.end(), ctr_bytes.begin(), ctr_bytes.end());
        Bytes block = basefwx::crypto::HmacSha256(block_key, data);
        std::size_t take = std::min<std::size_t>(block.size(), buf.size() - offset);
        for (std::size_t i = 0; i < take; ++i) {
            buf[offset + i] = static_cast<std::uint8_t>(buf[offset + i] ^ block[i]);
        }
        offset += take;
        ctr += 1;
    }
}

struct ChunkParams {
    std::uint64_t seed;
    std::uint8_t rotation;
    bool swap;
};

ChunkParams NextParams(const Bytes& perm_material, std::size_t& chunk_index) {
    std::array<std::uint8_t, 8> idx_bytes{};
    std::uint64_t idx = static_cast<std::uint64_t>(chunk_index);
    for (int i = 7; i >= 0; --i) {
        idx_bytes[i] = static_cast<std::uint8_t>(idx & 0xFF);
        idx >>= 8;
    }
    Bytes info(constants::kStreamInfoPerm.begin(), constants::kStreamInfoPerm.end());
    info.insert(info.end(), idx_bytes.begin(), idx_bytes.end());
    Bytes seed_bytes = basefwx::crypto::HkdfSha256(perm_material, AsStringView(info), 16);
    ChunkParams params;
    params.seed = Seed64FromBytes(seed_bytes);
    params.rotation = static_cast<std::uint8_t>(seed_bytes[0] & 0x07);
    params.swap = (seed_bytes[1] & 0x01) != 0;
    chunk_index += 1;
    return params;
}

EVP_CIPHER_CTX* CreateAesCtrContext(const Bytes& key, const Bytes& iv) {
    if (key.size() != 32 || iv.size() != 16) {
        throw std::runtime_error("AES-CTR requires 32-byte key and 16-byte IV");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("AES-CTR context allocation failed");
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-CTR init failed");
    }
    return ctx;
}

Bytes ApplyAesCtr(EVP_CIPHER_CTX* ctx, const Bytes& input) {
    Bytes output(input.size());
    if (input.empty()) {
        return output;
    }
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, output.data(), &out_len, input.data(),
                          static_cast<int>(input.size())) != 1) {
        throw std::runtime_error("AES-CTR update failed");
    }
    output.resize(static_cast<std::size_t>(out_len));
    return output;
}

void ApplyAesCtrInPlace(EVP_CIPHER_CTX* ctx, Bytes& buffer) {
    if (buffer.empty()) {
        return;
    }
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, buffer.data(), &out_len, buffer.data(),
                          static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("AES-CTR update failed");
    }
    if (out_len != static_cast<int>(buffer.size())) {
        throw std::runtime_error("AES-CTR output size mismatch");
    }
}

}  // namespace

Bytes ObfuscateBytes(const Bytes& data, const Bytes& key, bool fast) {
    if (data.empty()) {
        return data;
    }
    Bytes out = data;
    XorKeystreamInPlace(out, key, constants::kObfInfoMask);
    if (!fast) {
        Bytes info = BuildInfoWithLength(constants::kObfInfoPerm, data.size());
        Bytes seed_bytes = basefwx::crypto::HkdfSha256(key, AsStringView(info), 16);
        std::uint64_t seed = Seed64FromBytes(seed_bytes);
        std::reverse(out.begin(), out.end());
        PermuteInPlace(out, seed);
    }
    return out;
}

Bytes DeobfuscateBytes(const Bytes& data, const Bytes& key, bool fast) {
    if (data.empty()) {
        return data;
    }
    Bytes out = data;
    if (!fast) {
        Bytes info = BuildInfoWithLength(constants::kObfInfoPerm, data.size());
        Bytes seed_bytes = basefwx::crypto::HkdfSha256(key, AsStringView(info), 16);
        std::uint64_t seed = Seed64FromBytes(seed_bytes);
        UnpermuteInPlace(out, seed);
        std::reverse(out.begin(), out.end());
    }
    XorKeystreamInPlace(out, key, constants::kObfInfoMask);
    return out;
}

StreamObfuscator::StreamObfuscator(Bytes perm_material, void* ctx, bool fast)
    : perm_material_(std::move(perm_material)), fast_(fast), ctx_(ctx) {}

StreamObfuscator::StreamObfuscator(StreamObfuscator&& other) noexcept {
    perm_material_ = std::move(other.perm_material_);
    ctx_ = other.ctx_;
    chunk_index_ = other.chunk_index_;
    fast_ = other.fast_;
    other.ctx_ = nullptr;
    other.chunk_index_ = 0;
    other.fast_ = false;
}

StreamObfuscator& StreamObfuscator::operator=(StreamObfuscator&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(ctx_));
        }
        perm_material_ = std::move(other.perm_material_);
        ctx_ = other.ctx_;
        chunk_index_ = other.chunk_index_;
        fast_ = other.fast_;
        other.ctx_ = nullptr;
        other.chunk_index_ = 0;
        other.fast_ = false;
    }
    return *this;
}

StreamObfuscator::~StreamObfuscator() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(ctx_));
    }
}

Bytes StreamObfuscator::GenerateSalt() {
    return basefwx::crypto::RandomBytes(kSaltLen);
}

StreamObfuscator StreamObfuscator::ForPassword(const std::string& password, const Bytes& salt, bool fast) {
    if (password.empty()) {
        throw std::runtime_error("Password required for streaming obfuscation");
    }
    if (salt.size() < kSaltLen) {
        throw std::runtime_error("Streaming obfuscation salt must be at least 16 bytes");
    }
    Bytes base_material(password.begin(), password.end());
    base_material.insert(base_material.end(), salt.begin(), salt.end());
    Bytes mask_key = basefwx::crypto::HkdfSha256(base_material, constants::kStreamInfoKey, 32);
    Bytes iv = basefwx::crypto::HkdfSha256(base_material, constants::kStreamInfoIv, 16);
    Bytes perm_material = basefwx::crypto::HkdfSha256(base_material, constants::kStreamInfoPerm, 32);
    EVP_CIPHER_CTX* ctx = CreateAesCtrContext(mask_key, iv);
    return StreamObfuscator(std::move(perm_material), ctx, fast);
}

Bytes StreamObfuscator::EncodeChunk(const Bytes& chunk) {
    if (chunk.empty()) {
        return {};
    }
    Bytes buffer = chunk;
    ApplyAesCtrInPlace(static_cast<EVP_CIPHER_CTX*>(ctx_), buffer);
    if (fast_) {
        chunk_index_ += 1;
        return buffer;
    }
    ChunkParams params = NextParams(perm_material_, chunk_index_);
    if (params.swap) {
        SwapNibblesInPlace(buffer);
    }
    if (params.rotation) {
        RotateLeftInPlace(buffer, params.rotation);
    }
    PermuteInPlace(buffer, params.seed);
    return buffer;
}

Bytes StreamObfuscator::DecodeChunk(const Bytes& chunk) {
    if (chunk.empty()) {
        return {};
    }
    Bytes buffer = chunk;
    if (fast_) {
        ApplyAesCtrInPlace(static_cast<EVP_CIPHER_CTX*>(ctx_), buffer);
        chunk_index_ += 1;
        return buffer;
    }
    ChunkParams params = NextParams(perm_material_, chunk_index_);
    UnpermuteInPlace(buffer, params.seed);
    if (params.rotation) {
        RotateRightInPlace(buffer, params.rotation);
    }
    if (params.swap) {
        SwapNibblesInPlace(buffer);
    }
    ApplyAesCtrInPlace(static_cast<EVP_CIPHER_CTX*>(ctx_), buffer);
    return buffer;
}

void StreamObfuscator::EncodeChunkInPlace(Bytes& buffer) {
    if (buffer.empty()) {
        return;
    }
    ApplyAesCtrInPlace(static_cast<EVP_CIPHER_CTX*>(ctx_), buffer);
    if (fast_) {
        chunk_index_ += 1;
        return;
    }
    ChunkParams params = NextParams(perm_material_, chunk_index_);
    if (params.swap) {
        SwapNibblesInPlace(buffer);
    }
    if (params.rotation) {
        RotateLeftInPlace(buffer, params.rotation);
    }
    PermuteInPlace(buffer, params.seed);
}

void StreamObfuscator::DecodeChunkInPlace(Bytes& buffer) {
    if (buffer.empty()) {
        return;
    }
    if (fast_) {
        ApplyAesCtrInPlace(static_cast<EVP_CIPHER_CTX*>(ctx_), buffer);
        chunk_index_ += 1;
        return;
    }
    ChunkParams params = NextParams(perm_material_, chunk_index_);
    UnpermuteInPlace(buffer, params.seed);
    if (params.rotation) {
        RotateRightInPlace(buffer, params.rotation);
    }
    if (params.swap) {
        SwapNibblesInPlace(buffer);
    }
    ApplyAesCtrInPlace(static_cast<EVP_CIPHER_CTX*>(ctx_), buffer);
}

}  // namespace basefwx::obf
