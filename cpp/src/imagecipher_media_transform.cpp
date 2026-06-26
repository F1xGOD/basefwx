/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "imagecipher_internal.hpp"

#include "basefwx/basefwx.hpp"
#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"
#include "basefwx/format.hpp"
#include "basefwx/keywrap.hpp"
#include "basefwx/pb512.hpp"
#include "basefwx/system_info.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <new>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <chrono>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include <openssl/evp.h>

#if defined(_WIN32)
#include <windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif
#else
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace basefwx::imagecipher::internal {

Bytes BaseKeyFromPassword(const std::string& password) {
    Bytes material = DeriveMaterial(password);
    return Bytes(material.begin(), material.begin() + 32);
}

namespace {

constexpr int kVideoGroupMaxFrames = 12;

Bytes UnitMaterial(const Bytes& base_key, const std::string& label, std::uint64_t index, std::size_t length) {
    Bytes info(label.begin(), label.end());
    info.push_back(static_cast<std::uint8_t>((index >> 56) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 48) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 40) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 32) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 24) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 16) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 8) & 0xFF));
    info.push_back(static_cast<std::uint8_t>(index & 0xFF));
    std::string info_str(reinterpret_cast<const char*>(info.data()), info.size());
    return basefwx::crypto::HkdfSha256(base_key, info_str, length);
}

std::uint64_t SplitMix64(std::uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t x = state;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

std::vector<std::size_t> PermuteIndices(std::size_t count, std::uint64_t seed) {
    std::vector<std::size_t> order(count);
    for (std::size_t i = 0; i < count; ++i) {
        order[i] = i;
    }
    std::uint64_t state = seed;
    if (count <= 1) {
        return order;
    }
    for (std::size_t i = count - 1; i > 0; --i) {
        std::uint64_t rnd = SplitMix64(state);
        std::size_t j = static_cast<std::size_t>(rnd % (i + 1));
        if (j != i) {
            std::swap(order[i], order[j]);
        }
    }
    return order;
}

std::size_t ResolveMediaWorkers(std::size_t max_tasks) {
    const char* raw = std::getenv("BASEFWX_MEDIA_WORKERS");
    if (raw && *raw) {
        try {
            std::size_t parsed = static_cast<std::size_t>(std::stoul(raw));
            if (parsed > 0) {
                return std::min(parsed, std::max<std::size_t>(1, max_tasks));
            }
        } catch (const std::exception&) {
        }
    }
    unsigned int hw = std::thread::hardware_concurrency();
    std::size_t workers = hw > 0 ? static_cast<std::size_t>(hw) : 1;
    return std::min(workers, std::max<std::size_t>(1, max_tasks));
}

template <typename Fn>
void ParallelFor(std::size_t count, std::size_t max_workers, Fn&& fn) {
    std::size_t workers = ResolveMediaWorkers(std::min(count, max_workers));
    if (count == 0 || workers <= 1) {
        for (std::size_t i = 0; i < count; ++i) {
            fn(i);
        }
        return;
    }
    std::atomic<std::size_t> next{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (std::size_t w = 0; w < workers; ++w) {
        threads.emplace_back([&]() {
            while (true) {
                std::size_t idx = next.fetch_add(1);
                if (idx >= count) {
                    break;
                }
                fn(idx);
            }
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}

Bytes ShuffleFrameBlocks(const Bytes& frame,
                         int width,
                         int height,
                         int channels,
                         std::uint64_t seed,
                         int block_size) {
    int blocks_x = (width + block_size - 1) / block_size;
    int blocks_y = (height + block_size - 1) / block_size;
    std::size_t total_blocks = static_cast<std::size_t>(blocks_x) * static_cast<std::size_t>(blocks_y);
    auto perm = PermuteIndices(total_blocks, seed);
    Bytes out(frame.size());
    for (std::size_t dest_idx = 0; dest_idx < total_blocks; ++dest_idx) {
        std::size_t src_idx = perm[dest_idx];
        int dx = static_cast<int>(dest_idx % blocks_x) * block_size;
        int dy = static_cast<int>(dest_idx / blocks_x) * block_size;
        int sx = static_cast<int>(src_idx % blocks_x) * block_size;
        int sy = static_cast<int>(src_idx / blocks_x) * block_size;
        int copy_w = std::min(block_size, width - dx);
        copy_w = std::min(copy_w, width - sx);
        int copy_h = std::min(block_size, height - dy);
        copy_h = std::min(copy_h, height - sy);
        for (int row = 0; row < copy_h; ++row) {
            std::size_t src_off = static_cast<std::size_t>(((sy + row) * width + sx) * channels);
            std::size_t dst_off = static_cast<std::size_t>(((dy + row) * width + dx) * channels);
            std::size_t span = static_cast<std::size_t>(copy_w * channels);
            std::memcpy(out.data() + dst_off, frame.data() + src_off, span);
        }
    }
    return out;
}

Bytes UnshuffleFrameBlocks(const Bytes& frame,
                           int width,
                           int height,
                           int channels,
                           std::uint64_t seed,
                           int block_size) {
    int blocks_x = (width + block_size - 1) / block_size;
    int blocks_y = (height + block_size - 1) / block_size;
    std::size_t total_blocks = static_cast<std::size_t>(blocks_x) * static_cast<std::size_t>(blocks_y);
    auto perm = PermuteIndices(total_blocks, seed);
    Bytes out(frame.size());
    for (std::size_t dest_idx = 0; dest_idx < total_blocks; ++dest_idx) {
        std::size_t src_idx = perm[dest_idx];
        int dx = static_cast<int>(dest_idx % blocks_x) * block_size;
        int dy = static_cast<int>(dest_idx / blocks_x) * block_size;
        int sx = static_cast<int>(src_idx % blocks_x) * block_size;
        int sy = static_cast<int>(src_idx / blocks_x) * block_size;
        int copy_w = std::min(block_size, width - dx);
        copy_w = std::min(copy_w, width - sx);
        int copy_h = std::min(block_size, height - dy);
        copy_h = std::min(copy_h, height - sy);
        for (int row = 0; row < copy_h; ++row) {
            std::size_t src_off = static_cast<std::size_t>(((dy + row) * width + dx) * channels);
            std::size_t dst_off = static_cast<std::size_t>(((sy + row) * width + sx) * channels);
            std::size_t span = static_cast<std::size_t>(copy_w * channels);
            std::memcpy(out.data() + dst_off, frame.data() + src_off, span);
        }
    }
    return out;
}

Bytes AudioMaskTransform(const Bytes& data,
                         const Bytes& key,
                         const Bytes& iv,
                         std::uint16_t mask_bits) {
    // Obfuscation-only: masks low bits to preserve audio fidelity, not confidentiality.
    if (data.empty()) {
        return {};
    }
    Bytes zeros(data.size(), 0);
    Bytes stream = basefwx::crypto::AesCtrTransform(key, iv, zeros);
    Bytes out = data;
    if (mask_bits > 16) {
        mask_bits = 16;
    }
    const std::uint16_t mask = mask_bits == 16
        ? static_cast<std::uint16_t>(0xFFFFu)
        : static_cast<std::uint16_t>((1u << mask_bits) - 1u);
    std::size_t samples = out.size() / 2;
    for (std::size_t i = 0; i < samples; ++i) {
        std::size_t off = i * 2;
        std::uint16_t sample = static_cast<std::uint16_t>(out[off])
                               | static_cast<std::uint16_t>(out[off + 1] << 8);
        std::uint16_t ks = static_cast<std::uint16_t>(stream[off])
                           | static_cast<std::uint16_t>(stream[off + 1] << 8);
        std::uint16_t mixed = static_cast<std::uint16_t>(sample ^ (ks & mask));
        out[off] = static_cast<std::uint8_t>(mixed & 0xFFu);
        out[off + 1] = static_cast<std::uint8_t>((mixed >> 8) & 0xFFu);
    }
    return out;
}

Bytes VideoMaskTransform(const Bytes& data,
                         const Bytes& key,
                         const Bytes& iv,
                         std::uint8_t mask_bits) {
    // Obfuscation-only: masks low bits to preserve video quality, not confidentiality.
    if (data.empty()) {
        return {};
    }
    Bytes zeros(data.size(), 0);
    Bytes stream = basefwx::crypto::AesCtrTransform(key, iv, zeros);
    Bytes out = data;
    if (mask_bits > 8) {
        mask_bits = 8;
    }
    const std::uint8_t mask = mask_bits == 8
        ? static_cast<std::uint8_t>(0xFFu)
        : static_cast<std::uint8_t>((1u << mask_bits) - 1u);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(out[i] ^ (stream[i] & mask));
    }
    return out;
}

Bytes ShuffleAudioSamples(const Bytes& block, std::uint64_t seed, bool inverse) {
    if (block.empty()) {
        return block;
    }
    std::size_t samples = block.size() / 2;
    if (samples <= 1) {
        return block;
    }
    auto perm = PermuteIndices(samples, seed);
    Bytes out(block.size());
    if (!inverse) {
        for (std::size_t dest_idx = 0; dest_idx < samples; ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            std::size_t src_off = src_idx * 2;
            std::size_t dst_off = dest_idx * 2;
            out[dst_off] = block[src_off];
            out[dst_off + 1] = block[src_off + 1];
        }
    } else {
        for (std::size_t dest_idx = 0; dest_idx < samples; ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            std::size_t src_off = src_idx * 2;
            std::size_t dst_off = dest_idx * 2;
            out[src_off] = block[dst_off];
            out[src_off + 1] = block[dst_off + 1];
        }
    }
    if (block.size() % 2) {
        out.back() = block.back();
    }
    return out;
}


}  // namespace

void ScrambleVideoRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const VideoInfo& video,
                      const Bytes& base_key,
                      std::uint8_t security_profile,
                      const std::function<void(double)>& progress_cb) {
    std::size_t frame_size = static_cast<std::size_t>(video.width) * static_cast<std::size_t>(video.height) * 3u;
    if (frame_size == 0) {
        throw std::runtime_error("Invalid video dimensions");
    }
    int group_frames = static_cast<int>(std::max(2.0, std::round((video.fps > 0.0 ? video.fps : 30.0) * 1.0)));
    group_frames = std::min(group_frames, kVideoGroupMaxFrames);
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw video buffers");
    }
    std::uint64_t frame_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_frames = 0;
    std::uint64_t total_frames = 0;
    const std::string frame_label = JmgProfileLabel("jmg-frame", security_profile);
    const std::string frame_block_label = JmgProfileLabel("jmg-fblk", security_profile);
    const std::string frame_group_label = JmgProfileLabel("jmg-fgrp", security_profile);
    const std::uint8_t video_mask_bits = JmgVideoMaskBitsForProfile(security_profile);
    if (progress_cb) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec && frame_size > 0) {
            total_frames = static_cast<std::uint64_t>(bytes / frame_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = frame_index;
        std::vector<Bytes> frames;
        frames.reserve(static_cast<std::size_t>(group_frames));
        for (int i = 0; i < group_frames; ++i) {
            Bytes frame(frame_size);
            input.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
            if (input.gcount() != static_cast<std::streamsize>(frame.size())) {
                break;
            }
            frames.push_back(std::move(frame));
            ++frame_index;
        }
        if (frames.empty()) {
            break;
        }
        std::vector<Bytes> processed(frames.size());
        ParallelFor(frames.size(), static_cast<std::size_t>(group_frames), [&](std::size_t idx) {
            std::uint64_t frame_id = group_start_index + idx;
            Bytes material = UnitMaterial(base_key, frame_label, frame_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            Bytes masked = VideoMaskTransform(frames[idx], key, iv, video_mask_bits);
            Bytes seed_bytes = UnitMaterial(base_key, frame_block_label, frame_id, 16);
            std::uint64_t seed = 0;
            for (std::uint8_t b : seed_bytes) {
                seed = (seed << 8) | b;
            }
            processed[idx] = ShuffleFrameBlocks(masked, video.width, video.height, 3, seed, 2);
        });
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, frame_group_label, seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(processed.size(), seed);
        for (auto idx : perm) {
            output.write(reinterpret_cast<const char*>(processed[idx].data()),
                         static_cast<std::streamsize>(processed[idx].size()));
        }
        processed_frames += processed.size();
        if (progress_cb && total_frames > 0) {
            double frac = static_cast<double>(processed_frames) / static_cast<double>(total_frames);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        ++group_index;
    }
}

void ScrambleAudioRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const AudioInfo& audio,
                      const Bytes& base_key,
                      std::uint8_t security_profile,
                      const std::function<void(double)>& progress_cb) {
    constexpr double kAudioBlockSeconds = 0.15;
    constexpr double kAudioGroupSeconds = 1.0;
    int samples_per_block = std::max(1, static_cast<int>(std::round(audio.sample_rate * kAudioBlockSeconds)));
    std::size_t block_size = static_cast<std::size_t>(samples_per_block * audio.channels * 2);
    int group_blocks = std::max(2, static_cast<int>(std::round(kAudioGroupSeconds / kAudioBlockSeconds)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw audio buffers");
    }
    std::uint64_t block_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_blocks = 0;
    std::uint64_t total_blocks = 0;
    const std::string audio_block_label = JmgProfileLabel("jmg-ablock", security_profile);
    const std::string audio_sample_label = JmgProfileLabel("jmg-asamp", security_profile);
    const std::string audio_group_label = JmgProfileLabel("jmg-agrp", security_profile);
    const std::uint16_t audio_mask_bits = JmgAudioMaskBitsForProfile(security_profile);
    if (progress_cb && block_size > 0) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec) {
            total_blocks = static_cast<std::uint64_t>((bytes + block_size - 1) / block_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = block_index;
        std::vector<Bytes> blocks;
        blocks.reserve(static_cast<std::size_t>(group_blocks));
        for (int i = 0; i < group_blocks; ++i) {
            Bytes block(block_size);
            input.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(block.size()));
            if (input.gcount() == 0) {
                break;
            }
            block.resize(static_cast<std::size_t>(input.gcount()));
            blocks.push_back(std::move(block));
            ++block_index;
        }
        if (blocks.empty()) {
            break;
        }
        std::vector<Bytes> processed(blocks.size());
        ParallelFor(blocks.size(), static_cast<std::size_t>(group_blocks), [&](std::size_t idx) {
            std::uint64_t block_id = group_start_index + idx;
            Bytes material = UnitMaterial(base_key, audio_block_label, block_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            Bytes masked = AudioMaskTransform(blocks[idx], key, iv, audio_mask_bits);
            Bytes seed_bytes = UnitMaterial(base_key, audio_sample_label, block_id, 16);
            std::uint64_t seed = 0;
            for (std::uint8_t b : seed_bytes) {
                seed = (seed << 8) | b;
            }
            processed[idx] = ShuffleAudioSamples(masked, seed, false);
        });
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, audio_group_label, seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(processed.size(), seed);
        for (auto idx : perm) {
            output.write(reinterpret_cast<const char*>(processed[idx].data()),
                         static_cast<std::streamsize>(processed[idx].size()));
        }
        processed_blocks += processed.size();
        if (progress_cb && total_blocks > 0) {
            double frac = static_cast<double>(processed_blocks) / static_cast<double>(total_blocks);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        ++group_index;
    }
}

void UnscrambleVideoRaw(const std::filesystem::path& raw_in,
                        const std::filesystem::path& raw_out,
                        const VideoInfo& video,
                        const Bytes& base_key,
                        std::uint8_t security_profile,
                        const std::function<void(double)>& progress_cb) {
    std::size_t frame_size = static_cast<std::size_t>(video.width) * static_cast<std::size_t>(video.height) * 3u;
    if (frame_size == 0) {
        throw std::runtime_error("Invalid video dimensions");
    }
    int group_frames = static_cast<int>(std::max(2.0, std::round((video.fps > 0.0 ? video.fps : 30.0) * 1.0)));
    group_frames = std::min(group_frames, kVideoGroupMaxFrames);
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw video buffers");
    }
    std::uint64_t frame_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_frames = 0;
    std::uint64_t total_frames = 0;
    const std::string frame_label = JmgProfileLabel("jmg-frame", security_profile);
    const std::string frame_block_label = JmgProfileLabel("jmg-fblk", security_profile);
    const std::string frame_group_label = JmgProfileLabel("jmg-fgrp", security_profile);
    const std::uint8_t video_mask_bits = JmgVideoMaskBitsForProfile(security_profile);
    if (progress_cb) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec && frame_size > 0) {
            total_frames = static_cast<std::uint64_t>(bytes / frame_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = frame_index;
        std::vector<Bytes> frames;
        frames.reserve(static_cast<std::size_t>(group_frames));
        for (int i = 0; i < group_frames; ++i) {
            Bytes frame(frame_size);
            input.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
            if (input.gcount() != static_cast<std::streamsize>(frame.size())) {
                break;
            }
            frames.push_back(std::move(frame));
        }
        if (frames.empty()) {
            break;
        }
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, frame_group_label, seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(frames.size(), seed);
        std::vector<Bytes> ordered(frames.size());
        for (std::size_t dest_idx = 0; dest_idx < perm.size(); ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            ordered[src_idx] = std::move(frames[dest_idx]);
        }
        std::vector<Bytes> restored(ordered.size());
        ParallelFor(ordered.size(), static_cast<std::size_t>(group_frames), [&](std::size_t idx) {
            std::uint64_t frame_id = group_start_index + idx;
            Bytes seed_bytes_local = UnitMaterial(base_key, frame_block_label, frame_id, 16);
            std::uint64_t seed_local = 0;
            for (std::uint8_t b : seed_bytes_local) {
                seed_local = (seed_local << 8) | b;
            }
            Bytes unshuffled = UnshuffleFrameBlocks(ordered[idx], video.width, video.height, 3, seed_local, 2);
            Bytes material = UnitMaterial(base_key, frame_label, frame_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            restored[idx] = VideoMaskTransform(unshuffled, key, iv, video_mask_bits);
        });
        for (const auto& frame : restored) {
            output.write(reinterpret_cast<const char*>(frame.data()),
                         static_cast<std::streamsize>(frame.size()));
        }
        processed_frames += restored.size();
        if (progress_cb && total_frames > 0) {
            double frac = static_cast<double>(processed_frames) / static_cast<double>(total_frames);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        frame_index += restored.size();
        ++group_index;
    }
}

void UnscrambleAudioRaw(const std::filesystem::path& raw_in,
                        const std::filesystem::path& raw_out,
                        const AudioInfo& audio,
                        const Bytes& base_key,
                        std::uint8_t security_profile,
                        const std::function<void(double)>& progress_cb) {
    constexpr double kAudioBlockSeconds = 0.15;
    constexpr double kAudioGroupSeconds = 1.0;
    int samples_per_block = std::max(1, static_cast<int>(std::round(audio.sample_rate * kAudioBlockSeconds)));
    std::size_t block_size = static_cast<std::size_t>(samples_per_block * audio.channels * 2);
    int group_blocks = std::max(2, static_cast<int>(std::round(kAudioGroupSeconds / kAudioBlockSeconds)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw audio buffers");
    }
    std::uint64_t block_index = 0;
    std::uint64_t group_index = 0;
    std::uint64_t processed_blocks = 0;
    std::uint64_t total_blocks = 0;
    const std::string audio_block_label = JmgProfileLabel("jmg-ablock", security_profile);
    const std::string audio_sample_label = JmgProfileLabel("jmg-asamp", security_profile);
    const std::string audio_group_label = JmgProfileLabel("jmg-agrp", security_profile);
    const std::uint16_t audio_mask_bits = JmgAudioMaskBitsForProfile(security_profile);
    if (progress_cb && block_size > 0) {
        std::error_code ec;
        auto bytes = std::filesystem::file_size(raw_in, ec);
        if (!ec) {
            total_blocks = static_cast<std::uint64_t>((bytes + block_size - 1) / block_size);
        }
    }
    while (true) {
        std::uint64_t group_start_index = block_index;
        std::vector<Bytes> blocks;
        blocks.reserve(static_cast<std::size_t>(group_blocks));
        for (int i = 0; i < group_blocks; ++i) {
            Bytes block(block_size);
            input.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(block.size()));
            if (input.gcount() == 0) {
                break;
            }
            block.resize(static_cast<std::size_t>(input.gcount()));
            blocks.push_back(std::move(block));
        }
        if (blocks.empty()) {
            break;
        }
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, audio_group_label, seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(blocks.size(), seed);
        std::vector<Bytes> ordered(blocks.size());
        for (std::size_t dest_idx = 0; dest_idx < perm.size(); ++dest_idx) {
            std::size_t src_idx = perm[dest_idx];
            ordered[src_idx] = std::move(blocks[dest_idx]);
        }
        std::vector<Bytes> restored(ordered.size());
        ParallelFor(ordered.size(), static_cast<std::size_t>(group_blocks), [&](std::size_t idx) {
            std::uint64_t block_id = group_start_index + idx;
            Bytes seed_bytes_local = UnitMaterial(base_key, audio_sample_label, block_id, 16);
            std::uint64_t seed_local = 0;
            for (std::uint8_t b : seed_bytes_local) {
                seed_local = (seed_local << 8) | b;
            }
            Bytes unshuffled = ShuffleAudioSamples(ordered[idx], seed_local, true);
            Bytes material = UnitMaterial(base_key, audio_block_label, block_id, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            restored[idx] = AudioMaskTransform(unshuffled, key, iv, audio_mask_bits);
        });
        for (const auto& block : restored) {
            output.write(reinterpret_cast<const char*>(block.data()),
                         static_cast<std::streamsize>(block.size()));
        }
        processed_blocks += restored.size();
        if (progress_cb && total_blocks > 0) {
            double frac = static_cast<double>(processed_blocks) / static_cast<double>(total_blocks);
            if (frac > 1.0) {
                frac = 1.0;
            }
            progress_cb(frac);
        }
        block_index += restored.size();
        ++group_index;
    }
}

}  // namespace basefwx::imagecipher::internal
