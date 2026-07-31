/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>

namespace basefwx::internal {

inline std::size_t CheckedDecodedImageBytes(int width,
                                            int height,
                                            int channels,
                                            std::size_t maximum,
                                            const char* context) {
    if (width <= 0 || height <= 0 || channels <= 0) {
        throw std::runtime_error(std::string(context) + " has invalid dimensions");
    }
    const auto image_width = static_cast<std::size_t>(width);
    const auto image_height = static_cast<std::size_t>(height);
    const auto image_channels = static_cast<std::size_t>(channels);
    if (image_width > maximum / image_height) {
        throw std::runtime_error(std::string(context) + " dimensions overflow");
    }
    const std::size_t pixels = image_width * image_height;
    if (pixels > maximum / image_channels) {
        throw std::runtime_error(std::string(context) + " exceeds decoded-size limit");
    }
    return pixels * image_channels;
}

}  // namespace basefwx::internal
