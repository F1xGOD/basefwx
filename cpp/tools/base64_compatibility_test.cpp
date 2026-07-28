/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#include "basefwx/base64.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main() {
    const std::vector<std::uint8_t> values{0xFB, 0xFF};
    if (basefwx::base64::Encode(values) != "+/8=") {
        std::cerr << "FAIL: producer did not use standard Base64 alphabet\n";
        return 1;
    }

    for (const std::string encoded : {"+/8=", "-_8="}) {
        bool ok = false;
        const auto decoded = basefwx::base64::Decode(encoded, &ok);
        if (!ok || decoded != values) {
            std::cerr << "FAIL: decoder rejected alphabet: " << encoded << "\n";
            return 1;
        }
        if (!basefwx::base64::IsLikelyBase64(encoded)) {
            std::cerr << "FAIL: detector rejected alphabet: " << encoded << "\n";
            return 1;
        }
    }
    return 0;
}
