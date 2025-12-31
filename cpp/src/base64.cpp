#include "basefwx/base64.hpp"

#include <array>
#include <cctype>
#include <string>
#include <vector>

namespace basefwx::base64 {

namespace {

constexpr char kEncTable[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<std::uint8_t, 256> BuildDecodeTable() {
    std::array<std::uint8_t, 256> table{};
    table.fill(0xFF);
    for (std::size_t i = 0; i < 64; ++i) {
        table[static_cast<std::uint8_t>(kEncTable[i])] = static_cast<std::uint8_t>(i);
    }
    return table;
}

const std::array<std::uint8_t, 256> kDecTable = BuildDecodeTable();

}  // namespace

std::string Encode(const std::vector<std::uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 2 < data.size()) {
        std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16)
                               | (static_cast<std::uint32_t>(data[i + 1]) << 8)
                               | static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kEncTable[(triple >> 18) & 0x3F]);
        out.push_back(kEncTable[(triple >> 12) & 0x3F]);
        out.push_back(kEncTable[(triple >> 6) & 0x3F]);
        out.push_back(kEncTable[triple & 0x3F]);
        i += 3;
    }
    if (i < data.size()) {
        std::uint32_t triple = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(kEncTable[(triple >> 18) & 0x3F]);
        if (i + 1 < data.size()) {
            triple |= static_cast<std::uint32_t>(data[i + 1]) << 8;
            out.push_back(kEncTable[(triple >> 12) & 0x3F]);
            out.push_back(kEncTable[(triple >> 6) & 0x3F]);
            out.push_back('=');
        } else {
            out.push_back(kEncTable[(triple >> 12) & 0x3F]);
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

std::vector<std::uint8_t> Decode(const std::string& input, bool* ok) {
    bool success = true;
    std::vector<std::uint8_t> out;
    out.reserve((input.size() / 4) * 3);

    int val = 0;
    int valb = -8;
    for (unsigned char c : input) {
        if (std::isspace(c)) {
            continue;
        }
        if (c == '=') {
            break;
        }
        std::uint8_t decoded = kDecTable[c];
        if (decoded == 0xFF) {
            success = false;
            break;
        }
        val = (val << 6) + decoded;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<std::uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    if (ok) {
        *ok = success;
    }
    if (!success) {
        out.clear();
    }
    return out;
}

bool IsLikelyBase64(const std::string& input) {
    if (input.empty()) {
        return true;
    }
    for (unsigned char c : input) {
        if (std::isspace(c)) {
            continue;
        }
        if (c == '=' || kDecTable[c] != 0xFF) {
            continue;
        }
        return false;
    }
    return true;
}

}  // namespace basefwx::base64
