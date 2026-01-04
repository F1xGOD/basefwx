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
    auto fail = [&](std::vector<std::uint8_t>& out) {
        if (ok) *ok = false;
        out.clear();
        return out;
    };

    std::vector<std::uint8_t> out;
    
    // Fast path: count non-whitespace characters first
    std::size_t valid_count = 0;
    for (unsigned char c : input) {
        if (!std::isspace(c)) ++valid_count;
    }
    
    if (valid_count == 0) {
        if (ok) *ok = true;
        return out;
    }
    
    if (valid_count % 4 != 0) {
        return fail(out);
    }
    
    // Pre-allocate output buffer with exact size needed
    out.reserve((valid_count / 4) * 3);
    
    // Process input directly without creating intermediate string
    unsigned char quad[4];
    std::size_t quad_pos = 0;
    std::size_t processed_quads = 0;
    std::size_t total_quads = valid_count / 4;
    
    for (unsigned char c : input) {
        if (std::isspace(c)) continue;
        
        quad[quad_pos++] = c;
        
        if (quad_pos == 4) {
            unsigned char c0 = quad[0];
            unsigned char c1 = quad[1];
            unsigned char c2 = quad[2];
            unsigned char c3 = quad[3];
            
            auto d0 = (c0 == '=') ? 0xFF : kDecTable[c0];
            auto d1 = (c1 == '=') ? 0xFF : kDecTable[c1];
            
            if (c0 == '=' || c1 == '=' || d0 == 0xFF || d1 == 0xFF) {
                return fail(out);
            }
            
            bool pad2 = (c2 == '=');
            bool pad3 = (c3 == '=');
            
            std::uint8_t d2 = 0, d3 = 0;
            if (!pad2) {
                d2 = kDecTable[c2];
                if (d2 == 0xFF) return fail(out);
            } else {
                // If c2 is '=', c3 must also be '='
                if (!pad3) return fail(out);
            }
            
            if (!pad3) {
                d3 = kDecTable[c3];
                if (d3 == 0xFF) return fail(out);
            }
            
            std::uint32_t triple =
                (static_cast<std::uint32_t>(d0) << 18) |
                (static_cast<std::uint32_t>(d1) << 12) |
                (static_cast<std::uint32_t>(d2) << 6)  |
                (static_cast<std::uint32_t>(d3));
            
            out.push_back(static_cast<std::uint8_t>((triple >> 16) & 0xFF));
            if (!pad2) out.push_back(static_cast<std::uint8_t>((triple >> 8) & 0xFF));
            if (!pad3) out.push_back(static_cast<std::uint8_t>(triple & 0xFF));
            
            processed_quads++;
            
            // If padding happened, it must be the last quartet
            if (pad2 || pad3) {
                if (processed_quads != total_quads) return fail(out);
                
                // Extra strict: ensure unused bits are zero when padded
                if (pad2) {
                    // "xx==" => last 4 bits of (d1) must be zero in output encoding
                    if ((triple & 0xFFFF) != 0) return fail(out);
                } else if (pad3) {
                    // "xxx=" => last 2 bits must be zero
                    if ((triple & 0xFF) != 0) return fail(out);
                }
            }
            
            quad_pos = 0;
        }
    }
    
    if (quad_pos != 0) {
        return fail(out);
    }

    if (ok) *ok = true;
    return out;
}

bool IsLikelyBase64(const std::string& input) {
    std::string compact;
    compact.reserve(input.size());
    for (unsigned char c : input) {
        if (!std::isspace(c)) {
            compact.push_back(static_cast<char>(c));
        }
    }
    if (compact.empty() || (compact.size() % 4u) != 0u) {
        return false;
    }
    bool seen_pad = false;
    std::size_t pad_count = 0;
    for (unsigned char c : compact) {
        if (c == '=') {
            seen_pad = true;
            pad_count += 1;
            continue;
        }
        if (seen_pad) {
            return false;
        }
        if (kDecTable[c] == 0xFF) {
            return false;
        }
    }
    if (pad_count > 2) {
        return false;
    }
    if (pad_count > 0) {
        if (compact.back() != '=') {
            return false;
        }
        if (pad_count == 2 && compact.size() < 2) {
            return false;
        }
        if (pad_count == 2 && compact[compact.size() - 2] != '=') {
            return false;
        }
    }
    return true;
}


}  // namespace basefwx::base64
