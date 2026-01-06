#include "basefwx/base64.hpp"

#include <array>
#include <cctype>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

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

inline bool IsSpace(unsigned char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\v' || c == '\f';
}

std::string EncodeRawFallback(const std::uint8_t* data, std::size_t size) {
    std::size_t out_len = ((size + 2u) / 3u) * 4u;
    std::string out(out_len, '\0');
    std::size_t i = 0;
    std::size_t o = 0;
    while (i + 2u < size) {
        std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16)
                               | (static_cast<std::uint32_t>(data[i + 1]) << 8)
                               | static_cast<std::uint32_t>(data[i + 2]);
        out[o++] = kEncTable[(triple >> 18) & 0x3F];
        out[o++] = kEncTable[(triple >> 12) & 0x3F];
        out[o++] = kEncTable[(triple >> 6) & 0x3F];
        out[o++] = kEncTable[triple & 0x3F];
        i += 3u;
    }
    if (i < size) {
        std::uint32_t triple = static_cast<std::uint32_t>(data[i]) << 16;
        out[o++] = kEncTable[(triple >> 18) & 0x3F];
        if (i + 1u < size) {
            triple |= static_cast<std::uint32_t>(data[i + 1]) << 8;
            out[o++] = kEncTable[(triple >> 12) & 0x3F];
            out[o++] = kEncTable[(triple >> 6) & 0x3F];
            out[o++] = '=';
        } else {
            out[o++] = kEncTable[(triple >> 12) & 0x3F];
            out[o++] = '=';
            out[o++] = '=';
        }
    }
    return out;
}

std::string EncodeRaw(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return std::string();
    }
    if (size <= static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        std::size_t out_len = ((size + 2u) / 3u) * 4u;
        std::string out(out_len, '\0');
        int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                                      reinterpret_cast<const unsigned char*>(data),
                                      static_cast<int>(size));
        if (written >= 0) {
            if (static_cast<std::size_t>(written) != out_len) {
                out.resize(static_cast<std::size_t>(written));
            }
            return out;
        }
    }
    return EncodeRawFallback(data, size);
}

bool ValidateBase64NoWhitespace(std::string_view input, std::size_t& pad_count) {
    pad_count = 0;
    if (input.empty()) {
        return true;
    }
    if ((input.size() % 4u) != 0u) {
        return false;
    }
    if (input.back() == '=') {
        pad_count += 1;
        if (input.size() >= 2 && input[input.size() - 2] == '=') {
            pad_count += 1;
        }
    }
    if (pad_count > 2) {
        return false;
    }
    std::size_t limit = input.size() - pad_count;
    for (std::size_t i = 0; i < limit; ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c == '=' || kDecTable[c] == 0xFF) {
            return false;
        }
    }
    for (std::size_t i = limit; i < input.size(); ++i) {
        if (input[i] != '=') {
            return false;
        }
    }
    if (pad_count > 0) {
        unsigned char c0 = static_cast<unsigned char>(input[input.size() - 4]);
        unsigned char c1 = static_cast<unsigned char>(input[input.size() - 3]);
        unsigned char c2 = static_cast<unsigned char>(input[input.size() - 2]);
        unsigned char c3 = static_cast<unsigned char>(input[input.size() - 1]);
        if (kDecTable[c0] == 0xFF || kDecTable[c1] == 0xFF) {
            return false;
        }
        std::uint8_t d2 = (c2 == '=') ? 0 : kDecTable[c2];
        std::uint8_t d3 = (c3 == '=') ? 0 : kDecTable[c3];
        if (c2 != '=' && kDecTable[c2] == 0xFF) {
            return false;
        }
        if (c3 != '=' && kDecTable[c3] == 0xFF) {
            return false;
        }
        std::uint32_t triple =
            (static_cast<std::uint32_t>(kDecTable[c0]) << 18) |
            (static_cast<std::uint32_t>(kDecTable[c1]) << 12) |
            (static_cast<std::uint32_t>(d2) << 6) |
            static_cast<std::uint32_t>(d3);
        if (pad_count == 2) {
            if ((triple & 0xFFFFu) != 0u) {
                return false;
            }
        } else if (pad_count == 1) {
            if ((triple & 0xFFu) != 0u) {
                return false;
            }
        }
    }
    return true;
}

bool DecodeOpenSslNoWhitespace(std::string_view input, std::vector<std::uint8_t>& out) {
    if (input.empty()) {
        out.clear();
        return true;
    }
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    std::size_t pad_count = 0;
    if (!ValidateBase64NoWhitespace(input, pad_count)) {
        return false;
    }
    std::size_t out_len = (input.size() / 4u) * 3u;
    out.assign(out_len, 0);
    int written = EVP_DecodeBlock(out.data(),
                                  reinterpret_cast<const unsigned char*>(input.data()),
                                  static_cast<int>(input.size()));
    if (written < 0) {
        out.clear();
        return false;
    }
    std::size_t final_len = static_cast<std::size_t>(written);
    if (pad_count > final_len) {
        out.clear();
        return false;
    }
    final_len -= pad_count;
    out.resize(final_len);
    return true;
}

bool DecodeOpenSslNoWhitespace(std::string_view input, std::string& out) {
    if (input.empty()) {
        out.clear();
        return true;
    }
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    std::size_t pad_count = 0;
    if (!ValidateBase64NoWhitespace(input, pad_count)) {
        return false;
    }
    std::size_t out_len = (input.size() / 4u) * 3u;
    out.assign(out_len, '\0');
    int written = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                                  reinterpret_cast<const unsigned char*>(input.data()),
                                  static_cast<int>(input.size()));
    if (written < 0) {
        out.clear();
        return false;
    }
    std::size_t final_len = static_cast<std::size_t>(written);
    if (pad_count > final_len) {
        out.clear();
        return false;
    }
    final_len -= pad_count;
    out.resize(final_len);
    return true;
}

}  // namespace

std::string Encode(const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return std::string();
    }
    return EncodeRaw(data.data(), data.size());
}

std::string Encode(std::string_view input) {
    if (input.empty()) {
        return std::string();
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(input.data());
    return EncodeRaw(bytes, input.size());
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
        if (!IsSpace(c)) ++valid_count;
    }

    if (valid_count == 0) {
        if (ok) *ok = true;
        return out;
    }
    
    if (valid_count % 4 != 0) {
        return fail(out);
    }

    if (!has_space && input.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        if (DecodeOpenSslNoWhitespace(input, out)) {
            if (ok) *ok = true;
            return out;
        }
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
        if (IsSpace(c)) continue;
        
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

std::string DecodeToString(std::string_view input, bool* ok) {
    auto fail = [&](std::string& out) {
        if (ok) *ok = false;
        out.clear();
        return out;
    };

    std::string out;

    std::size_t valid_count = 0;
    bool has_space = false;
    for (unsigned char c : input) {
        if (IsSpace(c)) {
            has_space = true;
        } else {
            ++valid_count;
        }
    }

    if (valid_count == 0) {
        if (ok) *ok = true;
        return out;
    }

    if (valid_count % 4 != 0) {
        return fail(out);
    }

    if (!has_space && input.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        if (DecodeOpenSslNoWhitespace(input, out)) {
            if (ok) *ok = true;
            return out;
        }
        return fail(out);
    }

    out.reserve((valid_count / 4) * 3);

    unsigned char quad[4];
    std::size_t quad_pos = 0;
    std::size_t processed_quads = 0;
    std::size_t total_quads = valid_count / 4;

    auto feed_char = [&](unsigned char c) -> bool {
        quad[quad_pos++] = c;
        if (quad_pos != 4) {
            return true;
        }

        unsigned char c0 = quad[0];
        unsigned char c1 = quad[1];
        unsigned char c2 = quad[2];
        unsigned char c3 = quad[3];

        auto d0 = (c0 == '=') ? 0xFF : kDecTable[c0];
        auto d1 = (c1 == '=') ? 0xFF : kDecTable[c1];

        if (c0 == '=' || c1 == '=' || d0 == 0xFF || d1 == 0xFF) {
            return false;
        }

        bool pad2 = (c2 == '=');
        bool pad3 = (c3 == '=');

        std::uint8_t d2 = 0;
        std::uint8_t d3 = 0;
        if (!pad2) {
            d2 = kDecTable[c2];
            if (d2 == 0xFF) return false;
        } else {
            if (!pad3) return false;
        }

        if (!pad3) {
            d3 = kDecTable[c3];
            if (d3 == 0xFF) return false;
        }

        std::uint32_t triple =
            (static_cast<std::uint32_t>(d0) << 18) |
            (static_cast<std::uint32_t>(d1) << 12) |
            (static_cast<std::uint32_t>(d2) << 6)  |
            (static_cast<std::uint32_t>(d3));

        out.push_back(static_cast<char>((triple >> 16) & 0xFF));
        if (!pad2) out.push_back(static_cast<char>((triple >> 8) & 0xFF));
        if (!pad3) out.push_back(static_cast<char>(triple & 0xFF));

        processed_quads++;

        if (pad2 || pad3) {
            if (processed_quads != total_quads) return false;
            if (pad2) {
                if ((triple & 0xFFFF) != 0) return false;
            } else if (pad3) {
                if ((triple & 0xFF) != 0) return false;
            }
        }

        quad_pos = 0;
        return true;
    };

    if (!has_space) {
        for (std::size_t i = 0; i < input.size(); i += 4) {
            if (!feed_char(static_cast<unsigned char>(input[i])) ||
                !feed_char(static_cast<unsigned char>(input[i + 1])) ||
                !feed_char(static_cast<unsigned char>(input[i + 2])) ||
                !feed_char(static_cast<unsigned char>(input[i + 3]))) {
                return fail(out);
            }
        }
    } else {
        for (unsigned char c : input) {
            if (IsSpace(c)) continue;
            if (!feed_char(c)) {
                return fail(out);
            }
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
        if (!IsSpace(c)) {
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
