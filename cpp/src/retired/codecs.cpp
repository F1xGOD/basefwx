/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#include "basefwx/retired/codecs.hpp"

#include "basefwx/codec.hpp"
#include "basefwx/crypto_utils.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string HexEncode(const std::vector<std::uint8_t>& data) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output;
    output.reserve(data.size() * 2);
    for (const std::uint8_t byte : data) {
        output.push_back(kHex[(byte >> 4) & 0x0Fu]);
        output.push_back(kHex[byte & 0x0Fu]);
    }
    return output;
}

std::string DigestHex(const std::string& input, const EVP_MD* digest) {
    using basefwx::crypto::detail::UniqueMDCtx;
    UniqueMDCtx context(EVP_MD_CTX_new());
    if (!context) {
        throw std::runtime_error("Digest context allocation failed");
    }
    std::array<std::uint8_t, 64> output{};
    unsigned int output_size = 0;
    if (EVP_DigestInit_ex(context.get(), digest, nullptr) != 1
        || (!input.empty()
            && EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1)
        || EVP_DigestFinal_ex(context.get(), output.data(), &output_size) != 1) {
        throw std::runtime_error("Digest operation failed");
    }
    return HexEncode(std::vector<std::uint8_t>(
        output.begin(), output.begin() + output_size));
}

std::string MdCode(const std::string& input) {
    std::string output;
    output.reserve(input.size() * 3);
    for (const unsigned char ch : input) {
        const unsigned int value = ch;
        if (value < 10) {
            output.push_back('1');
            output.push_back(static_cast<char>('0' + value));
        } else if (value < 100) {
            output.push_back('2');
            output.push_back(static_cast<char>('0' + value / 10));
            output.push_back(static_cast<char>('0' + value % 10));
        } else {
            output.push_back('3');
            output.push_back(static_cast<char>('0' + value / 100));
            output.push_back(static_cast<char>('0' + (value / 10) % 10));
            output.push_back(static_cast<char>('0' + value % 10));
        }
    }
    return output;
}

std::string StripLeadingZeros(const std::string& input) {
    const auto first = input.find_first_not_of('0');
    return first == std::string::npos ? "0" : input.substr(first);
}

int CompareMagnitude(const std::string& left, const std::string& right) {
    const std::string normalized_left = StripLeadingZeros(left);
    const std::string normalized_right = StripLeadingZeros(right);
    if (normalized_left.size() != normalized_right.size()) {
        return normalized_left.size() < normalized_right.size() ? -1 : 1;
    }
    if (normalized_left == normalized_right) {
        return 0;
    }
    return normalized_left < normalized_right ? -1 : 1;
}

std::string AddMagnitude(const std::string& left, const std::string& right) {
    int left_index = static_cast<int>(left.size()) - 1;
    int right_index = static_cast<int>(right.size()) - 1;
    int carry = 0;
    std::string output;
    while (left_index >= 0 || right_index >= 0 || carry > 0) {
        const int left_digit = left_index >= 0
            ? left[static_cast<std::size_t>(left_index)] - '0' : 0;
        const int right_digit = right_index >= 0
            ? right[static_cast<std::size_t>(right_index)] - '0' : 0;
        const int sum = left_digit + right_digit + carry;
        output.push_back(static_cast<char>('0' + sum % 10));
        carry = sum / 10;
        --left_index;
        --right_index;
    }
    std::reverse(output.begin(), output.end());
    return StripLeadingZeros(output);
}

std::string SubtractMagnitude(const std::string& left, const std::string& right) {
    int left_index = static_cast<int>(left.size()) - 1;
    int right_index = static_cast<int>(right.size()) - 1;
    int borrow = 0;
    std::string output;
    while (left_index >= 0) {
        int left_digit =
            (left[static_cast<std::size_t>(left_index)] - '0') - borrow;
        const int right_digit = right_index >= 0
            ? right[static_cast<std::size_t>(right_index)] - '0' : 0;
        if (left_digit < right_digit) {
            left_digit += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        output.push_back(static_cast<char>('0' + left_digit - right_digit));
        --left_index;
        --right_index;
    }
    std::reverse(output.begin(), output.end());
    return StripLeadingZeros(output);
}

struct SignedNumber {
    bool negative = false;
    std::string digits = "0";
};

SignedNumber ParseSigned(const std::string& input) {
    SignedNumber result;
    if (input.empty()) {
        return result;
    }
    std::size_t start = 0;
    if (input.front() == '-') {
        result.negative = true;
        start = 1;
    }
    result.digits = StripLeadingZeros(input.substr(start));
    if (result.digits == "0") {
        result.negative = false;
    }
    return result;
}

std::string AddSigned(const std::string& left, const std::string& right) {
    const SignedNumber parsed_left = ParseSigned(left);
    const SignedNumber parsed_right = ParseSigned(right);
    if (parsed_left.negative == parsed_right.negative) {
        const std::string sum = AddMagnitude(parsed_left.digits, parsed_right.digits);
        return sum == "0" ? sum : (parsed_left.negative ? "-" : "") + sum;
    }
    const int comparison = CompareMagnitude(parsed_left.digits, parsed_right.digits);
    if (comparison == 0) {
        return "0";
    }
    if (comparison > 0) {
        return (parsed_left.negative ? "-" : "")
            + SubtractMagnitude(parsed_left.digits, parsed_right.digits);
    }
    return (parsed_right.negative ? "-" : "")
        + SubtractMagnitude(parsed_right.digits, parsed_left.digits);
}

std::string ReplaceAll(std::string input, const std::string& from, const std::string& to) {
    std::size_t position = 0;
    while (!from.empty()
           && (position = input.find(from, position)) != std::string::npos) {
        input.replace(position, from.size(), to);
        position += to.size();
    }
    return input;
}

std::string MCode(const std::string& input) {
    std::string output;
    output.reserve(input.size() / 2);  // Rough estimate
    std::size_t index = 0;
    while (index < input.size()) {
        if (input[index] < '0' || input[index] > '9') {
            throw std::runtime_error("Invalid mcode input");
        }
        const int length = input[index++] - '0';
        if (index + static_cast<std::size_t>(length) > input.size()) {
            throw std::runtime_error("Invalid mcode length");
        }
        int value = 0;
        if (length == 1) {
            value = input[index] - '0';
        } else if (length == 2) {
            value = (input[index] - '0') * 10 + (input[index + 1] - '0');
        } else if (length == 3) {
            value = (input[index] - '0') * 100
                + (input[index + 1] - '0') * 10
                + (input[index + 2] - '0');
        } else {
            value = std::stoi(input.substr(index, static_cast<std::size_t>(length)));
        }
        output.push_back(static_cast<char>(value));
        index += static_cast<std::size_t>(length);
    }
    return output;
}

std::string B256EncodeSilent(const std::string& input) {
    const std::string coded = basefwx::codec::Code(input);
    const std::vector<std::uint8_t> raw(coded.begin(), coded.end());
    std::string encoded = basefwx::codec::Base32HexEncode(raw);
    const std::size_t padding = static_cast<std::size_t>(
        std::count(encoded.begin(), encoded.end(), '='));
    encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
    if (padding > 9) {
        throw std::runtime_error("Base32 padding count exceeded single digit");
    }
    encoded.push_back(static_cast<char>('0' + padding));
    return encoded;
}

std::string B256DecodeSilent(const std::string& input) {
    if (input.empty()) {
        return "";
    }
    const char padding_marker = input.back();
    if (padding_marker < '0' || padding_marker > '9') {
        throw std::runtime_error("Invalid b256 padding marker");
    }
    std::string encoded = input.substr(0, input.size() - 1);
    encoded.append(static_cast<std::size_t>(padding_marker - '0'), '=');
    bool valid = false;
    const auto decoded = basefwx::codec::Base32HexDecode(encoded, &valid);
    if (!valid) {
        throw std::runtime_error("Invalid base32 payload");
    }
    return basefwx::codec::Decode(std::string(decoded.begin(), decoded.end()));
}

void WarnB256RetiredOnce() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        std::cerr << "b256 is available only for retired-data compatibility; "
                     "use base64 for new reversible encodings.\n";
    });
}

}  // namespace

namespace basefwx::codec {

std::string B256Encode(const std::string& input) {
    return B256EncodeSilent(input);
}

std::string B256Decode(const std::string& input) {
    return B256DecodeSilent(input);
}

}  // namespace basefwx::codec

namespace basefwx {

std::string B256Encode(const std::string& input) {
    WarnB256RetiredOnce();
    return codec::B256Encode(input);
}

std::string B256Decode(const std::string& input) {
    WarnB256RetiredOnce();
    return codec::B256Decode(input);
}

std::string Uhash513(const std::string& input) {
    const std::string first = DigestHex(input, EVP_sha256());
    const std::string compatibility_sha1 = DigestHex(first, EVP_sha1());
    const std::string chained = DigestHex(compatibility_sha1, EVP_sha512());
    const std::string direct = DigestHex(input, EVP_sha512());
    return DigestHex(chained + direct, EVP_sha256());
}

std::string Bi512Encode(const std::string& input) {
    if (input.empty()) {
        throw std::runtime_error("bi512encode expects non-empty input");
    }
    std::string code;
    code.push_back(input.front());
    code.push_back(input.back());
    const std::string encoded = MdCode(input);
    const std::string encoded_code = MdCode(code);
    const std::string difference = CompareMagnitude(encoded, encoded_code) >= 0
        ? SubtractMagnitude(encoded, encoded_code)
        : "0" + SubtractMagnitude(encoded_code, encoded);
    return DigestHex(
        ReplaceAll(B256EncodeSilent(difference), "=", "4G5tRA"),
        EVP_sha256());
}

std::string A512Encode(const std::string& input) {
    const std::string encoded = MdCode(input);
    const std::string encoded_size = std::to_string(encoded.size());
    const std::string prefix = std::to_string(encoded_size.size()) + encoded_size;
    const std::size_t size = encoded.size();
    const std::string encoded_code = MdCode(std::to_string(size * size));
    const std::string difference = CompareMagnitude(encoded, encoded_code) >= 0
        ? SubtractMagnitude(encoded, encoded_code)
        : "0" + SubtractMagnitude(encoded_code, encoded);
    return prefix + ReplaceAll(B256EncodeSilent(difference), "=", "4G5tRA");
}

std::string A512Decode(const std::string& input) {
    try {
        if (input.empty() || input.front() < '0' || input.front() > '9') {
            throw std::runtime_error("Invalid a512 length marker");
        }
        const int length_size = input.front() - '0';
        if (length_size <= 0
            || input.size() < static_cast<std::size_t>(length_size) + 1) {
            throw std::runtime_error("Invalid a512 length encoding");
        }
        const std::size_t encoded_size = static_cast<std::size_t>(
            std::stoul(input.substr(1, static_cast<std::size_t>(length_size))));
        const std::string encoded_code = MdCode(
            std::to_string(encoded_size * encoded_size));
        std::string restored = B256DecodeSilent(ReplaceAll(
            input.substr(static_cast<std::size_t>(length_size) + 1),
            "4G5tRA", "="));
        if (!restored.empty() && restored.front() == '0') {
            restored = "-" + restored.substr(1);
        }
        const std::string sum = AddSigned(restored, encoded_code);
        if (!sum.empty() && sum.front() == '-') {
            throw std::runtime_error("Negative a512 value");
        }
        return MCode(sum);
    } catch (...) {
        return "AN ERROR OCCURED!";
    }
}

}  // namespace basefwx
