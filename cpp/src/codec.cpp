#include "basefwx/codec.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace basefwx::codec {

namespace {

struct CodeEntry {
    char ch;
    const char* token;
};

constexpr CodeEntry kCodeMap[] = {
    {'a', "e*1"}, {'b', "&hl"}, {'c', "*&Gs"}, {'d', "*YHA"}, {'e', "K5a{"}, {'f', "(*HGA("},
    {'g', "*&GD2"}, {'h', "+*jsGA"}, {'i', "(aj*a"}, {'j', "g%"}, {'k', "&G{A"}, {'l', "/IHa"},
    {'m', "*(oa"}, {'n', "*KA^7"}, {'o', ")i*8A"}, {'p', "*H)PA-G"}, {'q', "*YFSA"},
    {'r', "O.-P[A"}, {'s', "{9sl"}, {'t', "*(HARR"}, {'u', "O&iA6u"}, {'v', "n):u"},
    {'w', "&^F*GV"}, {'x', "(*HskW"}, {'y', "{JM"}, {'z', "J.!dA"}, {'A', "(&Tav"},
    {'B', "t5"}, {'C', "*TGA3"}, {'D', "*GABD"}, {'E', "{A"}, {'F', "pW"}, {'G', "*UAK("},
    {'H', "&GH+"}, {'I', "&AN)"}, {'J', "L&VA"}, {'K', "(HAF5"}, {'L', "&F*Va"},
    {'M', "^&FVB"}, {'N', "(*HSA$i"}, {'O', "*IHda&gT"}, {'P', "&*FAl"}, {'Q', ")P{A]"},
    {'R', "*Ha$g"}, {'S', "G)OA&"}, {'T', "|QG6"}, {'U', "Qd&^"}, {'V', "hA"},
    {'W', "8h^va"}, {'X', "_9xlA"}, {'Y', "*J"}, {'Z', "*;pY&"}, {' ', "R7a{"},
    {'-', "}F"}, {'=', "OJ)_A"}, {'+', "}J"}, {'&', "%A"}, {'%', "y{A3s"},
    {'#', ".aGa!"}, {'@', "l@"}, {'!', "/A"}, {'^', "OIp*a"}, {'*', "(U"},
    {'(', "I*Ua]"}, {')', "{0aD"}, {'{', "Av["}, {'}', "9j"}, {'[', "[a)"},
    {']', "*&GBA"}, {'|', "]Vc!A"}, {'/', ")*HND_"}, {'~', "(&*GHA"},
    {';', "K}N=O"}, {':', "YGOI&Ah"}, {'?', "Oa"}, {'.', "8y)a"},
    {'>', "0{a9"}, {'<', "v6Yha"}, {',', "I8ys#"}, {'0', "(HPA7"},
    {'1', "}v"}, {'2', "*HAl%"}, {'3', "_)JHS"}, {'4', "IG(A"}, {'5', "(*GFD"},
    {'6', "IU(&V"}, {'7', "(JH*G"}, {'8', "*GHBA"}, {'9', "U&G*C"}, {'"', "I(a-s"},
};

constexpr char kBase32HexAlphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

std::array<int, 256> BuildBase32DecodeTable() {
    std::array<int, 256> table{};
    table.fill(-1);
    for (int i = 0; i < 32; ++i) {
        table[static_cast<unsigned char>(kBase32HexAlphabet[i])] = i;
        table[static_cast<unsigned char>(std::tolower(kBase32HexAlphabet[i]))] = i;
    }
    return table;
}

const std::array<int, 256> kBase32DecodeTable = BuildBase32DecodeTable();

// Build a lookup table for fast character-to-token mapping
std::array<const char*, 256> BuildCodeLookupTable() {
    std::array<const char*, 256> table{};
    table.fill(nullptr);
    for (const auto& entry : kCodeMap) {
        table[static_cast<unsigned char>(entry.ch)] = entry.token;
    }
    return table;
}

const std::array<const char*, 256> kCodeLookupTable = BuildCodeLookupTable();

// Build sorted tokens for decoding (build once at startup)
std::vector<std::pair<std::string, char>> BuildSortedTokens() {
    std::vector<std::pair<std::string, char>> tokens;
    tokens.reserve(sizeof(kCodeMap) / sizeof(kCodeMap[0]));
    for (const auto& entry : kCodeMap) {
        tokens.emplace_back(entry.token, entry.ch);
    }
    std::sort(tokens.begin(), tokens.end(),
              [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });
    return tokens;
}

const std::vector<std::pair<std::string, char>> kSortedTokens = BuildSortedTokens();

}  // namespace

std::string Code(const std::string& input) {
    if (input.empty()) {
        return input;
    }
    std::string out;
    out.reserve(input.size() * 4);
    for (unsigned char ch : input) {
        const char* token = kCodeLookupTable[ch];
        if (token != nullptr) {
            out.append(token);
        } else {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

std::string Decode(const std::string& input) {
    if (input.empty()) {
        return input;
    }
    std::string out;
    out.reserve(input.size());
    std::size_t idx = 0;
    while (idx < input.size()) {
        bool matched = false;
        for (const auto& token : kSortedTokens) {
            if (token.first.size() == 0) {
                continue;
            }
            if (idx + token.first.size() <= input.size()
                && input.compare(idx, token.first.size(), token.first) == 0) {
                out.push_back(token.second);
                idx += token.first.size();
                matched = true;
                break;
            }
        }
        if (!matched) {
            out.push_back(input[idx]);
            ++idx;
        }
    }
    return out;
}

std::string Base32HexEncode(const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return "";
    }
    std::string out;
    out.reserve(((data.size() + 4) / 5) * 8);
    std::uint32_t buffer = 0;
    int bits_left = 0;

    for (std::uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits_left += 8;
        while (bits_left >= 5) {
            int index = (buffer >> (bits_left - 5)) & 0x1F;
            out.push_back(kBase32HexAlphabet[index]);
            bits_left -= 5;
        }
    }
    if (bits_left > 0) {
        buffer <<= (5 - bits_left);
        int index = buffer & 0x1F;
        out.push_back(kBase32HexAlphabet[index]);
    }
    while (out.size() % 8 != 0) {
        out.push_back('=');
    }
    return out;
}

std::vector<std::uint8_t> Base32HexDecode(const std::string& input, bool* ok) {
    bool success = true;
    std::vector<std::uint8_t> out;
    std::uint32_t buffer = 0;
    int bits_left = 0;

    for (unsigned char c : input) {
        if (std::isspace(c)) {
            continue;
        }
        if (c == '=') {
            break;
        }
        int val = kBase32DecodeTable[c];
        if (val < 0) {
            success = false;
            break;
        }
        buffer = (buffer << 5) | static_cast<std::uint32_t>(val);
        bits_left += 5;
        if (bits_left >= 8) {
            std::uint8_t byte = static_cast<std::uint8_t>((buffer >> (bits_left - 8)) & 0xFF);
            out.push_back(byte);
            bits_left -= 8;
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

std::string B256Encode(const std::string& input) {
    std::string coded = Code(input);
    std::vector<std::uint8_t> raw(coded.begin(), coded.end());
    std::string encoded = Base32HexEncode(raw);
    std::size_t padding_count = std::count(encoded.begin(), encoded.end(), '=');
    encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
    if (padding_count > 9) {
        throw std::runtime_error("Base32 padding count exceeded single digit");
    }
    encoded.push_back(static_cast<char>('0' + padding_count));
    return encoded;
}

std::string B256Decode(const std::string& input) {
    if (input.empty()) {
        return "";
    }
    char pad_char = input.back();
    if (pad_char < '0' || pad_char > '9') {
        throw std::runtime_error("Invalid b256 padding marker");
    }
    std::size_t padding_count = static_cast<std::size_t>(pad_char - '0');
    std::string base32 = input.substr(0, input.size() - 1);
    base32.append(padding_count, '=');
    bool ok = false;
    std::vector<std::uint8_t> decoded = Base32HexDecode(base32, &ok);
    if (!ok) {
        throw std::runtime_error("Invalid base32 payload");
    }
    std::string decoded_text(decoded.begin(), decoded.end());
    return Decode(decoded_text);
}

}  // namespace basefwx::codec
