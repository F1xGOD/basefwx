#include "basefwx/codec.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <memory>
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

// Trie node for efficient token decoding (matches Java implementation)
struct TrieNode {
    std::array<std::unique_ptr<TrieNode>, 256> children{};
    char value = '\0';
    bool terminal = false;
};

// Build Trie for token decoding (much faster than linear search)
std::unique_ptr<TrieNode> BuildTokenTrie() {
    auto root = std::make_unique<TrieNode>();
    for (const auto& entry : kCodeMap) {
        const char* token = entry.token;
        TrieNode* node = root.get();
        for (const char* p = token; *p != '\0'; ++p) {
            unsigned char idx = static_cast<unsigned char>(*p);
            if (!node->children[idx]) {
                node->children[idx] = std::make_unique<TrieNode>();
            }
            node = node->children[idx].get();
        }
        node->terminal = true;
        node->value = entry.ch;
    }
    return root;
}

// Meyer's singleton pattern to avoid static initialization order issues
const TrieNode* GetTokenTrie() {
    static const std::unique_ptr<TrieNode> trie = BuildTokenTrie();
    return trie.get();
}

}  // namespace

std::string Code(const std::string& input) {
    if (input.empty()) {
        return input;
    }
    std::string out;
    out.reserve(input.size() * 4);
    for (char ch : input) {
        unsigned char idx = static_cast<unsigned char>(ch);
        const char* token = kCodeLookupTable[idx];
        if (token != nullptr) {
            out.append(token);
        } else {
            out.push_back(ch);
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
    const TrieNode* root = GetTokenTrie();
    
    while (idx < input.size()) {
        unsigned char ch = static_cast<unsigned char>(input[idx]);
        const TrieNode* node = root->children[ch].get();
        
        if (!node) {
            // No token starts with this character, output as-is
            out.push_back(input[idx]);
            ++idx;
            continue;
        }
        
        // Traverse the trie to find the longest match
        std::size_t scan = idx + 1;
        const TrieNode* current = node;
        char match_char = '\0';
        std::size_t match_len = 0;
        
        if (current->terminal) {
            match_char = current->value;
            match_len = 1;
        }
        
        while (scan < input.size()) {
            unsigned char next = static_cast<unsigned char>(input[scan]);
            const TrieNode* next_node = current->children[next].get();
            if (!next_node) {
                break;
            }
            current = next_node;
            ++scan;
            if (current->terminal) {
                match_char = current->value;
                match_len = scan - idx;
            }
        }
        
        if (match_len > 0) {
            out.push_back(match_char);
            idx += match_len;
        } else {
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
