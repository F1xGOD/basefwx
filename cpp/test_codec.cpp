#include <iostream>
#include <string>
#include "basefwx/codec.hpp"

int main() {
    std::string pythonEncoded = "59A4EG9J9SN2QK2R84KMIAHO85TJISRCFCSN6R3T8ONKII31CKL32AIB85F3EAH68T234JP6D50JCTB558OIK9I78GP4MDB1FD93EOBR58K4GGAIA95JAOBRFCSN6R1A51442KIIA8RM2UPA910MO99891842DPA910MO9A98SK423";
    std::string expected = "Cross-language test 2024";
    
    std::cout << "C++ decoding Python-encoded string:" << std::endl;
    std::string decoded = basefwx::codec::B256Decode(pythonEncoded);
    std::cout << "  Encoded (from Python): " << pythonEncoded << std::endl;
    std::cout << "  Decoded (in C++): " << decoded << std::endl;
    std::cout << "  Expected: " << expected << std::endl;
    std::cout << "  Match: " << (decoded == expected ? "true" : "false") << std::endl;
    
    // Test encoding in C++
    std::string cppTest = "C++ to Python/Java test";
    std::string cppEncoded = basefwx::codec::B256Encode(cppTest);
    std::cout << "\nC++ encoding for Python/Java:" << std::endl;
    std::cout << "  Original: " << cppTest << std::endl;
    std::cout << "  Encoded: " << cppEncoded << std::endl;
    
    return 0;
}
