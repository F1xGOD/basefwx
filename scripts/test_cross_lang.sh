#!/bin/bash
# Cross-Language Compatibility Test Suite
# Tests encryption/decryption across Python, C++, and Java

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
export BASEFWX_USER_KDF=pbkdf2
PW="test_password_123"
TEST_DIR="/tmp/basefwx_cross_lang_test_$$"
mkdir -p "$TEST_DIR"

# Track results
TESTS_PASSED=0
TESTS_FAILED=0
FAILURES=()

# Helper functions
log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    FAILURES+=("$1")
}

cleanup() {
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
}

# Only cleanup on script exit, not on subshell exit
trap cleanup EXIT

# Check if executables exist
check_prerequisites() {
    log_test "Checking prerequisites..."
    
    if ! command -v python3 &> /dev/null; then
        echo "ERROR: python3 not found"
        exit 1
    fi
    
    if ! [ -f cpp/build/basefwx_cpp ]; then
        echo "ERROR: C++ binary not found at cpp/build/basefwx_cpp"
        echo "Build it first with: cd cpp && cmake -B build -S . -DBASEFWX_REQUIRE_ARGON2=OFF && cmake --build build"
        exit 1
    fi
    
    if ! [ -f java/build/libs/basefwx-java.jar ]; then
        echo "ERROR: Java JAR not found at java/build/libs/basefwx-java.jar"
        echo "Build it first with: cd java && gradle build -x test"
        exit 1
    fi
    
    log_success "All prerequisites found"
}

# Test 1: pb512 Python -> C++
test_pb512_py_to_cpp() {
    log_test "Test pb512: Python encrypt -> C++ decrypt"
    
    local encrypted="$TEST_DIR/pb512_py.enc"
    local expected="Hello from Python to C++!"
    
    python3 -c "
import basefwx, os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
enc = basefwx.basefwx.pb512encode('$expected', '$PW', use_master=False)
with open('$encrypted', 'w') as f:
    f.write(enc)
" 2>&1
    
    local result=$(./cpp/build/basefwx_cpp pb512-dec "$(cat $encrypted)" -p "$PW" --no-master --kdf pbkdf2 2>&1)
    
    if [ "$result" = "$expected" ]; then
        log_success "pb512 Python -> C++ works"
    else
        log_failure "pb512 Python -> C++ failed. Expected '$expected', got '$result'"
    fi
}

# Test 2: pb512 C++ -> Python
test_pb512_cpp_to_py() {
    log_test "Test pb512: C++ encrypt -> Python decrypt"
    
    local encrypted="$TEST_DIR/pb512_cpp.enc"
    local expected="Hello from C++ to Python!"
    
    ./cpp/build/basefwx_cpp pb512-enc "$expected" -p "$PW" --no-master --kdf pbkdf2 > "$encrypted" 2>&1
    
    local result=$(python3 -c "
import basefwx, os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
enc = open('$encrypted').read().strip()
print(basefwx.basefwx.pb512decode(enc, '$PW', use_master=False))
" 2>&1)
    
    if [ "$result" = "$expected" ]; then
        log_success "pb512 C++ -> Python works"
    else
        log_failure "pb512 C++ -> Python failed. Expected '$expected', got '$result'"
    fi
}

# Test 3: pb512 Java -> Python
test_pb512_java_to_py() {
    log_test "Test pb512: Java encrypt -> Python decrypt"
    
    local encrypted="$TEST_DIR/pb512_java.enc"
    local expected="Hello from Java to Python!"
    
    java -jar java/build/libs/basefwx-java.jar pb512-enc "$expected" "$PW" --no-master > "$encrypted" 2>&1
    
    local result=$(python3 -c "
import basefwx, os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
enc = open('$encrypted').read().strip()
print(basefwx.basefwx.pb512decode(enc, '$PW', use_master=False))
" 2>&1)
    
    if [ "$result" = "$expected" ]; then
        log_success "pb512 Java -> Python works"
    else
        log_failure "pb512 Java -> Python failed. Expected '$expected', got '$result'"
    fi
}

# Test 4: pb512 Python -> Java
test_pb512_py_to_java() {
    log_test "Test pb512: Python encrypt -> Java decrypt"
    
    local encrypted="$TEST_DIR/pb512_py_java.enc"
    local expected="Hello from Python to Java!"
    
    python3 -c "
import basefwx, os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
enc = basefwx.basefwx.pb512encode('$expected', '$PW', use_master=False)
with open('$encrypted', 'w') as f:
    f.write(enc)
" 2>&1
    
    local result=$(java -jar java/build/libs/basefwx-java.jar pb512-dec "$(cat $encrypted)" "$PW" --no-master 2>&1)
    
    if [ "$result" = "$expected" ]; then
        log_success "pb512 Python -> Java works"
    else
        log_failure "pb512 Python -> Java failed. Expected '$expected', got '$result'"
    fi
}

# Test 5: b512 Python -> C++
test_b512_py_to_cpp() {
    log_test "Test b512: Python encrypt -> C++ decrypt"
    
    local encrypted="$TEST_DIR/b512_py.enc"
    local expected="B512 test message!"
    
    python3 -c "
import basefwx, os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
enc = basefwx.basefwx.b512encode('$expected', '$PW', use_master=False)
with open('$encrypted', 'w') as f:
    f.write(enc)
" 2>&1
    
    local result=$(./cpp/build/basefwx_cpp b512-dec "$(cat $encrypted)" -p "$PW" --no-master --kdf pbkdf2 2>&1)
    
    if [ "$result" = "$expected" ]; then
        log_success "b512 Python -> C++ works"
    else
        log_failure "b512 Python -> C++ failed. Expected '$expected', got '$result'"
    fi
}

# Test 6: fwxAES file Python -> C++
test_fwxaes_file_py_to_cpp() {
    log_test "Test fwxAES: Python encrypt file -> C++ decrypt"
    
    local test_file="$TEST_DIR/test_input.txt"
    local encrypted="$TEST_DIR/test_encrypted.fwx"
    local decrypted="$TEST_DIR/test_decrypted.txt"
    local expected="FwxAES file encryption test!"
    
    echo "$expected" > "$test_file"
    
    python3 -c "
import basefwx, os
from pathlib import Path
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'

with open('$test_file', 'rb') as f:
    data = f.read()

encrypted = basefwx.basefwx.fwxAES_encrypt_raw(data, '$PW', use_master=False)

with open('$encrypted', 'wb') as f:
    f.write(encrypted)
" 2>&1
    
    ./cpp/build/basefwx_cpp fwxaes-dec "$encrypted" -p "$PW" --no-master --out "$decrypted" 2>&1
    
    local result=$(cat "$decrypted")
    
    if [ "$result" = "$expected" ]; then
        log_success "fwxAES file Python -> C++ works"
    else
        log_failure "fwxAES file Python -> C++ failed. Expected '$expected', got '$result'"
    fi
}

# Test 7: Argon2 compatibility (if available)
test_argon2_compat() {
    log_test "Test Argon2: Python encrypt -> C++ decrypt (if available)"
    
    # Remove KDF restriction for this test
    unset BASEFWX_USER_KDF
    
    local encrypted="$TEST_DIR/argon2_test.enc"
    local expected="Argon2 test!"
    
    # Try to encrypt with Argon2 in Python
    python3 -c "
import basefwx, os
os.environ.pop('BASEFWX_USER_KDF', None)
try:
    enc = basefwx.basefwx.pb512encode('$expected', '$PW', use_master=False)
    with open('$encrypted', 'w') as f:
        f.write(enc)
except Exception as e:
    print(f'Argon2 not available: {e}')
    exit(1)
" 2>&1
    
    if [ $? -eq 0 ] && [ -f "$encrypted" ]; then
        # Try to decrypt with C++ (will auto-detect Argon2)
        local result=$(./cpp/build/basefwx_cpp pb512-dec "$(cat $encrypted)" -p "$PW" --no-master 2>&1)
        
        if [ "$result" = "$expected" ]; then
            log_success "Argon2 cross-language works"
        else
            log_failure "Argon2 cross-language failed. Expected '$expected', got '$result'"
        fi
    else
        echo -e "${YELLOW}[SKIP]${NC} Argon2 not available in Python, skipping test"
    fi
    
    # Restore KDF for other tests
    export BASEFWX_USER_KDF=pbkdf2
}

# Main test execution
main() {
    echo "================================"
    echo "Cross-Language Compatibility Test"
    echo "================================"
    echo
    
    check_prerequisites
    echo
    
    # Run all tests
    test_pb512_py_to_cpp
    test_pb512_cpp_to_py
    test_pb512_java_to_py
    test_pb512_py_to_java
    test_b512_py_to_cpp
    test_fwxaes_file_py_to_cpp
    test_argon2_compat
    
    echo
    echo "================================"
    echo "Test Summary"
    echo "================================"
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED"
    
    if [ $TESTS_FAILED -gt 0 ]; then
        echo
        echo "Failed tests:"
        for failure in "${FAILURES[@]}"; do
            echo -e "  ${RED}✗${NC} $failure"
        done
        exit 1
    else
        echo
        echo -e "${GREEN}All tests passed!${NC} ✓"
        exit 0
    fi
}

main
