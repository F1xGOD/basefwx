cmake_minimum_required(VERSION 3.16)
project(basefwx_cpp LANGUAGES CXX)

option(BASEFWX_BUILD_CLI "Build basefwx_cpp CLI" ON)
option(BASEFWX_REQUIRE_ARGON2 "Require libargon2 for Argon2id support" OFF)
option(BASEFWX_REQUIRE_OQS "Require liboqs for ML-KEM-768 support" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(PkgConfig QUIET)

set(BASEFWX_HAS_ARGON2 0)
set(BASEFWX_HAS_OQS 0)

if(PkgConfig_FOUND)
    pkg_check_modules(ARGON2 QUIET libargon2)
    pkg_check_modules(OQS QUIET liboqs)
endif()

if(NOT ARGON2_FOUND)
    find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
    find_library(ARGON2_LIBRARY NAMES argon2)
    if(ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
        set(ARGON2_FOUND TRUE)
        set(ARGON2_INCLUDE_DIRS ${ARGON2_INCLUDE_DIR})
        set(ARGON2_LIBRARIES ${ARGON2_LIBRARY})
    endif()
endif()

if(NOT OQS_FOUND)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h)
    find_library(OQS_LIBRARY NAMES oqs)
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
        set(OQS_FOUND TRUE)
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
        set(OQS_LIBRARIES ${OQS_LIBRARY})
    endif()
endif()

if(BASEFWX_REQUIRE_ARGON2 AND NOT ARGON2_FOUND)
    message(FATAL_ERROR "libargon2 not found (install libargon2-dev or set BASEFWX_REQUIRE_ARGON2=OFF)")
endif()

if(BASEFWX_REQUIRE_OQS AND NOT OQS_FOUND)
    message(FATAL_ERROR "liboqs not found (install liboqs-dev or set BASEFWX_REQUIRE_OQS=OFF)")
endif()

if(ARGON2_FOUND)
    set(BASEFWX_HAS_ARGON2 1)
endif()

if(OQS_FOUND)
    set(BASEFWX_HAS_OQS 1)
endif()

add_library(basefwxcpp
    src/base64.cpp
    src/format.cpp
    src/basefwx.cpp
    src/crypto.cpp
    src/codec.cpp
    src/pb512.cpp
    src/fwxaes.cpp
    src/env.cpp
    src/pq.cpp
    src/keywrap.cpp
    src/obfuscation.cpp
    src/metadata.cpp
    src/filecodec.cpp
)

target_include_directories(basefwxcpp
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(basefwxcpp PUBLIC OpenSSL::Crypto ZLIB::ZLIB)

if(ARGON2_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${ARGON2_INCLUDE_DIRS})
    target_link_libraries(basefwxcpp PUBLIC ${ARGON2_LIBRARIES})
endif()

if(OQS_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${OQS_INCLUDE_DIRS})
    target_link_libraries(basefwxcpp PUBLIC ${OQS_LIBRARIES})
endif()

target_compile_definitions(basefwxcpp PUBLIC
    BASEFWX_HAS_ARGON2=${BASEFWX_HAS_ARGON2}
    BASEFWX_HAS_OQS=${BASEFWX_HAS_OQS}
)

if(BASEFWX_BUILD_CLI)
    add_executable(basefwx_cpp
        src/main.cpp
    )
    target_link_libraries(basefwx_cpp PRIVATE basefwxcpp)
endif()
