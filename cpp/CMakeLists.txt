cmake_minimum_required(VERSION 3.16)
project(basefwx_cpp LANGUAGES CXX)

option(BASEFWX_BUILD_CLI "Build basefwx_cpp CLI" ON)
option(BASEFWX_REQUIRE_ARGON2 "Require libargon2 for Argon2id support" OFF)
option(BASEFWX_REQUIRE_OQS "Require liboqs for ML-KEM-768 support" OFF)
option(BASEFWX_OQS_STATIC "Prefer static liboqs when available" OFF)
option(BASEFWX_REQUIRE_LZMA "Require liblzma for xz support" OFF)
option(BASEFWX_NATIVE_OPT "Enable -march/-mtune native optimizations" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CheckIPOSupported)
check_ipo_supported(RESULT BASEFWX_IPO_SUPPORTED OUTPUT BASEFWX_IPO_ERROR)
if(BASEFWX_IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options($<$<CONFIG:Release>:-O3>)
    if(BASEFWX_NATIVE_OPT AND NOT CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_PROCESSOR STREQUAL CMAKE_HOST_SYSTEM_PROCESSOR)
        add_compile_options(
            $<$<CONFIG:Release>:-march=native>
            $<$<CONFIG:Release>:-mtune=native>
        )
    endif()
    add_compile_options($<$<CONFIG:Release>:-flto>)
    add_link_options($<$<CONFIG:Release>:-flto>)
elseif(MSVC)
    add_compile_options($<$<CONFIG:Release>:/O2 /GL>)
    add_link_options($<$<CONFIG:Release>:/LTCG>)
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(PkgConfig QUIET)
if(CMAKE_CROSSCOMPILING)
    set(PkgConfig_FOUND FALSE)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()

set(BASEFWX_HAS_ARGON2 0)
set(BASEFWX_HAS_OQS 0)
set(BASEFWX_HAS_LZMA 0)

if(PkgConfig_FOUND)
    pkg_check_modules(ARGON2 QUIET libargon2)
    pkg_check_modules(OQS QUIET liboqs)
    pkg_check_modules(LZMA QUIET liblzma)
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

if(OQS_FOUND AND BASEFWX_OQS_STATIC)
    set(_basefwx_oqs_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(OQS_LIBRARY_STATIC NAMES oqs)
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_basefwx_oqs_suffixes}")
    if(OQS_LIBRARY_STATIC)
        set(OQS_LIBRARIES ${OQS_LIBRARY_STATIC})
    endif()
endif()

if(NOT LZMA_FOUND)
    find_path(LZMA_INCLUDE_DIR NAMES lzma.h)
    find_library(LZMA_LIBRARY NAMES lzma)
    if(LZMA_INCLUDE_DIR AND LZMA_LIBRARY)
        set(LZMA_FOUND TRUE)
        set(LZMA_INCLUDE_DIRS ${LZMA_INCLUDE_DIR})
        set(LZMA_LIBRARIES ${LZMA_LIBRARY})
    endif()
endif()

if(BASEFWX_REQUIRE_ARGON2 AND NOT ARGON2_FOUND)
    message(FATAL_ERROR "libargon2 not found (install libargon2-dev or set BASEFWX_REQUIRE_ARGON2=OFF)")
endif()

if(BASEFWX_REQUIRE_OQS AND NOT OQS_FOUND)
    message(FATAL_ERROR "liboqs not found (install liboqs-dev or set BASEFWX_REQUIRE_OQS=OFF)")
endif()

if(BASEFWX_REQUIRE_LZMA AND NOT LZMA_FOUND)
    message(FATAL_ERROR "liblzma not found (install liblzma-dev or set BASEFWX_REQUIRE_LZMA=OFF)")
endif()

if(ARGON2_FOUND)
    set(BASEFWX_HAS_ARGON2 1)
endif()

if(OQS_FOUND)
    set(BASEFWX_HAS_OQS 1)
endif()

if(LZMA_FOUND)
    set(BASEFWX_HAS_LZMA 1)
endif()

add_library(basefwxcpp
    src/archive.cpp
    src/base64.cpp
    src/format.cpp
    src/basefwx.cpp
    src/crypto.cpp
    src/codec.cpp
    src/imagecipher.cpp
    src/ec.cpp
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
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
target_link_libraries(basefwxcpp PUBLIC OpenSSL::Crypto ZLIB::ZLIB)

if(CMAKE_CROSSCOMPILING)
    get_target_property(_basefwx_includes basefwxcpp INCLUDE_DIRECTORIES)
    if(_basefwx_includes)
        list(REMOVE_ITEM _basefwx_includes "/usr/include" "/usr/include/")
        set_target_properties(basefwxcpp PROPERTIES INCLUDE_DIRECTORIES "${_basefwx_includes}")
    endif()
endif()

if(ARGON2_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${ARGON2_INCLUDE_DIRS})
    target_link_libraries(basefwxcpp PUBLIC ${ARGON2_LIBRARIES})
endif()

if(OQS_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${OQS_INCLUDE_DIRS})
    target_link_libraries(basefwxcpp PUBLIC ${OQS_LIBRARIES})
endif()

if(LZMA_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${LZMA_INCLUDE_DIRS})
    target_link_libraries(basefwxcpp PUBLIC ${LZMA_LIBRARIES})
endif()

target_compile_definitions(basefwxcpp PUBLIC
    BASEFWX_HAS_ARGON2=${BASEFWX_HAS_ARGON2}
    BASEFWX_HAS_OQS=${BASEFWX_HAS_OQS}
    BASEFWX_HAS_LZMA=${BASEFWX_HAS_LZMA}
)

if(BASEFWX_BUILD_CLI)
    add_executable(basefwx_cpp
        src/main.cpp
    )
    target_link_libraries(basefwx_cpp PRIVATE basefwxcpp)
endif()
