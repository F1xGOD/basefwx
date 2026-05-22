# BaseFWX aead-wrapped-keyed plugin — Profile B reference example.
#
# Demonstrates the keyed forward / inverse path with HKDF, AES-256-CTR,
# and HMAC-SHA256. Suitable for raw-mode use; defends against THREAT_MODEL.md
# TM-1..TM-4.
#
# Build:
#     cmake -S examples/plugins/aead-wrapped-keyed -B examples/plugins/aead-wrapped-keyed/build
#     cmake --build examples/plugins/aead-wrapped-keyed/build
#
# Produces:  libbasefwx-aead-wrapped-keyed.so / .dll / .dylib

cmake_minimum_required(VERSION 3.16)
project(basefwx-aead-wrapped-keyed CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

if(NOT DEFINED BASEFWX_INCLUDE_DIR)
    get_filename_component(_default "${CMAKE_CURRENT_SOURCE_DIR}/../../../cpp/include" ABSOLUTE)
    set(BASEFWX_INCLUDE_DIR "${_default}")
endif()

if(NOT EXISTS "${BASEFWX_INCLUDE_DIR}/basefwx/plugin.hpp")
    message(FATAL_ERROR
        "Cannot find basefwx/plugin.hpp under BASEFWX_INCLUDE_DIR=${BASEFWX_INCLUDE_DIR}. "
        "Pass -DBASEFWX_INCLUDE_DIR=<path-to-basefwx-cpp-include>.")
endif()

find_package(OpenSSL REQUIRED)

add_library(basefwx-aead-wrapped-keyed SHARED aead_wrapped_keyed.cpp)
target_include_directories(basefwx-aead-wrapped-keyed PRIVATE "${BASEFWX_INCLUDE_DIR}")
target_link_libraries(basefwx-aead-wrapped-keyed PRIVATE OpenSSL::Crypto)
target_compile_options(basefwx-aead-wrapped-keyed PRIVATE
    -Wall -Wextra -Wpedantic)

if(WIN32)
    set_target_properties(basefwx-aead-wrapped-keyed PROPERTIES PREFIX "")
endif()
