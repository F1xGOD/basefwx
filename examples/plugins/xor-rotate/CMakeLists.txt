# BaseFWX xor-rotate plugin — example C++ plugin using the helper header.
#
# Build:
#     cmake -S examples/plugins/xor-rotate -B examples/plugins/xor-rotate/build
#     cmake --build examples/plugins/xor-rotate/build
#
# Produces:  libbasefwx-xor-rotate.so / .dll / .dylib

cmake_minimum_required(VERSION 3.16)
project(basefwx-xor-rotate CXX)

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

add_library(basefwx-xor-rotate SHARED xor_rotate.cpp)
target_include_directories(basefwx-xor-rotate PRIVATE "${BASEFWX_INCLUDE_DIR}")
target_compile_options(basefwx-xor-rotate PRIVATE
    -Wall -Wextra -Wpedantic)

if(WIN32)
    set_target_properties(basefwx-xor-rotate PROPERTIES PREFIX "")
endif()
