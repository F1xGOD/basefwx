# BaseFWX example plugin build file
# Copyright (C) 2020-2026  FixCraft Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is intentionally permissive so plugin authors can use it as a starting template.
#
# BaseFWX time-tweak plugin — self-derived-entropy example.
#
# Demonstrates how a plugin can produce different output for the same
# input on every call (using unix time as an entropy source) while
# still being fully decodable from the wire bytes alone. The tweak is
# embedded at the head of the plugin's output; the decoder reads it
# back without needing any host coordination.
#
# Build:
#     cmake -S examples/plugins/time-tweak -B examples/plugins/time-tweak/build
#     cmake --build examples/plugins/time-tweak/build
#
# Produces:  libbasefwx-time-tweak.so / .dll / .dylib

cmake_minimum_required(VERSION 3.16)
project(basefwx-time-tweak CXX)

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

add_library(basefwx-time-tweak SHARED time_tweak.cpp)
target_include_directories(basefwx-time-tweak PRIVATE "${BASEFWX_INCLUDE_DIR}")
target_link_libraries(basefwx-time-tweak PRIVATE OpenSSL::Crypto)
target_compile_options(basefwx-time-tweak PRIVATE
    -Wall -Wextra -Wpedantic)

if(WIN32)
    set_target_properties(basefwx-time-tweak PROPERTIES PREFIX "")
endif()
