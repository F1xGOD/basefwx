# BaseFWX example plugin build file
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0, with the
# BaseFWX Plugin-Template Exception (see LICENCE clause 5).
#
# BaseFWX static-embed example — Profile C reference.
#
# Demonstrates the in-process Registry API. The plugin source is
# compiled directly into this host executable; there is no .so on
# disk. The Registry resolves the plugin by its 16-byte ID at
# runtime.
#
# Build:
#     cmake -S examples/plugins/static-embed -B examples/plugins/static-embed/build
#     cmake --build examples/plugins/static-embed/build
#     examples/plugins/static-embed/build/basefwx-static-embed-demo
#
# Expect output:  "PASS: static-embed plugin round-trip OK ..."

cmake_minimum_required(VERSION 3.16)
project(basefwx-static-embed-demo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT DEFINED BASEFWX_INCLUDE_DIR)
    get_filename_component(_default "${CMAKE_CURRENT_SOURCE_DIR}/../../../cpp/include" ABSOLUTE)
    set(BASEFWX_INCLUDE_DIR "${_default}")
endif()

if(NOT EXISTS "${BASEFWX_INCLUDE_DIR}/basefwx/plugin_static.hpp")
    message(FATAL_ERROR
        "Cannot find basefwx/plugin_static.hpp under BASEFWX_INCLUDE_DIR=${BASEFWX_INCLUDE_DIR}. "
        "Pass -DBASEFWX_INCLUDE_DIR=<path-to-basefwx-cpp-include>.")
endif()

add_executable(basefwx-static-embed-demo static_embed_demo.cpp)
target_include_directories(basefwx-static-embed-demo PRIVATE "${BASEFWX_INCLUDE_DIR}")
target_compile_options(basefwx-static-embed-demo PRIVATE
    -Wall -Wextra -Wpedantic)
target_link_libraries(basefwx-static-embed-demo PRIVATE pthread)
