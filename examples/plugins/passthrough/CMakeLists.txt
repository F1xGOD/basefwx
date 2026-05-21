# BaseFWX passthrough plugin — minimal example.
#
# Stand-alone CMakeLists; does NOT live in the main basefwx build tree.
# Build it like any out-of-tree library:
#
#     cmake -S examples/plugins/passthrough -B examples/plugins/passthrough/build
#     cmake --build examples/plugins/passthrough/build
#
# Produces:  libbasefwx-passthrough.so  (Linux)
#            basefwx-passthrough.dll    (Windows)
#            libbasefwx-passthrough.dylib (macOS)
#
# Copy this file into your own plugin dir, edit the project name, and
# replace passthrough.c with your real transform.

cmake_minimum_required(VERSION 3.16)
project(basefwx-passthrough C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

# Point at the basefwx public include dir. By default we look two
# levels up (when this file is built in-tree). Override via:
#     cmake -DBASEFWX_INCLUDE_DIR=/path/to/basefwx/cpp/include
if(NOT DEFINED BASEFWX_INCLUDE_DIR)
    get_filename_component(_default "${CMAKE_CURRENT_SOURCE_DIR}/../../../cpp/include" ABSOLUTE)
    set(BASEFWX_INCLUDE_DIR "${_default}")
endif()

if(NOT EXISTS "${BASEFWX_INCLUDE_DIR}/basefwx/plugin.h")
    message(FATAL_ERROR
        "Cannot find basefwx/plugin.h under BASEFWX_INCLUDE_DIR=${BASEFWX_INCLUDE_DIR}. "
        "Pass -DBASEFWX_INCLUDE_DIR=<path-to-basefwx-cpp-include>.")
endif()

add_library(basefwx-passthrough SHARED passthrough.c)
target_include_directories(basefwx-passthrough PRIVATE "${BASEFWX_INCLUDE_DIR}")
target_compile_options(basefwx-passthrough PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Drop the "lib" prefix on Windows DLLs so the artifact matches the
# documented name. Linux/macOS keep the conventional "lib" prefix.
if(WIN32)
    set_target_properties(basefwx-passthrough PROPERTIES PREFIX "")
endif()
