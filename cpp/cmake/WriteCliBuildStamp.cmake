if(NOT DEFINED OUTPUT_FILE OR OUTPUT_FILE STREQUAL "")
    message(FATAL_ERROR "OUTPUT_FILE is required")
endif()

if(NOT DEFINED SOURCE_ROOT OR SOURCE_ROOT STREQUAL "")
    set(SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
endif()

if(NOT DEFINED BUILD_TYPE OR BUILD_TYPE STREQUAL "")
    set(BUILD_TYPE "unknown")
endif()

string(TIMESTAMP BASEFWX_BUILD_UTC "%Y-%m-%dT%H:%M:%SZ" UTC)
set(BASEFWX_GIT_COMMIT "unknown")
execute_process(
    COMMAND git -C "${SOURCE_ROOT}" rev-parse --short=12 HEAD
    OUTPUT_VARIABLE BASEFWX_GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE BASEFWX_GIT_RESULT
)
if(NOT BASEFWX_GIT_RESULT EQUAL 0 OR BASEFWX_GIT_COMMIT STREQUAL "")
    set(BASEFWX_GIT_COMMIT "unknown")
endif()

set(_basefwx_cli_build_stamp [=[
#pragma once
#define BASEFWX_CLI_GIT_COMMIT "@BASEFWX_GIT_COMMIT@"
#define BASEFWX_CLI_BUILD_UTC "@BASEFWX_BUILD_UTC@"
#define BASEFWX_CLI_BUILD_TYPE "@BUILD_TYPE@"
]=])
string(CONFIGURE "${_basefwx_cli_build_stamp}" _basefwx_cli_build_stamp @ONLY)

if(EXISTS "${OUTPUT_FILE}")
    file(READ "${OUTPUT_FILE}" _existing_content)
else()
    set(_existing_content "")
endif()

get_filename_component(_output_dir "${OUTPUT_FILE}" DIRECTORY)
file(MAKE_DIRECTORY "${_output_dir}")

if(NOT _existing_content STREQUAL _basefwx_cli_build_stamp)
    file(WRITE "${OUTPUT_FILE}" "${_basefwx_cli_build_stamp}")
endif()
