# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

foreach(required_var
        BASEFWX_BUILD_DIR
        BASEFWX_TEST_PREFIX
        BASEFWX_CONSUMER_TEST)
    if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
        message(FATAL_ERROR "${required_var} is required")
    endif()
endforeach()

file(REMOVE_RECURSE "${BASEFWX_TEST_PREFIX}")

set(install_command
    "${CMAKE_COMMAND}" --install "${BASEFWX_BUILD_DIR}"
    --prefix "${BASEFWX_TEST_PREFIX}")
if(DEFINED BASEFWX_BUILD_CONFIG AND NOT BASEFWX_BUILD_CONFIG STREQUAL "")
    list(APPEND install_command --config "${BASEFWX_BUILD_CONFIG}")
endif()

execute_process(
    COMMAND ${install_command}
    RESULT_VARIABLE install_result
    OUTPUT_VARIABLE install_output
    ERROR_VARIABLE install_error
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR
        "staged BaseFWX install failed (${install_result})\n"
        "${install_output}\n${install_error}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
        "BASEFWX_TEST_PREFIX=${BASEFWX_TEST_PREFIX}"
        /bin/sh "${BASEFWX_CONSUMER_TEST}"
    RESULT_VARIABLE consumer_result
    OUTPUT_VARIABLE consumer_output
    ERROR_VARIABLE consumer_error
)
if(NOT consumer_result EQUAL 0)
    message(FATAL_ERROR
        "staged BaseFWX consumer failed (${consumer_result})\n"
        "${consumer_output}\n${consumer_error}")
endif()

message(STATUS "staged BaseFWX pkg-config and CMake consumers passed")
