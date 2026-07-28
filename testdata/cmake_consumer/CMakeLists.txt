cmake_minimum_required(VERSION 3.16)
project(basefwx_add_subdirectory_smoke LANGUAGES CXX)

if(NOT DEFINED BASEFWX_SOURCE_DIR)
    message(FATAL_ERROR "BASEFWX_SOURCE_DIR is required")
endif()

add_subdirectory("${BASEFWX_SOURCE_DIR}" basefwx)

foreach(_internal_target
        peer_kdf_policy_test
        bench_memory_policy_test
        base64_compatibility_test)
    if(TARGET "${_internal_target}")
        message(FATAL_ERROR
            "BaseFWX internal test leaked into add_subdirectory consumer: "
            "${_internal_target}")
    endif()
endforeach()

add_custom_target(consumer_smoke ALL
    COMMAND "${CMAKE_COMMAND}" -E echo
        "BaseFWX add_subdirectory consumer smoke passed"
)
