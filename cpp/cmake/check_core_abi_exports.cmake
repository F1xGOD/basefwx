# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

if(NOT DEFINED BASEFWX_LIBRARY OR BASEFWX_LIBRARY STREQUAL "")
    message(FATAL_ERROR "BASEFWX_LIBRARY is required")
endif()
if(NOT EXISTS "${BASEFWX_LIBRARY}")
    message(FATAL_ERROR "BaseFWX library does not exist: ${BASEFWX_LIBRARY}")
endif()
if(NOT DEFINED BASEFWX_NM OR BASEFWX_NM STREQUAL "")
    message(FATAL_ERROR "BASEFWX_NM is required")
endif()

execute_process(
    COMMAND "${BASEFWX_NM}" -D -C --defined-only "${BASEFWX_LIBRARY}"
    RESULT_VARIABLE nm_result
    OUTPUT_VARIABLE exported_symbols
    ERROR_VARIABLE nm_error
)
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "nm failed (${nm_result}): ${nm_error}")
endif()

if(exported_symbols MATCHES "basefwx::cli::")
    message(FATAL_ERROR
        "libbasefwx exports private GPL command-line symbols; CLI sources must "
        "be linked only into the basefwx executable")
endif()

foreach(required_symbol
        "basefwx::crypto::HkdfSha256"
        "basefwx::pq::GenerateKeyPair"
        "basefwx::x25519::GenerateKeyPair")
    string(FIND "${exported_symbols}" "${required_symbol}" symbol_offset)
    if(symbol_offset EQUAL -1)
        message(FATAL_ERROR
            "libbasefwx is missing required 3.8 API symbol: ${required_symbol}")
    endif()
endforeach()

message(STATUS "BaseFWX core ABI exports contain required 3.8 APIs and no CLI symbols")
