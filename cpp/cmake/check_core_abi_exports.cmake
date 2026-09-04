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
if(NOT DEFINED BASEFWX_EXPECT_RETIRED_MEDIA)
    message(FATAL_ERROR "BASEFWX_EXPECT_RETIRED_MEDIA is required")
endif()
if(NOT DEFINED BASEFWX_EXPECT_SOVERSION
        OR BASEFWX_EXPECT_SOVERSION STREQUAL "")
    message(FATAL_ERROR "BASEFWX_EXPECT_SOVERSION is required")
endif()
if(NOT DEFINED BASEFWX_SONAME_FILE_NAME
        OR BASEFWX_SONAME_FILE_NAME STREQUAL "")
    message(FATAL_ERROR "BASEFWX_SONAME_FILE_NAME is required")
endif()

set(expected_soname "libbasefwx.so.${BASEFWX_EXPECT_SOVERSION}")
if(NOT BASEFWX_SONAME_FILE_NAME STREQUAL expected_soname)
    message(FATAL_ERROR
        "BaseFWX shared-library SONAME file is ${BASEFWX_SONAME_FILE_NAME}; "
        "expected ${expected_soname}")
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
        "basefwx::crypto::CompatPrfStreamSha256"
        "basefwx::crypto::AeadContext::"
        "basefwx::pq::GenerateKeyPair"
        "basefwx::x25519::GenerateKeyPair")
    string(FIND "${exported_symbols}" "${required_symbol}" symbol_offset)
    if(symbol_offset EQUAL -1)
        message(FATAL_ERROR
            "libbasefwx is missing required 3.8 API symbol: ${required_symbol}")
    endif()
endforeach()

set(retired_symbols
    "basefwx::codec::B256Encode"
    "basefwx::codec::B256Decode"
    "basefwx::B256Encode"
    "basefwx::B256Decode"
    "basefwx::A512Encode"
    "basefwx::A512Decode"
    "basefwx::Bi512Encode"
    "basefwx::Uhash513"
    "basefwx::InspectKfmCarrierFile"
    "basefwx::Jmge"
    "basefwx::Jmgd"
    "basefwx::Kfme"
    "basefwx::Kfmd"
    "basefwx::Kfae"
    "basefwx::Kfad"
    "basefwx::imagecipher::")

if(BASEFWX_EXPECT_RETIRED_MEDIA)
    foreach(required_symbol IN LISTS retired_symbols)
        string(FIND "${exported_symbols}" "${required_symbol}" symbol_offset)
        if(symbol_offset EQUAL -1)
            message(FATAL_ERROR
                "compatibility libbasefwx is missing retired API symbol: ${required_symbol}")
        endif()
    endforeach()
else()
    foreach(forbidden_symbol IN LISTS retired_symbols)
        string(FIND "${exported_symbols}" "${forbidden_symbol}" symbol_offset)
        if(NOT symbol_offset EQUAL -1)
            message(FATAL_ERROR
                "default libbasefwx exports retired API symbol: ${forbidden_symbol}")
        endif()
    endforeach()
endif()

message(STATUS
    "BaseFWX ABI exports match the requested compatibility profile and contain no CLI symbols")
