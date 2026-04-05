cmake_minimum_required(VERSION 3.16)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION" BASEFWX_PROJECT_VERSION)
string(STRIP "${BASEFWX_PROJECT_VERSION}" BASEFWX_PROJECT_VERSION)
if(BASEFWX_PROJECT_VERSION STREQUAL "")
    message(FATAL_ERROR "Repository VERSION file is empty")
endif()

project(basefwx_cpp VERSION ${BASEFWX_PROJECT_VERSION} LANGUAGES CXX)

option(BASEFWX_BUILD_CLI "Build BaseFWX CLI" ON)
option(BASEFWX_REQUIRE_ARGON2 "Require libargon2 for Argon2id support" ON)
option(BASEFWX_REQUIRE_OQS "Require liboqs for ML-KEM-768 support" OFF)
option(BASEFWX_OQS_STATIC "Prefer static liboqs when available" OFF)
option(BASEFWX_REQUIRE_LZMA "Require liblzma for xz support" OFF)
option(BASEFWX_NATIVE_OPT "Enable -march/-mtune native optimizations" ON)
option(BASEFWX_USE_VENDOR_DEPS "Prefer vendored liboqs/argon2 when available" ON)
option(BASEFWX_FORCE_CROSS "Treat build as cross for dependency path hygiene" OFF)
option(BASEFWX_WIN_IPO "Enable IPO/LTCG on Windows Release builds" OFF)
set(BASEFWX_VENDOR_DIR "" CACHE PATH "Path to vendored dependencies root")
set(BASEFWX_CLI_GPG_PUBLIC_KEY_FILE "" CACHE FILEPATH "ASCII-armored GPG public key to embed into the CLI for detached signature verification")
set(BASEFWX_CLI_GPG_FINGERPRINT "" CACHE STRING "Expected GPG signing key fingerprint to display in CLI version output")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE AND (NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET OR CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL ""))
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "" FORCE)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT BASEFWX_IPO_SUPPORTED OUTPUT BASEFWX_IPO_ERROR)
if(BASEFWX_IPO_SUPPORTED)
    if(NOT WIN32 OR BASEFWX_WIN_IPO)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options($<$<CONFIG:Release>:-O3>)
    # Suppress OpenSSL 3.0 deprecation warnings for EC key functions
    add_compile_options(-Wno-deprecated-declarations)
    if(BASEFWX_NATIVE_OPT AND NOT CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_PROCESSOR STREQUAL CMAKE_HOST_SYSTEM_PROCESSOR)
        add_compile_options(
            $<$<CONFIG:Release>:-march=native>
            $<$<CONFIG:Release>:-mtune=native>
        )
    endif()
    # Performance optimizations
    add_compile_options(
        $<$<CONFIG:Release>:-ffast-math>
        $<$<CONFIG:Release>:-funroll-loops>
        $<$<CONFIG:Release>:-finline-functions>
        $<$<CONFIG:Release>:-fomit-frame-pointer>
    )
    add_compile_options($<$<CONFIG:Release>:-flto>)
    add_link_options($<$<CONFIG:Release>:-flto>)
elseif(MSVC)
    add_compile_options(
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/Oi>
        $<$<CONFIG:Release>:/Ot>
        $<$<CONFIG:Release>:/Oy>
        $<$<CONFIG:Release>:/fp:fast>
    )
    if(BASEFWX_WIN_IPO)
        add_compile_options($<$<CONFIG:Release>:/GL>)
        add_link_options($<$<CONFIG:Release>:/LTCG>)
    endif()
endif()

if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(PkgConfig QUIET)
if(CMAKE_CROSSCOMPILING)
    set(PkgConfig_FOUND FALSE)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()
if(CMAKE_CROSSCOMPILING AND VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
    list(APPEND CMAKE_FIND_ROOT_PATH "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
endif()

set(BASEFWX_GITHUB_BUILD "no")
if(DEFINED ENV{GITHUB_ACTIONS} AND NOT "$ENV{GITHUB_ACTIONS}" STREQUAL "")
    set(BASEFWX_GITHUB_BUILD "yes")
endif()

set(BASEFWX_TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
if(NOT BASEFWX_TARGET_ARCH)
    set(BASEFWX_TARGET_ARCH "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()
if(BASEFWX_TARGET_ARCH MATCHES "^(x86_64|amd64)$")
    set(BASEFWX_TARGET_ARCH "amd64")
elseif(BASEFWX_TARGET_ARCH MATCHES "^(aarch64|arm64)$")
    set(BASEFWX_TARGET_ARCH "arm64")
elseif(BASEFWX_TARGET_ARCH MATCHES "^(i[3-6]86|x86)$")
    set(BASEFWX_TARGET_ARCH "x86")
endif()

set(BASEFWX_CLI_LINKAGE "dynamic")
if((WIN32 AND DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "static")
   OR CMAKE_EXE_LINKER_FLAGS MATCHES "(^| )-static($| )"
   OR CMAKE_EXE_LINKER_FLAGS_RELEASE MATCHES "(^| )-static($| )")
    set(BASEFWX_CLI_LINKAGE "static")
elseif(OPENSSL_USE_STATIC_LIBS)
    set(BASEFWX_CLI_LINKAGE "mixed")
endif()

set(BASEFWX_GPG_PUBLIC_KEY "")
set(BASEFWX_GPG_PUBLIC_KEY_AVAILABLE 0)
if(BASEFWX_CLI_GPG_PUBLIC_KEY_FILE AND EXISTS "${BASEFWX_CLI_GPG_PUBLIC_KEY_FILE}")
    file(READ "${BASEFWX_CLI_GPG_PUBLIC_KEY_FILE}" BASEFWX_GPG_PUBLIC_KEY)
    string(REPLACE "\r\n" "\n" BASEFWX_GPG_PUBLIC_KEY "${BASEFWX_GPG_PUBLIC_KEY}")
    set(BASEFWX_GPG_PUBLIC_KEY_AVAILABLE 1)
endif()
set(BASEFWX_GPG_PUBLIC_KEY_ESCAPED "${BASEFWX_GPG_PUBLIC_KEY}")
string(REPLACE "\\" "\\\\" BASEFWX_GPG_PUBLIC_KEY_ESCAPED "${BASEFWX_GPG_PUBLIC_KEY_ESCAPED}")
string(REPLACE "\"" "\\\"" BASEFWX_GPG_PUBLIC_KEY_ESCAPED "${BASEFWX_GPG_PUBLIC_KEY_ESCAPED}")
string(REPLACE "\n" "\\n\"\n\"" BASEFWX_GPG_PUBLIC_KEY_ESCAPED "${BASEFWX_GPG_PUBLIC_KEY_ESCAPED}")

set(_basefwx_build_info_content [=[
#pragma once
#define BASEFWX_CLI_GITHUB_BUILD "@BASEFWX_GITHUB_BUILD@"
#define BASEFWX_CLI_TARGET_ARCH "@BASEFWX_TARGET_ARCH@"
#define BASEFWX_CLI_LINKAGE "@BASEFWX_CLI_LINKAGE@"
#define BASEFWX_CLI_GPG_FINGERPRINT "@BASEFWX_CLI_GPG_FINGERPRINT@"
#define BASEFWX_CLI_GPG_PUBLIC_KEY_AVAILABLE @BASEFWX_GPG_PUBLIC_KEY_AVAILABLE@
namespace basefwx_build_info {
inline constexpr const char kCliGpgPublicKey[] =
"@BASEFWX_GPG_PUBLIC_KEY_ESCAPED@";
}  // namespace basefwx_build_info
#define BASEFWX_CLI_GPG_PUBLIC_KEY basefwx_build_info::kCliGpgPublicKey
]=])
string(CONFIGURE "${_basefwx_build_info_content}" _basefwx_build_info_content @ONLY)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/generated/basefwx_build_info.hpp" "${_basefwx_build_info_content}")

set(BASEFWX_CLI_BUILD_TYPE_VALUE "${CMAKE_BUILD_TYPE}")
if(BASEFWX_CLI_BUILD_TYPE_VALUE STREQUAL "")
    set(BASEFWX_CLI_BUILD_TYPE_VALUE "unknown")
endif()

set(BASEFWX_CLI_BUILD_STAMP_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/basefwx_build_stamp.hpp")
add_custom_target(basefwx_cli_build_stamp
    COMMAND ${CMAKE_COMMAND}
        "-DOUTPUT_FILE=${BASEFWX_CLI_BUILD_STAMP_HEADER}"
        "-DSOURCE_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/.."
        "-DBUILD_TYPE=${BASEFWX_CLI_BUILD_TYPE_VALUE}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/WriteCliBuildStamp.cmake"
    COMMENT "Refreshing BaseFWX CLI build metadata"
    VERBATIM
)

# Harden static OpenSSL selection: some environments still resolve OpenSSL::Crypto
# to libcrypto.so even with OPENSSL_USE_STATIC_LIBS=TRUE.
if(OPENSSL_USE_STATIC_LIBS)
    set(_basefwx_openssl_crypto_static "")
    if(DEFINED OPENSSL_CRYPTO_LIBRARY
       AND OPENSSL_CRYPTO_LIBRARY
       AND OPENSSL_CRYPTO_LIBRARY MATCHES "\\.a$"
       AND EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        set(_basefwx_openssl_crypto_static "${OPENSSL_CRYPTO_LIBRARY}")
    endif()

    if(NOT _basefwx_openssl_crypto_static AND DEFINED OPENSSL_CRYPTO_LIBRARY AND OPENSSL_CRYPTO_LIBRARY)
        get_filename_component(_basefwx_openssl_libdir "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
        if(EXISTS "${_basefwx_openssl_libdir}/libcrypto.a")
            set(_basefwx_openssl_crypto_static "${_basefwx_openssl_libdir}/libcrypto.a")
        endif()
    endif()

    if(NOT _basefwx_openssl_crypto_static)
        find_library(_basefwx_openssl_crypto_static
            NAMES crypto libcrypto
            PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu
        )
    endif()

    if(NOT _basefwx_openssl_crypto_static OR NOT _basefwx_openssl_crypto_static MATCHES "\\.a$")
        message(FATAL_ERROR
            "OPENSSL_USE_STATIC_LIBS=TRUE but static libcrypto.a was not selected. "
            "Set -DOPENSSL_CRYPTO_LIBRARY=/path/to/libcrypto.a (and optionally OPENSSL_SSL_LIBRARY).")
    endif()

    set(OPENSSL_CRYPTO_LIBRARY "${_basefwx_openssl_crypto_static}" CACHE FILEPATH "OpenSSL crypto library" FORCE)
    if(TARGET OpenSSL::Crypto)
        set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}")
        foreach(_cfg RELEASE RELWITHDEBINFO MINSIZEREL DEBUG)
            set_target_properties(OpenSSL::Crypto PROPERTIES "IMPORTED_LOCATION_${_cfg}" "${OPENSSL_CRYPTO_LIBRARY}")
        endforeach()
    endif()
endif()

set(BASEFWX_HAS_ARGON2 0)
set(BASEFWX_HAS_OQS 0)
set(BASEFWX_HAS_LZMA 0)

if(CMAKE_CROSSCOMPILING AND VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
    set(_oqs_prefix "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
    if(EXISTS "${_oqs_prefix}/include/oqs/oqs.h")
        if(EXISTS "${_oqs_prefix}/lib/liboqs.a")
            set(OQS_LIBRARY "${_oqs_prefix}/lib/liboqs.a" CACHE FILEPATH "liboqs library" FORCE)
        elseif(EXISTS "${_oqs_prefix}/lib/liboqs.dll.a")
            set(OQS_LIBRARY "${_oqs_prefix}/lib/liboqs.dll.a" CACHE FILEPATH "liboqs library" FORCE)
        elseif(EXISTS "${_oqs_prefix}/lib/liboqs.dylib")
            set(OQS_LIBRARY "${_oqs_prefix}/lib/liboqs.dylib" CACHE FILEPATH "liboqs library" FORCE)
        endif()
        if(OQS_LIBRARY)
            set(OQS_INCLUDE_DIR "${_oqs_prefix}/include" CACHE PATH "liboqs include dir" FORCE)
            set(OQS_FOUND TRUE)
            set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
            set(OQS_LIBRARIES ${OQS_LIBRARY})
            set(BASEFWX_HAS_OQS 1)
        endif()
    endif()
endif()
if(CMAKE_CROSSCOMPILING AND VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
    set(_argon2_prefix "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
    if(EXISTS "${_argon2_prefix}/include/argon2.h")
        if(EXISTS "${_argon2_prefix}/lib/libargon2.a")
            set(ARGON2_LIBRARY "${_argon2_prefix}/lib/libargon2.a" CACHE FILEPATH "argon2 library" FORCE)
        elseif(EXISTS "${_argon2_prefix}/lib/libargon2.dll.a")
            set(ARGON2_LIBRARY "${_argon2_prefix}/lib/libargon2.dll.a" CACHE FILEPATH "argon2 library" FORCE)
        elseif(EXISTS "${_argon2_prefix}/lib/libargon2.dylib")
            set(ARGON2_LIBRARY "${_argon2_prefix}/lib/libargon2.dylib" CACHE FILEPATH "argon2 library" FORCE)
        endif()
        if(ARGON2_LIBRARY)
            set(ARGON2_INCLUDE_DIR "${_argon2_prefix}/include" CACHE PATH "argon2 include dir" FORCE)
            set(ARGON2_FOUND TRUE)
            set(ARGON2_INCLUDE_DIRS ${ARGON2_INCLUDE_DIR})
            set(ARGON2_LIBRARIES ${ARGON2_LIBRARY})
            set(BASEFWX_HAS_ARGON2 1)
        endif()
    endif()
endif()

# Prefer vendored dependencies if available.
if(BASEFWX_USE_VENDOR_DEPS)
    set(_basefwx_vendor_root "${BASEFWX_VENDOR_DIR}")
    if(NOT _basefwx_vendor_root)
        set(_basefwx_vendor_root "${CMAKE_CURRENT_SOURCE_DIR}/../../vendor")
    endif()
    if(EXISTS "${_basefwx_vendor_root}")
        set(_basefwx_vendor_inc "${_basefwx_vendor_root}/include")
        set(_basefwx_vendor_lib "${_basefwx_vendor_root}/lib")
        if(EXISTS "${_basefwx_vendor_inc}/oqs/oqs.h")
            if(EXISTS "${_basefwx_vendor_lib}/liboqs.a")
                set(OQS_FOUND TRUE)
                set(OQS_INCLUDE_DIR "${_basefwx_vendor_inc}")
                set(OQS_INCLUDE_DIRS "${_basefwx_vendor_inc}")
                set(OQS_LIBRARY "${_basefwx_vendor_lib}/liboqs.a")
                set(OQS_LIBRARIES "${_basefwx_vendor_lib}/liboqs.a")
                set(BASEFWX_HAS_OQS 1)
                set(BASEFWX_OQS_STATIC ON)
            elseif(EXISTS "${_basefwx_vendor_lib}/liboqs.so")
                set(OQS_FOUND TRUE)
                set(OQS_INCLUDE_DIR "${_basefwx_vendor_inc}")
                set(OQS_INCLUDE_DIRS "${_basefwx_vendor_inc}")
                set(OQS_LIBRARY "${_basefwx_vendor_lib}/liboqs.so")
                set(OQS_LIBRARIES "${_basefwx_vendor_lib}/liboqs.so")
                set(BASEFWX_HAS_OQS 1)
            endif()
        endif()
        if(EXISTS "${_basefwx_vendor_inc}/argon2.h")
            if(EXISTS "${_basefwx_vendor_lib}/libargon2.a")
                set(ARGON2_FOUND TRUE)
                set(ARGON2_INCLUDE_DIR "${_basefwx_vendor_inc}")
                set(ARGON2_INCLUDE_DIRS "${_basefwx_vendor_inc}")
                set(ARGON2_LIBRARY "${_basefwx_vendor_lib}/libargon2.a")
                set(ARGON2_LIBRARIES "${_basefwx_vendor_lib}/libargon2.a")
                set(BASEFWX_HAS_ARGON2 1)
            elseif(EXISTS "${_basefwx_vendor_lib}/libargon2.so")
                set(ARGON2_FOUND TRUE)
                set(ARGON2_INCLUDE_DIR "${_basefwx_vendor_inc}")
                set(ARGON2_INCLUDE_DIRS "${_basefwx_vendor_inc}")
                set(ARGON2_LIBRARY "${_basefwx_vendor_lib}/libargon2.so")
                set(ARGON2_LIBRARIES "${_basefwx_vendor_lib}/libargon2.so")
                set(BASEFWX_HAS_ARGON2 1)
            endif()
        endif()
    endif()
endif()

# Prefer explicit Argon2 paths when provided to avoid pkg-config picking a different install.
if(ARGON2_LIBRARY OR ARGON2_INCLUDE_DIR)
    if(ARGON2_LIBRARY AND ARGON2_INCLUDE_DIR)
        set(ARGON2_FOUND TRUE)
        set(ARGON2_INCLUDE_DIRS ${ARGON2_INCLUDE_DIR})
        set(ARGON2_LIBRARIES ${ARGON2_LIBRARY})
    endif()
endif()

# Prefer explicit OQS paths when provided to avoid pkg-config picking a different install.
if(OQS_LIBRARY OR OQS_INCLUDE_DIR)
    if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
        set(OQS_FOUND TRUE)
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
        set(OQS_LIBRARIES ${OQS_LIBRARY})
    endif()
endif()

if(PkgConfig_FOUND)
    if(NOT ARGON2_FOUND)
        pkg_check_modules(ARGON2 QUIET libargon2)
    endif()
    if(NOT OQS_FOUND AND NOT CMAKE_CROSSCOMPILING)
        pkg_check_modules(OQS QUIET liboqs)
    endif()
    if(NOT LZMA_FOUND)
        pkg_check_modules(LZMA QUIET liblzma)
    endif()
endif()

if(NOT ARGON2_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
    find_library(ARGON2_LIBRARY NAMES argon2)
    if(ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
        set(ARGON2_FOUND TRUE)
        set(ARGON2_INCLUDE_DIRS ${ARGON2_INCLUDE_DIR})
        set(ARGON2_LIBRARIES ${ARGON2_LIBRARY})
    endif()
endif()

# Normalize Argon2 discovery for Homebrew/legacy pkg-config setups where only
# bare -largon2 is returned and no link directory is propagated.
set(_basefwx_argon2_lib_hints
    /opt/homebrew/opt/argon2/lib
    /opt/homebrew/lib
    /usr/local/opt/argon2/lib
    /usr/local/lib
)
set(_basefwx_argon2_inc_hints
    /opt/homebrew/opt/argon2/include
    /opt/homebrew/include
    /usr/local/opt/argon2/include
    /usr/local/include
)
if(NOT ARGON2_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_path(ARGON2_INCLUDE_DIR NAMES argon2.h HINTS ${_basefwx_argon2_inc_hints})
    find_library(ARGON2_LIBRARY NAMES argon2 HINTS ${_basefwx_argon2_lib_hints})
    if(ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
        set(ARGON2_FOUND TRUE)
        set(ARGON2_INCLUDE_DIRS ${ARGON2_INCLUDE_DIR})
        set(ARGON2_LIBRARIES ${ARGON2_LIBRARY})
    endif()
endif()
if(ARGON2_FOUND)
    set(_basefwx_argon2_resolved "")
    foreach(_basefwx_argon2_entry IN LISTS ARGON2_LIBRARIES)
        if(EXISTS "${_basefwx_argon2_entry}")
            list(APPEND _basefwx_argon2_resolved "${_basefwx_argon2_entry}")
        elseif(_basefwx_argon2_entry MATCHES "^-l(.+)$")
            find_library(_basefwx_argon2_lib
                NAMES "${CMAKE_MATCH_1}"
                HINTS ${_basefwx_argon2_lib_hints}
            )
            if(_basefwx_argon2_lib)
                list(APPEND _basefwx_argon2_resolved "${_basefwx_argon2_lib}")
            else()
                list(APPEND _basefwx_argon2_resolved "${_basefwx_argon2_entry}")
            endif()
        elseif(NOT _basefwx_argon2_entry STREQUAL "")
            find_library(_basefwx_argon2_lib
                NAMES "${_basefwx_argon2_entry}"
                HINTS ${_basefwx_argon2_lib_hints}
            )
            if(_basefwx_argon2_lib)
                list(APPEND _basefwx_argon2_resolved "${_basefwx_argon2_lib}")
            else()
                list(APPEND _basefwx_argon2_resolved "${_basefwx_argon2_entry}")
            endif()
        endif()
    endforeach()
    if(NOT _basefwx_argon2_resolved AND ARGON2_LIBRARY AND EXISTS "${ARGON2_LIBRARY}")
        list(APPEND _basefwx_argon2_resolved "${ARGON2_LIBRARY}")
    endif()
    if(_basefwx_argon2_resolved)
        set(ARGON2_LIBRARIES ${_basefwx_argon2_resolved})
    endif()
    if(ARGON2_INCLUDE_DIR AND NOT ARGON2_INCLUDE_DIRS)
        set(ARGON2_INCLUDE_DIRS ${ARGON2_INCLUDE_DIR})
    endif()
endif()

# Normalize OQS discovery for Homebrew/legacy pkg-config setups where only
# bare -loqs is returned and no link directory is propagated.
set(_basefwx_oqs_lib_hints
    /opt/homebrew/opt/liboqs/lib
    /opt/homebrew/lib
    /usr/local/opt/liboqs/lib
    /usr/local/lib
)
set(_basefwx_oqs_inc_hints
    /opt/homebrew/opt/liboqs/include
    /opt/homebrew/include
    /usr/local/opt/liboqs/include
    /usr/local/include
)
if(NOT OQS_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h HINTS ${_basefwx_oqs_inc_hints})
    find_library(OQS_LIBRARY NAMES oqs HINTS ${_basefwx_oqs_lib_hints})
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
        set(OQS_FOUND TRUE)
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
        set(OQS_LIBRARIES ${OQS_LIBRARY})
    endif()
endif()
if(OQS_FOUND)
    set(_basefwx_oqs_resolved "")
    foreach(_basefwx_oqs_entry IN LISTS OQS_LIBRARIES)
        if(EXISTS "${_basefwx_oqs_entry}")
            list(APPEND _basefwx_oqs_resolved "${_basefwx_oqs_entry}")
        elseif(_basefwx_oqs_entry MATCHES "^-l(.+)$")
            find_library(_basefwx_oqs_lib
                NAMES "${CMAKE_MATCH_1}"
                HINTS ${_basefwx_oqs_lib_hints}
            )
            if(_basefwx_oqs_lib)
                list(APPEND _basefwx_oqs_resolved "${_basefwx_oqs_lib}")
            else()
                list(APPEND _basefwx_oqs_resolved "${_basefwx_oqs_entry}")
            endif()
        elseif(NOT _basefwx_oqs_entry STREQUAL "")
            find_library(_basefwx_oqs_lib
                NAMES "${_basefwx_oqs_entry}"
                HINTS ${_basefwx_oqs_lib_hints}
            )
            if(_basefwx_oqs_lib)
                list(APPEND _basefwx_oqs_resolved "${_basefwx_oqs_lib}")
            else()
                list(APPEND _basefwx_oqs_resolved "${_basefwx_oqs_entry}")
            endif()
        endif()
    endforeach()
    if(NOT _basefwx_oqs_resolved AND OQS_LIBRARY AND EXISTS "${OQS_LIBRARY}")
        list(APPEND _basefwx_oqs_resolved "${OQS_LIBRARY}")
    endif()
    if(_basefwx_oqs_resolved)
        set(OQS_LIBRARIES ${_basefwx_oqs_resolved})
    endif()
    if(OQS_INCLUDE_DIR AND NOT OQS_INCLUDE_DIRS)
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
    endif()
endif()

if(NOT OQS_FOUND AND CMAKE_CROSSCOMPILING AND VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
    set(_oqs_prefix "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
    if(EXISTS "${_oqs_prefix}/include/oqs/oqs.h")
        set(OQS_INCLUDE_DIR "${_oqs_prefix}/include")
        if(EXISTS "${_oqs_prefix}/lib/liboqs.a")
            set(OQS_LIBRARY "${_oqs_prefix}/lib/liboqs.a")
        elseif(EXISTS "${_oqs_prefix}/lib/liboqs.dll.a")
            set(OQS_LIBRARY "${_oqs_prefix}/lib/liboqs.dll.a")
        elseif(EXISTS "${_oqs_prefix}/lib/liboqs.dylib")
            set(OQS_LIBRARY "${_oqs_prefix}/lib/liboqs.dylib")
        endif()
        if(OQS_LIBRARY)
            set(OQS_FOUND TRUE)
            set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
            set(OQS_LIBRARIES ${OQS_LIBRARY})
            set(BASEFWX_HAS_OQS 1)
        endif()
    endif()
endif()

if(NOT OQS_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h)
    find_library(OQS_LIBRARY NAMES oqs)
    if(OQS_INCLUDE_DIR AND NOT OQS_LIBRARY)
        get_filename_component(_oqs_prefix "${OQS_INCLUDE_DIR}" DIRECTORY)
        set(_oqs_lib_dir "${_oqs_prefix}/lib")
        file(GLOB _oqs_libs
            "${_oqs_lib_dir}/liboqs.so*"
            "${_oqs_lib_dir}/liboqs.a"
        )
        list(LENGTH _oqs_libs _oqs_libs_len)
        if(_oqs_libs_len GREATER 0)
            list(GET _oqs_libs 0 OQS_LIBRARY)
        endif()
    endif()
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
        set(OQS_FOUND TRUE)
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
        set(OQS_LIBRARIES ${OQS_LIBRARY})
    endif()
endif()

# If explicit OQS paths were provided, force-enable PQ support.
if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
    set(OQS_FOUND TRUE)
    if(NOT OQS_INCLUDE_DIRS)
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
    endif()
    if(NOT OQS_LIBRARIES)
        set(OQS_LIBRARIES ${OQS_LIBRARY})
    endif()
    set(BASEFWX_HAS_OQS 1)
endif()

if(OQS_FOUND AND BASEFWX_OQS_STATIC)
    if(OQS_LIBRARY MATCHES "\\.a$")
        set(OQS_LIBRARY_STATIC ${OQS_LIBRARY})
        set(OQS_LIBRARIES ${OQS_LIBRARY_STATIC})
    else()
        set(_basefwx_oqs_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        if(OQS_LIBRARY)
            get_filename_component(_oqs_lib_dir "${OQS_LIBRARY}" DIRECTORY)
            find_library(OQS_LIBRARY_STATIC NAMES oqs PATHS "${_oqs_lib_dir}" NO_DEFAULT_PATH)
        endif()
        if(NOT OQS_LIBRARY_STATIC)
            find_library(OQS_LIBRARY_STATIC NAMES oqs)
        endif()
        set(CMAKE_FIND_LIBRARY_SUFFIXES "${_basefwx_oqs_suffixes}")
        if(OQS_LIBRARY_STATIC)
            set(OQS_LIBRARIES ${OQS_LIBRARY_STATIC})
        endif()
    endif()
endif()

if(NOT LZMA_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_path(LZMA_INCLUDE_DIR NAMES lzma.h)
    find_library(LZMA_LIBRARY NAMES lzma)
    if(LZMA_INCLUDE_DIR AND LZMA_LIBRARY)
        set(LZMA_FOUND TRUE)
        set(LZMA_INCLUDE_DIRS ${LZMA_INCLUDE_DIR})
        set(LZMA_LIBRARIES ${LZMA_LIBRARY})
    endif()
endif()

if(BASEFWX_REQUIRE_ARGON2 AND NOT ARGON2_FOUND)
    message(FATAL_ERROR "libargon2 not found (install libargon2-dev or set BASEFWX_REQUIRE_ARGON2=OFF)")
endif()

# Avoid pulling host liboqs paths when cross-compiling.
if((CMAKE_CROSSCOMPILING OR BASEFWX_FORCE_CROSS) AND OQS_FOUND)
    set(_basefwx_host_oqs 0)
    if(OQS_INCLUDE_DIR MATCHES "^/usr/include" OR OQS_INCLUDE_DIR MATCHES "^/usr/local/include")
        set(_basefwx_host_oqs 1)
    endif()
    if(OQS_LIBRARY MATCHES "^/usr/" OR OQS_LIBRARY MATCHES "^/usr/local/")
        set(_basefwx_host_oqs 1)
    endif()
    if(_basefwx_host_oqs)
        message(STATUS "Cross build: ignoring host liboqs from ${OQS_LIBRARY}")
        set(OQS_FOUND FALSE)
        set(OQS_INCLUDE_DIR "")
        set(OQS_INCLUDE_DIRS "")
        set(OQS_LIBRARY "")
        set(OQS_LIBRARIES "")
        set(BASEFWX_HAS_OQS 0)
    endif()
endif()

if(BASEFWX_REQUIRE_OQS AND NOT OQS_FOUND)
    message(FATAL_ERROR "liboqs not found (install liboqs-dev or set BASEFWX_REQUIRE_OQS=OFF)")
endif()

if(BASEFWX_REQUIRE_LZMA AND NOT LZMA_FOUND)
    message(FATAL_ERROR "liblzma not found (install liblzma-dev or set BASEFWX_REQUIRE_LZMA=OFF)")
endif()

if(ARGON2_FOUND)
    set(BASEFWX_HAS_ARGON2 1)
endif()

if(OQS_FOUND)
    set(BASEFWX_HAS_OQS 1)
endif()

if(LZMA_FOUND)
    set(BASEFWX_HAS_LZMA 1)
endif()

add_library(basefwxcpp
    src/archive.cpp
    src/an7.cpp
    src/base64.cpp
    src/cli_colors.cpp
    src/format.cpp
    src/basefwx.cpp
    src/crypto.cpp
    src/codec.cpp
    src/imagecipher.cpp
    src/ec.cpp
    src/pb512.cpp
    src/fwxaes.cpp
    src/env.cpp
    src/pq.cpp
    src/keywrap.cpp
    src/livecipher.cpp
    src/obfuscation.cpp
    src/metadata.cpp
    src/filecodec.cpp
    src/system_info.cpp
)

target_include_directories(basefwxcpp
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
target_link_libraries(basefwxcpp PUBLIC OpenSSL::Crypto ZLIB::ZLIB)

# GCC 8 and older keep std::filesystem in a separate support library.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(basefwxcpp PUBLIC stdc++fs)
endif()

if(ARGON2_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${ARGON2_INCLUDE_DIRS})
    if(ARGON2_LIBRARY_DIRS)
        target_link_directories(basefwxcpp PUBLIC ${ARGON2_LIBRARY_DIRS})
    endif()
    target_link_libraries(basefwxcpp PUBLIC ${ARGON2_LIBRARIES})
endif()

if(OQS_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${OQS_INCLUDE_DIRS})
    if(OQS_LIBRARY_DIRS)
        target_link_directories(basefwxcpp PUBLIC ${OQS_LIBRARY_DIRS})
    endif()
    target_link_libraries(basefwxcpp PUBLIC ${OQS_LIBRARIES})
endif()

if(LZMA_FOUND)
    target_include_directories(basefwxcpp PUBLIC ${LZMA_INCLUDE_DIRS})
    target_link_libraries(basefwxcpp PUBLIC ${LZMA_LIBRARIES})
endif()

if(CMAKE_CROSSCOMPILING OR BASEFWX_FORCE_CROSS OR CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    get_target_property(_basefwx_includes basefwxcpp INCLUDE_DIRECTORIES)
    if(_basefwx_includes)
        list(REMOVE_ITEM _basefwx_includes "/usr/include" "/usr/include/")
        list(REMOVE_DUPLICATES _basefwx_includes)
        set_target_properties(basefwxcpp PROPERTIES INCLUDE_DIRECTORIES "${_basefwx_includes}")
    endif()
endif()

target_compile_definitions(basefwxcpp PUBLIC
    BASEFWX_VERSION_STRING="${BASEFWX_PROJECT_VERSION}"
    BASEFWX_HAS_ARGON2=${BASEFWX_HAS_ARGON2}
    BASEFWX_HAS_OQS=${BASEFWX_HAS_OQS}
    BASEFWX_HAS_LZMA=${BASEFWX_HAS_LZMA}
)

if(BASEFWX_BUILD_CLI)
    add_executable(basefwx_cpp
        src/main.cpp
    )
    add_dependencies(basefwx_cpp basefwx_cli_build_stamp)
    set_target_properties(basefwx_cpp PROPERTIES OUTPUT_NAME "basefwx")
    target_link_libraries(basefwx_cpp PRIVATE basefwxcpp)
    target_include_directories(basefwx_cpp PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
endif()
