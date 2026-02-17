cmake_minimum_required(VERSION 3.16)
project(basefwx_cpp LANGUAGES CXX)

option(BASEFWX_BUILD_CLI "Build basefwx_cpp CLI" ON)
option(BASEFWX_REQUIRE_ARGON2 "Require libargon2 for Argon2id support" ON)
option(BASEFWX_REQUIRE_OQS "Require liboqs for ML-KEM-768 support" OFF)
option(BASEFWX_OQS_STATIC "Prefer static liboqs when available" OFF)
option(BASEFWX_REQUIRE_LZMA "Require liblzma for xz support" OFF)
option(BASEFWX_NATIVE_OPT "Enable -march/-mtune native optimizations" ON)
option(BASEFWX_USE_VENDOR_DEPS "Prefer vendored liboqs/argon2 when available" ON)
set(BASEFWX_VENDOR_DIR "" CACHE PATH "Path to vendored dependencies root")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE AND (NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET OR CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL ""))
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "" FORCE)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT BASEFWX_IPO_SUPPORTED OUTPUT BASEFWX_IPO_ERROR)
if(BASEFWX_IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
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
    add_compile_options($<$<CONFIG:Release>:/O2 /GL /Oi /Ot /Oy /fp:fast>)
    add_link_options($<$<CONFIG:Release>:/LTCG>)
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
if((CMAKE_CROSSCOMPILING OR YUME_FORCE_CROSS OR CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin") AND OQS_FOUND)
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

if(CMAKE_CROSSCOMPILING OR YUME_FORCE_CROSS OR CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    get_target_property(_basefwx_includes basefwxcpp INCLUDE_DIRECTORIES)
    if(_basefwx_includes)
        list(REMOVE_ITEM _basefwx_includes "/usr/include" "/usr/include/")
        list(REMOVE_DUPLICATES _basefwx_includes)
        set_target_properties(basefwxcpp PROPERTIES INCLUDE_DIRECTORIES "${_basefwx_includes}")
    endif()
endif()

target_compile_definitions(basefwxcpp PUBLIC
    BASEFWX_HAS_ARGON2=${BASEFWX_HAS_ARGON2}
    BASEFWX_HAS_OQS=${BASEFWX_HAS_OQS}
    BASEFWX_HAS_LZMA=${BASEFWX_HAS_LZMA}
)

if(BASEFWX_BUILD_CLI)
    add_executable(basefwx_cpp
        src/main.cpp
    )
    target_link_libraries(basefwx_cpp PRIVATE basefwxcpp)
endif()
