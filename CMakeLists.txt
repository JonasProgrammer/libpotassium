# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 4.5)
project(libpotassium LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libsodium REQUIRED IMPORTED_TARGET libsodium libsodium>=1.0.22)

configure_file(src/base.cpp.in generated/base.cpp @ONLY)

add_library(potassium)
target_compile_features(potassium PUBLIC cxx_std_26)
target_sources(potassium PUBLIC
        FILE_SET CXX_MODULES
        FILES
        # entry
        src/libpotassium.cpp
        # partitions
        src/aead/aead.cpp
        src/auth/auth.cpp
        src/auth/hmac.cpp
        src/box/box.cpp
        src/core/core_iface.cpp
        src/core/crypto.cpp
        src/core/memory.cpp
        src/hash/hash.cpp
        src/internal/internal.cpp
        src/kem/kem.cpp
        src/secretbox/secretbox.cpp
        src/secretstream/secretstream.cpp
        src/sign/sign.cpp
        FILE_SET generated_modules TYPE CXX_MODULES
        BASE_DIRS "${CMAKE_CURRENT_BINARY_DIR}/generated"
        FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/base.cpp"
        PRIVATE
        # implementations
        src/aead/aead_impl.cpp
        src/auth/auth_impl.cpp
        src/box/box_impl.cpp
        src/core/crypto_impl.cpp
        src/core/memory_impl.cpp
        src/hash/hash_impl.cpp
        src/kem/kem_impl.cpp
        src/secretbox/secretbox_impl.cpp
        src/secretstream/secretstream_impl.cpp
        src/sign/sign_impl.cpp
)
target_link_libraries(potassium PUBLIC PkgConfig::libsodium)

if (LIBPOTASSIUM_HASH_ASSERTS)
    target_compile_definitions(potassium PUBLIC POTASSIUM_HASH_ASSERTS)
endif ()

option(LIBPOTASSIUM_BUILD_DOCS "Enable the Doxygen documentation target" OFF)
if (LIBPOTASSIUM_BUILD_DOCS)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/DoxygenSetup.cmake")
endif ()

set(LIBPOTASSIUM_EXAMPLE_TOPICS init core aead auth box hash kem secretbox secretstream sign)
foreach (topic IN LISTS LIBPOTASSIUM_EXAMPLE_TOPICS)
    add_executable(potassium_example_${topic} examples/${topic}.cpp)
    target_link_libraries(potassium_example_${topic} PRIVATE potassium)
endforeach ()

option(LIBPOTASSIUM_BUILD_TESTS "Enable tests" OFF)
if (PROJECT_IS_TOP_LEVEL)
    # make BUILD_TESTING variable available
    include(CTest)
    #  prevent double inclusion
    set(LIBPOTASSIUM_CTEST_INCLUDED ON)
endif ()

if ((PROJECT_IS_TOP_LEVEL AND BUILD_TESTING) OR LIBPOTASSIUM_BUILD_TESTS)
    add_subdirectory(tests)
endif ()
