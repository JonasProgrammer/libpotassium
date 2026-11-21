# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 4.5)
project(libpotassium LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
find_library(SODIUM_LIBRARY NAMES sodium REQUIRED)

configure_file(src/internal/version.hpp.in generated/libpotassium/internal/version.hpp @ONLY)

add_library(libpotassium)
set_target_properties(libpotassium PROPERTIES OUTPUT_NAME potassium)
target_compile_features(libpotassium PUBLIC cxx_std_26)
target_sources(libpotassium PUBLIC
        FILE_SET CXX_MODULES
        FILES
        # entry
        src/libpotassium.cpp
        # partitions
        src/base.cpp
        src/box/box.cpp
        src/core/core_iface.cpp
        src/core/crypto.cpp
        src/core/memory.cpp
        src/hash/hash.cpp
        src/secretbox/secretbox.cpp
        PRIVATE
        # implementations
        src/box/box_impl.cpp
        src/core/crypto_impl.cpp
        src/core/memory_impl.cpp
        src/hash/hash_impl.cpp
        src/secretbox/secretbox_impl.cpp
)
target_include_directories(libpotassium PRIVATE
        "${SODIUM_INCLUDE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
target_link_libraries(libpotassium PRIVATE "${SODIUM_LIBRARY}")

if (PROJECT_IS_TOP_LEVEL)
    include(CTest)

    option(LIBPOTASSIUM_BUILD_DOCS "Enable the Doxygen documentation target" OFF)
    if (LIBPOTASSIUM_BUILD_DOCS)
        find_package(Doxygen QUIET)
        if (Doxygen_FOUND)
            set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs")
            set(DOXYGEN_GENERATE_LATEX NO)
            doxygen_add_docs(libpotassium_docs src)
        else ()
            message(WARNING "Doxygen was not found. The libpotassium_docs target is unavailable.")
        endif ()
    endif ()

    add_executable(libpotassium_example examples/main.cpp)
    target_link_libraries(libpotassium_example PRIVATE libpotassium)

    if (BUILD_TESTING)
        add_test(NAME libpotassium.example COMMAND libpotassium_example)

        find_package(Catch2 3 REQUIRED)
        add_executable(libpotassium_tests
                # entrypoint
                tests/main.cpp
                # case files
                tests/base.cpp
                tests/box.cpp
                tests/hash.cpp
                tests/hash_interop.cpp
                tests/key_traits.cpp
                tests/memory.cpp
                tests/secretbox.cpp
        )
        target_include_directories(libpotassium_tests PRIVATE "${SODIUM_INCLUDE_DIR}")
        target_link_libraries(libpotassium_tests PRIVATE libpotassium Catch2::Catch2 "${SODIUM_LIBRARY}")

        add_library(hash_finalize_lvalue OBJECT EXCLUDE_FROM_ALL tests/hash_finalize_lvalue.cpp)
        target_link_libraries(hash_finalize_lvalue PRIVATE libpotassium)
        add_test(NAME libpotassium.hash.finalize-diagnostic
                COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_hash_diagnostic.cmake")

        add_executable(hash_contract tests/hash_contract.cpp)
        target_link_libraries(hash_contract PRIVATE libpotassium)
        foreach(mode IN ITEMS finalized-update finalized-finalize moved-reset)
            add_test(NAME libpotassium.hash.${mode} COMMAND hash_contract ${mode})
            set_tests_properties(libpotassium.hash.${mode} PROPERTIES WILL_FAIL TRUE)
        endforeach()

        include(Catch)
        catch_discover_tests(libpotassium_tests TEST_PREFIX "libpotassium.")
    endif ()
endif ()
