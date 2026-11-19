# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 4.5)
project(libpotassium LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
find_library(SODIUM_LIBRARY NAMES sodium REQUIRED)

configure_file(src/version.hpp.in generated/libpotassium/version.hpp @ONLY)

add_library(libpotassium)
set_target_properties(libpotassium PROPERTIES OUTPUT_NAME potassium)
target_compile_features(libpotassium PUBLIC cxx_std_23)
target_sources(libpotassium PUBLIC
        FILE_SET CXX_MODULES
        FILES
        src/libpotassium.cpp
        src/base.cpp
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
    endif ()
endif ()
