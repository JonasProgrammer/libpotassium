# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

# include CTest if not already included
if (NOT LIBPOTASSIUM_CTEST_INCLUDED)
    include(CTest)
endif ()

foreach (topic IN LISTS LIBPOTASSIUM_EXAMPLE_TOPICS)
    add_test(NAME potassium.example.${topic} COMMAND potassium_example_${topic})
endforeach ()

find_package(Catch2 3 REQUIRED)
add_executable(potassium_tests
        # entrypoint
        main.cpp
        # case files
        aead.cpp
        auth.cpp
        base.cpp
        box.cpp
        hash.cpp
        hash_interop.cpp
        kem.cpp
        key_traits.cpp
        memory.cpp
        secretbox.cpp
        secretstream.cpp
        sign.cpp
)
target_sources(potassium_tests PRIVATE FILE_SET CXX_MODULES FILES nacl_vector.cpp)
target_link_libraries(potassium_tests PRIVATE potassium Catch2::Catch2)

include(Catch)
catch_discover_tests(potassium_tests TEST_PREFIX "potassium.")
