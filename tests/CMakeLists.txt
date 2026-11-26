# include CTest if not already included
if (NOT LIBPOTASSIUM_CTEST_INCLUDED)
    include(CTest)
endif ()

add_test(NAME potassium.example COMMAND potassium_example)

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
        key_traits.cpp
        memory.cpp
        secretbox.cpp
)
target_sources(potassium_tests PRIVATE FILE_SET CXX_MODULES FILES nacl_vector.cpp)
target_link_libraries(potassium_tests PRIVATE potassium Catch2::Catch2)

include(Catch)
catch_discover_tests(potassium_tests TEST_PREFIX "potassium.")
