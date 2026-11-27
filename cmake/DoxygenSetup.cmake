find_package(Doxygen REQUIRED)

set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs")
set(DOXYGEN_GENERATE_LATEX NO)
set(DOXYGEN_PROJECT_LOGO
        "${CMAKE_CURRENT_SOURCE_DIR}/docs/img/libpotassium-banana-flame.svg")
set(DOXYGEN_PROJECT_ICON
        "${CMAKE_CURRENT_SOURCE_DIR}/docs/img/libpotassium-banana-flame.svg")

# Generate the default Doxygen HTML header.
set(DOXYGEN_TEMPLATE_DIR "${CMAKE_CURRENT_BINARY_DIR}/doxygen")
set(DOXYGEN_HTML_HEADER "${DOXYGEN_TEMPLATE_DIR}/header.html")

add_custom_command(
        OUTPUT "${DOXYGEN_HTML_HEADER}"
        BYPRODUCTS
        "${DOXYGEN_TEMPLATE_DIR}/footer.html"
        "${DOXYGEN_TEMPLATE_DIR}/doxygen.css"
        COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${DOXYGEN_TEMPLATE_DIR}"
        COMMAND Doxygen::doxygen -w html
        "${DOXYGEN_HTML_HEADER}"
        "${DOXYGEN_TEMPLATE_DIR}/footer.html"
        "${DOXYGEN_TEMPLATE_DIR}/doxygen.css"
        COMMAND "${CMAKE_COMMAND}"
        "-DHEADER=${DOXYGEN_HTML_HEADER}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PatchDoxygenHeader.cmake"
        DEPENDS
        Doxygen::doxygen
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PatchDoxygenHeader.cmake"
        COMMENT "Generating patched Doxygen HTML header"
        VERBATIM
)

add_custom_target(potassium_docs_header
        DEPENDS "${DOXYGEN_HTML_HEADER}"
)

get_target_property(module_interfaces potassium CXX_MODULE_SET)
get_target_property(generated_module_interfaces potassium CXX_MODULE_SET_generated_modules)
set(DOXYGEN_EXCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/src/internal")

doxygen_add_docs(potassium_docs ${module_interfaces} ${generated_module_interfaces})
add_dependencies(potassium_docs potassium_docs_header)
