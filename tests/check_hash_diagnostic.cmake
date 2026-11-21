# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

execute_process(COMMAND "${CMAKE_COMMAND}" --build . --target hash_finalize_lvalue
                RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(status EQUAL 0 OR NOT "${output}${errors}" MATCHES "finalize\\(\\) consumes the hasher: use std::move")
    message(FATAL_ERROR "Expected the deleted lvalue finalize diagnostic.\n${output}${errors}")
endif()
