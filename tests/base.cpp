// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_test_macros.hpp>

import potassium;
import std;

TEST_CASE("Multi-init works", "[base]")
{
    CHECK(potassium::init(std::nothrow));
    CHECK(potassium::init(std::nothrow));
    CHECK_NOTHROW(potassium::init());
    CHECK_NOTHROW(potassium::init());
}