// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_session.hpp>

import libpotassium;

int main(int argc, char* argv[])
{
    potassium::init();
    return Catch::Session().run(argc, argv);
}
