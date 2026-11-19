// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
#include "libpotassium/version.hpp"

export module libpotassium:base;

import std;

export namespace potassium
{
/// The libpotassium version followed by the libsodium version, separated by a hyphen.
constexpr std::string_view version_string{LIBPOTASSIUM_VERSION "-" SODIUM_VERSION_STRING};
}  // namespace potassium
