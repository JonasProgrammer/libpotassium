// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
#include "libpotassium/internal/version.hpp"

export module potassium:base;

import std;

/// Parent namespace for all libpotassium's contents.
export namespace potassium
{
/// The libpotassium version followed by the libsodium version, separated by a hyphen.
constinit std::string_view version_string{LIBPOTASSIUM_VERSION "-" SODIUM_VERSION_STRING};

}  // namespace potassium
