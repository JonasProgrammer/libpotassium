// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
#include "libpotassium/version.hpp"

export module libpotassium:base;

import std;

/// Parent namespace for all libpotassium's contents.
export namespace potassium
{
/// The libpotassium version followed by the libsodium version, separated by a hyphen.
constexpr std::string_view version_string{LIBPOTASSIUM_VERSION "-" SODIUM_VERSION_STRING};

/// @brief Initializes libpotassium and libsodium.
/// @return @c true on success, @c false on failure.
bool init(std::nothrow_t const&) noexcept
{
    // will return -1 on error, 0 on first init and 1 for subsequent inits
    return sodium_init() != -1;
}

/// @brief Initializes libpotassium and libsodium.
/// @throws std::runtime_error If libsodium initialization fails.
void init()
{
    if (!init(std::nothrow)) throw std::runtime_error{"Failed to initialize sodium"};
}

}  // namespace potassium
