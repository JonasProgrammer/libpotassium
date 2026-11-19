module;
#include <sodium.h>
#include "libpotassium/version.hpp"

export module libpotassium:base;

import std;

export namespace potassium
{
constexpr std::string_view version_string{LIBPOTASSIUM_VERSION "-" SODIUM_VERSION_STRING};
}
