// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

/// @brief Internal byte-pointer conversions for libsodium calls.
/// @private Only for internal use, not guaranteed to be stable.
export module potassium.internal;

import std;

export namespace potassium::internal
{
/// View writable bytes as a libsodium output pointer.
/// @private Only for internal use, not guaranteed to be stable.
inline unsigned char* sodium_bytes(void* data) noexcept
{
    return static_cast<unsigned char*>(data);
}

/// View read-only bytes as a libsodium input pointer.
/// @private Only for internal use, not guaranteed to be stable.
inline unsigned char const* sodium_bytes(void const* data) noexcept
{
    return static_cast<unsigned char const*>(data);
}
}  // namespace potassium::internal
