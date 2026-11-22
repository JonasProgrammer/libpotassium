// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
module potassium.core;
import std;

namespace potassium
{

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

crypto_error::crypto_error()
    : std::runtime_error{"Cryptographic operation failed"}
{
}

void throw_error(errc error)
{
    if (error == errc::allocation_failed) throw std::bad_alloc{};
    throw crypto_error{};
}

void random_fill(std::span<std::byte> bytes) noexcept
{
    if (!bytes.empty()) randombytes_buf(bytes.data(), bytes.size());
}

void wipe(std::span<std::byte> bytes) noexcept
{
    if (!bytes.empty()) sodium_memzero(bytes.data(), bytes.size());
}

secure_buffer::secure_buffer(std::size_t size)
    : storage_(size)
{
}

}  // namespace potassium
