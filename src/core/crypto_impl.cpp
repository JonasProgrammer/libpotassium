// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
module potassium.core;
import std;

namespace potassium
{

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
