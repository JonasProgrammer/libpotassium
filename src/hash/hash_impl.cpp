// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

module potassium.hash;
import potassium.internal;
import std;

using potassium::internal::sodium_bytes;

/// @cond INTERNAL
namespace potassium::hash::detail
{
static_assert(crypto_generichash_blake2b_BYTES_MIN == 16 && crypto_generichash_blake2b_BYTES_MAX == 64);
static_assert(hash_traits<default_algorithm>::digest_size == crypto_generichash_blake2b_BYTES);

void check_status(int status) noexcept
{
    if (status != 0) std::terminate();
}

bool equal(std::span<std::byte const> left, std::span<std::byte const> right) noexcept
{
    return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

void blake2b_ops::init(state_type& state, std::size_t size, std::span<std::byte const> key) noexcept
{
    check_status(crypto_generichash_blake2b_init(&state, sodium_bytes(key.data()), key.size(), size));
}

void blake2b_ops::update(state_type& state, std::span<std::byte const> message) noexcept
{
    check_status(crypto_generichash_blake2b_update(&state, sodium_bytes(message.data()), message.size()));
}

void blake2b_ops::final(state_type& state, std::span<std::byte> output) noexcept
{
    check_status(crypto_generichash_blake2b_final(&state, sodium_bytes(output.data()), output.size()));
}

void blake2b_ops::one_shot(std::span<std::byte> output, std::span<std::byte const> message, std::span<std::byte const> key) noexcept
{
    check_status(crypto_generichash_blake2b(sodium_bytes(output.data()), output.size(), sodium_bytes(message.data()), message.size(), sodium_bytes(key.data()), key.size()));
}

void ops<sha256>::init(state_type& state) noexcept
{
    check_status(crypto_hash_sha256_init(&state));
}

void ops<sha256>::update(state_type& state, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha256_update(&state, sodium_bytes(message.data()), message.size()));
}

void ops<sha256>::final(state_type& state, output_type output) noexcept
{
    check_status(crypto_hash_sha256_final(&state, sodium_bytes(output.data())));
}

void ops<sha256>::one_shot(output_type output, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha256(sodium_bytes(output.data()), sodium_bytes(message.data()), message.size()));
}

void ops<sha512>::init(state_type& state) noexcept
{
    check_status(crypto_hash_sha512_init(&state));
}

void ops<sha512>::update(state_type& state, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha512_update(&state, sodium_bytes(message.data()), message.size()));
}

void ops<sha512>::final(state_type& state, output_type output) noexcept
{
    check_status(crypto_hash_sha512_final(&state, sodium_bytes(output.data())));
}

void ops<sha512>::one_shot(output_type output, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha512(sodium_bytes(output.data()), sodium_bytes(message.data()), message.size()));
}

void ops<sha3_256>::init(state_type& state) noexcept
{
    check_status(crypto_hash_sha3256_init(&state));
}

void ops<sha3_256>::update(state_type& state, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha3256_update(&state, sodium_bytes(message.data()), message.size()));
}

void ops<sha3_256>::final(state_type& state, output_type output) noexcept
{
    check_status(crypto_hash_sha3256_final(&state, sodium_bytes(output.data())));
}

void ops<sha3_256>::one_shot(output_type output, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha3256(sodium_bytes(output.data()), sodium_bytes(message.data()), message.size()));
}

void ops<sha3_512>::init(state_type& state) noexcept
{
    check_status(crypto_hash_sha3512_init(&state));
}

void ops<sha3_512>::update(state_type& state, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha3512_update(&state, sodium_bytes(message.data()), message.size()));
}

void ops<sha3_512>::final(state_type& state, output_type output) noexcept
{
    check_status(crypto_hash_sha3512_final(&state, sodium_bytes(output.data())));
}

void ops<sha3_512>::one_shot(output_type output, std::span<std::byte const> message) noexcept
{
    check_status(crypto_hash_sha3512(sodium_bytes(output.data()), sodium_bytes(message.data()), message.size()));
}
}  // namespace potassium::hash::detail

/// @endcond
