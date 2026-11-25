// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

export module potassium.hash:hmac;
export import potassium.core;
import std;

export namespace potassium::auth
{
/// @struct potassium::auth::hmac_sha256
/// @brief HMAC using SHA-256.
struct hmac_sha256;
/// @struct potassium::auth::hmac_sha512
/// @brief HMAC using SHA-512.
struct hmac_sha512;
/// @struct potassium::auth::hmac_sha512256
/// @brief HMAC using SHA-512, with its output truncated to 256 bits.
struct hmac_sha512256;

/// Algorithm used by libsodium's crypto_auth.
using default_algorithm = hmac_sha512256;

/// An HMAC algorithm supported by this module.
template <class A>
concept hmac_algorithm = std::same_as<A, hmac_sha256> || std::same_as<A, hmac_sha512> || std::same_as<A, hmac_sha512256>;

/// Backend stream state and fixed byte sizes for one-shot authentication.
template <hmac_algorithm A>
struct auth_traits
{
    /// Libsodium state stored by the HMAC stream.
    using state_type = std::conditional_t<std::same_as<A, hmac_sha256>, crypto_auth_hmacsha256_state, crypto_auth_hmacsha512_state>;
    /// Required one-shot key size in bytes.
    static constexpr std::size_t key_size = 32;
    /// Authentication tag size in bytes.
    static constexpr std::size_t tag_size = std::same_as<A, hmac_sha512> ? 64 : 32;
};

/// One-shot secret key purpose for A.
template <hmac_algorithm A = default_algorithm>
struct hmac_key_tag;
}  // namespace potassium::auth

export namespace potassium
{
/// Fixed-size HMAC keys can be generated from uniform random bytes.
template <auth::hmac_algorithm A>
struct key_traits<auth::hmac_key_tag<A>>
{
    /// Fill key storage with uniformly random bytes.
    using generator = random_key_generator;
    /// Size of the typed key in bytes.
    static constexpr std::size_t size = auth::auth_traits<A>::key_size;
};
}  // namespace potassium

export namespace potassium::auth::detail
{
/// @cond INTERNAL
template <hmac_algorithm A>
struct hmac_ops
{
    using state_type = typename auth_traits<A>::state_type;
    using output_type = std::span<std::byte, auth_traits<A>::tag_size>;
    using key_type = key_ref<hmac_key_tag<A>>;
    static void init(state_type&, std::span<std::byte const> key) noexcept;
    static void update(state_type&, std::span<std::byte const> message) noexcept;
    static void final(state_type&, output_type) noexcept;
    static void authenticate(key_type, std::span<std::byte const> message, output_type) noexcept;
    static bool verify(key_type, std::span<std::byte const> message, std::span<std::byte const, auth_traits<A>::tag_size>) noexcept;
};

/// @endcond
}  // namespace potassium::auth::detail
