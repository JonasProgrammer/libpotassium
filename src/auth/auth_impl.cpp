// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

module potassium.hash;

import potassium.internal;
import std;

namespace potassium::auth
{
namespace
{
using hash::detail::check_status;
using internal::sodium_bytes;

static_assert(auth_traits<hmac_sha256>::key_size == crypto_auth_hmacsha256_KEYBYTES);
static_assert(auth_traits<hmac_sha256>::tag_size == crypto_auth_hmacsha256_BYTES);
static_assert(auth_traits<hmac_sha512>::key_size == crypto_auth_hmacsha512_KEYBYTES);
static_assert(auth_traits<hmac_sha512>::tag_size == crypto_auth_hmacsha512_BYTES);
static_assert(auth_traits<hmac_sha512256>::key_size == crypto_auth_hmacsha512256_KEYBYTES);
static_assert(auth_traits<hmac_sha512256>::tag_size == crypto_auth_hmacsha512256_BYTES);
static_assert(auth_traits<default_algorithm>::key_size == crypto_auth_KEYBYTES);
static_assert(auth_traits<default_algorithm>::tag_size == crypto_auth_BYTES);

template <class A>
struct backend;

template <>
struct backend<hmac_sha256>
{
    static constexpr auto authenticate = crypto_auth_hmacsha256;
    static constexpr auto verify = crypto_auth_hmacsha256_verify;
    static constexpr auto init = crypto_auth_hmacsha256_init;
    static constexpr auto update = crypto_auth_hmacsha256_update;
    static constexpr auto final = crypto_auth_hmacsha256_final;
};

template <>
struct backend<hmac_sha512>
{
    static constexpr auto authenticate = crypto_auth_hmacsha512;
    static constexpr auto verify = crypto_auth_hmacsha512_verify;
    static constexpr auto init = crypto_auth_hmacsha512_init;
    static constexpr auto update = crypto_auth_hmacsha512_update;
    static constexpr auto final = crypto_auth_hmacsha512_final;
};

template <>
struct backend<hmac_sha512256>
{
    static constexpr auto authenticate = crypto_auth_hmacsha512256;
    static constexpr auto verify = crypto_auth_hmacsha512256_verify;
    static constexpr auto init = crypto_auth_hmacsha512256_init;
    static constexpr auto update = crypto_auth_hmacsha512256_update;
    static constexpr auto final = crypto_auth_hmacsha512256_final;
};

unsigned char const* message_data(std::span<std::byte const> message) noexcept
{
    static constexpr unsigned char empty{};
    return message.empty() ? &empty : sodium_bytes(message.data());
}

}  // namespace

namespace detail
{
template <hmac_algorithm A>
void hmac_ops<A>::init(state_type& state, std::span<std::byte const> key) noexcept
{
    check_status(backend<A>::init(&state, sodium_bytes(key.data()), key.size()));
}

template <hmac_algorithm A>
void hmac_ops<A>::update(state_type& state, std::span<std::byte const> message) noexcept
{
    check_status(backend<A>::update(&state, message_data(message), message.size()));
}

template <hmac_algorithm A>
void hmac_ops<A>::final(state_type& state, output_type tag) noexcept
{
    check_status(backend<A>::final(&state, sodium_bytes(tag.data())));
}

template <hmac_algorithm A>
void hmac_ops<A>::authenticate(key_type key, std::span<std::byte const> message, output_type tag) noexcept
{
    check_status(backend<A>::authenticate(sodium_bytes(tag.data()), message_data(message), message.size(), sodium_bytes(key.bytes().data())));
}

template <hmac_algorithm A>
bool hmac_ops<A>::verify(key_type key, std::span<std::byte const> message, std::span<std::byte const, auth_traits<A>::tag_size> tag) noexcept
{
    return backend<A>::verify(sodium_bytes(tag.data()), message_data(message), message.size(), sodium_bytes(key.bytes().data())) == 0;
}

template struct hmac_ops<hmac_sha256>;
template struct hmac_ops<hmac_sha512>;
template struct hmac_ops<hmac_sha512256>;
}  // namespace detail
}  // namespace potassium::auth
