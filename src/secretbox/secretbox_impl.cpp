// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;

#include <sodium.h>

module potassium.secretbox;

import potassium.internal;
import std;

using potassium::internal::unwrap;

namespace potassium::secretbox
{

namespace
{

static_assert(std::string_view{crypto_secretbox_PRIMITIVE} == "xsalsa20poly1305");

using xsalsa20poly1305_traits = algorithm_traits<xsalsa20poly1305>;
static_assert(xsalsa20poly1305_traits::key_size == crypto_secretbox_KEYBYTES);
static_assert(xsalsa20poly1305_traits::nonce_size == crypto_secretbox_NONCEBYTES);
static_assert(xsalsa20poly1305_traits::mac_size == crypto_secretbox_MACBYTES);
static_assert(xsalsa20poly1305_traits::messagebytes_max == crypto_secretbox_MESSAGEBYTES_MAX);

using xchacha20poly1305_traits = algorithm_traits<xchacha20poly1305>;
static_assert(xchacha20poly1305_traits::key_size == crypto_secretbox_xchacha20poly1305_KEYBYTES);
static_assert(xchacha20poly1305_traits::nonce_size == crypto_secretbox_xchacha20poly1305_NONCEBYTES);
static_assert(xchacha20poly1305_traits::mac_size == crypto_secretbox_xchacha20poly1305_MACBYTES);
static_assert(xchacha20poly1305_traits::messagebytes_max == crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX);

}  // namespace

// XChaCha20-Poly1305

void seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xchacha_nonce_ref nonce)
{
    return unwrap(seal_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::transform<internal::direction::seal>(crypto_secretbox_xchacha20poly1305_easy, plaintext, out, nonce, key);
}

void open_into(xchacha_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xchacha_nonce_ref nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xchacha_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::transform<internal::direction::open>(crypto_secretbox_xchacha20poly1305_open_easy, ciphertext, out, nonce, key);
}

xchacha_nonce_buffer seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<xchacha_nonce_buffer, errc> seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    return internal::seal_into_with_nonce<xchacha20poly1305>([&](auto& nonce) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

std::vector<std::byte> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, xchacha_nonce_ref nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::allocate_ciphertext<xchacha20poly1305>(plaintext.size(), [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

xchacha_seal_result seal(xchacha_key_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<xchacha_seal_result, errc> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    return internal::seal_with_nonce<xchacha20poly1305, xchacha_seal_result>([&](auto& nonce) { return seal(key, plaintext, nonce, std::nothrow); });
}

secure_buffer open(xchacha_key_ref key, std::span<std::byte const> ciphertext, xchacha_nonce_ref nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_key_ref key, std::span<std::byte const> ciphertext, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::allocate_plaintext<xchacha20poly1305>(ciphertext.size(), [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xchacha_key_ref key, xchacha_seal_result const& sealed)
{
    return unwrap(open(key, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_key_ref key, xchacha_seal_result const& sealed, std::nothrow_t) noexcept
{
    return open(key, sealed.ciphertext, sealed.nonce, std::nothrow);
}

// XSalsa20-Poly1305

void seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xsalsa_nonce_ref nonce)
{
    return unwrap(seal_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::transform<internal::direction::seal>(crypto_secretbox_easy, plaintext, out, nonce, key);
}

void open_into(xsalsa_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xsalsa_nonce_ref nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xsalsa_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::transform<internal::direction::open>(crypto_secretbox_open_easy, ciphertext, out, nonce, key);
}

xsalsa_nonce_buffer seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<xsalsa_nonce_buffer, errc> seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    return internal::seal_into_with_nonce<xsalsa20poly1305>([&](auto& nonce) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

std::vector<std::byte> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, xsalsa_nonce_ref nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::allocate_ciphertext<xsalsa20poly1305>(plaintext.size(), [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

xsalsa_seal_result seal(xsalsa_key_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<xsalsa_seal_result, errc> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    return internal::seal_with_nonce<xsalsa20poly1305, xsalsa_seal_result>([&](auto& nonce) { return seal(key, plaintext, nonce, std::nothrow); });
}

secure_buffer open(xsalsa_key_ref key, std::span<std::byte const> ciphertext, xsalsa_nonce_ref nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_key_ref key, std::span<std::byte const> ciphertext, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    return internal::allocate_plaintext<xsalsa20poly1305>(ciphertext.size(), [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xsalsa_key_ref key, xsalsa_seal_result const& sealed)
{
    return unwrap(open(key, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_key_ref key, xsalsa_seal_result const& sealed, std::nothrow_t) noexcept
{
    return open(key, sealed.ciphertext, sealed.nonce, std::nothrow);
}

}  // namespace potassium::secretbox
