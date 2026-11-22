// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;

#include <sodium.h>

module potassium.secretbox;

import potassium.internal;
import std;

using potassium::internal::sodium_bytes;

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

template <class T>
T unwrap(std::expected<T, errc> result)
{
    if (!result) throw_error(result.error());
    if constexpr (!std::is_void_v<T>) return std::move(*result);
}

template <class Buffer, class Operation>
std::expected<Buffer, errc> allocate_and_transform(std::size_t size, Operation operation) noexcept
try
{
    Buffer out(size);
    auto result = operation(out);
    if (!result) return std::unexpected(result.error());
    return out;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}
catch (std::length_error const&)
{
    return std::unexpected(errc::allocation_failed);
}

template <class A, class Function>
std::expected<void, errc> transform(Function function, key_ref<A> key, std::span<std::byte const> input, std::span<std::byte> out, nonce_ref<A> nonce) noexcept
{
    unsigned char empty{};
    auto const status = function(out.empty() ? &empty : sodium_bytes(out.data()),
                                 input.empty() ? &empty : sodium_bytes(input.data()),
                                 input.size(),
                                 sodium_bytes(nonce.bytes().data()),
                                 sodium_bytes(key.bytes().data()));
    if (status != 0) return std::unexpected(errc::crypto_failed);
    return {};
}
}  // namespace

// XChaCha20-Poly1305

void seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xchacha_nonce_ref nonce)
{
    return unwrap(seal_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return transform(crypto_secretbox_xchacha20poly1305_easy, key, plaintext, out, nonce);
}

void open_into(xchacha_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xchacha_nonce_ref nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xchacha_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return transform(crypto_secretbox_xchacha20poly1305_open_easy, key, ciphertext, out, nonce);
}

xchacha_nonce_buffer seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<xchacha_nonce_buffer, errc> seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<xchacha20poly1305>();
    auto result = seal_into(key, plaintext, out, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return nonce;
}

std::vector<std::byte> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, xchacha_nonce_ref nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext.size() + xchacha20poly1305_traits::mac_size, [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

xchacha_seal_result seal(xchacha_key_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<xchacha_seal_result, errc> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<xchacha20poly1305>();
    auto result = seal(key, plaintext, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return xchacha_seal_result{std::move(*result), nonce};
}

secure_buffer open(xchacha_key_ref key, std::span<std::byte const> ciphertext, xchacha_nonce_ref nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_key_ref key, std::span<std::byte const> ciphertext, xchacha_nonce_ref nonce, std::nothrow_t) noexcept
{
    auto const plaintext_size = ciphertext.size() - std::min(ciphertext.size(), xchacha20poly1305_traits::mac_size);
    return allocate_and_transform<secure_buffer>(plaintext_size, [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
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
    return transform(crypto_secretbox_easy, key, plaintext, out, nonce);
}

void open_into(xsalsa_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xsalsa_nonce_ref nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xsalsa_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    return transform(crypto_secretbox_open_easy, key, ciphertext, out, nonce);
}

xsalsa_nonce_buffer seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<xsalsa_nonce_buffer, errc> seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<xsalsa20poly1305>();
    auto result = seal_into(key, plaintext, out, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return nonce;
}

std::vector<std::byte> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, xsalsa_nonce_ref nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext.size() + xsalsa20poly1305_traits::mac_size, [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

xsalsa_seal_result seal(xsalsa_key_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<xsalsa_seal_result, errc> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<xsalsa20poly1305>();
    auto result = seal(key, plaintext, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return xsalsa_seal_result{std::move(*result), nonce};
}

secure_buffer open(xsalsa_key_ref key, std::span<std::byte const> ciphertext, xsalsa_nonce_ref nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_key_ref key, std::span<std::byte const> ciphertext, xsalsa_nonce_ref nonce, std::nothrow_t) noexcept
{
    auto const plaintext_size = ciphertext.size() - std::min(ciphertext.size(), xsalsa20poly1305_traits::mac_size);
    return allocate_and_transform<secure_buffer>(plaintext_size, [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
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
