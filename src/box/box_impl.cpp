// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;

#include <sodium.h>

module potassium.box;

import std;

#include "../internal/sodium_interop_macros.hpp"

namespace potassium::box
{

namespace
{

static_assert(std::string_view{crypto_box_PRIMITIVE} == "curve25519xsalsa20poly1305");
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::public_key_size == crypto_box_PUBLICKEYBYTES);
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::secret_key_size == crypto_box_SECRETKEYBYTES);
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::seed_size == crypto_box_SEEDBYTES);
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::precomputed_key_size == crypto_box_BEFORENMBYTES);
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::nonce_size == crypto_box_NONCEBYTES);
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::mac_size == crypto_box_MACBYTES);
static_assert(algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max == crypto_box_MESSAGEBYTES_MAX);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::public_key_size == crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::secret_key_size == crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::seed_size == crypto_box_curve25519xchacha20poly1305_SEEDBYTES);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::precomputed_key_size == crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::nonce_size == crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::mac_size == crypto_box_curve25519xchacha20poly1305_MACBYTES);
static_assert(algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max == crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX);

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

template <class Function, class A, class... Keys>
std::expected<void, errc> transform(Function function, std::span<std::byte const> input, std::span<std::byte> out, nonce_ref<A> nonce, Keys... keys) noexcept
{
    unsigned char empty{};
    if (function(out.empty() ? &empty : POTASSIUM_MUTABLE_BYTES(out.data()),
                 input.empty() ? &empty : POTASSIUM_CONST_BYTES(input.data()),
                 input.size(),
                 POTASSIUM_CONST_BYTES(nonce.bytes().data()),
                 POTASSIUM_CONST_BYTES(keys.bytes().data())...) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}
}  // namespace

std::expected<void, errc> generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, std::span<std::byte, 32> secret, std::nothrow_t) noexcept
{
    if (crypto_box_keypair(POTASSIUM_MUTABLE_BYTES(pub.storage.data()), POTASSIUM_MUTABLE_BYTES(secret.data())) != 0) return std::unexpected(errc::crypto_failed);
    return {};
}

void generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, std::span<std::byte, 32> secret)
{
    unwrap(generate_keypair_into(pub, secret, std::nothrow));
}

std::expected<secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>>, errc> precompute(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::nothrow_t) noexcept
try
{
    secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>> result;
    if (crypto_box_beforenm(POTASSIUM_MUTABLE_BYTES(result.writable_bytes().data()), POTASSIUM_CONST_BYTES(peer.bytes().data()), POTASSIUM_CONST_BYTES(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>> precompute(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer)
{
    return unwrap(precompute(key, peer, std::nothrow));
}

void seal_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal_into(key, peer, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xsalsa_private_ref key,
                                    public_key_ref<curve25519xsalsa20poly1305> peer,
                                    std::span<std::byte const> plaintext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xsalsa20poly1305> nonce,
                                    std::nothrow_t) noexcept
{
    return transform(crypto_box_easy, plaintext, out, nonce, peer, key);
}

void open_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_into(key, peer, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xsalsa_private_ref key,
                                    public_key_ref<curve25519xsalsa20poly1305> peer,
                                    std::span<std::byte const> ciphertext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xsalsa20poly1305> nonce,
                                    std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xsalsa20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    return transform(crypto_box_open_easy, ciphertext, out, nonce, peer, key);
}

nonce_buffer<curve25519xsalsa20poly1305> seal_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, peer, plaintext, out, std::nothrow));
}

std::expected<nonce_buffer<curve25519xsalsa20poly1305>, errc> seal_into(xsalsa_private_ref key,
                                                                        public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                        std::span<std::byte const> plaintext,
                                                                        std::span<std::byte> out,
                                                                        std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    auto result = seal_into(key, peer, plaintext, out, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return nonce;
}

std::vector<std::byte> seal(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal(key, peer, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xsalsa_private_ref key,
                                                 public_key_ref<curve25519xsalsa20poly1305> peer,
                                                 std::span<std::byte const> plaintext,
                                                 nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                 std::nothrow_t) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext.size() + algorithm_traits<curve25519xsalsa20poly1305>::mac_size,
                                                          [&](auto& out) { return seal_into(key, peer, plaintext, out, nonce, std::nothrow); });
}

seal_result<curve25519xsalsa20poly1305> seal(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, peer, plaintext, std::nothrow));
}

std::expected<seal_result<curve25519xsalsa20poly1305>, errc> seal(xsalsa_private_ref key,
                                                                  public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                  std::span<std::byte const> plaintext,
                                                                  std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    auto result = seal(key, peer, plaintext, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return seal_result<curve25519xsalsa20poly1305>{std::move(*result), nonce};
}

secure_buffer open(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open(key, peer, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_private_ref key,
                                        public_key_ref<curve25519xsalsa20poly1305> peer,
                                        std::span<std::byte const> ciphertext,
                                        nonce_ref<curve25519xsalsa20poly1305> nonce,
                                        std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xsalsa20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    auto const plaintext_size = ciphertext.size() - algorithm_traits<curve25519xsalsa20poly1305>::mac_size;
    return allocate_and_transform<secure_buffer>(plaintext_size, [&](auto& out) { return open_into(key, peer, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, seal_result<curve25519xsalsa20poly1305> const& sealed)
{
    return unwrap(open(key, peer, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, seal_result<curve25519xsalsa20poly1305> const& sealed, std::nothrow_t) noexcept
{
    return open(key, peer, sealed.ciphertext, sealed.nonce, std::nothrow);
}

void seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    return transform(crypto_box_easy_afternm, plaintext, out, nonce, key);
}

void open_into(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xsalsa20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    return transform(crypto_box_open_easy_afternm, ciphertext, out, nonce, key);
}

nonce_buffer<curve25519xsalsa20poly1305> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<nonce_buffer<curve25519xsalsa20poly1305>, errc> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    auto result = seal_into(key, plaintext, out, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return nonce;
}

std::vector<std::byte> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext.size() + algorithm_traits<curve25519xsalsa20poly1305>::mac_size,
                                                          [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

seal_result<curve25519xsalsa20poly1305> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<seal_result<curve25519xsalsa20poly1305>, errc> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    auto result = seal(key, plaintext, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return seal_result<curve25519xsalsa20poly1305>{std::move(*result), nonce};
}

secure_buffer open(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xsalsa20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    auto const plaintext_size = ciphertext.size() - algorithm_traits<curve25519xsalsa20poly1305>::mac_size;
    return allocate_and_transform<secure_buffer>(plaintext_size, [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xsalsa_precomputed_ref key, seal_result<curve25519xsalsa20poly1305> const& sealed)
{
    return unwrap(open(key, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_precomputed_ref key, seal_result<curve25519xsalsa20poly1305> const& sealed, std::nothrow_t) noexcept
{
    return open(key, sealed.ciphertext, sealed.nonce, std::nothrow);
}

std::expected<void, errc> generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub, std::span<std::byte, 32> secret, std::nothrow_t) noexcept
{
    if (crypto_box_curve25519xchacha20poly1305_keypair(POTASSIUM_MUTABLE_BYTES(pub.storage.data()), POTASSIUM_MUTABLE_BYTES(secret.data())) != 0) return std::unexpected(errc::crypto_failed);
    return {};
}

void generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub, std::span<std::byte, 32> secret)
{
    unwrap(generate_keypair_into(pub, secret, std::nothrow));
}

std::expected<secret_key<precomputed_key_tag<curve25519xchacha20poly1305>>, errc> precompute(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::nothrow_t) noexcept
try
{
    secret_key<precomputed_key_tag<curve25519xchacha20poly1305>> result;
    if (crypto_box_curve25519xchacha20poly1305_beforenm(
                POTASSIUM_MUTABLE_BYTES(result.writable_bytes().data()), POTASSIUM_CONST_BYTES(peer.bytes().data()), POTASSIUM_CONST_BYTES(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

secret_key<precomputed_key_tag<curve25519xchacha20poly1305>> precompute(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer)
{
    return unwrap(precompute(key, peer, std::nothrow));
}

void seal_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal_into(key, peer, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xchacha_private_ref key,
                                    public_key_ref<curve25519xchacha20poly1305> peer,
                                    std::span<std::byte const> plaintext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                    std::nothrow_t) noexcept
{
    return transform(crypto_box_curve25519xchacha20poly1305_easy, plaintext, out, nonce, peer, key);
}

void open_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_into(key, peer, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xchacha_private_ref key,
                                    public_key_ref<curve25519xchacha20poly1305> peer,
                                    std::span<std::byte const> ciphertext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                    std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xchacha20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    return transform(crypto_box_curve25519xchacha20poly1305_open_easy, ciphertext, out, nonce, peer, key);
}

nonce_buffer<curve25519xchacha20poly1305> seal_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, peer, plaintext, out, std::nothrow));
}

std::expected<nonce_buffer<curve25519xchacha20poly1305>, errc> seal_into(xchacha_private_ref key,
                                                                         public_key_ref<curve25519xchacha20poly1305> peer,
                                                                         std::span<std::byte const> plaintext,
                                                                         std::span<std::byte> out,
                                                                         std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    auto result = seal_into(key, peer, plaintext, out, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return nonce;
}

std::vector<std::byte> seal(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal(key, peer, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xchacha_private_ref key,
                                                 public_key_ref<curve25519xchacha20poly1305> peer,
                                                 std::span<std::byte const> plaintext,
                                                 nonce_ref<curve25519xchacha20poly1305> nonce,
                                                 std::nothrow_t) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext.size() + algorithm_traits<curve25519xchacha20poly1305>::mac_size,
                                                          [&](auto& out) { return seal_into(key, peer, plaintext, out, nonce, std::nothrow); });
}

seal_result<curve25519xchacha20poly1305> seal(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, peer, plaintext, std::nothrow));
}

std::expected<seal_result<curve25519xchacha20poly1305>, errc> seal(xchacha_private_ref key,
                                                                   public_key_ref<curve25519xchacha20poly1305> peer,
                                                                   std::span<std::byte const> plaintext,
                                                                   std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    auto result = seal(key, peer, plaintext, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return seal_result<curve25519xchacha20poly1305>{std::move(*result), nonce};
}

secure_buffer open(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open(key, peer, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_private_ref key,
                                        public_key_ref<curve25519xchacha20poly1305> peer,
                                        std::span<std::byte const> ciphertext,
                                        nonce_ref<curve25519xchacha20poly1305> nonce,
                                        std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xchacha20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    auto const plaintext_size = ciphertext.size() - algorithm_traits<curve25519xchacha20poly1305>::mac_size;
    return allocate_and_transform<secure_buffer>(plaintext_size, [&](auto& out) { return open_into(key, peer, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, seal_result<curve25519xchacha20poly1305> const& sealed)
{
    return unwrap(open(key, peer, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, seal_result<curve25519xchacha20poly1305> const& sealed, std::nothrow_t) noexcept
{
    return open(key, peer, sealed.ciphertext, sealed.nonce, std::nothrow);
}

void seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<void, errc> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    return transform(crypto_box_curve25519xchacha20poly1305_easy_afternm, plaintext, out, nonce, key);
}

void open_into(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xchacha20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    return transform(crypto_box_curve25519xchacha20poly1305_open_easy_afternm, ciphertext, out, nonce, key);
}

nonce_buffer<curve25519xchacha20poly1305> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<nonce_buffer<curve25519xchacha20poly1305>, errc> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    auto result = seal_into(key, plaintext, out, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return nonce;
}

std::vector<std::byte> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext.size() + algorithm_traits<curve25519xchacha20poly1305>::mac_size,
                                                          [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

seal_result<curve25519xchacha20poly1305> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<seal_result<curve25519xchacha20poly1305>, errc> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    auto result = seal(key, plaintext, nonce, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return seal_result<curve25519xchacha20poly1305>{std::move(*result), nonce};
}

secure_buffer open(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    if (ciphertext.size() < algorithm_traits<curve25519xchacha20poly1305>::mac_size) return std::unexpected(errc::crypto_failed);
    auto const plaintext_size = ciphertext.size() - algorithm_traits<curve25519xchacha20poly1305>::mac_size;
    return allocate_and_transform<secure_buffer>(plaintext_size, [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xchacha_precomputed_ref key, seal_result<curve25519xchacha20poly1305> const& sealed)
{
    return unwrap(open(key, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_precomputed_ref key, seal_result<curve25519xchacha20poly1305> const& sealed, std::nothrow_t) noexcept
{
    return open(key, sealed.ciphertext, sealed.nonce, std::nothrow);
}

}  // namespace potassium::box
