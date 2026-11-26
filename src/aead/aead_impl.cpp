// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

module potassium.aead;

import potassium.internal;
import std;

namespace potassium::aead::detail
{
namespace
{
using internal::sodium_bytes;

template <class A>
struct sodium_aead;

template <>
struct sodium_aead<chacha20poly1305>
{
    static constexpr auto encrypt = crypto_aead_chacha20poly1305_encrypt;
    static constexpr auto decrypt = crypto_aead_chacha20poly1305_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_chacha20poly1305_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_chacha20poly1305_decrypt_detached;
};

template <>
struct sodium_aead<chacha20poly1305_ietf>
{
    static constexpr auto encrypt = crypto_aead_chacha20poly1305_ietf_encrypt;
    static constexpr auto decrypt = crypto_aead_chacha20poly1305_ietf_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_chacha20poly1305_ietf_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_chacha20poly1305_ietf_decrypt_detached;
};

template <>
struct sodium_aead<xchacha20poly1305_ietf>
{
    static constexpr auto encrypt = crypto_aead_xchacha20poly1305_ietf_encrypt;
    static constexpr auto decrypt = crypto_aead_xchacha20poly1305_ietf_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
};

template <class A>
consteval bool matches_backend(std::size_t key, std::size_t nonce, std::size_t mac, std::size_t messagebytes_max)
{
    using traits = algorithm_traits<A>;
    return traits::key_size == key && traits::nonce_size == nonce && traits::mac_size == mac && traits::messagebytes_max == messagebytes_max;
}

static_assert(matches_backend<chacha20poly1305>(crypto_aead_chacha20poly1305_KEYBYTES,
                                                crypto_aead_chacha20poly1305_NPUBBYTES,
                                                crypto_aead_chacha20poly1305_ABYTES,
                                                crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX));
static_assert(matches_backend<chacha20poly1305_ietf>(crypto_aead_chacha20poly1305_ietf_KEYBYTES,
                                                     crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                                     crypto_aead_chacha20poly1305_ietf_ABYTES,
                                                     crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX));
static_assert(matches_backend<xchacha20poly1305_ietf>(crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                                                      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                                      crypto_aead_xchacha20poly1305_ietf_ABYTES,
                                                      crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX));

template <class A>
bool valid_lengths(std::size_t message, std::size_t ad) noexcept
{
    return message <= algorithm_traits<A>::messagebytes_max && std::in_range<std::uint64_t>(ad);
}
}  // namespace

template <class A>
std::expected<void, errc> backend<A>::seal_into(key_ref<A> key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept
{
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    if (!valid_lengths<A>(plaintext.size(), ad.size()) || out.size() < mac_size || out.size() - mac_size != plaintext.size()) return std::unexpected(errc::crypto_failed);

    if (sodium_aead<A>::encrypt(sodium_bytes(out.data()),
                                nullptr,
                                sodium_bytes(plaintext.data()),
                                plaintext.size(),
                                sodium_bytes(ad.data()),
                                ad.size(),
                                nullptr,
                                sodium_bytes(nonce.bytes().data()),
                                sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class A>
std::expected<void, errc> backend<A>::open_into(key_ref<A> key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept
{
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    if (ciphertext.size() < mac_size || out.size() != ciphertext.size() - mac_size || !valid_lengths<A>(out.size(), ad.size())) return std::unexpected(errc::crypto_failed);

    if (sodium_aead<A>::decrypt(sodium_bytes(out.data()),
                                nullptr,
                                nullptr,
                                sodium_bytes(ciphertext.data()),
                                ciphertext.size(),
                                sodium_bytes(ad.data()),
                                ad.size(),
                                sodium_bytes(nonce.bytes().data()),
                                sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class A>
std::expected<mac_buffer<A>, errc> backend<A>::seal_detached_into(key_ref<A> key,
                                                                  std::span<std::byte const> plaintext,
                                                                  std::span<std::byte const> ad,
                                                                  std::span<std::byte> out,
                                                                  nonce_ref<A> nonce) noexcept
{
    if (!valid_lengths<A>(plaintext.size(), ad.size()) || out.size() != plaintext.size()) return std::unexpected(errc::crypto_failed);
    mac_buffer<A> mac;
    unsigned char empty{};
    if (sodium_aead<A>::encrypt_detached(out.empty() ? &empty : sodium_bytes(out.data()),
                                         sodium_bytes(mac.bytes().data()),
                                         nullptr,
                                         sodium_bytes(plaintext.data()),
                                         plaintext.size(),
                                         sodium_bytes(ad.data()),
                                         ad.size(),
                                         nullptr,
                                         sodium_bytes(nonce.bytes().data()),
                                         sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return mac;
}

template <class A>
std::expected<void, errc> backend<A>::open_detached_into(key_ref<A> key,
                                                         std::span<std::byte const> ciphertext,
                                                         std::span<std::byte const> ad,
                                                         mac_buffer<A> const& mac,
                                                         std::span<std::byte> out,
                                                         nonce_ref<A> nonce) noexcept
{
    if (!valid_lengths<A>(ciphertext.size(), ad.size()) || out.size() != ciphertext.size()) return std::unexpected(errc::crypto_failed);
    unsigned char empty{};
    if (sodium_aead<A>::decrypt_detached(sodium_bytes(out.data()),
                                         nullptr,
                                         ciphertext.empty() ? &empty : sodium_bytes(ciphertext.data()),
                                         ciphertext.size(),
                                         sodium_bytes(mac.bytes().data()),
                                         sodium_bytes(ad.data()),
                                         ad.size(),
                                         sodium_bytes(nonce.bytes().data()),
                                         sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template struct backend<chacha20poly1305>;
template struct backend<chacha20poly1305_ietf>;
template struct backend<xchacha20poly1305_ietf>;
}  // namespace potassium::aead::detail
