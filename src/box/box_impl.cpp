// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;

#include <sodium.h>
#include <cassert>

module potassium.box;

import potassium.internal;
import std;

using potassium::internal::sodium_bytes;
using potassium::internal::unwrap;

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

template <class Function, class A>
std::expected<void, errc> generate_seeded_pair(Function generate,
                                               public_key<A>& pub,
                                               std::type_identity_t<key_out<private_key_tag<A>>> secret,
                                               std::type_identity_t<key_ref<seed_tag<A>>> seed) noexcept
{
    assert(internal::disjoint_bytes(pub.storage, secret.bytes()));
    assert(internal::disjoint_bytes(pub.storage, seed.bytes()));
    assert(internal::disjoint_bytes(secret.bytes(), seed.bytes()));
    if (generate(sodium_bytes(pub.storage.data()), sodium_bytes(secret.bytes().data()), sodium_bytes(seed.bytes().data())) != 0)
    {
        wipe(secret.bytes());
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

template <class A, class Function, class... Keys>
std::expected<mac_buffer<A>, errc> seal_detached_to(Function seal, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<A> nonce, Keys... keys) noexcept
{
    assert(plaintext.size() <= algorithm_traits<A>::messagebytes_max);
    assert(out.size() == plaintext.size());
    assert(internal::disjoint_bytes(out, plaintext));
    assert(internal::disjoint_bytes(out, nonce.bytes()));
    assert((internal::disjoint_bytes(out, keys.bytes()) && ...));
    mac_buffer<A> mac;
    unsigned char empty{};
    if (seal(out.empty() ? &empty : sodium_bytes(out.data()),
             sodium_bytes(mac.bytes().data()),
             plaintext.empty() ? &empty : sodium_bytes(plaintext.data()),
             plaintext.size(),
             sodium_bytes(nonce.bytes().data()),
             sodium_bytes(keys.bytes().data())...) != 0)
        return std::unexpected(errc::crypto_failed);
    return mac;
}

template <class A, class Function, class... Keys>
std::expected<void, errc> open_detached_to(Function open, std::span<std::byte const> ciphertext, mac_buffer<A> const& mac, std::span<std::byte> out, nonce_ref<A> nonce, Keys... keys) noexcept
{
    assert(out.size() == ciphertext.size());
    assert(internal::disjoint_bytes(out, ciphertext));
    assert(internal::disjoint_bytes(out, mac.bytes()));
    assert(internal::disjoint_bytes(out, nonce.bytes()));
    assert((internal::disjoint_bytes(out, keys.bytes()) && ...));
    if (ciphertext.size() > algorithm_traits<A>::messagebytes_max) return std::unexpected(errc::crypto_failed);
    unsigned char empty{};
    if (open(out.empty() ? &empty : sodium_bytes(out.data()),
             ciphertext.empty() ? &empty : sodium_bytes(ciphertext.data()),
             sodium_bytes(mac.bytes().data()),
             ciphertext.size(),
             sodium_bytes(nonce.bytes().data()),
             sodium_bytes(keys.bytes().data())...) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class A>
constexpr auto anonymous_message_max = std::min(algorithm_traits<A>::messagebytes_max, std::numeric_limits<std::size_t>::max() - algorithm_traits<A>::sealed_overhead);

template <class Function, class A>
std::expected<void, errc> seal_anonymous_to(Function seal, public_key_ref<A> recipient, std::span<std::byte const> plaintext, std::span<std::byte> out) noexcept
{
    assert(plaintext.size() <= anonymous_message_max<A>);
    assert(out.size() == plaintext.size() + algorithm_traits<A>::sealed_overhead);
    assert(internal::disjoint_bytes(out, plaintext));
    assert(internal::disjoint_bytes(out, recipient.bytes()));
    unsigned char empty{};
    if (seal(sodium_bytes(out.data()), plaintext.empty() ? &empty : sodium_bytes(plaintext.data()), plaintext.size(), sodium_bytes(recipient.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class Function, class A>
std::expected<void, errc> open_anonymous_to(Function open, key_ref<private_key_tag<A>> key, public_key_ref<A> recipient, std::span<std::byte const> ciphertext, std::span<std::byte> out) noexcept
{
    constexpr auto overhead = algorithm_traits<A>::sealed_overhead;
    if (ciphertext.size() < overhead || ciphertext.size() - overhead > anonymous_message_max<A>) return std::unexpected(errc::crypto_failed);
    assert(out.size() == ciphertext.size() - overhead);
    assert(internal::disjoint_bytes(out, ciphertext));
    assert(internal::disjoint_bytes(out, recipient.bytes()));
    assert(internal::disjoint_bytes(out, key.bytes()));
    unsigned char empty{};
    if (open(out.empty() ? &empty : sodium_bytes(out.data()), sodium_bytes(ciphertext.data()), ciphertext.size(), sodium_bytes(recipient.bytes().data()), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class A, class Function>
std::expected<secure_buffer, errc> allocate_anonymous_plaintext(std::size_t ciphertext_size, Function open) noexcept
{
    constexpr auto overhead = algorithm_traits<A>::sealed_overhead;
    if (ciphertext_size < overhead || ciphertext_size - overhead > anonymous_message_max<A>) return std::unexpected(errc::crypto_failed);
    return internal::allocate_and_transform<secure_buffer>(ciphertext_size - overhead, open);
}

}  // namespace

std::expected<void, errc> generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, std::span<std::byte, 32> secret, std::nothrow_t) noexcept
{
    if (crypto_box_keypair(sodium_bytes(pub.storage.data()), sodium_bytes(secret.data())) != 0) return std::unexpected(errc::crypto_failed);
    return {};
}

void generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, std::span<std::byte, 32> secret)
{
    unwrap(generate_keypair_into(pub, secret, std::nothrow));
}

std::expected<void, errc> precompute_into(xsalsa_private_ref key,
                                          public_key_ref<curve25519xsalsa20poly1305> peer,
                                          key_out<precomputed_key_tag<curve25519xsalsa20poly1305>> out,
                                          std::nothrow_t) noexcept
{
    if (crypto_box_beforenm(sodium_bytes(out.bytes().data()), sodium_bytes(peer.bytes().data()), sodium_bytes(key.bytes().data())) != 0) return std::unexpected(errc::crypto_failed);
    return {};
}

void precompute_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, key_out<precomputed_key_tag<curve25519xsalsa20poly1305>> out)
{
    unwrap(precompute_into(key, peer, out, std::nothrow));
}

std::expected<secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>>, errc> precompute(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::nothrow_t) noexcept
try
{
    secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>> result{for_overwrite};
    auto status = precompute_into(key, peer, result, std::nothrow);
    if (!status) return std::unexpected(status.error());
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
    return internal::transform<internal::direction::seal>(crypto_box_easy, plaintext, out, nonce, peer, key);
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
    return internal::transform<internal::direction::open>(crypto_box_open_easy, ciphertext, out, nonce, peer, key);
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
    return internal::seal_into_with_nonce<curve25519xsalsa20poly1305>([&](auto& nonce) { return seal_into(key, peer, plaintext, out, nonce, std::nothrow); });
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
    return internal::allocate_ciphertext<curve25519xsalsa20poly1305>(plaintext.size(), [&](auto& out) { return seal_into(key, peer, plaintext, out, nonce, std::nothrow); });
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
    return internal::seal_with_nonce<curve25519xsalsa20poly1305, seal_result<curve25519xsalsa20poly1305>>([&](auto& nonce) { return seal(key, peer, plaintext, nonce, std::nothrow); });
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
    return internal::allocate_plaintext<curve25519xsalsa20poly1305>(ciphertext.size(), [&](auto& out) { return open_into(key, peer, ciphertext, out.bytes(), nonce, std::nothrow); });
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
    return internal::transform<internal::direction::seal>(crypto_box_easy_afternm, plaintext, out, nonce, key);
}

void open_into(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    return internal::transform<internal::direction::open>(crypto_box_open_easy_afternm, ciphertext, out, nonce, key);
}

nonce_buffer<curve25519xsalsa20poly1305> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<nonce_buffer<curve25519xsalsa20poly1305>, errc> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    return internal::seal_into_with_nonce<curve25519xsalsa20poly1305>([&](auto& nonce) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

std::vector<std::byte> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    return internal::allocate_ciphertext<curve25519xsalsa20poly1305>(plaintext.size(), [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

seal_result<curve25519xsalsa20poly1305> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<seal_result<curve25519xsalsa20poly1305>, errc> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    return internal::seal_with_nonce<curve25519xsalsa20poly1305, seal_result<curve25519xsalsa20poly1305>>([&](auto& nonce) { return seal(key, plaintext, nonce, std::nothrow); });
}

secure_buffer open(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t) noexcept
{
    return internal::allocate_plaintext<curve25519xsalsa20poly1305>(ciphertext.size(), [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
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
    if (crypto_box_curve25519xchacha20poly1305_keypair(sodium_bytes(pub.storage.data()), sodium_bytes(secret.data())) != 0) return std::unexpected(errc::crypto_failed);
    return {};
}

void generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub, std::span<std::byte, 32> secret)
{
    unwrap(generate_keypair_into(pub, secret, std::nothrow));
}

std::expected<void, errc> precompute_into(xchacha_private_ref key,
                                          public_key_ref<curve25519xchacha20poly1305> peer,
                                          key_out<precomputed_key_tag<curve25519xchacha20poly1305>> out,
                                          std::nothrow_t) noexcept
{
    if (crypto_box_curve25519xchacha20poly1305_beforenm(sodium_bytes(out.bytes().data()), sodium_bytes(peer.bytes().data()), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

void precompute_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, key_out<precomputed_key_tag<curve25519xchacha20poly1305>> out)
{
    unwrap(precompute_into(key, peer, out, std::nothrow));
}

std::expected<secret_key<precomputed_key_tag<curve25519xchacha20poly1305>>, errc> precompute(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::nothrow_t) noexcept
try
{
    secret_key<precomputed_key_tag<curve25519xchacha20poly1305>> result{for_overwrite};
    auto status = precompute_into(key, peer, result, std::nothrow);
    if (!status) return std::unexpected(status.error());
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
    return internal::transform<internal::direction::seal>(crypto_box_curve25519xchacha20poly1305_easy, plaintext, out, nonce, peer, key);
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
    return internal::transform<internal::direction::open>(crypto_box_curve25519xchacha20poly1305_open_easy, ciphertext, out, nonce, peer, key);
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
    return internal::seal_into_with_nonce<curve25519xchacha20poly1305>([&](auto& nonce) { return seal_into(key, peer, plaintext, out, nonce, std::nothrow); });
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
    return internal::allocate_ciphertext<curve25519xchacha20poly1305>(plaintext.size(), [&](auto& out) { return seal_into(key, peer, plaintext, out, nonce, std::nothrow); });
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
    return internal::seal_with_nonce<curve25519xchacha20poly1305, seal_result<curve25519xchacha20poly1305>>([&](auto& nonce) { return seal(key, peer, plaintext, nonce, std::nothrow); });
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
    return internal::allocate_plaintext<curve25519xchacha20poly1305>(ciphertext.size(), [&](auto& out) { return open_into(key, peer, ciphertext, out.bytes(), nonce, std::nothrow); });
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
    return internal::transform<internal::direction::seal>(crypto_box_curve25519xchacha20poly1305_easy_afternm, plaintext, out, nonce, key);
}

void open_into(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_into(key, ciphertext, out, nonce, std::nothrow));
}

std::expected<void, errc> open_into(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    return internal::transform<internal::direction::open>(crypto_box_curve25519xchacha20poly1305_open_easy_afternm, ciphertext, out, nonce, key);
}

nonce_buffer<curve25519xchacha20poly1305> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_into(key, plaintext, out, std::nothrow));
}

std::expected<nonce_buffer<curve25519xchacha20poly1305>, errc> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    return internal::seal_into_with_nonce<curve25519xchacha20poly1305>([&](auto& nonce) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

std::vector<std::byte> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal(key, plaintext, nonce, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    return internal::allocate_ciphertext<curve25519xchacha20poly1305>(plaintext.size(), [&](auto& out) { return seal_into(key, plaintext, out, nonce, std::nothrow); });
}

seal_result<curve25519xchacha20poly1305> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal(key, plaintext, std::nothrow));
}

std::expected<seal_result<curve25519xchacha20poly1305>, errc> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    return internal::seal_with_nonce<curve25519xchacha20poly1305, seal_result<curve25519xchacha20poly1305>>([&](auto& nonce) { return seal(key, plaintext, nonce, std::nothrow); });
}

secure_buffer open(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open(key, ciphertext, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t) noexcept
{
    return internal::allocate_plaintext<curve25519xchacha20poly1305>(ciphertext.size(), [&](auto& out) { return open_into(key, ciphertext, out.bytes(), nonce, std::nothrow); });
}

secure_buffer open(xchacha_precomputed_ref key, seal_result<curve25519xchacha20poly1305> const& sealed)
{
    return unwrap(open(key, sealed, std::nothrow));
}

std::expected<secure_buffer, errc> open(xchacha_precomputed_ref key, seal_result<curve25519xchacha20poly1305> const& sealed, std::nothrow_t) noexcept
{
    return open(key, sealed.ciphertext, sealed.nonce, std::nothrow);
}

void generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, key_out<private_key_tag<curve25519xsalsa20poly1305>> secret, key_ref<seed_tag<curve25519xsalsa20poly1305>> seed)
{
    return unwrap(generate_keypair_into(pub, secret, seed, std::nothrow));
}

std::expected<void, errc> generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub,
                                                key_out<private_key_tag<curve25519xsalsa20poly1305>> secret,
                                                key_ref<seed_tag<curve25519xsalsa20poly1305>> seed,
                                                std::nothrow_t) noexcept
{
    return generate_seeded_pair(crypto_box_seed_keypair, pub, secret, seed);
}

std::vector<std::byte> seal_anonymous(public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> plaintext)
{
    return unwrap(seal_anonymous(recipient, plaintext, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal_anonymous(public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    assert(plaintext.size() <= anonymous_message_max<curve25519xsalsa20poly1305>);
    return internal::allocate_and_transform<std::vector<std::byte>>(plaintext.size() + algorithm_traits<curve25519xsalsa20poly1305>::sealed_overhead,
                                                                    [&](auto& out) { return seal_anonymous_into(recipient, plaintext, out, std::nothrow); });
}

void seal_anonymous_into(public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_anonymous_into(recipient, plaintext, out, std::nothrow));
}

std::expected<void, errc> seal_anonymous_into(public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    return seal_anonymous_to(crypto_box_seal, recipient, plaintext, out);
}

secure_buffer open_anonymous(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> ciphertext)
{
    return unwrap(open_anonymous(key, recipient, ciphertext, std::nothrow));
}

std::expected<secure_buffer, errc> open_anonymous(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> ciphertext, std::nothrow_t) noexcept
{
    return allocate_anonymous_plaintext<curve25519xsalsa20poly1305>(ciphertext.size(), [&](auto& out) { return open_anonymous_into(key, recipient, ciphertext, out.bytes(), std::nothrow); });
}

void open_anonymous_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> recipient, std::span<std::byte const> ciphertext, std::span<std::byte> out)
{
    return unwrap(open_anonymous_into(key, recipient, ciphertext, out, std::nothrow));
}

std::expected<void, errc> open_anonymous_into(xsalsa_private_ref key,
                                              public_key_ref<curve25519xsalsa20poly1305> recipient,
                                              std::span<std::byte const> ciphertext,
                                              std::span<std::byte> out,
                                              std::nothrow_t) noexcept
{
    return open_anonymous_to(crypto_box_seal_open, key, recipient, ciphertext, out);
}

mac_buffer<curve25519xsalsa20poly1305> seal_detached_into(xsalsa_private_ref key,
                                                          public_key_ref<curve25519xsalsa20poly1305> peer,
                                                          std::span<std::byte const> plaintext,
                                                          std::span<std::byte> out,
                                                          nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal_detached_into(key, peer, plaintext, out, nonce, std::nothrow));
}

std::expected<mac_buffer<curve25519xsalsa20poly1305>, errc> seal_detached_into(xsalsa_private_ref key,
                                                                               public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                               std::span<std::byte const> plaintext,
                                                                               std::span<std::byte> out,
                                                                               nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                                               std::nothrow_t) noexcept
{
    return seal_detached_to(crypto_box_detached, plaintext, out, nonce, peer, key);
}

detached_mac_nonce<curve25519xsalsa20poly1305> seal_detached_into(xsalsa_private_ref key,
                                                                  public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                  std::span<std::byte const> plaintext,
                                                                  std::span<std::byte> out)
{
    return unwrap(seal_detached_into(key, peer, plaintext, out, std::nothrow));
}

std::expected<detached_mac_nonce<curve25519xsalsa20poly1305>, errc> seal_detached_into(xsalsa_private_ref key,
                                                                                       public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                                       std::span<std::byte const> plaintext,
                                                                                       std::span<std::byte> out,
                                                                                       std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    return seal_detached_into(key, peer, plaintext, out, nonce, std::nothrow).transform([&](auto const& mac) { return detached_mac_nonce<curve25519xsalsa20poly1305>{mac, nonce}; });
}

detached_ciphertext<curve25519xsalsa20poly1305> seal_detached(xsalsa_private_ref key,
                                                              public_key_ref<curve25519xsalsa20poly1305> peer,
                                                              std::span<std::byte const> plaintext,
                                                              nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal_detached(key, peer, plaintext, nonce, std::nothrow));
}

std::expected<detached_ciphertext<curve25519xsalsa20poly1305>, errc> seal_detached(xsalsa_private_ref key,
                                                                                   public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                                   std::span<std::byte const> plaintext,
                                                                                   nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                                                   std::nothrow_t) noexcept
{
    return internal::allocate_detached_ciphertext<curve25519xsalsa20poly1305>(plaintext.size(), [&](auto& out) { return seal_detached_into(key, peer, plaintext, out, nonce, std::nothrow); });
}

detached_seal_result<curve25519xsalsa20poly1305> seal_detached(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext)
{
    return unwrap(seal_detached(key, peer, plaintext, std::nothrow));
}

std::expected<detached_seal_result<curve25519xsalsa20poly1305>, errc> seal_detached(xsalsa_private_ref key,
                                                                                    public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                                    std::span<std::byte const> plaintext,
                                                                                    std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    return seal_detached(key, peer, plaintext, nonce, std::nothrow)
            .transform([&](auto&& sealed) { return detached_seal_result<curve25519xsalsa20poly1305>{std::move(sealed.ciphertext), sealed.mac, nonce}; });
}

secure_buffer open_detached(xsalsa_private_ref key,
                            public_key_ref<curve25519xsalsa20poly1305> peer,
                            std::span<std::byte const> ciphertext,
                            mac_buffer<curve25519xsalsa20poly1305> const& mac,
                            nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_detached(key, peer, ciphertext, mac, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open_detached(xsalsa_private_ref key,
                                                 public_key_ref<curve25519xsalsa20poly1305> peer,
                                                 std::span<std::byte const> ciphertext,
                                                 mac_buffer<curve25519xsalsa20poly1305> const& mac,
                                                 nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                 std::nothrow_t) noexcept
{
    return internal::allocate_detached_plaintext<curve25519xsalsa20poly1305>(ciphertext.size(),
                                                                             [&](auto& out) { return open_detached_into(key, peer, ciphertext, mac, out.bytes(), nonce, std::nothrow); });
}

void open_detached_into(xsalsa_private_ref key,
                        public_key_ref<curve25519xsalsa20poly1305> peer,
                        std::span<std::byte const> ciphertext,
                        mac_buffer<curve25519xsalsa20poly1305> const& mac,
                        std::span<std::byte> out,
                        nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_detached_into(key, peer, ciphertext, mac, out, nonce, std::nothrow));
}

std::expected<void, errc> open_detached_into(xsalsa_private_ref key,
                                             public_key_ref<curve25519xsalsa20poly1305> peer,
                                             std::span<std::byte const> ciphertext,
                                             mac_buffer<curve25519xsalsa20poly1305> const& mac,
                                             std::span<std::byte> out,
                                             nonce_ref<curve25519xsalsa20poly1305> nonce,
                                             std::nothrow_t) noexcept
{
    return open_detached_to(crypto_box_open_detached, ciphertext, mac, out, nonce, peer, key);
}

mac_buffer<curve25519xsalsa20poly1305> seal_detached_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal_detached_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<mac_buffer<curve25519xsalsa20poly1305>, errc> seal_detached_into(xsalsa_precomputed_ref key,
                                                                               std::span<std::byte const> plaintext,
                                                                               std::span<std::byte> out,
                                                                               nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                                               std::nothrow_t) noexcept
{
    return seal_detached_to(crypto_box_detached_afternm, plaintext, out, nonce, key);
}

detached_mac_nonce<curve25519xsalsa20poly1305> seal_detached_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_detached_into(key, plaintext, out, std::nothrow));
}

std::expected<detached_mac_nonce<curve25519xsalsa20poly1305>, errc> seal_detached_into(xsalsa_precomputed_ref key,
                                                                                       std::span<std::byte const> plaintext,
                                                                                       std::span<std::byte> out,
                                                                                       std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    return seal_detached_into(key, plaintext, out, nonce, std::nothrow).transform([&](auto const& mac) { return detached_mac_nonce<curve25519xsalsa20poly1305>{mac, nonce}; });
}

detached_ciphertext<curve25519xsalsa20poly1305> seal_detached(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(seal_detached(key, plaintext, nonce, std::nothrow));
}

std::expected<detached_ciphertext<curve25519xsalsa20poly1305>, errc> seal_detached(xsalsa_precomputed_ref key,
                                                                                   std::span<std::byte const> plaintext,
                                                                                   nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                                                   std::nothrow_t) noexcept
{
    return internal::allocate_detached_ciphertext<curve25519xsalsa20poly1305>(plaintext.size(), [&](auto& out) { return seal_detached_into(key, plaintext, out, nonce, std::nothrow); });
}

detached_seal_result<curve25519xsalsa20poly1305> seal_detached(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal_detached(key, plaintext, std::nothrow));
}

std::expected<detached_seal_result<curve25519xsalsa20poly1305>, errc> seal_detached(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xsalsa20poly1305>();
    return seal_detached(key, plaintext, nonce, std::nothrow)
            .transform([&](auto&& sealed) { return detached_seal_result<curve25519xsalsa20poly1305>{std::move(sealed.ciphertext), sealed.mac, nonce}; });
}

secure_buffer open_detached(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, mac_buffer<curve25519xsalsa20poly1305> const& mac, nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_detached(key, ciphertext, mac, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open_detached(xsalsa_precomputed_ref key,
                                                 std::span<std::byte const> ciphertext,
                                                 mac_buffer<curve25519xsalsa20poly1305> const& mac,
                                                 nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                 std::nothrow_t) noexcept
{
    return internal::allocate_detached_plaintext<curve25519xsalsa20poly1305>(ciphertext.size(), [&](auto& out) { return open_detached_into(key, ciphertext, mac, out.bytes(), nonce, std::nothrow); });
}

void open_detached_into(xsalsa_precomputed_ref key,
                        std::span<std::byte const> ciphertext,
                        mac_buffer<curve25519xsalsa20poly1305> const& mac,
                        std::span<std::byte> out,
                        nonce_ref<curve25519xsalsa20poly1305> nonce)
{
    return unwrap(open_detached_into(key, ciphertext, mac, out, nonce, std::nothrow));
}

std::expected<void, errc> open_detached_into(xsalsa_precomputed_ref key,
                                             std::span<std::byte const> ciphertext,
                                             mac_buffer<curve25519xsalsa20poly1305> const& mac,
                                             std::span<std::byte> out,
                                             nonce_ref<curve25519xsalsa20poly1305> nonce,
                                             std::nothrow_t) noexcept
{
    return open_detached_to(crypto_box_open_detached_afternm, ciphertext, mac, out, nonce, key);
}

void generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub, key_out<private_key_tag<curve25519xchacha20poly1305>> secret, key_ref<seed_tag<curve25519xchacha20poly1305>> seed)
{
    return unwrap(generate_keypair_into(pub, secret, seed, std::nothrow));
}

std::expected<void, errc> generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub,
                                                key_out<private_key_tag<curve25519xchacha20poly1305>> secret,
                                                key_ref<seed_tag<curve25519xchacha20poly1305>> seed,
                                                std::nothrow_t) noexcept
{
    return generate_seeded_pair(crypto_box_curve25519xchacha20poly1305_seed_keypair, pub, secret, seed);
}

std::vector<std::byte> seal_anonymous(public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> plaintext)
{
    return unwrap(seal_anonymous(recipient, plaintext, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> seal_anonymous(public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    assert(plaintext.size() <= anonymous_message_max<curve25519xchacha20poly1305>);
    return internal::allocate_and_transform<std::vector<std::byte>>(plaintext.size() + algorithm_traits<curve25519xchacha20poly1305>::sealed_overhead,
                                                                    [&](auto& out) { return seal_anonymous_into(recipient, plaintext, out, std::nothrow); });
}

void seal_anonymous_into(public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_anonymous_into(recipient, plaintext, out, std::nothrow));
}

std::expected<void, errc> seal_anonymous_into(public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t) noexcept
{
    return seal_anonymous_to(crypto_box_curve25519xchacha20poly1305_seal, recipient, plaintext, out);
}

secure_buffer open_anonymous(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> ciphertext)
{
    return unwrap(open_anonymous(key, recipient, ciphertext, std::nothrow));
}

std::expected<secure_buffer, errc> open_anonymous(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> ciphertext, std::nothrow_t) noexcept
{
    return allocate_anonymous_plaintext<curve25519xchacha20poly1305>(ciphertext.size(), [&](auto& out) { return open_anonymous_into(key, recipient, ciphertext, out.bytes(), std::nothrow); });
}

void open_anonymous_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> recipient, std::span<std::byte const> ciphertext, std::span<std::byte> out)
{
    return unwrap(open_anonymous_into(key, recipient, ciphertext, out, std::nothrow));
}

std::expected<void, errc> open_anonymous_into(xchacha_private_ref key,
                                              public_key_ref<curve25519xchacha20poly1305> recipient,
                                              std::span<std::byte const> ciphertext,
                                              std::span<std::byte> out,
                                              std::nothrow_t) noexcept
{
    return open_anonymous_to(crypto_box_curve25519xchacha20poly1305_seal_open, key, recipient, ciphertext, out);
}

mac_buffer<curve25519xchacha20poly1305> seal_detached_into(xchacha_private_ref key,
                                                           public_key_ref<curve25519xchacha20poly1305> peer,
                                                           std::span<std::byte const> plaintext,
                                                           std::span<std::byte> out,
                                                           nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal_detached_into(key, peer, plaintext, out, nonce, std::nothrow));
}

std::expected<mac_buffer<curve25519xchacha20poly1305>, errc> seal_detached_into(xchacha_private_ref key,
                                                                                public_key_ref<curve25519xchacha20poly1305> peer,
                                                                                std::span<std::byte const> plaintext,
                                                                                std::span<std::byte> out,
                                                                                nonce_ref<curve25519xchacha20poly1305> nonce,
                                                                                std::nothrow_t) noexcept
{
    return seal_detached_to(crypto_box_curve25519xchacha20poly1305_detached, plaintext, out, nonce, peer, key);
}

detached_mac_nonce<curve25519xchacha20poly1305> seal_detached_into(xchacha_private_ref key,
                                                                   public_key_ref<curve25519xchacha20poly1305> peer,
                                                                   std::span<std::byte const> plaintext,
                                                                   std::span<std::byte> out)
{
    return unwrap(seal_detached_into(key, peer, plaintext, out, std::nothrow));
}

std::expected<detached_mac_nonce<curve25519xchacha20poly1305>, errc> seal_detached_into(xchacha_private_ref key,
                                                                                        public_key_ref<curve25519xchacha20poly1305> peer,
                                                                                        std::span<std::byte const> plaintext,
                                                                                        std::span<std::byte> out,
                                                                                        std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    return seal_detached_into(key, peer, plaintext, out, nonce, std::nothrow).transform([&](auto const& mac) { return detached_mac_nonce<curve25519xchacha20poly1305>{mac, nonce}; });
}

detached_ciphertext<curve25519xchacha20poly1305> seal_detached(xchacha_private_ref key,
                                                               public_key_ref<curve25519xchacha20poly1305> peer,
                                                               std::span<std::byte const> plaintext,
                                                               nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal_detached(key, peer, plaintext, nonce, std::nothrow));
}

std::expected<detached_ciphertext<curve25519xchacha20poly1305>, errc> seal_detached(xchacha_private_ref key,
                                                                                    public_key_ref<curve25519xchacha20poly1305> peer,
                                                                                    std::span<std::byte const> plaintext,
                                                                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                                                                    std::nothrow_t) noexcept
{
    return internal::allocate_detached_ciphertext<curve25519xchacha20poly1305>(plaintext.size(), [&](auto& out) { return seal_detached_into(key, peer, plaintext, out, nonce, std::nothrow); });
}

detached_seal_result<curve25519xchacha20poly1305> seal_detached(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext)
{
    return unwrap(seal_detached(key, peer, plaintext, std::nothrow));
}

std::expected<detached_seal_result<curve25519xchacha20poly1305>, errc> seal_detached(xchacha_private_ref key,
                                                                                     public_key_ref<curve25519xchacha20poly1305> peer,
                                                                                     std::span<std::byte const> plaintext,
                                                                                     std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    return seal_detached(key, peer, plaintext, nonce, std::nothrow)
            .transform([&](auto&& sealed) { return detached_seal_result<curve25519xchacha20poly1305>{std::move(sealed.ciphertext), sealed.mac, nonce}; });
}

secure_buffer open_detached(xchacha_private_ref key,
                            public_key_ref<curve25519xchacha20poly1305> peer,
                            std::span<std::byte const> ciphertext,
                            mac_buffer<curve25519xchacha20poly1305> const& mac,
                            nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_detached(key, peer, ciphertext, mac, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open_detached(xchacha_private_ref key,
                                                 public_key_ref<curve25519xchacha20poly1305> peer,
                                                 std::span<std::byte const> ciphertext,
                                                 mac_buffer<curve25519xchacha20poly1305> const& mac,
                                                 nonce_ref<curve25519xchacha20poly1305> nonce,
                                                 std::nothrow_t) noexcept
{
    return internal::allocate_detached_plaintext<curve25519xchacha20poly1305>(ciphertext.size(),
                                                                              [&](auto& out) { return open_detached_into(key, peer, ciphertext, mac, out.bytes(), nonce, std::nothrow); });
}

void open_detached_into(xchacha_private_ref key,
                        public_key_ref<curve25519xchacha20poly1305> peer,
                        std::span<std::byte const> ciphertext,
                        mac_buffer<curve25519xchacha20poly1305> const& mac,
                        std::span<std::byte> out,
                        nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_detached_into(key, peer, ciphertext, mac, out, nonce, std::nothrow));
}

std::expected<void, errc> open_detached_into(xchacha_private_ref key,
                                             public_key_ref<curve25519xchacha20poly1305> peer,
                                             std::span<std::byte const> ciphertext,
                                             mac_buffer<curve25519xchacha20poly1305> const& mac,
                                             std::span<std::byte> out,
                                             nonce_ref<curve25519xchacha20poly1305> nonce,
                                             std::nothrow_t) noexcept
{
    return open_detached_to(crypto_box_curve25519xchacha20poly1305_open_detached, ciphertext, mac, out, nonce, peer, key);
}

mac_buffer<curve25519xchacha20poly1305> seal_detached_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal_detached_into(key, plaintext, out, nonce, std::nothrow));
}

std::expected<mac_buffer<curve25519xchacha20poly1305>, errc> seal_detached_into(xchacha_precomputed_ref key,
                                                                                std::span<std::byte const> plaintext,
                                                                                std::span<std::byte> out,
                                                                                nonce_ref<curve25519xchacha20poly1305> nonce,
                                                                                std::nothrow_t) noexcept
{
    return seal_detached_to(crypto_box_curve25519xchacha20poly1305_detached_afternm, plaintext, out, nonce, key);
}

detached_mac_nonce<curve25519xchacha20poly1305> seal_detached_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out)
{
    return unwrap(seal_detached_into(key, plaintext, out, std::nothrow));
}

std::expected<detached_mac_nonce<curve25519xchacha20poly1305>, errc> seal_detached_into(xchacha_precomputed_ref key,
                                                                                        std::span<std::byte const> plaintext,
                                                                                        std::span<std::byte> out,
                                                                                        std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    return seal_detached_into(key, plaintext, out, nonce, std::nothrow).transform([&](auto const& mac) { return detached_mac_nonce<curve25519xchacha20poly1305>{mac, nonce}; });
}

detached_ciphertext<curve25519xchacha20poly1305> seal_detached(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(seal_detached(key, plaintext, nonce, std::nothrow));
}

std::expected<detached_ciphertext<curve25519xchacha20poly1305>, errc> seal_detached(xchacha_precomputed_ref key,
                                                                                    std::span<std::byte const> plaintext,
                                                                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                                                                    std::nothrow_t) noexcept
{
    return internal::allocate_detached_ciphertext<curve25519xchacha20poly1305>(plaintext.size(), [&](auto& out) { return seal_detached_into(key, plaintext, out, nonce, std::nothrow); });
}

detached_seal_result<curve25519xchacha20poly1305> seal_detached(xchacha_precomputed_ref key, std::span<std::byte const> plaintext)
{
    return unwrap(seal_detached(key, plaintext, std::nothrow));
}

std::expected<detached_seal_result<curve25519xchacha20poly1305>, errc> seal_detached(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t) noexcept
{
    auto nonce = generate_nonce<curve25519xchacha20poly1305>();
    return seal_detached(key, plaintext, nonce, std::nothrow)
            .transform([&](auto&& sealed) { return detached_seal_result<curve25519xchacha20poly1305>{std::move(sealed.ciphertext), sealed.mac, nonce}; });
}

secure_buffer open_detached(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, mac_buffer<curve25519xchacha20poly1305> const& mac, nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_detached(key, ciphertext, mac, nonce, std::nothrow));
}

std::expected<secure_buffer, errc> open_detached(xchacha_precomputed_ref key,
                                                 std::span<std::byte const> ciphertext,
                                                 mac_buffer<curve25519xchacha20poly1305> const& mac,
                                                 nonce_ref<curve25519xchacha20poly1305> nonce,
                                                 std::nothrow_t) noexcept
{
    return internal::allocate_detached_plaintext<curve25519xchacha20poly1305>(ciphertext.size(), [&](auto& out) { return open_detached_into(key, ciphertext, mac, out.bytes(), nonce, std::nothrow); });
}

void open_detached_into(xchacha_precomputed_ref key,
                        std::span<std::byte const> ciphertext,
                        mac_buffer<curve25519xchacha20poly1305> const& mac,
                        std::span<std::byte> out,
                        nonce_ref<curve25519xchacha20poly1305> nonce)
{
    return unwrap(open_detached_into(key, ciphertext, mac, out, nonce, std::nothrow));
}

std::expected<void, errc> open_detached_into(xchacha_precomputed_ref key,
                                             std::span<std::byte const> ciphertext,
                                             mac_buffer<curve25519xchacha20poly1305> const& mac,
                                             std::span<std::byte> out,
                                             nonce_ref<curve25519xchacha20poly1305> nonce,
                                             std::nothrow_t) noexcept
{
    return open_detached_to(crypto_box_curve25519xchacha20poly1305_open_detached_afternm, ciphertext, mac, out, nonce, key);
}

}  // namespace potassium::box
