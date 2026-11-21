// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import potassium;
import std;

using namespace potassium;
using namespace potassium::box;

TEMPLATE_TEST_CASE("Box direct and precomputed keys interoperate with libsodium", "[box]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    static_assert(!std::copy_constructible<keypair<A>>);
    static_assert(std::move_constructible<keypair<A>>);
    static_assert(std::copyable<public_key<A>>);
    static_assert(std::constructible_from<public_key_ref<A>, typename public_key_ref<A>::span_type>);
    static_assert(!std::convertible_to<typename public_key_ref<A>::span_type, public_key_ref<A>>);
    static_assert(!std::convertible_to<public_key<A> const&&, public_key_ref<A>>);
    static_assert(!std::convertible_to<public_key<A>&&, public_key_ref<A>>);
    static_assert(!std::convertible_to<secret_key<private_key_tag<A>>&, key_ref<precomputed_key_tag<A>>>);
    auto alice = generate_keypair<A>();
    public_key<A> bob_public;
    key_buffer_storage<private_key_tag<A>> bob_secret;
    generate_keypair_into(bob_public, bob_secret.writable_bytes());
    auto sender = precompute(alice.secret_key, bob_public);
    auto recipient = precompute(bob_secret, alice.public_key);
    std::vector<std::byte> message;
    SECTION("empty") {}
    SECTION("binary")
    {
        message = {std::byte{0xff}, std::byte{}, std::byte{1}};
    }

    auto sealed = seal(alice.secret_key, bob_public, message);
    CHECK(seal(sender, message, sealed.nonce) == sealed.ciphertext);
    auto opened = open(recipient, sealed);
    CHECK(std::ranges::equal(opened.bytes(), message));
    std::vector<std::byte> out(message.size() + algorithm_traits<A>::mac_size);
    auto nonce = seal_into(sender, message, out);
    std::vector<std::byte> clear(message.size());
    open_into(bob_secret, alice.public_key, out, clear, nonce);
    CHECK(clear == message);

    auto raw_seal = crypto_box_easy;
    auto raw_open = crypto_box_open_easy;
    if constexpr (std::same_as<A, curve25519xchacha20poly1305>)
    {
        raw_seal = crypto_box_curve25519xchacha20poly1305_easy;
        raw_open = crypto_box_curve25519xchacha20poly1305_open_easy;
    }
    unsigned char empty{};
    auto bytes = [](auto const& range)
    {
        return reinterpret_cast<unsigned char const*>(range.data());
    };
    auto raw_cipher = reinterpret_cast<unsigned char*>(out.data());
    REQUIRE(raw_seal(raw_cipher, message.empty() ? &empty : bytes(message), message.size(), bytes(sealed.nonce.storage), bytes(bob_public.storage), bytes(alice.secret_key.ref().bytes())) == 0);
    CHECK(out == sealed.ciphertext);
    REQUIRE(raw_open(clear.empty() ? &empty : reinterpret_cast<unsigned char*>(clear.data()),
                     raw_cipher,
                     out.size(),
                     bytes(sealed.nonce.storage),
                     bytes(alice.public_key.storage),
                     bytes(bob_secret.ref().bytes())) == 0);
    CHECK(clear == message);
    out.front() ^= std::byte{1};
    std::ranges::fill(clear, std::byte{0x55});
    CHECK(open_into(bob_secret, alice.public_key, out, clear, sealed.nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(std::ranges::all_of(clear, [](auto b) { return b == std::byte{0x55}; }));
    CHECK(open(recipient, out, sealed.nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_THROWS_AS(open(bob_secret, alice.public_key, out, sealed.nonce), crypto_error);
    out.resize(15);
    CHECK(open_into(recipient, out, clear, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_THROWS_AS(open(bob_secret, alice.public_key, out, nonce), crypto_error);

    public_key<A> invalid;
    CHECK(precompute(alice.secret_key, invalid, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(seal(alice.secret_key, invalid, message, std::nothrow) == std::unexpected(errc::crypto_failed));
}
