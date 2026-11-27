// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import potassium.box;
import potassium.tests.nacl_vector;
import std;

using namespace potassium;
using namespace potassium::box;

TEMPLATE_TEST_CASE("Box invokes the supplied generator in its original value category", "[box][keys]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    using output = std::span<std::byte, algorithm_traits<A>::secret_key_size>;

    struct generator
    {
        std::array<unsigned, 3>& calls;

        explicit generator(std::array<unsigned, 3>& counts)
            : calls(counts)
        {
        }

        generator(generator const&) = delete;

        void operator()(public_key<A>& pub, output secret) &
        {
            ++calls[0];
            generate_keypair_into(pub, secret);
        }

        void operator()(public_key<A>& pub, output secret) const&
        {
            ++calls[1];
            generate_keypair_into(pub, secret);
        }

        void operator()(public_key<A>& pub, output secret) &&
        {
            ++calls[2];
            generate_keypair_into(pub, secret);
        }

        void operator()(public_key<A>&, output) const&& = delete;
    };

    static_assert(!std::constructible_from<keypair<A>, generator const&&>);
    static_assert(!std::constructible_from<keypair<A>, int (*)(public_key<A>&, output)>);
    std::array<unsigned, 3> calls{};
    generator gen{calls};
    keypair<A> sender{gen};
    keypair<A> recipient{std::as_const(gen)};
    keypair<A> other{std::move(gen)};
    CHECK(calls == std::array{1U, 1U, 1U});
    auto sealed = seal(sender.secret_key, recipient.public_key, {});
    auto opened = open(recipient.secret_key, sender.public_key, sealed);
    CHECK(opened.bytes().empty());

    auto fail = [](public_key<A>&, output secret)
    {
        secret.front() = std::byte{1};
        throw crypto_error{};
    };
    CHECK_THROWS_AS(keypair<A>{fail}, crypto_error);
}

TEMPLATE_TEST_CASE("Box supports zeroed, overwrite and factory keypairs", "[box][keys]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    keypair<A> zeroed{zero};
    auto is_zero = [](std::byte b)
    {
        return b == std::byte{};
    };
    CHECK(std::ranges::all_of(zeroed.public_key.storage, is_zero));
    CHECK(std::ranges::all_of(zeroed.secret_key.ref().bytes(), is_zero));
    keypair<A> pair{for_overwrite};
    generate_keypair_into(pair.public_key, pair.secret_key.writable_bytes());
    auto sender = generate_keypair<A>(std::nothrow);
    REQUIRE(sender.has_value());
    auto sealed = seal(sender->secret_key, pair.public_key, {});
    auto opened = open(pair.secret_key, sender->public_key, sealed);
    CHECK(opened.bytes().empty());
    static_assert(!std::default_initializable<secret_key<precomputed_key_tag<A>>>);
}

TEMPLATE_TEST_CASE("Box direct and precomputed keys interoperate with libsodium", "[box][interop]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
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
    keypair<A> alice;
    public_key<A> bob_public;
    key_buffer_storage<private_key_tag<A>> bob_secret{for_overwrite};
    generate_keypair_into(bob_public, bob_secret);
    auto sender = precompute(alice.secret_key, bob_public);
    key_buffer_storage<precomputed_key_tag<A>> recipient{for_overwrite};
    precompute_into(bob_secret, alice.public_key, recipient);
    static_assert(!std::convertible_to<decltype(bob_secret)&, key_out<precomputed_key_tag<A>>>);
    std::vector<std::byte> message;
    SECTION("empty") {}
    SECTION("binary")
    {
        message = {std::byte{0xff}, std::byte{}, std::byte{1}};
    }

    SECTION("multi-block binary")
    {
        message.assign(test_vectors::nacl::message.begin(), test_vectors::nacl::message.end());
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
    auto raw_precompute = crypto_box_beforenm;
    auto raw_open_precomputed = crypto_box_open_easy_afternm;
    auto raw_open = crypto_box_open_easy;
    if constexpr (std::same_as<A, curve25519xchacha20poly1305>)
    {
        raw_seal = crypto_box_curve25519xchacha20poly1305_easy;
        raw_precompute = crypto_box_curve25519xchacha20poly1305_beforenm;
        raw_open_precomputed = crypto_box_curve25519xchacha20poly1305_open_easy_afternm;
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
    std::ranges::fill(clear, std::byte{0x55});
    REQUIRE(raw_open(clear.empty() ? &empty : reinterpret_cast<unsigned char*>(clear.data()),
                     bytes(sealed.ciphertext),
                     sealed.ciphertext.size(),
                     bytes(sealed.nonce.storage),
                     bytes(alice.public_key.storage),
                     bytes(bob_secret.ref().bytes())) == 0);
    CHECK(clear == message);
    auto from_sodium = open(recipient, out, sealed.nonce);
    CHECK(std::ranges::equal(from_sodium.bytes(), message));
    std::array<unsigned char, algorithm_traits<A>::precomputed_key_size> raw_shared{};
    REQUIRE(raw_precompute(raw_shared.data(), bytes(alice.public_key.storage), bytes(bob_secret.ref().bytes())) == 0);
    CHECK(std::ranges::equal(recipient.ref().bytes(), std::as_bytes(std::span{raw_shared})));
    std::ranges::fill(clear, std::byte{0x55});
    REQUIRE(raw_open_precomputed(
                    clear.empty() ? &empty : reinterpret_cast<unsigned char*>(clear.data()), bytes(sealed.ciphertext), sealed.ciphertext.size(), bytes(sealed.nonce.storage), raw_shared.data()) == 0);
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

TEMPLATE_TEST_CASE("Box matches fixed vectors with the NaCl keypairs", "[box][vectors]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    using namespace test_vectors::nacl;
    using test_vectors::hex_bytes;

    // XChaCha20 fixture derived using X25519, HChaCha20 with a zero input, and XChaCha20 SecretBox.
    constexpr auto xchacha_key = hex_bytes("8e47ca376bdc7e59d2ced8107ceb2c27f4a80e8575f996baffb1a869ffcd5179");
    constexpr auto xchacha_ciphertext = hex_bytes(
            "0b4ff00742f3c1aa99a6321e3883b03cef2c6061b7bcec0cfd723055f61f1ccca"
            "2946d5a04dbf83151f4894223ac9bc790c660e19dc64cc0d7f9c7689ad190995"
            "5e7a9a7bdac777d6a7967d000ce841fc0f8f31d6d8720b374bc28982764a7dbe"
            "b4daa977aae1b7350fac79a177ece7541fed264461ea93e6d7ad9fc08c91e774"
            "abe79036e7f79ddcc6aab3abf527631048ce1");
    constexpr bool xsalsa = std::same_as<A, curve25519xsalsa20poly1305>;
    auto const& expected_key = xsalsa ? shared_key : xchacha_key;
    auto const& expected_ciphertext = xsalsa ? ciphertext : xchacha_ciphertext;

    auto alice = key_ref<private_key_tag<A>>{alice_secret};
    auto bob = key_ref<private_key_tag<A>>{bob_secret};
    auto alice_peer = public_key_ref<A>{alice_public};
    auto bob_peer = public_key_ref<A>{bob_public};
    auto fixed_nonce = nonce_ref<A>{nonce};

    auto sender = precompute(alice, bob_peer);
    auto recipient = precompute(bob, alice_peer);
    CHECK(std::ranges::equal(sender.ref().bytes(), expected_key));
    CHECK(std::ranges::equal(recipient.ref().bytes(), expected_key));
    CHECK(std::ranges::equal(seal(alice, bob_peer, message, fixed_nonce), expected_ciphertext));
    CHECK(std::ranges::equal(seal(sender, message, fixed_nonce), expected_ciphertext));

    auto direct = open(bob, alice_peer, expected_ciphertext, fixed_nonce);
    auto precomputed = open(recipient, expected_ciphertext, fixed_nonce);
    CHECK(std::ranges::equal(direct.bytes(), message));
    CHECK(std::ranges::equal(precomputed.bytes(), message));
}

namespace
{
auto writable_bytes(auto& range)
{
    return reinterpret_cast<unsigned char*>(range.data());
}

auto readable_bytes(auto const& range)
{
    return reinterpret_cast<unsigned char const*>(range.data());
}
}  // namespace

TEMPLATE_TEST_CASE("Box seeded key pairs match native generation", "[box][keys][interop]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    constexpr auto raw_generate = std::same_as<A, curve25519xsalsa20poly1305> ? crypto_box_seed_keypair : crypto_box_curve25519xchacha20poly1305_seed_keypair;
    key_buffer_storage<seed_tag<A>> seed{zero};
    seed.writable_bytes().front() = std::byte{0xa5};
    public_key<A> expected_public;
    key_buffer_storage<private_key_tag<A>> expected_secret{for_overwrite};
    auto expected_secret_bytes = expected_secret.writable_bytes();
    REQUIRE(raw_generate(writable_bytes(expected_public.storage), writable_bytes(expected_secret_bytes), readable_bytes(seed.ref().bytes())) == 0);

    auto pair = generate_keypair(seed.ref(), std::nothrow);
    REQUIRE(pair);
    CHECK(pair->public_key.storage == expected_public.storage);
    CHECK(std::ranges::equal(pair->secret_key.ref().bytes(), expected_secret.ref().bytes()));

    public_key<A> pub;
    key_buffer_storage<private_key_tag<A>> secret{for_overwrite};
    generate_keypair_into(pub, secret, seed);
    CHECK(pub.storage == expected_public.storage);
    CHECK(std::ranges::equal(secret.ref().bytes(), expected_secret.ref().bytes()));
}

TEMPLATE_TEST_CASE("Detached Box interoperates directly and after precomputation", "[box][interop]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    constexpr bool xsalsa = std::same_as<A, curve25519xsalsa20poly1305>;
    constexpr auto raw_seal = xsalsa ? crypto_box_detached : crypto_box_curve25519xchacha20poly1305_detached;
    constexpr auto raw_open = xsalsa ? crypto_box_open_detached : crypto_box_curve25519xchacha20poly1305_open_detached;
    constexpr auto raw_seal_shared = xsalsa ? crypto_box_detached_afternm : crypto_box_curve25519xchacha20poly1305_detached_afternm;
    constexpr auto raw_open_shared = xsalsa ? crypto_box_open_detached_afternm : crypto_box_curve25519xchacha20poly1305_open_detached_afternm;

    keypair<A> sender;
    keypair<A> recipient;
    auto sending_key = precompute(sender.secret_key, recipient.public_key);
    auto receiving_key = precompute(recipient.secret_key, sender.public_key);
    std::vector<std::byte> message;
    SECTION("empty") {}
    SECTION("binary")
    {
        message = {std::byte{0xff}, std::byte{0x80}, std::byte{}, std::byte{1}};
    }

    auto sealed = seal_detached(sender.secret_key, recipient.public_key, message);
    CHECK(sealed.ciphertext.size() == message.size());
    auto from_direct = open_detached(recipient.secret_key, sender.public_key, sealed.ciphertext, sealed.mac, sealed.nonce);
    CHECK(std::ranges::equal(from_direct.bytes(), message));
    auto from_shared = open_detached(receiving_key, sealed.ciphertext, sealed.mac, sealed.nonce);
    CHECK(std::ranges::equal(from_shared.bytes(), message));

    std::vector<std::byte> clear(message.size());
    auto* const nonce = readable_bytes(sealed.nonce.storage);
    unsigned char empty{};
    auto const* message_bytes = message.empty() ? &empty : readable_bytes(message);
    auto const* sealed_bytes = message.empty() ? &empty : readable_bytes(sealed.ciphertext);
    auto* clear_bytes = message.empty() ? &empty : writable_bytes(clear);
    REQUIRE(raw_open(clear_bytes,
                     sealed_bytes,
                     readable_bytes(sealed.mac.storage),
                     message.size(),
                     nonce,
                     readable_bytes(sender.public_key.storage),
                     readable_bytes(recipient.secret_key.ref().bytes())) == 0);
    CHECK(clear == message);
    REQUIRE(raw_open_shared(clear_bytes, sealed_bytes, readable_bytes(sealed.mac.storage), message.size(), nonce, readable_bytes(receiving_key.ref().bytes())) == 0);
    CHECK(clear == message);

    auto shared_seal = seal_detached(sending_key, message, sealed.nonce);
    CHECK(shared_seal.ciphertext == sealed.ciphertext);
    CHECK(shared_seal.mac.storage == sealed.mac.storage);
    std::vector<std::byte> native_ciphertext(message.size());
    auto* native_out = message.empty() ? &empty : writable_bytes(native_ciphertext);
    mac_buffer<A> native_mac;
    REQUIRE(raw_seal(native_out,
                     writable_bytes(native_mac.storage),
                     message_bytes,
                     message.size(),
                     nonce,
                     readable_bytes(recipient.public_key.storage),
                     readable_bytes(sender.secret_key.ref().bytes())) == 0);
    CHECK(native_ciphertext == sealed.ciphertext);
    CHECK(native_mac.storage == sealed.mac.storage);
    open_detached_into(receiving_key, native_ciphertext, native_mac, clear, sealed.nonce);
    CHECK(clear == message);
    REQUIRE(raw_seal_shared(native_out, writable_bytes(native_mac.storage), message_bytes, message.size(), nonce, readable_bytes(sending_key.ref().bytes())) == 0);
    open_detached_into(recipient.secret_key, sender.public_key, native_ciphertext, native_mac, clear, sealed.nonce);
    CHECK(clear == message);

    auto into = seal_detached_into(sender.secret_key, recipient.public_key, message, native_ciphertext);
    auto verified = open_detached(receiving_key, native_ciphertext, into.mac, into.nonce);
    CHECK(std::ranges::equal(verified.bytes(), message));
    auto shared_into = seal_detached_into(sending_key, message, native_ciphertext);
    verified = open_detached(recipient.secret_key, sender.public_key, native_ciphertext, shared_into.mac, shared_into.nonce);
    CHECK(std::ranges::equal(verified.bytes(), message));

    auto combined = seal(sender.secret_key, recipient.public_key, message, sealed.nonce);
    CHECK(std::ranges::equal(std::span{combined}.first(algorithm_traits<A>::mac_size), sealed.mac.storage));
    CHECK(std::ranges::equal(std::span{combined}.subspan(algorithm_traits<A>::mac_size), sealed.ciphertext));

    sealed.mac.storage.front() ^= std::byte{1};
    CHECK(open_detached_into(recipient.secret_key, sender.public_key, sealed.ciphertext, sealed.mac, clear, sealed.nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_THROWS_AS(open_detached(receiving_key, sealed.ciphertext, sealed.mac, sealed.nonce), crypto_error);
    public_key<A> invalid;
    CHECK(seal_detached(sender.secret_key, invalid, message, std::nothrow) == std::unexpected(errc::crypto_failed));
}

TEMPLATE_TEST_CASE("Anonymous sealed boxes interoperate with native seal functions", "[box][interop]", curve25519xsalsa20poly1305, curve25519xchacha20poly1305)
{
    using A = TestType;
    constexpr bool xsalsa = std::same_as<A, curve25519xsalsa20poly1305>;
    constexpr auto raw_seal = xsalsa ? crypto_box_seal : crypto_box_curve25519xchacha20poly1305_seal;
    constexpr auto raw_open = xsalsa ? crypto_box_seal_open : crypto_box_curve25519xchacha20poly1305_seal_open;
    constexpr auto overhead = algorithm_traits<A>::sealed_overhead;
    keypair<A> recipient;
    std::vector<std::byte> message;
    SECTION("empty") {}
    SECTION("binary")
    {
        message = {std::byte{0x80}, std::byte{}, std::byte{0xff}};
    }

    auto sealed = seal_anonymous(recipient.public_key, message);
    REQUIRE(sealed.size() == message.size() + overhead);
    std::vector<std::byte> clear(message.size());
    unsigned char empty{};
    auto* clear_bytes = message.empty() ? &empty : writable_bytes(clear);
    auto const* message_bytes = message.empty() ? &empty : readable_bytes(message);
    REQUIRE(raw_open(clear_bytes, readable_bytes(sealed), sealed.size(), readable_bytes(recipient.public_key.storage), readable_bytes(recipient.secret_key.ref().bytes())) == 0);
    CHECK(clear == message);
    REQUIRE(raw_seal(writable_bytes(sealed), message_bytes, message.size(), readable_bytes(recipient.public_key.storage)) == 0);
    auto opened = open_anonymous(recipient.secret_key, recipient.public_key, sealed);
    CHECK(std::ranges::equal(opened.bytes(), message));
    seal_anonymous_into(recipient.public_key, message, sealed);
    open_anonymous_into(recipient.secret_key, recipient.public_key, sealed, clear);
    CHECK(clear == message);

    keypair<A> other;
    CHECK(open_anonymous(other.secret_key, other.public_key, sealed, std::nothrow) == std::unexpected(errc::crypto_failed));
    sealed.back() ^= std::byte{1};
    CHECK_THROWS_AS(open_anonymous(recipient.secret_key, recipient.public_key, sealed), crypto_error);
    CHECK(open_anonymous_into(recipient.secret_key, recipient.public_key, std::span{sealed}.first(overhead - 1), clear, std::nothrow) == std::unexpected(errc::crypto_failed));
    public_key<A> invalid;
    CHECK(seal_anonymous(invalid, message, std::nothrow) == std::unexpected(errc::crypto_failed));
}
