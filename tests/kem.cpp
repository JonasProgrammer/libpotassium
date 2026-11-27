// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_test_macros.hpp>

import potassium.kem;
import std;

using namespace potassium;

namespace
{
auto writable_bytes(auto&& range)
{
    return reinterpret_cast<unsigned char*>(range.data());
}

auto readable_bytes(auto const& range)
{
    return reinterpret_cast<unsigned char const*>(range.data());
}

bool erased(key_ref<kem::shared_secret_tag> secret)
{
    return std::ranges::all_of(secret.bytes(), [](auto b) { return b == std::byte{}; });
}
}  // namespace

TEST_CASE("X-Wing seeded key pairs match libsodium", "[kem][keys][interop]")
{
    static_assert(!std::copy_constructible<kem::keypair>);
    static_assert(!std::default_initializable<secret_key<kem::decapsulation_key_tag>>);
    static_assert(!std::convertible_to<key_ref<kem::decapsulation_key_tag>, key_ref<kem::shared_secret_tag>>);

    key_buffer_storage<kem::seed_tag> seed{zero};
    seed.writable_bytes().front() = std::byte{0xa9};
    public_key<kem::xwing> native_pub;
    key_buffer_storage<kem::decapsulation_key_tag> native_secret{for_overwrite};
    REQUIRE(crypto_kem_seed_keypair(writable_bytes(native_pub.storage), writable_bytes(native_secret.writable_bytes()), readable_bytes(seed.ref().bytes())) == 0);
    auto pair = kem::generate_keypair(seed);
    CHECK(pair.public_key.storage == native_pub.storage);
    CHECK(std::ranges::equal(pair.secret_key.ref().bytes(), native_secret.ref().bytes()));

    public_key<kem::xwing> pub;
    key_buffer_storage<kem::decapsulation_key_tag> secret{for_overwrite};
    REQUIRE(kem::generate_keypair_into(pub, secret, seed, std::nothrow).has_value());
    CHECK(pub.storage == native_pub.storage);
    CHECK(std::ranges::equal(secret.ref().bytes(), native_secret.ref().bytes()));
}

TEST_CASE("X-Wing interoperates with native encapsulation and decapsulation", "[kem][interop]")
{
    auto pair = kem::generate_keypair(std::nothrow);
    REQUIRE(pair);
    auto sent = kem::encapsulate(pair->public_key);
    key_buffer_storage<kem::shared_secret_tag> native_secret{for_overwrite};
    REQUIRE(crypto_kem_dec(writable_bytes(native_secret.writable_bytes()), readable_bytes(sent.ciphertext.storage), readable_bytes(pair->secret_key.ref().bytes())) == 0);
    CHECK(std::ranges::equal(sent.shared_secret.ref().bytes(), native_secret.ref().bytes()));

    public_key<kem::xwing> pub;
    key_buffer_storage<kem::decapsulation_key_tag> private_key{for_overwrite};
    kem::generate_keypair_into(pub, private_key);
    kem::ciphertext_buffer ciphertext;
    REQUIRE(crypto_kem_enc(writable_bytes(ciphertext.storage), writable_bytes(native_secret.writable_bytes()), readable_bytes(pub.storage)) == 0);
    auto received = kem::decapsulate(private_key, ciphertext.bytes());
    CHECK(std::ranges::equal(received.ref().bytes(), native_secret.ref().bytes()));

    key_buffer_storage<kem::shared_secret_tag> sent_secret{for_overwrite};
    key_buffer_storage<kem::shared_secret_tag> received_secret{for_overwrite};
    kem::encapsulate_into(pub, ciphertext, sent_secret);
    kem::decapsulate_into(private_key, ciphertext.bytes(), received_secret);
    CHECK(std::ranges::equal(sent_secret.ref().bytes(), received_secret.ref().bytes()));
}

TEST_CASE("X-Wing preserves implicit rejection and reports explicit failures", "[kem][interop]")
{
    kem::keypair pair;
    auto sent = kem::encapsulate(pair.public_key);
    key_buffer_storage<kem::shared_secret_tag> native_secret{for_overwrite};
    key_buffer_storage<kem::shared_secret_tag> received_secret{for_overwrite};
    auto& ciphertext = sent.ciphertext;
    SECTION("malformed ML-KEM component yields the native fallback secret")
    {
        ciphertext.storage.front() ^= std::byte{1};
        REQUIRE(crypto_kem_dec(writable_bytes(native_secret.writable_bytes()), readable_bytes(ciphertext.storage), readable_bytes(pair.secret_key.ref().bytes())) == 0);
        REQUIRE(kem::decapsulate_into(pair.secret_key, ciphertext.bytes(), received_secret, std::nothrow).has_value());
        CHECK(std::ranges::equal(received_secret.ref().bytes(), native_secret.ref().bytes()));
        CHECK_FALSE(std::ranges::equal(sent.shared_secret.ref().bytes(), received_secret.ref().bytes()));
    }

    SECTION("low-order X25519 component is explicitly rejected")
    {
        std::ranges::fill(ciphertext.bytes().last(crypto_scalarmult_curve25519_BYTES), std::byte{});
        CHECK(crypto_kem_dec(writable_bytes(native_secret.writable_bytes()), readable_bytes(ciphertext.storage), readable_bytes(pair.secret_key.ref().bytes())) != 0);
        std::ranges::fill(received_secret.writable_bytes(), std::byte{0xa5});
        CHECK(kem::decapsulate_into(pair.secret_key, ciphertext.bytes(), received_secret, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(erased(received_secret));
        CHECK_THROWS_AS(kem::decapsulate(pair.secret_key, ciphertext.bytes()), crypto_error);
    }

    SECTION("wrong wire length is rejected before the backend call")
    {
        auto truncated = ciphertext.bytes().first(ciphertext.bytes().size() - 1);
        std::ranges::fill(received_secret.writable_bytes(), std::byte{0xa5});
        CHECK(kem::decapsulate_into(pair.secret_key, truncated, received_secret, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(erased(received_secret));
        CHECK(kem::decapsulate(pair.secret_key, truncated, std::nothrow) == std::unexpected(errc::crypto_failed));
    }

    SECTION("low-order X25519 recipient public key is rejected")
    {
        auto invalid_public = pair.public_key;
        std::ranges::fill(std::span{invalid_public.storage}.last(crypto_scalarmult_curve25519_BYTES), std::byte{});
        std::ranges::fill(received_secret.writable_bytes(), std::byte{0xa5});
        CHECK(kem::encapsulate_into(invalid_public, ciphertext, received_secret, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(erased(received_secret));
        CHECK_THROWS_AS(kem::encapsulate(invalid_public), crypto_error);
    }
}
