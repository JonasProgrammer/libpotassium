// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_test_macros.hpp>

import potassium.sign;
import std;

using namespace potassium;
namespace signatures = potassium::sign;

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

bool erased(signatures::state_type const& state)
{
    return std::ranges::all_of(std::as_bytes(std::span{&state, 1}), [](auto b) { return b == std::byte{}; });
}
}  // namespace

TEST_CASE("Ed25519 seeded key pairs and key extraction match libsodium", "[sign][keys][interop]")
{
    static_assert(!std::copy_constructible<signatures::keypair>);
    static_assert(!std::default_initializable<secret_key<signatures::signing_key_tag>>);
    static_assert(!std::is_convertible_v<signatures::signature, signatures::prehash_signature>);

    key_buffer_storage<signatures::seed_tag> seed{zero};
    seed.writable_bytes().front() = std::byte{0xd5};
    public_key<signatures::ed25519> native_public;
    key_buffer_storage<signatures::signing_key_tag> native_secret{for_overwrite};
    REQUIRE(crypto_sign_seed_keypair(writable_bytes(native_public.storage), writable_bytes(native_secret.writable_bytes()), readable_bytes(seed.ref().bytes())) == 0);

    auto seeded_pair = signatures::generate_keypair(seed);
    CHECK(seeded_pair.public_key.storage == native_public.storage);
    CHECK(std::ranges::equal(seeded_pair.secret_key.ref().bytes(), native_secret.ref().bytes()));
    public_key<signatures::ed25519> pub;
    key_buffer_storage<signatures::signing_key_tag> secret{for_overwrite};
    signatures::generate_keypair_into(pub, secret, seed);
    CHECK(pub.storage == native_public.storage);
    CHECK(std::ranges::equal(secret.ref().bytes(), native_secret.ref().bytes()));

    auto extracted_seed = signatures::seed_from_secret_key(secret);
    CHECK(std::ranges::equal(extracted_seed.ref().bytes(), seed.ref().bytes()));
    key_buffer_storage<signatures::seed_tag> seed_destination{for_overwrite};
    signatures::seed_from_secret_key_into(seeded_pair.secret_key, seed_destination);
    CHECK(std::ranges::equal(seed_destination.ref().bytes(), seed.ref().bytes()));
    CHECK(signatures::public_key_from_secret_key(seeded_pair.secret_key).storage == seeded_pair.public_key.storage);

    auto random_pair = signatures::generate_keypair(std::nothrow);
    REQUIRE(random_pair);
    CHECK(signatures::public_key_from_secret_key(random_pair->secret_key).storage == random_pair->public_key.storage);
    signatures::generate_keypair_into(pub, secret);
    CHECK(signatures::public_key_from_secret_key(secret).storage == pub.storage);
}

TEST_CASE("Ed25519 signed messages and detached signatures interoperate with libsodium", "[sign][interop]")
{
    signatures::keypair pair;
    std::vector<std::byte> message;
    SECTION("empty") {}
    SECTION("binary")
    {
        message = {std::byte{0xff}, std::byte{0x80}, std::byte{}, std::byte{1}};
    }

    unsigned char empty{};
    auto const* native_message = message.empty() ? &empty : readable_bytes(message);
    auto signed_message = signatures::sign(pair.secret_key, message);
    REQUIRE(signed_message.size() == message.size() + crypto_sign_BYTES);
    std::vector<std::byte> clear(message.size());
    auto* native_clear = message.empty() ? &empty : writable_bytes(clear);
    REQUIRE(crypto_sign_open(native_clear, nullptr, readable_bytes(signed_message), signed_message.size(), readable_bytes(pair.public_key.storage)) == 0);
    CHECK(clear == message);

    std::vector<std::byte> native_signed(signed_message.size());
    REQUIRE(crypto_sign(writable_bytes(native_signed), nullptr, native_message, message.size(), readable_bytes(pair.secret_key.ref().bytes())) == 0);
    auto opened = signatures::open(pair.public_key, native_signed);
    CHECK(std::ranges::equal(opened.bytes(), message));
    signatures::sign_into(pair.secret_key, message, signed_message);
    signatures::open_into(pair.public_key, signed_message, clear);
    CHECK(clear == message);

    auto detached = signatures::sign_detached(pair.secret_key, message);
    REQUIRE(crypto_sign_verify_detached(readable_bytes(detached.storage), native_message, message.size(), readable_bytes(pair.public_key.storage)) == 0);
    signatures::signature native_detached;
    REQUIRE(crypto_sign_detached(writable_bytes(native_detached.storage), nullptr, native_message, message.size(), readable_bytes(pair.secret_key.ref().bytes())) == 0);
    CHECK(signatures::verify_detached(pair.public_key, message, native_detached, std::nothrow).has_value());

    detached.storage.front() ^= std::byte{1};
    CHECK(signatures::verify_detached(pair.public_key, message, detached, std::nothrow) == std::unexpected(errc::crypto_failed));
    signatures::keypair other;
    CHECK_THROWS_AS(signatures::verify_detached(other.public_key, message, native_detached), crypto_error);

    signed_message.front() ^= std::byte{1};
    CHECK(signatures::open_into(pair.public_key, signed_message, clear, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_THROWS_AS(signatures::open(other.public_key, native_signed), crypto_error);
    auto truncated = std::span{native_signed}.first(crypto_sign_BYTES - 1);
    CHECK(signatures::open_into(pair.public_key, truncated, clear, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(signatures::open(pair.public_key, truncated, std::nothrow) == std::unexpected(errc::crypto_failed));
}

TEST_CASE("Ed25519ph interoperates with native multipart signing and verification", "[sign][interop]")
{
    signatures::keypair pair;
    constexpr std::array message{std::byte{0xff}, std::byte{0x80}, std::byte{}, std::byte{1}};
    auto signer = signatures::start_prehash();
    signer.update(std::span{message}.first(1));
    signer.update({});
    signer.update(std::span{message}.subspan(1));
    auto sig = signer.finish_sign(pair.secret_key);
    CHECK(signer.update({}, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(signer.finish_sign(pair.secret_key, std::nothrow) == std::unexpected(errc::crypto_failed));

    crypto_sign_state native{};
    REQUIRE(crypto_sign_init(&native) == 0);
    REQUIRE(crypto_sign_update(&native, readable_bytes(message), message.size()) == 0);
    REQUIRE(crypto_sign_final_verify(&native, readable_bytes(sig.storage), readable_bytes(pair.public_key.storage)) == 0);

    signatures::prehash_signature native_sig;
    REQUIRE(crypto_sign_init(&native) == 0);
    REQUIRE(crypto_sign_update(&native, readable_bytes(message), message.size()) == 0);
    REQUIRE(crypto_sign_final_create(&native, writable_bytes(native_sig.storage), nullptr, readable_bytes(pair.secret_key.ref().bytes())) == 0);

    auto verifier = signatures::start_prehash(std::move(signer).close_for_reuse());
    verifier.update(std::span{message}.first(3));
    verifier.update(std::span{message}.last(1));
    CHECK(verifier.finish_verify(pair.public_key, native_sig, std::nothrow).has_value());

    signatures::signature wrong_mode{native_sig.storage};
    CHECK_THROWS_AS(signatures::verify_detached(pair.public_key, message, wrong_mode), crypto_error);
    auto one_shot = signatures::sign_detached(pair.secret_key, message);
    auto verify_one_shot = signatures::start_prehash();
    verify_one_shot.update(message);
    CHECK_THROWS_AS(verify_one_shot.finish_verify(pair.public_key, signatures::prehash_signature{one_shot.storage}), crypto_error);
}

TEST_CASE("Ed25519ph wipes borrowed state on signing, verification, abandonment and move assignment", "[sign][state]")
{
    signatures::keypair pair;
    signatures::inplace_state inline_storage;
    signatures::state_type custom_storage;
    auto& first = inline_storage.get();
    std::ranges::fill(std::as_writable_bytes(std::span{&custom_storage, 1}), std::byte{0xff});
    signatures::state_storage supplied{custom_storage};
    CHECK(erased(custom_storage));

    constexpr std::array message{std::byte{0x80}, std::byte{0xff}};
    auto signer = signatures::start_prehash(signatures::state_storage{first});
    signer.update(message);
    auto sig = signer.finish_sign(pair.secret_key);
    CHECK(erased(first));

    auto verify_success = signatures::start_prehash(std::move(signer).close_for_reuse());
    verify_success.update(message);
    verify_success.finish_verify(pair.public_key, sig);
    CHECK(erased(first));

    auto verify_failure = signatures::start_prehash(std::move(verify_success).close_for_reuse());
    verify_failure.update(message);
    sig.storage.front() ^= std::byte{1};
    CHECK(verify_failure.finish_verify(pair.public_key, sig, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(erased(first));
    CHECK(verify_failure.update(message, std::nothrow) == std::unexpected(errc::crypto_failed));

    auto reuse = std::move(verify_failure).close_for_reuse();
    auto old = signatures::start_prehash(std::move(reuse));
    CHECK(signatures::start_prehash(std::move(reuse), std::nothrow) == std::unexpected(errc::crypto_failed));
    old.update(message);
    {
        auto replacement = signatures::start_prehash(std::move(supplied));
        replacement.update(message);
        old = std::move(replacement);
        CHECK(erased(first));
        CHECK(replacement.update(message, std::nothrow) == std::unexpected(errc::crypto_failed));
    }
    CHECK_FALSE(erased(custom_storage));
    auto after_close = std::move(old).close_for_reuse();
    CHECK(erased(custom_storage));
    CHECK_FALSE(std::move(old).close_for_reuse());

    {
        auto abandoned = signatures::start_prehash(std::move(after_close));
        abandoned.update(message);
    }
    CHECK(erased(custom_storage));
}
