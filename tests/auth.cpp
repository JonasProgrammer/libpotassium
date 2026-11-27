// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import potassium.auth;
import std;

namespace
{
namespace auth = potassium::auth;

template <class Key>
concept can_authenticate_default = requires(Key key) { auth::authenticate(key, {}); };

template <class Stream>
concept can_finalize_lvalue = requires(Stream& stream) { stream.finalize(); };

using default_stream = potassium::hash::keyed_hasher<auth::default_algorithm>;
using sha256_key_ref = potassium::key_ref<auth::hmac_key_tag<auth::hmac_sha256>>;
static_assert(!can_authenticate_default<sha256_key_ref>);
static_assert(!std::same_as<auth::tag_buffer<>, auth::tag_buffer<auth::hmac_sha256>>);
static_assert(!std::is_copy_constructible_v<default_stream>);
static_assert(std::is_nothrow_move_constructible_v<default_stream>);
static_assert(std::is_nothrow_move_assignable_v<default_stream>);
static_assert(!can_finalize_lvalue<default_stream>);

namespace h = potassium::hash;

template <class A>
constexpr bool simple_only = h::SimpleDigest<A> && !h::KeyedDigest<A> && h::SimpleHasher<h::hasher<A>>;

template <class A>
constexpr bool keyed_only = !h::SimpleDigest<A> && h::KeyedDigest<A> && h::KeyedHasher<h::keyed_hasher<A>>;

static_assert(simple_only<h::sha256> && simple_only<h::sha512> && simple_only<h::sha3_256> && simple_only<h::sha3_512>);
static_assert(keyed_only<auth::hmac_sha256> && keyed_only<auth::hmac_sha512> && keyed_only<auth::hmac_sha512256>);
static_assert(h::SimpleDigest<h::blake2b<>> && h::KeyedDigest<h::blake2b<>>);
static_assert(h::SimpleHasher<h::hasher<h::blake2b<>>> && h::KeyedHasher<h::keyed_hasher<h::blake2b<>>>);
static_assert(!h::SimpleHasher<default_stream> && !h::KeyedHasher<h::hasher<h::blake2b<>>>);
static_assert(!std::default_initializable<default_stream> && !std::constructible_from<default_stream, sha256_key_ref>);

template <class S>
concept keyless_reset = requires(S& stream) { stream.reset(); } || requires(S& stream, typename S::token_type token) { stream.reset(std::move(token)); };

template <class Left, class Right>
concept comparable_tags = requires(Left left, Right right) { left == right; };

static_assert(!keyless_reset<default_stream>);
static_assert(!comparable_tags<auth::tag_buffer<>, auth::tag_buffer<auth::hmac_sha256>>);
static_assert(!comparable_tags<auth::tag_buffer<>, h::digest_buffer<h::sha256>>);

template <h::Hasher S>
auto finish_message(S& stream, std::span<std::byte const> message)
{
    stream.update(message);
    return std::move(stream).finalize();
}

template <h::SimpleHasher S>
auto restart(S& stream, typename S::token_type token)
{
    stream.reset(std::move(token));
}

template <h::KeyedHasher S>
auto restart(S& stream, typename S::key_type key, typename S::token_type token)
{
    stream.reset(key, std::move(token));
}

template <class A>
auto reference_authenticate()
{
    if constexpr (std::same_as<A, auth::hmac_sha256>)
        return crypto_auth_hmacsha256;
    else if constexpr (std::same_as<A, auth::hmac_sha512>)
        return crypto_auth_hmacsha512;
    else
        return crypto_auth_hmacsha512256;
}

template <class State, class Init, class Update, class Final>
void reference_stream(Init init, Update update, Final final, std::span<unsigned char const> key, std::span<unsigned char const> message, std::span<unsigned char> tag)
{
    State state;
    REQUIRE(init(&state, key.data(), key.size()) == 0);
    REQUIRE(update(&state, message.data(), message.size()) == 0);
    REQUIRE(final(&state, tag.data()) == 0);
}

template <class A>
void reference_stream(std::span<unsigned char const> key, std::span<unsigned char const> message, std::span<unsigned char> tag)
{
    if constexpr (std::same_as<A, auth::hmac_sha256>)
        reference_stream<crypto_auth_hmacsha256_state>(crypto_auth_hmacsha256_init, crypto_auth_hmacsha256_update, crypto_auth_hmacsha256_final, key, message, tag);
    else if constexpr (std::same_as<A, auth::hmac_sha512>)
        reference_stream<crypto_auth_hmacsha512_state>(crypto_auth_hmacsha512_init, crypto_auth_hmacsha512_update, crypto_auth_hmacsha512_final, key, message, tag);
    else
        reference_stream<crypto_auth_hmacsha512256_state>(crypto_auth_hmacsha512256_init, crypto_auth_hmacsha512256_update, crypto_auth_hmacsha512256_final, key, message, tag);
}
}  // namespace

TEMPLATE_TEST_CASE("One-shot HMAC interoperates with libsodium and rejects mismatches", "[auth][interop]", auth::hmac_sha256, auth::hmac_sha512, auth::hmac_sha512256)
{
    using A = TestType;
    using key_tag = auth::hmac_key_tag<A>;
    std::array<unsigned char, auth::auth_traits<A>::key_size> key_bytes;
    std::ranges::iota(key_bytes, 0u);
    potassium::key_ref<key_tag> key{std::as_bytes(std::span{key_bytes})};
    std::array<unsigned char, 257> input;
    std::ranges::iota(input, 1u);
    auto const message = std::as_bytes(std::span{input});
    auto const compute = reference_authenticate<A>();

    std::array<unsigned char, auth::auth_traits<A>::tag_size> reference;
    REQUIRE(compute(reference.data(), input.data(), input.size(), key_bytes.data()) == 0);
    auto const tag = auth::authenticate<A>(key, message);
    static_assert(decltype(tag.bytes())::extent == auth::auth_traits<A>::tag_size);
    CHECK(std::ranges::equal(tag.bytes(), std::as_bytes(std::span{reference})));

    auth::tag_buffer<A> out;
    auth::authenticate_into<A>(key, message, out.storage);
    CHECK(out == tag);
    auth::authenticate_into<A>(key, {}, out.storage);
    REQUIRE(compute(reference.data(), input.data(), 0, key_bytes.data()) == 0);
    CHECK(std::ranges::equal(out.bytes(), std::as_bytes(std::span{reference})));
    CHECK(auth::verify<A>(key, {}, out.bytes(), std::nothrow).has_value());

    CHECK(auth::verify<A>(key, message, tag.bytes(), std::nothrow).has_value());
    CHECK_NOTHROW(auth::verify<A>(key, message, tag.bytes()));

    auto changed_tag = tag;
    changed_tag.storage.back() ^= std::byte{1};
    CHECK(changed_tag != tag);
    changed_tag = tag;
    changed_tag.storage.front() ^= std::byte{1};
    CHECK(changed_tag != tag);
    auto const failure = std::unexpected(potassium::errc::crypto_failed);
    CHECK(auth::verify<A>(key, message, changed_tag.bytes(), std::nothrow) == failure);
    CHECK_THROWS_AS(auth::verify<A>(key, message, changed_tag.bytes()), potassium::crypto_error);
    CHECK(auth::verify<A>(key, message.first(message.size() - 1), tag.bytes(), std::nothrow) == failure);
    CHECK_THROWS_AS(auth::verify<A>(key, message.first(message.size() - 1), tag.bytes()), potassium::crypto_error);
    key_bytes.front() ^= 1;
    CHECK(auth::verify<A>(key, message, tag.bytes(), std::nothrow) == failure);
    CHECK_THROWS_AS(auth::verify<A>(key, message, tag.bytes()), potassium::crypto_error);
}

TEMPLATE_TEST_CASE("Guarded HMAC streams support chunked input and arbitrary key lengths", "[auth][interop]", auth::hmac_sha256, auth::hmac_sha512, auth::hmac_sha512256)
{
    using A = TestType;
    using stream_type = h::keyed_hasher<A>;
    std::array<unsigned char, 257> input;
    std::ranges::iota(input, 2u);

    for (auto length : {0u, 13u, 32u, 257u})
    {
        CAPTURE(length);
        std::array<unsigned char, 257> key_bytes;
        std::ranges::iota(key_bytes, 3u);
        auto const key = length == 0 ? std::span<unsigned char const>{} : std::span<unsigned char const>{key_bytes}.first(length);
        auto const message = std::as_bytes(std::span{input});
        std::array<unsigned char, auth::auth_traits<A>::tag_size> reference;
        reference_stream<A>(key, input, reference);

        auto result = stream_type::create(std::as_bytes(key), std::nothrow);
        REQUIRE(result.has_value());
        using storage = h::inplace_hash_state<typename h::keyed_hash_traits<A>::state_type>;
        using inline_stream = h::keyed_hasher<A, storage>;
        static_assert(h::KeyedHasher<inline_stream> && !std::move_constructible<inline_stream>);
        auto inplace = inline_stream::create(std::as_bytes(key), std::nothrow);
        REQUIRE(inplace.has_value());
        key_bytes.front() ^= 1;
        result->update({});
        result->update(message.first(127));
        auto moved = std::move(*result);
        auto stream = stream_type::create({});
        stream.update(message.first(1));
        stream = std::move(moved);
        stream.update(message.subspan(127));
        auto const tag = std::move(stream).finalize();
        CHECK(std::ranges::equal(tag.bytes(), std::as_bytes(std::span{reference})));

        inplace->update(message.first(128));
        CHECK(finish_message(*inplace, message.subspan(128)) == tag);

        reference_stream<A>(key, std::span{input}.first(0), reference);
        auto const empty_tag = stream_type::create(std::as_bytes(key)).finalize();
        CHECK(std::ranges::equal(empty_tag.bytes(), std::as_bytes(std::span{reference})));
        auto reused = inline_stream::create({});
        for (int i = 0; i < 3; ++i)
        {
            reused.update(message);
            reused.reset(std::as_bytes(key));
            auto [actual, token] = std::move(reused).finalize_for_reuse();
            CHECK(actual == empty_tag);
            reused.reset(std::as_bytes(key), std::move(token));
        }
    }
}

TEST_CASE("Default authentication interoperates with crypto_auth and truncates HMAC-SHA-512", "[auth][interop]")
{
    auto const key = potassium::make_secret_key<auth::hmac_key_tag<>>(std::nothrow);
    REQUIRE(key.has_value());
    auto const message = std::as_bytes(std::span{std::string_view{"message"}});
    auto const tag = auth::authenticate(*key, message);
    auth::tag_buffer<> direct;
    auth::authenticate_into(*key, message, direct.storage);
    CHECK(direct.storage == tag.storage);

    auto const* sodium_message = reinterpret_cast<unsigned char const*>(message.data());
    auto const* sodium_key = reinterpret_cast<unsigned char const*>(key->ref().bytes().data());
    std::array<unsigned char, crypto_auth_BYTES> reference;
    REQUIRE(crypto_auth(reference.data(), sodium_message, message.size(), sodium_key) == 0);
    CHECK(std::ranges::equal(tag.bytes(), std::as_bytes(std::span{reference})));
    CHECK(crypto_auth_verify(reinterpret_cast<unsigned char const*>(tag.bytes().data()), sodium_message, message.size(), sodium_key) == 0);
    CHECK_NOTHROW(auth::verify(*key, message, std::as_bytes(std::span{reference})));

    potassium::key_ref<auth::hmac_key_tag<auth::hmac_sha512>> full_key{key->ref().bytes()};
    auto const full_tag = auth::authenticate<auth::hmac_sha512>(full_key, message);
    CHECK(std::ranges::equal(tag.bytes(), full_tag.bytes().first<crypto_auth_BYTES>()));
}

TEST_CASE("Generic digest consumers restart simple and keyed streams", "[auth][hash][reset]")
{
    h::hasher<h::sha256> simple;
    auto [digest, simple_token] = std::move(simple).finalize_for_reuse();
    restart(simple, std::move(simple_token));
    CHECK(finish_message(simple, {}) == digest);

    potassium::key_buffer_storage<auth::hmac_key_tag<>> first;
    potassium::key_buffer_storage<auth::hmac_key_tag<>> second;
    default_stream stream(first);
    auto owner = std::move(stream);
    owner.update(first.ref().bytes());
    auto [tag, token] = default_stream(second).finalize_for_reuse();
    restart(stream, second.ref(), std::move(token));
    CHECK(finish_message(stream, {}) == tag);
    CHECK(finish_message(owner, {}) == auth::authenticate(first, first.ref().bytes()));
}
