// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import potassium;
import std;

namespace
{
namespace h = potassium::hash;

using default_hash = h::default_algorithm;

template <class Key>
concept accepted = requires(Key k) { h::hash<default_hash>(k, {}); };

static_assert(!accepted<potassium::secretbox::xsalsa_key_ref>);
static_assert(!accepted<potassium::key_ref<potassium::box::private_key_tag<potassium::box::box_default>>>);

template <std::size_t K>
void check_key(std::string_view expected)
{
    CAPTURE(K);

    potassium::key_buffer_storage<h::blake2b_key_tag<K>> key;
    for (std::size_t i = 0; i < K; ++i) key.writable_bytes()[i] = static_cast<std::byte>(i);

    std::array<unsigned char, 256> data;
    std::iota(data.begin(), data.end(), 0u);
    auto message = std::as_bytes(std::span{data});

    unsigned char reference[32];
    REQUIRE(crypto_generichash_blake2b(reference, sizeof(reference), data.data(), data.size(), reinterpret_cast<unsigned char const*>(key.ref().bytes().data()), K) == 0);

    char hex[65];
    CHECK(std::string_view{sodium_bin2hex(hex, sizeof(hex), reference, sizeof(reference))} == expected);

    auto one_shot = h::hash<default_hash>(key, message);
    CHECK(std::ranges::equal(one_shot.bytes(), std::as_bytes(std::span{reference})));

    static_assert(std::same_as<decltype(one_shot), h::tag_buffer<default_hash>>);
    static_assert(!std::convertible_to<h::digest_buffer<default_hash>, decltype(one_shot)>);
    h::tag_buffer<default_hash> output;
    h::hash_into<default_hash>(key.ref(), message, output.storage);
    CHECK(output == one_shot);

    auto stream = h::make_keyed_hasher<default_hash>(key, std::nothrow);
    REQUIRE(stream.has_value());

    stream->update(message.first(127));
    stream->update({});
    stream->update(message.subspan(127));
    auto [chunked, chunked_token] = std::move(*stream).finalize_for_reuse();
    CHECK(chunked == one_shot);

    stream->reset(key, std::move(chunked_token));
    stream->update(message);
    key.writable_bytes()[0] ^= std::byte{1};
    auto [whole, whole_token] = std::move(*stream).finalize_for_reuse();
    CHECK(whole == one_shot);

    stream->reset(key, std::move(whole_token));
    stream->update(message);

    stream->reset(key);
    CHECK(std::move(*stream).finalize() == h::hash<default_hash>(key, {}));
}
}  // namespace

TEST_CASE("Keyed BLAKE2b interoperates across key sizes", "[hash]")
{
    check_key<16>("443e4f4a491b01408563361c1b9be0aab534a8151571fe8e10459d9e5896bd20");
    check_key<32>("b42be36ea26392f67d1d3706ffa72b6c61c2ff38e1fabd9a49e154d54b967d83");
    check_key<64>("1ee3b6312b4e0f0b9663b812b8c129e6d45c410b1c9c5a1667bfc6dd951db79f");
}

TEMPLATE_TEST_CASE("Unkeyed hash streams match libsodium after repeated resets",
                   "[hash][interop][reset]",
                   h::sha256,
                   h::sha512,
                   h::sha3_256,
                   h::sha3_512,
                   h::blake2b<16>,
                   h::blake2b<32>,
                   h::blake2b<64>)
{
    using A = TestType;
    using state = h::hash_traits<A>::state_type;
    std::array<unsigned char, 257> input;
    std::iota(input.begin(), input.end(), 0u);
    h::hasher<A, h::guarded_hash_state<state>> stream;

    for (auto length : {0u, 55u, 56u, 63u, 64u, 71u, 72u, 73u, 111u, 112u, 127u, 128u, 129u, 135u, 136u, 137u, 257u})
    {
        CAPTURE(length);
        std::array<unsigned char, h::hash_traits<A>::digest_size> reference{};
        auto status = [&]
        {
            if constexpr (std::same_as<A, h::sha256>)
                return crypto_hash_sha256(reference.data(), input.data(), length);
            else if constexpr (std::same_as<A, h::sha512>)
                return crypto_hash_sha512(reference.data(), input.data(), length);
            else if constexpr (std::same_as<A, h::sha3_256>)
                return crypto_hash_sha3256(reference.data(), input.data(), length);
            else if constexpr (std::same_as<A, h::sha3_512>)
                return crypto_hash_sha3512(reference.data(), input.data(), length);
            else
                return crypto_generichash_blake2b(reference.data(), reference.size(), input.data(), length, nullptr, 0);
        }();
        REQUIRE(status == 0);

        auto message = std::as_bytes(std::span{input}).first(length);
        auto digest = h::hash<A>(message);
        CHECK(std::ranges::equal(digest.bytes(), std::as_bytes(std::span{reference})));

        stream.update(std::as_bytes(std::span{input}));
        stream.reset();
        for (auto& byte : message) stream.update(std::span{&byte, 1});
        auto [chunked, token] = std::move(stream).finalize_for_reuse();
        CHECK(std::ranges::equal(chunked.bytes(), std::as_bytes(std::span{reference})));
        stream.reset(std::move(token));
    }
}

TEMPLATE_TEST_CASE("Keyed BLAKE2b reuse switches key sizes and matches libsodium", "[hash][interop][reset]", h::blake2b<16>, h::blake2b<17>, h::blake2b<32>, h::blake2b<63>, h::blake2b<64>)
{
    using A = TestType;
    std::array<unsigned char, 16> short_key;
    std::array<unsigned char, 64> long_key;
    std::iota(short_key.begin(), short_key.end(), 0u);
    std::iota(long_key.begin(), long_key.end(), 0u);
    potassium::key_ref<h::blake2b_key_tag<16>> first{std::as_bytes(std::span{short_key})};
    potassium::key_ref<h::blake2b_key_tag<64>> second{std::as_bytes(std::span{long_key})};
    std::array<unsigned char, 255> input;
    std::iota(input.begin(), input.end(), 0u);

    h::keyed_hasher<A> stream(first);
    for (auto length : {0u, 1u, 127u, 128u, 129u, 255u})
    {
        CAPTURE(length);
        auto verify = [&](auto key, auto const& raw_key)
        {
            std::array<unsigned char, h::hash_traits<A>::digest_size> reference{};
            REQUIRE(crypto_generichash_blake2b(reference.data(), reference.size(), input.data(), length, raw_key.data(), raw_key.size()) == 0);
            auto message = std::as_bytes(std::span{input}).first(length);
            auto one_shot = h::hash<A>(key, message);
            CHECK(std::ranges::equal(one_shot.bytes(), std::as_bytes(std::span{reference})));

            auto split = std::min<std::size_t>(length, 128);
            stream.update(message.first(split));
            stream.update({});
            stream.update(message.subspan(split));
            auto [chunked, token] = std::move(stream).finalize_for_reuse();
            CHECK(std::ranges::equal(chunked.bytes(), std::as_bytes(std::span{reference})));
            return token;
        };

        stream.update(std::as_bytes(std::span{input}));
        stream.reset(second);
        stream.reset(first, verify(second, long_key));
        stream.reset(first, verify(first, short_key));
    }
}

TEST_CASE("Keyed BLAKE2b-512 matches the published empty and one-byte KATs", "[hash][vectors]")
{
    // BLAKE2/BLAKE2 testvectors/blake2b-kat.txt, BLAKE2b with a 64-byte sequential key.
    std::array<unsigned char, 64> key_bytes;
    std::iota(key_bytes.begin(), key_bytes.end(), 0u);
    potassium::key_ref<h::blake2b_key_tag<64>> key{std::as_bytes(std::span{key_bytes})};
    std::array<std::byte, 1> input{};
    constexpr std::array<std::string_view, 2> expected{
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b"
            "5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
            "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e41"
            "87b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"};
    for (std::size_t length = 0; length < expected.size(); ++length)
    {
        CAPTURE(length);
        auto tag = h::hash<h::blake2b<64>>(key, std::span{input}.first(length));
        std::array<char, 129> hex{};
        auto bytes = reinterpret_cast<unsigned char const*>(tag.bytes().data());
        CHECK(std::string_view{sodium_bin2hex(hex.data(), hex.size(), bytes, tag.bytes().size())} == expected[length]);
    }
}
