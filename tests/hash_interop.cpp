// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
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
    CHECK(std::move(*stream).finalize() == one_shot);

    stream->reset(key);
    stream->update(message);
    key.writable_bytes()[0] ^= std::byte{1};
    CHECK(std::move(*stream).finalize() == one_shot);

    stream->reset(key);
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
