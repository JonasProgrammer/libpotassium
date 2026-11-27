// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import potassium.aead;
import potassium.box;
import potassium.secretbox;
import std;

namespace
{
using namespace potassium;
using aead::aegis128l;
using aead::aegis256;
using aead::aes256gcm;
using aead::chacha20poly1305;
using aead::chacha20poly1305_ietf;
using aead::xchacha20poly1305_ietf;
using bytes = std::span<std::byte const>;
using writable_bytes = std::span<std::byte>;

template <class A>
concept GeneratesNonce = requires { generate_nonce<A>(); };

template <class K, bool Enabled>
consteval bool check_generated_overloads()
{
    static_assert(requires(K& key, bytes msg, bytes ad) { aead::seal(key, msg, ad); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad) { aead::seal(key, msg, ad, std::nothrow); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad, writable_bytes out) { aead::seal_into(key, msg, ad, out); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad, writable_bytes out) { aead::seal_into(key, msg, ad, out, std::nothrow); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad) { aead::seal_detached(key, msg, ad); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad) { aead::seal_detached(key, msg, ad, std::nothrow); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad, writable_bytes out) { aead::seal_detached_into(key, msg, ad, out); } == Enabled);
    static_assert(requires(K& key, bytes msg, bytes ad, writable_bytes out) { aead::seal_detached_into(key, msg, ad, out, std::nothrow); } == Enabled);
    return true;
}

template <class K, class M, class N>
concept OpensDetached = requires(K&& key, bytes packet, bytes ad, M const& mac, N& nonce) {
    { aead::open_detached(std::forward<K>(key), packet, ad, mac, nonce, std::nothrow) } noexcept -> std::same_as<std::expected<secure_buffer, errc>>;
};

template <class A, class Other>
consteval bool check_algorithm_types()
{
    static_assert(OpensDetached<key_ref<A>, mac_buffer<A>, nonce_buffer<A>>);
    static_assert(OpensDetached<secret_key<A>&, mac_buffer<A>, nonce_buffer<A>>);
    static_assert(OpensDetached<key_buffer_storage<A> const&, mac_buffer<A>, nonce_buffer<A>>);
    static_assert(!OpensDetached<secret_key<A>, mac_buffer<A>, nonce_buffer<A>>);
    static_assert(!OpensDetached<key_buffer_storage<A>, mac_buffer<A>, nonce_buffer<A>>);
    static_assert(!OpensDetached<secret_key<Other>&, mac_buffer<A>, nonce_buffer<A>>);
    static_assert(!OpensDetached<secret_key<A>&, mac_buffer<Other>, nonce_buffer<A>>);
    static_assert(!OpensDetached<secret_key<A>&, mac_buffer<A>, nonce_buffer<Other>>);
    return true;
}

static_assert(std::same_as<aead::default_algorithm, xchacha20poly1305_ietf>);
static_assert(!GeneratesNonce<chacha20poly1305>);
static_assert(!GeneratesNonce<chacha20poly1305_ietf>);
static_assert(GeneratesNonce<xchacha20poly1305_ietf>);
static_assert(GeneratesNonce<aegis128l>);
static_assert(GeneratesNonce<aegis256>);
static_assert(!GeneratesNonce<aes256gcm>);
static_assert(GeneratesNonce<box::box_default>);
static_assert(GeneratesNonce<box::curve25519xchacha20poly1305>);
static_assert(GeneratesNonce<secretbox::secretbox_default>);
static_assert(GeneratesNonce<secretbox::xchacha20poly1305>);
static_assert(check_generated_overloads<secret_key<chacha20poly1305>, false>());
static_assert(check_generated_overloads<secret_key<chacha20poly1305_ietf>, false>());
static_assert(check_generated_overloads<secret_key<xchacha20poly1305_ietf>, true>());
static_assert(check_generated_overloads<secret_key<aegis128l>, true>());
static_assert(check_generated_overloads<secret_key<aegis256>, true>());
static_assert(check_generated_overloads<secret_key<aes256gcm>, false>());
static_assert(check_generated_overloads<aead::aes256gcm_precomputed, false>());
static_assert(check_algorithm_types<chacha20poly1305, chacha20poly1305_ietf>());
static_assert(check_algorithm_types<chacha20poly1305_ietf, xchacha20poly1305_ietf>());
static_assert(check_algorithm_types<xchacha20poly1305_ietf, chacha20poly1305>());
static_assert(check_algorithm_types<xchacha20poly1305_ietf, secretbox::xchacha20poly1305>());
static_assert(check_algorithm_types<aegis128l, aegis256>());
static_assert(check_algorithm_types<aegis256, xchacha20poly1305_ietf>());
static_assert(check_algorithm_types<aes256gcm, chacha20poly1305_ietf>());
static_assert(OpensDetached<aead::aes256gcm_precomputed const&, mac_buffer<aes256gcm>, nonce_buffer<aes256gcm>>);
static_assert(!OpensDetached<aead::aes256gcm_precomputed, mac_buffer<aes256gcm>, nonce_buffer<aes256gcm>>);
static_assert(!OpensDetached<aead::aes256gcm_precomputed&, mac_buffer<chacha20poly1305_ietf>, nonce_buffer<aes256gcm>>);
static_assert(!OpensDetached<aead::aes256gcm_precomputed&, mac_buffer<aes256gcm>, nonce_buffer<chacha20poly1305_ietf>>);
static_assert(!std::copy_constructible<aead::aes256gcm_precomputed>);
static_assert(!std::move_constructible<aead::aes256gcm_inplace_state>);

template <class A>
struct native;

template <>
struct native<chacha20poly1305>
{
    static constexpr auto encrypt = crypto_aead_chacha20poly1305_encrypt;
    static constexpr auto decrypt = crypto_aead_chacha20poly1305_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_chacha20poly1305_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_chacha20poly1305_decrypt_detached;
};

template <>
struct native<chacha20poly1305_ietf>
{
    static constexpr auto encrypt = crypto_aead_chacha20poly1305_ietf_encrypt;
    static constexpr auto decrypt = crypto_aead_chacha20poly1305_ietf_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_chacha20poly1305_ietf_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_chacha20poly1305_ietf_decrypt_detached;
};

template <>
struct native<xchacha20poly1305_ietf>
{
    static constexpr auto encrypt = crypto_aead_xchacha20poly1305_ietf_encrypt;
    static constexpr auto decrypt = crypto_aead_xchacha20poly1305_ietf_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
};

template <>
struct native<aegis128l>
{
    static constexpr auto encrypt = crypto_aead_aegis128l_encrypt;
    static constexpr auto decrypt = crypto_aead_aegis128l_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_aegis128l_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_aegis128l_decrypt_detached;
};

template <>
struct native<aegis256>
{
    static constexpr auto encrypt = crypto_aead_aegis256_encrypt;
    static constexpr auto decrypt = crypto_aead_aegis256_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_aegis256_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_aegis256_decrypt_detached;
};

template <>
struct native<aes256gcm>
{
    static constexpr auto encrypt = crypto_aead_aes256gcm_encrypt;
    static constexpr auto decrypt = crypto_aead_aes256gcm_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_aes256gcm_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_aes256gcm_decrypt_detached;
};

auto native_bytes(bytes data)
{
    return reinterpret_cast<unsigned char const*>(data.data());
}
}  // namespace

TEMPLATE_TEST_CASE("AEAD interoperates with libsodium", "[aead][interop]", chacha20poly1305, chacha20poly1305_ietf, xchacha20poly1305_ietf, aegis128l, aegis256, aes256gcm)
{
    using A = TestType;
    if constexpr (std::same_as<A, aes256gcm>)
        if (!aead::aes256gcm_available()) SKIP("AES256-GCM requires hardware support");
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    key_buffer_storage<A> key;
    auto key_bytes = native_bytes(key.ref().bytes());
    std::array<unsigned char, 257> input;
    std::iota(input.begin(), input.end(), 0x20u);
    std::array<unsigned char, 5> metadata{0x11, 0, 0xff, 0x3e, 0x05};
    std::array<std::byte, algorithm_traits<A>::nonce_size> nonce_bits{};
    unsigned char nonce_counter{};
    std::array<unsigned char, input.size()> clear{};
    std::array<unsigned char, input.size() + mac_size> native_combined{};
    std::array<unsigned char, input.size()> native_detached{};
    std::array<unsigned char, mac_size> native_mac{};

    for (auto length : {0u, 1u, 63u, 64u, 65u, 257u})
    {
        for (auto ad_length : {std::size_t{0}, metadata.size()})
        {
            CAPTURE(length, ad_length);
            auto message = std::span{input}.first(length);
            auto ad = std::span{metadata}.first(ad_length);
            nonce_bits.back() = std::byte{++nonce_counter};
            nonce_buffer<A> nonce{nonce_bits};
            auto nonce_bytes = native_bytes(nonce.ref().bytes());

            // Reuse the fixture nonce only to compare identical key, message and AD tuples across APIs.
            unsigned long long combined_length{};
            REQUIRE(native<A>::encrypt(native_combined.data(), &combined_length, message.data(), length, ad.data(), ad_length, nullptr, nonce_bytes, key_bytes) == 0);
            REQUIRE(combined_length == length + mac_size);
            auto combined_wire = std::as_bytes(std::span{native_combined}.first(combined_length));

            unsigned long long mac_length{};
            REQUIRE(native<A>::encrypt_detached(native_detached.data(), native_mac.data(), &mac_length, message.data(), length, ad.data(), ad_length, nullptr, nonce_bytes, key_bytes) == 0);
            REQUIRE(mac_length == mac_size);
            auto detached_wire = std::as_bytes(std::span{native_detached}.first(length));
            mac_buffer<A> mac{};
            std::ranges::copy(std::as_bytes(std::span{native_mac}), mac.bytes().begin());
            CHECK(std::ranges::equal(combined_wire.first(length), detached_wire));
            CHECK(std::ranges::equal(combined_wire.last(mac_size), mac.bytes()));

            auto associated = ad.empty() ? bytes{} : std::as_bytes(ad);
            auto recovered = aead::open(key, combined_wire, associated, nonce, std::nothrow);
            REQUIRE(recovered);
            CHECK(std::ranges::equal(recovered->bytes(), std::as_bytes(message)));
            auto detached_clear = aead::open_detached(key, detached_wire, associated, mac, nonce);
            CHECK(std::ranges::equal(detached_clear.bytes(), std::as_bytes(message)));
            auto out = std::span{clear}.first(length);
            std::ranges::fill(out, 0x55);
            aead::open_into(key, combined_wire, associated, std::as_writable_bytes(out), nonce);
            CHECK(std::ranges::equal(out, message));
            std::ranges::fill(out, 0x55);
            REQUIRE(aead::open_detached_into(key, detached_wire, associated, mac, std::as_writable_bytes(out), nonce, std::nothrow));
            CHECK(std::ranges::equal(out, message));

            auto check_native_combined = [&](bytes ciphertext, nonce_buffer<A> const& packet_nonce)
            {
                REQUIRE(ciphertext.size() == length + mac_size);
                std::ranges::fill(out, 0x55);
                unsigned long long opened_length{};
                REQUIRE(native<A>::decrypt(
                                out.data(), &opened_length, nullptr, native_bytes(ciphertext), ciphertext.size(), ad.data(), ad_length, native_bytes(packet_nonce.ref().bytes()), key_bytes) == 0);
                CHECK(opened_length == length);
                CHECK(std::ranges::equal(out, message));
            };
            auto check_native_detached = [&](bytes ciphertext, mac_buffer<A> const& packet_mac, nonce_buffer<A> const& packet_nonce)
            {
                REQUIRE(ciphertext.size() == length);
                unsigned char empty{};
                auto ciphertext_bytes = ciphertext.empty() ? &empty : native_bytes(ciphertext);
                std::ranges::fill(out, 0x55);
                REQUIRE(native<A>::decrypt_detached(out.data(),
                                                    nullptr,
                                                    ciphertext_bytes,
                                                    ciphertext.size(),
                                                    native_bytes(packet_mac.bytes()),
                                                    ad.data(),
                                                    ad_length,
                                                    native_bytes(packet_nonce.ref().bytes()),
                                                    key_bytes) == 0);
                CHECK(std::ranges::equal(out, message));
            };

            auto plaintext = message.empty() ? bytes{} : std::as_bytes(message);
            auto combined = aead::seal(key, plaintext, associated, nonce);
            CHECK(std::ranges::equal(combined, combined_wire));
            check_native_combined(combined, nonce);

            std::vector<std::byte> combined_out(length + mac_size);
            REQUIRE(aead::seal_into(key, plaintext, associated, combined_out, nonce, std::nothrow));
            CHECK(std::ranges::equal(combined_out, combined_wire));
            check_native_combined(combined_out, nonce);

            auto detached = aead::seal_detached(key, plaintext, associated, nonce, std::nothrow);
            REQUIRE(detached);
            CHECK(std::ranges::equal(detached->ciphertext, detached_wire));
            CHECK(std::ranges::equal(detached->mac.bytes(), mac.bytes()));
            check_native_detached(detached->ciphertext, detached->mac, nonce);

            std::vector<std::byte> detached_out(length);
            auto detached_mac = aead::seal_detached_into(key, plaintext, associated, detached_out, nonce);
            CHECK(std::ranges::equal(detached_out, detached_wire));
            CHECK(std::ranges::equal(detached_mac.bytes(), mac.bytes()));
            check_native_detached(detached_out, detached_mac, nonce);

            if constexpr (RandomNonceAlgorithm<A>)
            {
                auto generated_combined = aead::seal(key, plaintext, associated, std::nothrow);
                REQUIRE(generated_combined);
                check_native_combined(generated_combined->ciphertext, generated_combined->nonce);
                auto reopened = aead::open(key, *generated_combined, associated);
                CHECK(std::ranges::equal(reopened.bytes(), plaintext));

                auto generated_nonce = aead::seal_into(key, plaintext, associated, combined_out);
                check_native_combined(combined_out, generated_nonce);

                auto [ciphertext, tag, generated_detached_nonce] = aead::seal_detached(key, plaintext, associated);
                check_native_detached(ciphertext, tag, generated_detached_nonce);

                auto generated_detached = aead::seal_detached_into(key, plaintext, associated, detached_out, std::nothrow);
                REQUIRE(generated_detached);
                check_native_detached(detached_out, generated_detached->mac, generated_detached->nonce);
            }
        }
    }
}

TEMPLATE_TEST_CASE("AEAD rejects unauthenticated inputs", "[aead]", chacha20poly1305, chacha20poly1305_ietf, xchacha20poly1305_ietf, aegis128l, aegis256, aes256gcm)
{
    using A = TestType;
    if constexpr (std::same_as<A, aes256gcm>)
        if (!aead::aes256gcm_available()) SKIP("AES256-GCM requires hardware support");
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    secret_key<A> key;
    secret_key<A> wrong_key;
    std::array message{std::byte{0x42}, std::byte{0x1b}, std::byte{0xff}};
    std::array ad{std::byte{0x30}, std::byte{0}, std::byte{0x09}};
    std::array<std::byte, algorithm_traits<A>::nonce_size> nonce_bits{};
    nonce_buffer<A> combined_nonce{nonce_bits};
    nonce_bits.back() = std::byte{1};
    nonce_buffer<A> detached_nonce{nonce_bits};
    nonce_bits.back() = std::byte{2};
    nonce_buffer<A> wrong_nonce{nonce_bits};

    auto combined = aead::seal(key, message, ad, combined_nonce);
    auto detached = aead::seal_detached(key, message, ad, detached_nonce);
    std::array<std::byte, message.size()> output;
    auto no_plaintext = [&](std::byte value)
    {
        return !std::ranges::contains(message, value);
    };

    auto check_combined_failure = [&](key_ref<A> key, bytes ciphertext, bytes ad, nonce_buffer<A> const& nonce)
    {
        CHECK(aead::open(key, ciphertext, ad, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        std::ranges::fill(output, std::byte{0x55});
        auto out = std::span{output}.first(ciphertext.size() >= mac_size ? ciphertext.size() - mac_size : 0);
        CHECK_THROWS_AS(aead::open_into(key, ciphertext, ad, out, nonce), crypto_error);
        CHECK(std::ranges::all_of(output, no_plaintext));
    };
    auto check_detached_failure = [&](key_ref<A> key, bytes ciphertext, bytes ad, mac_buffer<A> const& mac, nonce_buffer<A> const& nonce)
    {
        CHECK_THROWS_AS(aead::open_detached(key, ciphertext, ad, mac, nonce), crypto_error);
        std::ranges::fill(output, std::byte{0x55});
        auto out = std::span{output}.first(ciphertext.size());
        CHECK(aead::open_detached_into(key, ciphertext, ad, mac, out, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(std::ranges::all_of(output, no_plaintext));
    };

    check_combined_failure(wrong_key, combined, ad, combined_nonce);
    check_combined_failure(key, combined, {}, combined_nonce);
    check_combined_failure(key, combined, ad, wrong_nonce);
    check_combined_failure(key, std::span{combined}.first(mac_size - 1), ad, combined_nonce);
    check_combined_failure(key, std::span{combined}.first(combined.size() - 1), ad, combined_nonce);
    combined.back() ^= std::byte{1};
    check_combined_failure(key, combined, ad, combined_nonce);

    check_detached_failure(wrong_key, detached.ciphertext, ad, detached.mac, detached_nonce);
    check_detached_failure(key, detached.ciphertext, {}, detached.mac, detached_nonce);
    check_detached_failure(key, detached.ciphertext, ad, detached.mac, wrong_nonce);
    check_detached_failure(key, {}, ad, detached.mac, detached_nonce);
    auto tampered_mac = detached.mac;
    tampered_mac.storage.front() ^= std::byte{1};
    check_detached_failure(key, detached.ciphertext, ad, tampered_mac, detached_nonce);
    detached.ciphertext.front() ^= std::byte{1};
    check_detached_failure(key, detached.ciphertext, ad, detached.mac, detached_nonce);
}

TEST_CASE("AES256-GCM reports runtime support and rejects unsupported operations", "[aead][aes256gcm]")
{
    REQUIRE(aead::aes256gcm_available() == (crypto_aead_aes256gcm_is_available() != 0));
    if (!aead::aes256gcm_available())
    {
        key_buffer_storage<aes256gcm> key;
        std::array<std::byte, algorithm_traits<aes256gcm>::nonce_size> nonce_bits{};
        nonce_buffer<aes256gcm> nonce{nonce_bits};
        std::array<std::byte, algorithm_traits<aes256gcm>::mac_size> ciphertext{};
        mac_buffer<aes256gcm> mac{};
        aead::aes256gcm_inplace_state inplace;
        aead::aes256gcm_state_storage storage{inplace.get()};

        CHECK(aead::seal_into(key, {}, {}, ciphertext, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::open_into(key, ciphertext, {}, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::seal_detached_into(key, {}, {}, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::open_detached_into(key, {}, {}, mac, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::seal(key, {}, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::open(key, ciphertext, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::seal_detached(key, {}, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::open_detached(key, {}, {}, mac, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(aead::precompute_into(key, std::move(storage), std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK(storage);
        CHECK(aead::precompute(key, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK_THROWS_AS(aead::precompute(key), crypto_error);
    }
}

TEST_CASE("AES256-GCM precomputed operations match the direct wire format", "[aead][aes256gcm][interop]")
{
    if (!aead::aes256gcm_available()) SKIP("AES256-GCM requires hardware support");
    key_buffer_storage<aes256gcm> key;
    auto schedule = aead::precompute(key, std::nothrow);
    REQUIRE(schedule);
    auto const& precomputed = *schedule;
    std::array message{std::byte{0x42}, std::byte{0}, std::byte{0xff}};
    std::array ad{std::byte{0x30}, std::byte{0}, std::byte{0x09}};
    std::array<std::byte, algorithm_traits<aes256gcm>::nonce_size> nonce_bits{};
    unsigned char nonce_counter{};
    for (auto plaintext : {bytes{}, bytes{message}})
    {
        for (auto associated : {bytes{}, bytes{ad}})
        {
            CAPTURE(plaintext.size(), associated.size());
            nonce_bits.back() = std::byte{++nonce_counter};
            nonce_buffer<aes256gcm> nonce{nonce_bits};

            // Compare direct and precomputed encryption with the same fixture inputs.
            auto combined = aead::seal(key, plaintext, associated, nonce);
            CHECK(aead::seal(precomputed, plaintext, associated, nonce) == combined);
            auto combined_out = combined;
            std::ranges::fill(combined_out, std::byte{});
            REQUIRE(aead::seal_into(precomputed, plaintext, associated, combined_out, nonce, std::nothrow));
            CHECK(combined_out == combined);

            auto detached = aead::seal_detached(precomputed, plaintext, associated, nonce, std::nothrow);
            REQUIRE(detached);
            CHECK(std::ranges::equal(detached->ciphertext, std::span{combined}.first(plaintext.size())));
            CHECK(std::ranges::equal(detached->mac.bytes(), std::span{combined}.last(algorithm_traits<aes256gcm>::mac_size)));
            std::array<std::byte, message.size()> buffer{};
            auto out = plaintext.empty() ? writable_bytes{} : writable_bytes{buffer}.first(plaintext.size());
            auto tag = aead::seal_detached_into(precomputed, plaintext, associated, out, nonce);
            CHECK(std::ranges::equal(tag.bytes(), detached->mac.bytes()));
            CHECK(std::ranges::equal(out, detached->ciphertext));

            auto clear = aead::open(precomputed, combined, associated, nonce);
            CHECK(std::ranges::equal(clear.bytes(), plaintext));
            aead::open_into(precomputed, combined, associated, out, nonce);
            CHECK(std::ranges::equal(out, plaintext));
            auto detached_clear = aead::open_detached(precomputed, detached->ciphertext, associated, detached->mac, nonce);
            CHECK(std::ranges::equal(detached_clear.bytes(), plaintext));
            REQUIRE(aead::open_detached_into(precomputed, detached->ciphertext, associated, detached->mac, out, nonce, std::nothrow));
            CHECK(std::ranges::equal(out, plaintext));

            combined.back() ^= std::byte{1};
            CHECK(aead::open(precomputed, combined, associated, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
            detached->mac.bytes().front() ^= std::byte{1};
            CHECK_THROWS_AS(aead::open_detached_into(precomputed, detached->ciphertext, associated, detached->mac, out, nonce), crypto_error);
        }
    }
}

TEST_CASE("AES256-GCM precomputed state is wiped and reused", "[aead][aes256gcm]")
{
    if (!aead::aes256gcm_available()) SKIP("AES256-GCM requires hardware support");
    key_buffer_storage<aes256gcm> key;
    key_buffer_storage<aes256gcm> new_key;
    std::array<std::byte, algorithm_traits<aes256gcm>::nonce_size> nonce_bits{};
    nonce_buffer<aes256gcm> nonce{nonce_bits};
    std::array<std::byte, algorithm_traits<aes256gcm>::mac_size> ciphertext{}, new_ciphertext{};

    aead::aes256gcm_inplace_state inplace;
    aead::aes256gcm_state_type custom{};
    auto inline_bytes = std::as_writable_bytes(std::span{&inplace.get(), 1});
    auto custom_bytes = std::as_writable_bytes(std::span{&custom, 1});
    auto is_wiped = [](bytes state)
    {
        return std::ranges::all_of(state, [](std::byte value) { return value == std::byte{}; });
    };
    std::ranges::fill(custom_bytes, std::byte{0xaa});
    aead::aes256gcm_state_storage borrowed{custom};
    CHECK(is_wiped(custom_bytes));

    {
        auto first = aead::precompute_into(key, aead::aes256gcm_state_storage{inplace.get()});
        CHECK_FALSE(is_wiped(inline_bytes));
        REQUIRE(aead::seal_into(first, {}, {}, ciphertext, nonce, std::nothrow));
        auto transferred = std::move(first);
        CHECK_FALSE(first);
        CHECK(transferred);
        CHECK_FALSE(std::move(first).close_for_reuse());
        CHECK(aead::open_into(first, ciphertext, {}, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));

        auto idle = std::move(transferred).close_for_reuse();
        CHECK(is_wiped(inline_bytes));
        CHECK_FALSE(transferred);
        CHECK(idle);
        auto second = aead::precompute_into(new_key, std::move(idle));
        CHECK_FALSE(idle);
        CHECK(aead::precompute_into(key, std::move(idle), std::nothrow) == std::unexpected(errc::crypto_failed));
        REQUIRE(aead::seal_into(second, {}, {}, new_ciphertext, nonce, std::nothrow));
        CHECK(new_ciphertext != ciphertext);
        CHECK(aead::open_into(second, ciphertext, {}, {}, nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        REQUIRE(aead::open_into(second, new_ciphertext, {}, {}, nonce, std::nothrow));
        CHECK_FALSE(is_wiped(inline_bytes));

        auto custom_schedule = aead::precompute_into(new_key, std::move(borrowed));
        CHECK_FALSE(is_wiped(custom_bytes));
        second = std::move(custom_schedule);
        CHECK(is_wiped(inline_bytes));
        CHECK_FALSE(custom_schedule);
        REQUIRE(aead::open_into(second, new_ciphertext, {}, {}, nonce, std::nothrow));
    }
    CHECK(is_wiped(custom_bytes));
    auto guarded = aead::precompute(new_key);
    auto idle = std::move(guarded).close_for_reuse();
    CHECK_FALSE(guarded);
    CHECK(idle);
    auto reused = aead::precompute_into(key, std::move(idle));
    aead::open_into(reused, ciphertext, {}, {}, nonce);
}
