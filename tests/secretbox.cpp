// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
import potassium;
import std;
using namespace potassium;
using namespace potassium::secretbox;
static_assert(std::same_as<secretbox_default, xsalsa20poly1305>);
static_assert(!std::convertible_to<secret_key<secretbox_default>&&, key_ref<secretbox_default>>);

TEMPLATE_TEST_CASE("SecretBox key construction writes into the selected storage",
                   "[secretbox][keys]",
                   secret_key<xsalsa20poly1305>,
                   secret_key<xchacha20poly1305>,
                   key_buffer_storage<xsalsa20poly1305>,
                   key_buffer_storage<xchacha20poly1305>)
{
    using output = decltype(std::declval<TestType&>().writable_bytes());
    static_assert(!std::constructible_from<TestType, int (*)(output)>);
    static_assert(!std::constructible_from<TestType, void (*)(std::span<std::byte, 16>)>);

    TestType zeroed{zero};
    CHECK(std::ranges::all_of(zeroed.ref().bytes(), [](auto b) { return b == std::byte{}; }));

    TestType imported{for_overwrite};
    std::ranges::fill(imported.writable_bytes(), std::byte{0xa5});
    unsigned calls{};
    std::byte* destination{};
    auto generate = [&](output out)
    {
        ++calls;
        destination = out.data();
        std::ranges::copy(imported.ref().bytes(), out.begin());
    };
    TestType generated{generate};
    CHECK(calls == 1);
    CHECK(destination == generated.ref().bytes().data());
    CHECK(std::ranges::equal(generated.ref().bytes(), imported.ref().bytes()));

    auto fail = [](output out)
    {
        out.front() = std::byte{1};
        throw crypto_error{};
    };
    CHECK_THROWS_AS(TestType{fail}, crypto_error);
}

TEMPLATE_TEST_CASE("SecretBox authenticates a message", "[secretbox]", xsalsa20poly1305, xchacha20poly1305)
{
    auto generated = make_secret_key<TestType>(std::nothrow);
    REQUIRE(generated.has_value());
    auto& key = *generated;
    std::array message{std::byte{0x42}};
    auto sealed = seal(key, message);
    CHECK(sealed.ciphertext.size() == message.size() + algorithm_traits<TestType>::mac_size);
    auto clear = open(key, sealed);
    CHECK(std::ranges::equal(clear.bytes(), message));
    std::array<std::byte, algorithm_traits<TestType>::mac_size> invalid{};
    for (auto length : {std::size_t{0}, invalid.size() - 1, invalid.size()})
    {
        auto ciphertext = std::span{invalid}.first(length);
        CHECK(open_into(key, ciphertext, {}, sealed.nonce, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK_THROWS_AS(open(key, ciphertext, sealed.nonce), crypto_error);
    }
    auto truncated = open(key, std::span<std::byte const>{}, sealed.nonce, std::nothrow);
    REQUIRE_FALSE(truncated.has_value());
    CHECK(truncated.error() == errc::crypto_failed);
    sealed.ciphertext.front() ^= std::byte{1};
    auto failed = open(key, sealed, std::nothrow);
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error() == errc::crypto_failed);
}

namespace
{
template <std::size_t N>
consteval auto hex_bytes(char const (&hex)[N])
{
    static_assert((N - 1) % 2 == 0);
    auto digit = [](char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw "Invalid hex digit in test vector";
    };
    std::array<std::byte, (N - 1) / 2> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::byte>(16 * digit(hex[2 * i]) + digit(hex[2 * i + 1]));
    return bytes;
}

template <class A>
void check_vector(key_ref<A> key, nonce_ref<A> nonce, std::span<std::byte const> plaintext, std::span<std::byte const> ciphertext)
{
    std::vector<std::byte> sealed(ciphertext.size());
    seal_into(key, plaintext, sealed, nonce);
    CHECK(std::ranges::equal(sealed, ciphertext));

    auto opened = open(key, ciphertext, nonce);
    CHECK(std::ranges::equal(opened.bytes(), plaintext));

    static_assert(!std::default_initializable<nonce_buffer<A>>);
    auto wrong_nonce = nonce_buffer<A>{nonce.bytes()};
    wrong_nonce.storage.back() ^= std::byte{1};
    CHECK_THROWS_AS(open(key, ciphertext, wrong_nonce), crypto_error);

    auto corrupted = sealed;
    corrupted.front() ^= std::byte{1};
    auto failed = open_into(key, corrupted, opened.bytes(), nonce, std::nothrow);
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error() == errc::crypto_failed);
}
}  // namespace

// Known answers from libsodium revision 7614ada615839697b4c176796f2f83eda004eb5b.
// test/default/secretbox.c and secretbox.exp use the NaCl padded API.
// The combined-mode fixture omits its 32 plaintext and 16 ciphertext padding bytes.
TEST_CASE("XSalsa20-Poly1305 matches the NaCl SecretBox vector", "[secretbox][vectors]")
{
    constexpr auto key = hex_bytes("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
    constexpr auto nonce = hex_bytes("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
    constexpr auto message = hex_bytes(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
            "5e0705");
    constexpr auto ciphertext = hex_bytes(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce"
            "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972"
            "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae"
            "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3"
            "7973f622a43d14a6599b1f654cb45a74e355a5");
    check_vector<xsalsa20poly1305>(key_ref<xsalsa20poly1305>{key}, nonce_ref<xsalsa20poly1305>{nonce}, message, ciphertext);
}

// test/default/xchacha20.c, tv_secretbox_xchacha20 vectors 0, 6 and 1.
TEST_CASE("XChaCha20-Poly1305 matches the empty SecretBox vector", "[secretbox][vectors]")
{
    constexpr auto key = hex_bytes("065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34");
    constexpr auto nonce = hex_bytes("f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5");
    constexpr auto message = hex_bytes("");
    constexpr auto ciphertext = hex_bytes("4c72340416339dcdea01b760db5adaf7");
    check_vector<xchacha20poly1305>(key_ref<xchacha20poly1305>{key}, nonce_ref<xchacha20poly1305>{nonce}, message, ciphertext);
}

TEST_CASE("XChaCha20-Poly1305 matches the short SecretBox vector", "[secretbox][vectors]")
{
    constexpr auto key = hex_bytes("10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189");
    constexpr auto nonce = hex_bytes("977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5");
    constexpr auto message = hex_bytes("518e4a27949812424b2a381c3efea6055ee5e75eff");
    constexpr auto ciphertext = hex_bytes(
            "0c801a037c2ed0500d6ef68e8d195eceb05a15f8edb68b35773e81ac2aca18e9"
            "be53416f9a");
    check_vector<xchacha20poly1305>(key_ref<xchacha20poly1305>{key}, nonce_ref<xchacha20poly1305>{nonce}, message, ciphertext);
}

TEST_CASE("XChaCha20-Poly1305 matches the multi-block SecretBox vector", "[secretbox][vectors]")
{
    constexpr auto key = hex_bytes("d3c71d54e6b13506e07aa2e7b412a17a7a1f34df3d3148cd3f45b91ccaa5f4d9");
    constexpr auto nonce = hex_bytes("943b454a853aa514c63cf99b1e197bbb99da24b2e2d93e47");
    constexpr auto message = hex_bytes(
            "76bd706e07741e713d90efdb34ad202067263f984942aae8bda159f30dfccc72"
            "200f8093520b85c5ad124ff7c8b2d920946e5cfff4b819abf84c7b35a6205ca7"
            "2c9f8747c3044dd73fb4bebda1b476");
    constexpr auto ciphertext = hex_bytes(
            "0384276f1cfa5c82c3e58f0f2acc1f821c6f526d2c19557cf8bd270fcde43fba"
            "1d88890663f7b2f5c6b1d7deccf5c91b4df5865dc55cc7e04d6793fc2db8f9e3"
            "b418f95cb796d67a7f3f7e097150cb607c435dacf82eac3d669866e5092ace");
    check_vector<xchacha20poly1305>(key_ref<xchacha20poly1305>{key}, nonce_ref<xchacha20poly1305>{nonce}, message, ciphertext);
}
