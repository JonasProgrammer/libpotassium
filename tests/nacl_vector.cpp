// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

export module potassium.tests.nacl_vector;

import std;

export namespace test_vectors
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

// libsodium test/default/box.c, box2.c and box.exp.
// Omit the legacy API's 32 plaintext and 16 ciphertext padding bytes.
namespace nacl
{
inline constexpr auto alice_secret = hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
inline constexpr auto alice_public = hex_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
inline constexpr auto bob_secret = hex_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
inline constexpr auto bob_public = hex_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
inline constexpr auto shared_key = hex_bytes("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
inline constexpr auto nonce = hex_bytes("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
inline constexpr auto message = hex_bytes(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
        "5e0705");
inline constexpr auto ciphertext = hex_bytes(
        "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce"
        "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972"
        "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae"
        "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3"
        "7973f622a43d14a6599b1f654cb45a74e355a5");
}  // namespace nacl
}  // namespace test_vectors
