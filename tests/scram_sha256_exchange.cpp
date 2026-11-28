// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

import potassium.contrib;
import potassium.tests.nacl_vector;
import std;

namespace
{
namespace scram = potassium::contrib::scram_sha256;
using test_vectors::hex_bytes;
constexpr auto salt = hex_bytes("5b6d99689d12358eeca04b141236fa81");
constexpr std::string_view salt_attribute = ",s=W22ZaJ0SNY7soEsUEjb6gQ==";
constexpr std::uint32_t iterations = 4096;
constexpr auto failure = std::unexpected(potassium::errc::crypto_failed);
constexpr scram::mechanism_offer both{.sha256 = true, .sha256_plus = true};
constexpr auto exporter_bytes = hex_bytes("0001ff030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e2c");
constexpr scram::channel_binding exporter{"tls-exporter", exporter_bytes};

struct exchange_parameters
{
    std::string_view header;
    scram::client_negotiation client;
    scram::server_negotiation server;
};

constexpr exchange_parameters plain{.header = "n,,"};
constexpr exchange_parameters plus{
        .header = "p=tls-exporter,,",
        .client = {.offered = both, .binding = exporter, .require_channel_binding = true},
        .server = {.selected = scram::mechanism::sha256_plus, .advertised = both, .binding = exporter},
};

std::string_view nonce(std::string_view start)
{
    auto first = std::size_t{2};
    if (!start.starts_with("r="))
    {
        auto attribute = start.find(",r=");
        REQUIRE(attribute != std::string_view::npos);
        first = attribute + 3;
    }
    return start.substr(first, start.find(',', first) - first);
}

bool wiped(std::span<std::byte const> bytes)
{
    return std::ranges::all_of(bytes, [](std::byte byte) { return byte == std::byte{0}; });
}

std::string base64(std::span<std::byte const> bytes)
{
    constexpr auto variant = sodium_base64_VARIANT_ORIGINAL;
    std::string encoded(sodium_base64_encoded_len(bytes.size(), variant), '\0');
    sodium_bin2base64(encoded.data(), encoded.size(), reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size(), variant);
    encoded.pop_back();
    return encoded;
}

std::string encoded_binding(std::string_view header, std::optional<scram::channel_binding> binding)
{
    std::string input{header};
    if (binding) input.append(reinterpret_cast<char const*>(binding->data.data()), binding->data.size());
    return base64(std::as_bytes(std::span{input}));
}
}  // namespace

TEST_CASE("SCRAM exchanges authenticate both peers and reuse wiped caller storage", "[scram]")
{
    auto params = GENERATE(plain, plus);
    CAPTURE(scram::mechanism_name(params.server.selected));
    scram::client_exchange_storage client_storage{potassium::for_overwrite};
    scram::server_verifier_storage server_storage{potassium::for_overwrite};
    scram::client_exchange client{client_storage};
    scram::server_exchange server{server_storage};
    auto verifier = scram::make_server_verifier(u8"caf\u00e9", salt, iterations);

    auto first = client.start(std::u8string{u8"a,=\u00e9"}, params.client);
    CHECK(first.selected == params.server.selected);
    CHECK(first.message.starts_with(std::format("{}n=a=2C=3D\xc3\xa9,r=", params.header)));
    CHECK(server.receive_client_first(first.message, params.server) == "a,=\xc3\xa9");
    auto challenge = server.challenge(verifier, salt, iterations);
    CHECK(nonce(challenge).starts_with(nonce(first.message)));
    CHECK(nonce(challenge).size() > nonce(first.message).size());
    CHECK(std::ranges::equal(server_storage.ref().bytes(), verifier.ref().bytes()));

    auto proof = client.respond(std::u8string_view{}, u8"caf\u00e9", std::nothrow);
    CHECK(proof == failure);
    CHECK(wiped(client_storage.ref().bytes()));
    client.reset();
    server.reset();
    CHECK(wiped(server_storage.ref().bytes()));

    auto next_first = client.start(std::string_view{"a,=\xc3\xa9"}, params.client);
    CHECK(next_first.message != first.message);
    CHECK(server.receive_client_first(next_first.message, params.server) == "a,=\xc3\xa9");
    auto next_challenge = server.challenge(verifier, salt, iterations);
    auto utf8_challenge = std::u8string(next_challenge.begin(), next_challenge.end());
    auto final = client.respond(utf8_challenge, std::u8string_view{u8"caf\u00e9"});
    CHECK(final.starts_with(std::format("c={},r=", encoded_binding(params.header, params.client.binding))));
    auto signature = server.finish(final);
    CHECK(signature.starts_with("v="));
    CHECK(wiped(server_storage.ref().bytes()));
    CHECK_NOTHROW(client.finish(signature));
    CHECK(wiped(client_storage.ref().bytes()));
    CHECK(server.finish(final, std::nothrow) == failure);
    CHECK(client.finish(signature, std::nothrow) == failure);
}

TEST_CASE("SCRAM cached keys are bound to the challenge salt and iteration count", "[scram]")
{
    auto params = GENERATE(plain, plus);
    CAPTURE(scram::mechanism_name(params.server.selected));
    auto credentials = scram::derive_client_credentials("pencil", salt, iterations);
    auto verifier = scram::make_server_verifier(credentials);
    scram::cached_client_credentials cache{credentials, salt, iterations};
    scram::client_exchange client;
    scram::server_exchange server;

    CHECK(server.receive_client_first(client.start("user", params.client).message, params.server) == "user");
    auto challenge = server.challenge(verifier, salt, iterations);
    auto final = client.respond(challenge, cache);
    CHECK_NOTHROW(client.finish(server.finish(final)));

    client.reset();
    server.reset();
    CHECK(server.receive_client_first(client.start("user", params.client).message, params.server) == "user");
    auto other_salt = salt;
    other_salt[0] ^= std::byte{1};
    challenge = server.challenge(verifier, other_salt, iterations);
    CHECK(client.respond(challenge, cache, std::nothrow) == failure);
    CHECK(client.respond(challenge, "pencil", std::nothrow) == failure);

    client.reset();
    server.reset();
    CHECK(server.receive_client_first(client.start("user", params.client).message, params.server) == "user");
    challenge = server.challenge(verifier, salt, iterations + 1);
    CHECK(client.respond(challenge, cache, std::nothrow) == failure);
}

TEST_CASE("SCRAM clients reject malformed and excessive server challenges", "[scram]")
{
    auto params = GENERATE(plain, plus);
    CAPTURE(scram::mechanism_name(params.server.selected));
    scram::client_exchange client;
    for (auto invalid_count : {"0", "+4096", "04096", "4095", "1000001", "4294967296", "4096extra"})
    {
        CAPTURE(invalid_count);
        auto first = client.start("user", params.client);
        auto challenge = std::format("r={}extra{},i={}", nonce(first.message), salt_attribute, invalid_count);
        CHECK(client.respond(challenge, "pencil", std::nothrow) == failure);
        client.reset();
    }

    for (auto invalid_salt : {"AB==", "AWI", "AW I=", "", "===="})
    {
        CAPTURE(invalid_salt);
        auto first = client.start("user", params.client);
        auto challenge = std::format("r={}extra,s={},i=4096", nonce(first.message), invalid_salt);
        CHECK(client.respond(challenge, "pencil", std::nothrow) == failure);
        client.reset();
    }

    for (auto suffix : {",i=4096", ",m=required", ",x=", ","})
    {
        CAPTURE(suffix);
        auto first = client.start("user", params.client);
        auto challenge = std::format("r={}extra{},i=4096{}", nonce(first.message), salt_attribute, suffix);
        CHECK(client.respond(challenge, "pencil", std::nothrow) == failure);
        client.reset();
    }

    for (auto suffix : {" with-space", ""})
    {
        auto first = client.start("user", params.client);
        CHECK(client.respond(std::format("r={}{}{},i=4096", nonce(first.message), suffix, salt_attribute), "pencil", std::nothrow) == failure);
        client.reset();
    }
    static_cast<void>(client.start("user", params.client));
    CHECK(client.respond(std::format("r=wrong{},i=4096", salt_attribute), "pencil", std::nothrow) == failure);
    client.reset();
    auto first = client.start("user", params.client);
    auto oversized = std::format("r={}{}{},i=4096", nonce(first.message), std::string(scram::max_message_size, 'x'), salt_attribute);
    CHECK(client.respond(oversized, "pencil", std::nothrow) == failure);
}

TEST_CASE("SCRAM servers validate GS2 headers, escaped identities, and optional extensions", "[scram]")
{
    auto params = GENERATE(plain, plus);
    CAPTURE(scram::mechanism_name(params.server.selected));
    scram::server_exchange server;
    auto wrong_header = params.server.selected == scram::mechanism::sha256 ? plus.header : plain.header;
    CHECK(server.receive_client_first(std::format("{}n=user,r=a", wrong_header), params.server, std::nothrow) == failure);
    server.reset();
    auto alternate_identity = std::format("{}a=admin,n=user,r=a", params.header.substr(0, params.header.size() - 1));
    CHECK(server.receive_client_first(alternate_identity, params.server, std::nothrow) == failure);
    server.reset();

    for (auto invalid : {"n=a=3d,r=a", "n=\xc0\x80,r=a", "n=\xed\xa0\x80,r=a", "n=,r=a", "n=user,r=a b", "n=user,r=", "n=user,r=a,", "m=required,n=user,r=a", "n=user,r=a,r=b"})
    {
        CAPTURE(invalid);
        CHECK(server.receive_client_first(std::format("{}{}", params.header, invalid), params.server, std::nothrow) == failure);
        server.reset();
    }

    auto credentials = scram::derive_client_credentials("pencil", salt, iterations);
    auto verifier = scram::make_server_verifier(credentials);
    constexpr std::string_view bare = "n=a=2C=3D,r=external,x=optional,x=also-optional";
    auto header = params.server.selected == scram::mechanism::sha256 ? "y,," : params.header;
    auto first = std::format("{}{}", header, bare);
    CHECK(server.receive_client_first(first, params.server) == "a,=");
    auto challenge = server.challenge(verifier, salt, iterations);
    auto without_proof = std::format("c={},r={},z=optional", encoded_binding(header, params.server.binding), nonce(challenge));
    scram::auth_message transcript{bare, challenge, without_proof};
    auto proof = scram::make_client_proof(credentials, transcript);
    auto expected_signature = scram::authenticate_client(verifier, transcript, proof.bytes());
    CHECK(server.finish(without_proof + ",p=" + base64(proof.bytes())) == "v=" + base64(expected_signature.bytes()));
}

TEST_CASE("SCRAM exchanges reject replays, tampered messages, and out-of-order use", "[scram]")
{
    auto params = GENERATE(plain, plus);
    CAPTURE(scram::mechanism_name(params.server.selected));
    auto credentials = scram::derive_client_credentials("pencil", salt, iterations);
    auto verifier = scram::make_server_verifier(credentials);
    scram::client_exchange client;
    scram::server_exchange server;
    CHECK(client.finish("v=", std::nothrow) == failure);
    CHECK(client.start("user", params.client, std::nothrow) == failure);
    CHECK(server.challenge(verifier, salt, iterations, std::nothrow) == failure);
    client.reset();
    server.reset();

    auto first = client.start("user", params.client).message;
    CHECK(server.receive_client_first(first, params.server) == "user");
    auto challenge = server.challenge(verifier, salt, iterations);
    auto final = client.respond(challenge, "pencil");
    auto signature = server.finish(final);
    CHECK_NOTHROW(client.finish(signature + ",x=optional"));

    server.reset();
    CHECK(server.receive_client_first(first, params.server) == "user");
    CHECK(server.challenge(verifier, salt, iterations) != challenge);
    CHECK(server.finish(final, std::nothrow) == failure);
    client.reset();
    CHECK(client.start("user", params.client).message != first);
    CHECK(client.respond(challenge, "pencil", std::nothrow) == failure);

    for (std::string_view tamper : {"binding", "nonce", "proof", "proof encoding"})
    {
        CAPTURE(tamper);
        client.reset();
        server.reset();
        first = client.start("user", params.client).message;
        CHECK(server.receive_client_first(first, params.server) == "user");
        challenge = server.challenge(verifier, salt, iterations);
        final = client.respond(challenge, "pencil");
        std::string modified;
        if (tamper == "proof")
        {
            modified = final;
            auto proof_attribute = modified.find(",p=");
            REQUIRE(proof_attribute != std::string::npos);
            REQUIRE(proof_attribute + 3 < modified.size());
            auto& first_proof_byte = modified[proof_attribute + 3];
            first_proof_byte = first_proof_byte == 'A' ? 'B' : 'A';
        }
        else if (tamper == "proof encoding")
        {
            modified = final;
            REQUIRE_FALSE(modified.empty());
            modified.pop_back();
        }
        else
        {
            // A correct proof still fails if the nonce or GS2 binding is wrong.
            auto binding_field = std::string_view{final}.substr(0, final.find(",r="));
            auto altered_final = tamper == "binding" ? std::format("c=eSws,r={}", nonce(challenge)) : std::format("{},r={}x", binding_field, nonce(challenge));
            scram::auth_message transcript{std::string_view{first}.substr(params.header.size()), challenge, altered_final};
            auto altered_proof = scram::make_client_proof(credentials, transcript);
            modified = altered_final + ",p=" + base64(altered_proof.bytes());
        }
        CHECK(server.finish(modified, std::nothrow) == failure);
        CHECK(server.finish(final, std::nothrow) == failure);
    }

    client.reset();
    server.reset();
    CHECK(server.receive_client_first(client.start("user", params.client).message, params.server) == "user");
    final = client.respond(server.challenge(verifier, salt, iterations), "pencil");
    auto expected_signature = server.finish(final);
    CHECK(client.finish(signature, std::nothrow) == failure);
    CHECK(client.finish(expected_signature, std::nothrow) == failure);

    client.reset();
    server.reset();
    CHECK(server.receive_client_first(client.start("user", params.client).message, params.server) == "user");
    final = client.respond(server.challenge(verifier, salt, iterations), "pencil");
    auto modified_signature = server.finish(final);
    REQUIRE(modified_signature.size() > 2);
    modified_signature[2] = modified_signature[2] == 'A' ? 'B' : 'A';
    CHECK(client.finish(modified_signature, std::nothrow) == failure);
}

TEST_CASE("SCRAM exchanges reject the wrong password and wipe both peers' state", "[scram]")
{
    auto params = GENERATE(plain, plus);
    CAPTURE(scram::mechanism_name(params.server.selected));
    auto verifier = scram::make_server_verifier("pencil", salt, iterations);
    scram::client_exchange_storage client_storage{potassium::for_overwrite};
    scram::server_verifier_storage server_storage{potassium::for_overwrite};
    scram::client_exchange client{client_storage};
    scram::server_exchange server{server_storage};

    CHECK(server.receive_client_first(client.start("user", params.client).message, params.server) == "user");
    auto challenge = server.challenge(verifier, salt, iterations);
    auto final = client.respond(challenge, u8"wrong password");

    CHECK(server.finish(final, std::nothrow) == failure);
    CHECK(wiped(server_storage.ref().bytes()));
    CHECK(client.finish("e=invalid-proof", std::nothrow) == failure);
    CHECK(wiped(client_storage.ref().bytes()));
}

TEST_CASE("SCRAM-SHA-256-PLUS authenticates transport bytes in the exact GS2 input", "[scram]")
{
    auto verifier = scram::make_server_verifier("pencil", salt, iterations);
    scram::client_exchange client;
    scram::server_exchange server;
    auto client_bytes = exporter_bytes;
    auto first = client.start(u8"user", {.offered = both, .binding = scram::channel_binding{"tls-exporter", client_bytes}});
    CHECK(first.selected == scram::mechanism::sha256_plus);
    CHECK(scram::mechanism_name(first.selected) == "SCRAM-SHA-256-PLUS");
    REQUIRE(first.message.starts_with("p=tls-exporter,,n=user,r="));
    client_bytes.front() ^= std::byte{1};

    auto server_bytes = exporter_bytes;
    auto username = server.receive_client_first(first.message, {.selected = first.selected, .advertised = both, .binding = scram::channel_binding{"tls-exporter", server_bytes}});
    CHECK(username == "user");
    server_bytes.back() ^= std::byte{1};
    auto challenge = server.challenge(verifier, salt, iterations);
    auto final = client.respond(challenge, "pencil");

    auto expected_c = "c=" + encoded_binding("p=tls-exporter,,", exporter) + ",r=";
    CHECK(final.starts_with(expected_c));
    CHECK_NOTHROW(client.finish(server.finish(final)));

    client.reset();
    server.reset();
    constexpr scram::mechanism_offer plus_only{.sha256 = false, .sha256_plus = true};
    constexpr auto binding_bytes = hex_bytes("0001022cff3d");
    constexpr std::string_view binding_type = "example-binding.v1";
    scram::channel_binding binding{binding_type, binding_bytes};
    first = client.start("user", {.offered = plus_only, .binding = binding, .require_channel_binding = true});
    CHECK(first.message.starts_with("p=example-binding.v1,,"));
    CHECK(server.receive_client_first(first.message, {.selected = first.selected, .advertised = plus_only, .binding = binding}) == "user");
    final = client.respond(server.challenge(verifier, salt, iterations), "pencil");
    CHECK_NOTHROW(client.finish(server.finish(final)));
}

TEST_CASE("SCRAM negotiation protects the non-PLUS fallback", "[scram]")
{
    auto verifier = scram::make_server_verifier("pencil", salt, iterations);
    scram::client_exchange client;
    scram::server_exchange server;
    auto first = client.start("user", {.binding = exporter});
    CHECK(first.selected == scram::mechanism::sha256);
    CHECK(scram::mechanism_name(first.selected) == "SCRAM-SHA-256");
    CHECK(first.message.starts_with("y,,"));

    CHECK(server.receive_client_first(first.message, {.selected = first.selected, .advertised = both, .binding = exporter}, std::nothrow) == failure);
    server.reset();
    CHECK(server.receive_client_first(first.message, {.selected = first.selected, .binding = exporter}, std::nothrow) == failure);
    server.reset();
    CHECK(server.receive_client_first(first.message) == "user");
    auto final = client.respond(server.challenge(verifier, salt, iterations), "pencil");
    CHECK(final.starts_with("c=eSws,r="));
    CHECK_NOTHROW(client.finish(server.finish(final)));

    client.reset();
    server.reset();
    first = client.start("user", {.offered = both});
    CHECK(first.selected == scram::mechanism::sha256);
    CHECK(first.message.starts_with("n,,"));
    CHECK(server.receive_client_first(first.message, {.selected = first.selected, .advertised = both, .binding = exporter}) == "user");
    final = client.respond(server.challenge(verifier, salt, iterations), "pencil");
    CHECK_NOTHROW(client.finish(server.finish(final)));

    client.reset();
    auto required = client.start("user", {.binding = exporter, .require_channel_binding = true}, std::nothrow);
    REQUIRE_FALSE(required.has_value());
    CHECK(required.error() == potassium::errc::crypto_failed);
    client.reset();
    auto unavailable = client.start("user", {.offered = {.sha256 = false, .sha256_plus = true}}, std::nothrow);
    REQUIRE_FALSE(unavailable.has_value());
    CHECK(unavailable.error() == potassium::errc::crypto_failed);
}

TEST_CASE("SCRAM-SHA-256-PLUS rejects invalid mechanisms, GS2 headers, and bindings", "[scram]")
{
    scram::server_exchange server;
    scram::server_negotiation selected_plus{.selected = scram::mechanism::sha256_plus, .advertised = both, .binding = exporter};
    for (auto message : {"n,,n=user,r=a",
                         "y,,n=user,r=a",
                         "p=,,n=user,r=a",
                         "p=tls-unique,,n=user,r=a",
                         "p=tls-exporter,n=user,r=a",
                         "p=tls-exporter,a=admin,n=user,r=a",
                         "p=tls-exporter,,,n=user,r=a",
                         "p=tls_exporter,,n=user,r=a"})
    {
        CAPTURE(message);
        CHECK(server.receive_client_first(message, selected_plus, std::nothrow) == failure);
        server.reset();
    }

    constexpr std::string_view plus_first = "p=tls-exporter,,n=user,r=a";
    CHECK(server.receive_client_first(plus_first, std::nothrow) == failure);
    server.reset();
    CHECK(server.receive_client_first(plus_first, {.selected = scram::mechanism::sha256, .advertised = both, .binding = exporter}, std::nothrow) == failure);
    server.reset();
    CHECK(server.receive_client_first(plus_first, {.selected = scram::mechanism::sha256_plus, .advertised = both}, std::nothrow) == failure);
    server.reset();
    CHECK(server.receive_client_first(plus_first, {.selected = scram::mechanism::sha256_plus, .binding = exporter}, std::nothrow) == failure);

    scram::client_exchange client;
    constexpr std::array<std::byte, scram::max_channel_binding_size> oversized_binding{};
    for (auto binding : {scram::channel_binding{"", exporter_bytes},
                         scram::channel_binding{"tls_exporter", exporter_bytes},
                         scram::channel_binding{"tls-exporter", {}},
                         scram::channel_binding{"tls-exporter", std::span{exporter_bytes}.first(31)},
                         scram::channel_binding{"example-binding", oversized_binding}})
    {
        CAPTURE(binding.type, binding.data.size());
        auto invalid = client.start("user", {.offered = both, .binding = binding}, std::nothrow);
        REQUIRE_FALSE(invalid.has_value());
        CHECK(invalid.error() == potassium::errc::crypto_failed);
        client.reset();

        server.reset();
        auto options = selected_plus;
        options.binding = binding;
        CHECK(server.receive_client_first(std::format("p={},,n=user,r=a", binding.type), options, std::nothrow) == failure);
    }

    auto verifier = scram::make_server_verifier("pencil", salt, iterations);
    auto other_bytes = exporter_bytes;
    other_bytes.back() ^= std::byte{1};
    selected_plus.binding = scram::channel_binding{"tls-exporter", other_bytes};
    auto first = client.start("user", {.offered = both, .binding = exporter});
    server.reset();
    CHECK(server.receive_client_first(first.message, selected_plus) == "user");
    auto final = client.respond(server.challenge(verifier, salt, iterations), "pencil");
    CHECK(server.finish(final, std::nothrow) == failure);
}
