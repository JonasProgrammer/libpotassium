// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_test_macros.hpp>

import potassium.contrib;
import potassium.tests.nacl_vector;
import std;

namespace
{
namespace scram = potassium::contrib::scram_sha256;
using test_vectors::hex_bytes;

// RFC 7677, Section 3.
constexpr auto salt = hex_bytes("5b6d99689d12358eeca04b141236fa81");
constexpr auto proof_bytes = hex_bytes("747cdb65aa56224e2352137e52d7bdcad6a0f738df30782caa69a2cfb0277554");
constexpr auto signature_bytes = hex_bytes("eabae24d1062db75a9451ff0b6ea7e98c8546549ff741e672d3251b2397de46e");
constexpr auto verifier_bytes = hex_bytes(
        "586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6"
        "c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5");
constexpr std::string_view client_first = "n=user,r=rOprNGfwEbeRWgbNEkqO";
constexpr std::u8string_view server_first = u8"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
constexpr std::string_view client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
constexpr std::uint32_t iterations = 4096;

static_assert(std::constructible_from<scram::auth_message, std::string&, std::u8string const&, std::string_view>);
static_assert(std::constructible_from<scram::auth_message, std::string_view, std::u8string_view, decltype("c=biws,r=nonce")>);
static_assert(!std::constructible_from<scram::auth_message, std::string, std::string_view, std::string_view>);
static_assert(!std::constructible_from<scram::auth_message, std::string_view, std::u8string, std::string_view>);
static_assert(!std::constructible_from<scram::auth_message, std::string_view, std::string_view, std::string>);
}  // namespace

TEST_CASE("SCRAM-SHA-256 matches the RFC 7677 exchange", "[scram]")
{
    scram::auth_message transcript{client_first, server_first, client_final};
    auto credentials = scram::derive_client_credentials(std::string{"pencil"}, salt, iterations);
    auto verifier = scram::make_server_verifier(std::u8string{u8"pencil"}, salt, iterations);
    CHECK(std::ranges::equal(verifier.ref().bytes(), verifier_bytes));

    scram::server_verifier_storage inline_verifier{potassium::for_overwrite};
    scram::make_server_verifier_into(credentials, inline_verifier);
    CHECK(std::ranges::equal(inline_verifier.ref().bytes(), verifier_bytes));

    auto proof = scram::make_client_proof(credentials, transcript);
    CHECK(std::ranges::equal(proof.bytes(), proof_bytes));

    scram::server_verifier_ref stored_verifier{verifier_bytes};
    auto signature = scram::authenticate_client(stored_verifier, transcript, proof.bytes());
    CHECK(std::ranges::equal(signature.bytes(), signature_bytes));
    CHECK_NOTHROW(scram::authenticate_server(credentials, transcript, signature_bytes));

    scram::auth_message next_transcript{"n=user,r=NEXT", "r=NEXTSERVER,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", "c=biws,r=NEXTSERVER"};
    CHECK(scram::authenticate_client(stored_verifier, next_transcript, proof.bytes(), std::nothrow) == std::unexpected(potassium::errc::crypto_failed));
    auto next_proof = scram::make_client_proof(credentials, next_transcript);
    auto next_signature = scram::authenticate_client(stored_verifier, next_transcript, next_proof.bytes());
    CHECK(scram::authenticate_server(credentials, next_transcript, next_signature.bytes(), std::nothrow).has_value());
}

TEST_CASE("SCRAM-SHA-256 rejects a wrong password and modified authentication data", "[scram]")
{
    auto credentials = scram::derive_client_credentials("pencil", salt, iterations);
    auto wrong_credentials = scram::derive_client_credentials("other", salt, iterations);
    scram::server_verifier_ref verifier{verifier_bytes};
    scram::auth_message transcript{client_first, server_first, client_final};
    scram::auth_message modified{client_first, server_first, "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,x=modified"};

    auto wrong_proof = scram::make_client_proof(wrong_credentials, transcript);
    auto modified_proof = proof_bytes;
    modified_proof.front() ^= std::byte{1};
    CHECK(scram::authenticate_client(verifier, transcript, wrong_proof.bytes(), std::nothrow) == std::unexpected(potassium::errc::crypto_failed));
    CHECK(scram::authenticate_client(verifier, modified, proof_bytes, std::nothrow) == std::unexpected(potassium::errc::crypto_failed));
    CHECK_THROWS_AS(static_cast<void>(scram::authenticate_client(verifier, transcript, modified_proof)), potassium::crypto_error);

    auto modified_signature = signature_bytes;
    modified_signature.back() ^= std::byte{1};
    CHECK(scram::authenticate_server(credentials, transcript, modified_signature, std::nothrow) == std::unexpected(potassium::errc::crypto_failed));
    CHECK(scram::authenticate_server(credentials, modified, signature_bytes, std::nothrow) == std::unexpected(potassium::errc::crypto_failed));
    CHECK_THROWS_AS(scram::authenticate_server(wrong_credentials, transcript, signature_bytes), potassium::crypto_error);
}

TEST_CASE("SCRAM-SHA-256 derives from prepared UTF-8 in reusable storage", "[scram]")
{
    auto long_salt = hex_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    constexpr auto utf8_credentials = hex_bytes(
            "2242e898ad69262837598711d86d8315a64fad5beab363a1bfd30de2c99d77a4"
            "5e66811e3c287b866698344dc4b239777f379686d8c1de0101a0562c6e513127");
    constexpr auto empty_password_credentials = hex_bytes(
            "9adbd363df1347bc7850208dd1aaaf4e64f7781693836dc2d719df5315d75185"
            "19c79d368f25998694a6057f7bf0a7578d3053a1ed0103f1f9bf39e6fdaaafcf");
    scram::client_credentials_storage storage{potassium::for_overwrite};
    scram::derive_client_credentials_into(std::u8string_view{u8"caf\u00e9"}, long_salt, 2, storage);
    CHECK(std::ranges::equal(storage.ref().bytes(), utf8_credentials));

    auto narrow = scram::derive_client_credentials(std::string_view{"caf\xc3\xa9"}, long_salt, 2, std::nothrow);
    REQUIRE(narrow.has_value());
    CHECK(std::ranges::equal(narrow->ref().bytes(), utf8_credentials));

    REQUIRE(scram::derive_client_credentials_into(std::string_view{}, long_salt, 1, storage, std::nothrow).has_value());
    CHECK(std::ranges::equal(storage.ref().bytes(), empty_password_credentials));

    CHECK(scram::derive_client_credentials_into("pencil", salt, 0, storage, std::nothrow) == std::unexpected(potassium::errc::crypto_failed));
    CHECK(std::ranges::equal(storage.ref().bytes(), empty_password_credentials));

    scram::server_verifier_storage inline_verifier{potassium::for_overwrite};
    REQUIRE(scram::make_server_verifier_into("pencil", salt, iterations, inline_verifier, std::nothrow).has_value());
    CHECK(std::ranges::equal(inline_verifier.ref().bytes(), verifier_bytes));
    auto invalid_verifier = scram::make_server_verifier(u8"pencil", salt, 0, std::nothrow);
    REQUIRE_FALSE(invalid_verifier.has_value());
    CHECK(invalid_verifier.error() == potassium::errc::crypto_failed);
}
