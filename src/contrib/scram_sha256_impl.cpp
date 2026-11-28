// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module potassium.contrib;

import potassium.auth;
import potassium.internal;
import std;

namespace potassium::contrib::scram_sha256
{
namespace
{
using hmac = auth::detail::hmac_ops<auth::hmac_sha256>;
using hmac_key = auth::hmac_key_tag<auth::hmac_sha256>;
using hmac_state = hash::inplace_hash_state<hmac::state_type>;
using key_bytes = std::span<std::byte const, key_size>;
using key_destination = std::span<std::byte, key_size>;

static_assert(key_size == hash::hash_traits<hash::sha256>::digest_size);
static_assert(key_size == auth::auth_traits<auth::hmac_sha256>::tag_size);

void xor_into(key_destination out, key_bytes bytes) noexcept
{
    std::ranges::transform(out, bytes, out.begin(), std::bit_xor<>{});
}

void derive_salted_password(std::span<std::byte const> password, std::span<std::byte const> salt, std::uint32_t iterations, key_destination out) noexcept
{
    constexpr std::array block_number{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
    constexpr std::array empty_key{std::byte{0}};
    hmac_state keyed;
    hmac_state work;
    hmac::init(keyed.get(), password.empty() ? std::span{empty_key}.first(0) : password);

    // PBKDF2 needs one block of SHA-256 output for a SCRAM salted password.
    key_buffer_storage<hmac_key> block{for_overwrite};
    auto u = block.writable_bytes();
    work.get() = keyed.get();
    hmac::update(work.get(), salt);
    hmac::update(work.get(), block_number);
    hmac::final(work.get(), u);
    std::ranges::copy(u, out.begin());

    for (std::uint32_t i = 1; i < iterations; ++i)
    {
        work.get() = keyed.get();
        hmac::update(work.get(), u);
        hmac::final(work.get(), u);
        xor_into(out, u);
    }
}

void authenticate_transcript(key_bytes key, auth_message transcript, key_destination out) noexcept
{
    constexpr std::array comma{std::byte{0x2c}};
    auto [client_first_bare, server_first, client_final_without_proof] = transcript.fragments();
    hmac_state state;
    hmac::init(state.get(), key);
    hmac::update(state.get(), client_first_bare);
    hmac::update(state.get(), comma);
    hmac::update(state.get(), server_first);
    hmac::update(state.get(), comma);
    hmac::update(state.get(), client_final_without_proof);
    hmac::final(state.get(), out);
}

template <class Output>
struct wiped_hash_output : Output
{
    ~wiped_hash_output() { wipe(this->storage); }
};

using confidential_digest = wiped_hash_output<hash::digest_buffer<hash::sha256>>;
using confidential_tag = wiped_hash_output<auth::tag_buffer<auth::hmac_sha256>>;
}  // namespace

namespace detail
{
std::expected<void, errc> derive_client_credentials_into(std::span<std::byte const> password, std::span<std::byte const> salt, std::uint32_t iterations, client_credentials_out out) noexcept
{
    if (iterations == 0) return std::unexpected(errc::crypto_failed);

    key_buffer_storage<hmac_key> salted_password{for_overwrite};
    derive_salted_password(password, salt, iterations, salted_password.writable_bytes());
    auth::authenticate_into<auth::hmac_sha256>(salted_password, as_bytes(u8"Client Key"), out.bytes().first<key_size>());
    auth::authenticate_into<auth::hmac_sha256>(salted_password, as_bytes(u8"Server Key"), out.bytes().last<key_size>());
    return {};
}

std::expected<client_credentials, errc> derive_client_credentials(std::span<std::byte const> password, std::span<std::byte const> salt, std::uint32_t iterations) noexcept
try
{
    if (iterations == 0) return std::unexpected(errc::crypto_failed);
    client_credentials result{for_overwrite};
    auto status = derive_client_credentials_into(password, salt, iterations, result);
    if (!status) return std::unexpected(status.error());
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

std::expected<void, errc> make_server_verifier_into(std::span<std::byte const> password, std::span<std::byte const> salt, std::uint32_t iterations, server_verifier_out out) noexcept
{
    client_credentials_storage credentials{for_overwrite};
    auto status = derive_client_credentials_into(password, salt, iterations, credentials);
    if (!status) return status;
    scram_sha256::make_server_verifier_into(credentials, out);
    return {};
}

std::expected<server_verifier, errc> make_server_verifier(std::span<std::byte const> password, std::span<std::byte const> salt, std::uint32_t iterations) noexcept
try
{
    if (iterations == 0) return std::unexpected(errc::crypto_failed);
    server_verifier result{for_overwrite};
    auto status = make_server_verifier_into(password, salt, iterations, result);
    if (!status) return std::unexpected(status.error());
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}
}  // namespace detail

void make_server_verifier_into(client_credentials_ref credentials, server_verifier_out out) noexcept
{
    auto keys = credentials.bytes();
    hash::hash_into<hash::sha256>(keys.first<key_size>(), out.bytes().first<key_size>());
    std::ranges::copy(keys.last<key_size>(), out.bytes().last<key_size>().begin());
}

std::expected<server_verifier, errc> make_server_verifier(client_credentials_ref credentials, std::nothrow_t) noexcept
try
{
    server_verifier result{for_overwrite};
    make_server_verifier_into(credentials, result);
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

server_verifier make_server_verifier(client_credentials_ref credentials)
{
    return internal::unwrap(make_server_verifier(credentials, std::nothrow));
}

client_proof make_client_proof(client_credentials_ref credentials, auth_message transcript) noexcept
{
    auto client_key = credentials.bytes().first<key_size>();
    confidential_digest stored_key;
    hash::hash_into<hash::sha256>(client_key, stored_key.storage);
    client_proof proof;
    authenticate_transcript(stored_key.bytes(), transcript, proof.storage);
    xor_into(proof.storage, client_key);
    return proof;
}

std::expected<server_signature, errc> authenticate_client(server_verifier_ref verifier, auth_message transcript, key_bytes proof, std::nothrow_t) noexcept
{
    auto keys = verifier.bytes();
    auto stored_key = keys.first<key_size>();
    {
        key_buffer_storage<hmac_key> client_key{for_overwrite};
        auto recovered_key = client_key.writable_bytes();
        authenticate_transcript(stored_key, transcript, recovered_key);
        xor_into(recovered_key, proof);

        confidential_digest actual;
        confidential_digest expected;
        hash::hash_into<hash::sha256>(recovered_key, actual.storage);
        std::ranges::copy(stored_key, expected.storage.begin());
        if (actual != expected) return std::unexpected(errc::crypto_failed);
    }

    server_signature signature;
    authenticate_transcript(keys.last<key_size>(), transcript, signature.storage);
    return signature;
}

server_signature authenticate_client(server_verifier_ref verifier, auth_message transcript, key_bytes proof)
{
    return internal::unwrap(authenticate_client(verifier, transcript, proof, std::nothrow));
}

std::expected<void, errc> authenticate_server(client_credentials_ref credentials, auth_message transcript, key_bytes signature, std::nothrow_t) noexcept
{
    confidential_tag expected;
    auth::tag_buffer<auth::hmac_sha256> received;
    authenticate_transcript(credentials.bytes().last<key_size>(), transcript, expected.storage);
    std::ranges::copy(signature, received.storage.begin());
    if (expected != received) return std::unexpected(errc::crypto_failed);
    return {};
}

void authenticate_server(client_credentials_ref credentials, auth_message transcript, key_bytes signature)
{
    internal::unwrap(authenticate_server(credentials, transcript, signature, std::nothrow));
}
}  // namespace potassium::contrib::scram_sha256
