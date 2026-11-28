// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

export module potassium.contrib:scram_sha256;

export import potassium.core;
import potassium.internal;
import std;

/// @brief SCRAM-SHA-256 cryptographic operations as specified by RFC 5802 and RFC 7677.
/// @details The caller handles SASL framing, exchange state, nonce and channel binding validation,
/// Base64, and the policy for accepting a server's salt and iteration count.
export namespace potassium::contrib::scram_sha256
{
/// Size of each SHA-256 key, proof, and signature in bytes.
inline constexpr std::size_t key_size = 32;
/// Minimum enrollment iteration count recommended by RFC 7677.
inline constexpr std::uint32_t recommended_min_iterations = 4096;

/// ClientKey followed by ServerKey, both bound to a password, salt, and iteration count.
struct client_credentials_tag;
/// StoredKey followed by ServerKey, both bound to a password, salt, and iteration count.
struct server_verifier_tag;
}  // namespace potassium::contrib::scram_sha256

export namespace potassium
{
/// Storage size for cached ClientKey and ServerKey.
template <>
struct key_traits<contrib::scram_sha256::client_credentials_tag>
{
    /// Combined length of the two keys in bytes.
    static constexpr std::size_t size = 2 * contrib::scram_sha256::key_size;
};

/// Storage size for the server's StoredKey and ServerKey.
template <>
struct key_traits<contrib::scram_sha256::server_verifier_tag>
{
    /// Combined length of the two keys in bytes.
    static constexpr std::size_t size = 2 * contrib::scram_sha256::key_size;
};
}  // namespace potassium

/// @cond INTERNAL
namespace potassium::contrib::scram_sha256::detail
{
template <class T>
concept text = std::is_nothrow_convertible_v<T const&, std::string_view> || std::is_nothrow_convertible_v<T const&, std::u8string_view>;

template <class T>
concept borrowed_text = text<std::remove_reference_t<T>> && (std::is_lvalue_reference_v<T> || std::ranges::borrowed_range<T>);

template <text T>
std::span<std::byte const> as_bytes(T const& text) noexcept
{
    if constexpr (std::is_nothrow_convertible_v<T const&, std::u8string_view>)
    {
        std::u8string_view view = text;
        return std::as_bytes(std::span{view});
    }
    else
    {
        std::string_view view = text;
        return std::as_bytes(std::span{view});
    }
}

std::expected<void, errc> derive_client_credentials_into(std::span<std::byte const>, std::span<std::byte const>, std::uint32_t, key_out<client_credentials_tag>) noexcept;
std::expected<secret_key<client_credentials_tag>, errc> derive_client_credentials(std::span<std::byte const>, std::span<std::byte const>, std::uint32_t) noexcept;
std::expected<void, errc> make_server_verifier_into(std::span<std::byte const>, std::span<std::byte const>, std::uint32_t, key_out<server_verifier_tag>) noexcept;
std::expected<secret_key<server_verifier_tag>, errc> make_server_verifier(std::span<std::byte const>, std::span<std::byte const>, std::uint32_t) noexcept;
}  // namespace potassium::contrib::scram_sha256::detail

/// @endcond

export namespace potassium::contrib::scram_sha256
{
/// Guarded client credentials. Protect them as a password equivalent for the associated salt and iteration count.
using client_credentials = secret_key<client_credentials_tag>;
/// Client credentials stored inline and wiped on destruction.
using client_credentials_storage = key_buffer_storage<client_credentials_tag>;
/// Borrowed client credentials.
using client_credentials_ref = key_ref<client_credentials_tag>;
/// Writable destination for client credentials.
using client_credentials_out = key_out<client_credentials_tag>;

/// Guarded server verifier. Store it with the salt and iteration count used to derive it.
using server_verifier = secret_key<server_verifier_tag>;
/// Server verifier stored inline and wiped on destruction.
using server_verifier_storage = key_buffer_storage<server_verifier_tag>;
/// Borrowed server verifier. Load stored bytes in StoredKey, ServerKey order.
using server_verifier_ref = key_ref<server_verifier_tag>;
/// Writable destination for a server verifier.
using server_verifier_out = key_out<server_verifier_tag>;

/// The three exact wire fragments that SCRAM authenticates, joined internally with commas.
class auth_message
{
    std::array<std::span<std::byte const>, 3> fragments_;

public:
    /// @pre The fragments remain valid and unchanged through every use of this view.
    /// @pre The caller validates the messages for the current exchange, including the nonce and channel binding.
    /// @pre The caller handles SASLprep of identities as specified by RFC 5802.
    template <detail::borrowed_text First, detail::borrowed_text Challenge, detail::borrowed_text Final>
    auth_message(First&& client_first_bare, Challenge&& server_first, Final&& client_final_without_proof) noexcept
        : fragments_{detail::as_bytes(client_first_bare), detail::as_bytes(server_first), detail::as_bytes(client_final_without_proof)}
    {
    }

    /// Borrow the fragments in the order defined by RFC 5802.
    [[nodiscard]] std::array<std::span<std::byte const>, 3> fragments() const noexcept { return fragments_; }
};

/// Client proof to encode as the client-final message's p attribute.
struct client_proof
{
    /// Proof bytes in wire order.
    std::array<std::byte, key_size> storage{};

    /// Borrow the bytes for the lifetime of this result.
    [[nodiscard]] std::span<std::byte const, key_size> bytes() const& noexcept { return storage; }

    /// Borrowing requires a live lvalue result.
    auto bytes() const&& = delete;
};

/// Server signature to encode as the server-final message's v attribute.
struct server_signature
{
    /// Signature bytes in wire order.
    std::array<std::byte, key_size> storage{};

    /// Borrow the bytes for the lifetime of this result.
    [[nodiscard]] std::span<std::byte const, key_size> bytes() const& noexcept { return storage; }

    /// Borrowing requires a live lvalue result.
    auto bytes() const&& = delete;
};

/// Derive reusable client credentials into caller storage. A zero iteration count fails.
/// @pre Password is UTF-8 prepared with SASLprep as a stored string, or is unchanged by that preparation.
/// @pre The caller accepts the salt and iteration count for this account and exchange.
/// @pre Output is disjoint from the password and salt.
template <detail::text Password>
std::expected<void, errc> derive_client_credentials_into(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, client_credentials_out out, std::nothrow_t) noexcept
{
    return detail::derive_client_credentials_into(detail::as_bytes(password), salt, iterations, out);
}

/// Derive client credentials into caller storage or throw.
/// @see derive_client_credentials_into
template <detail::text Password>
void derive_client_credentials_into(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, client_credentials_out out)
{
    internal::unwrap(derive_client_credentials_into(password, salt, iterations, out, std::nothrow));
}

/// Derive reusable client credentials in guarded storage.
/// @see derive_client_credentials_into
template <detail::text Password>
[[nodiscard]] std::expected<client_credentials, errc> derive_client_credentials(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, std::nothrow_t) noexcept
{
    return detail::derive_client_credentials(detail::as_bytes(password), salt, iterations);
}

/// Derive reusable client credentials in guarded storage or throw.
/// @see derive_client_credentials_into
template <detail::text Password>
[[nodiscard]] client_credentials derive_client_credentials(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations)
{
    return internal::unwrap(derive_client_credentials(password, salt, iterations, std::nothrow));
}

/// Create a server verifier from existing client credentials into caller storage.
/// @pre Input and output are disjoint.
void make_server_verifier_into(client_credentials_ref credentials, server_verifier_out out) noexcept;

/// Create a guarded server verifier from existing client credentials.
[[nodiscard]] std::expected<server_verifier, errc> make_server_verifier(client_credentials_ref credentials, std::nothrow_t) noexcept;

/// Create a guarded server verifier from existing client credentials or throw.
[[nodiscard]] server_verifier make_server_verifier(client_credentials_ref credentials);

/// Derive a server verifier into caller storage. A zero iteration count fails.
/// @pre Password is UTF-8 prepared with SASLprep as a stored string, or is unchanged by that preparation.
/// @pre For new enrollment, supply a freshly generated random salt and an iteration count meeting local policy.
/// @pre Output is disjoint from the password and salt.
template <detail::text Password>
std::expected<void, errc> make_server_verifier_into(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, server_verifier_out out, std::nothrow_t) noexcept
{
    return detail::make_server_verifier_into(detail::as_bytes(password), salt, iterations, out);
}

/// Derive a server verifier into caller storage or throw.
/// @see make_server_verifier_into
template <detail::text Password>
void make_server_verifier_into(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, server_verifier_out out)
{
    internal::unwrap(make_server_verifier_into(password, salt, iterations, out, std::nothrow));
}

/// Derive a server verifier in guarded storage.
/// @see make_server_verifier_into
template <detail::text Password>
[[nodiscard]] std::expected<server_verifier, errc> make_server_verifier(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, std::nothrow_t) noexcept
{
    return detail::make_server_verifier(detail::as_bytes(password), salt, iterations);
}

/// Derive a server verifier in guarded storage or throw.
/// @see make_server_verifier_into
template <detail::text Password>
[[nodiscard]] server_verifier make_server_verifier(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations)
{
    return internal::unwrap(make_server_verifier(password, salt, iterations, std::nothrow));
}

/// Create a proof bound to the transcript.
/// @pre Credentials correspond to the salt and iteration count in the server-first message.
[[nodiscard]] client_proof make_client_proof(client_credentials_ref credentials, auth_message transcript) noexcept;

/// Verify a proof in constant time and return the signature only after successful authentication.
/// @pre The verifier corresponds to the account, salt, and iteration count in the exchange.
[[nodiscard]] std::expected<server_signature, errc> authenticate_client(server_verifier_ref verifier, auth_message transcript, std::span<std::byte const, key_size> proof, std::nothrow_t) noexcept;

/// Verify a proof and return the server signature or throw on authentication failure.
/// @see authenticate_client
[[nodiscard]] server_signature authenticate_client(server_verifier_ref verifier, auth_message transcript, std::span<std::byte const, key_size> proof);

/// Verify a server signature in constant time.
/// @pre Use the same credentials and transcript used to generate the client proof.
std::expected<void, errc> authenticate_server(client_credentials_ref credentials, auth_message transcript, std::span<std::byte const, key_size> signature, std::nothrow_t) noexcept;

/// Verify a server signature or throw on authentication failure.
/// @see authenticate_server
void authenticate_server(client_credentials_ref credentials, auth_message transcript, std::span<std::byte const, key_size> signature);
}  // namespace potassium::contrib::scram_sha256
