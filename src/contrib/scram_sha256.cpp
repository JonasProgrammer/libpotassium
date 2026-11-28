// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

export module potassium.contrib:scram_sha256;

export import potassium.core;
import potassium.internal;
import std;

/// @brief SCRAM-SHA-256 cryptographic operations as specified by RFC 5802 and RFC 7677.
/// @details Use client_exchange and server_exchange for SASL messages and nonce validation,
/// or the standalone operations when a protocol layer already performs those tasks.
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
/// Expected server signature held until the client finishes an exchange.
struct expected_server_signature_tag;
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

/// Storage size for an expected server signature.
template <>
struct key_traits<contrib::scram_sha256::expected_server_signature_tag>
{
    /// Signature length in bytes.
    static constexpr std::size_t size = contrib::scram_sha256::key_size;
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

template <text T>
std::string_view as_string_view(T const& text) noexcept
{
    auto bytes = as_bytes(text);
    if (bytes.empty()) return {};
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
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
[[nodiscard]] std::expected<void, errc> derive_client_credentials_into(Password const& password,
                                                                       std::span<std::byte const> salt,
                                                                       std::uint32_t iterations,
                                                                       client_credentials_out out,
                                                                       std::nothrow_t) noexcept
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
[[nodiscard]] std::expected<void, errc> make_server_verifier_into(Password const& password, std::span<std::byte const> salt, std::uint32_t iterations, server_verifier_out out, std::nothrow_t) noexcept
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
[[nodiscard]] std::expected<void, errc> authenticate_server(client_credentials_ref credentials, auth_message transcript, std::span<std::byte const, key_size> signature, std::nothrow_t) noexcept;

/// Verify a server signature or throw on authentication failure.
/// @see authenticate_server
void authenticate_server(client_credentials_ref credentials, auth_message transcript, std::span<std::byte const, key_size> signature);

/// Inclusive bounds applied by a client before password derivation.
struct iteration_policy
{
    /// Lowest accepted server iteration count.
    std::uint32_t minimum = recommended_min_iterations;
    /// Highest accepted server iteration count.
    std::uint32_t maximum = 1'000'000;
};

/// Cached keys and the challenge parameters for which they were derived.
struct cached_client_credentials
{
    /// Keys for the service and identity selected by the caller.
    client_credentials_ref credentials;
    /// Raw decoded salt for the cached keys.
    std::span<std::byte const> salt;
    /// Iteration count used to derive the cached keys.
    std::uint32_t iterations;
};

/// Maximum size in bytes of one wire message accepted or produced by the exchange API.
inline constexpr std::size_t max_message_size = 4096;
/// Maximum decoded salt length accepted by the exchange API.
inline constexpr std::size_t max_salt_size = 1024;
/// Maximum decoded size of the GS2 header and channel-binding bytes together.
inline constexpr std::size_t max_channel_binding_size = 1024;

/// SASL mechanism selected for one SCRAM exchange.
enum class mechanism
{
    /// SCRAM-SHA-256.
    sha256,
    /// SCRAM-SHA-256-PLUS with channel binding.
    sha256_plus,
};

/// Return the name used by the SASL transport for the selected mechanism.
[[nodiscard]] constexpr std::string_view mechanism_name(mechanism selected) noexcept
{
    switch (selected)
    {
    case mechanism::sha256:
        return "SCRAM-SHA-256";
    case mechanism::sha256_plus:
        return "SCRAM-SHA-256-PLUS";
    }
    return {};
}

/// SCRAM mechanisms advertised by the server for this connection.
struct mechanism_offer
{
    /// The server advertises SCRAM-SHA-256.
    bool sha256 = true;
    /// The server advertises SCRAM-SHA-256-PLUS.
    bool sha256_plus = false;
};

/// Borrowed channel-binding data supplied by the transport.
/// @pre The data was obtained independently from the secure channel for this exchange.
/// @pre Both ranges remain valid throughout the call that initiates the exchange.
struct channel_binding
{
    /// GS2 channel-binding type name, such as tls-exporter.
    std::string_view type;
    /// Raw binary binding data, transmitted Base64-encoded in the client-final message.
    std::span<std::byte const> data;
};

/// Mechanism negotiation and channel binding for one client exchange.
struct client_negotiation
{
    /// The mechanisms the client received from the server's SASL advertisement.
    mechanism_offer offered;
    /// The client's binding for the current secure channel, if available.
    std::optional<channel_binding> binding;
    /// Require SCRAM-SHA-256-PLUS to be available.
    bool require_channel_binding = false;
};

/// Mechanism negotiation and channel binding for one server exchange.
struct server_negotiation
{
    /// The mechanism selected by the SASL transport.
    mechanism selected = mechanism::sha256;
    /// The mechanisms the server actually advertised for the current connection.
    mechanism_offer advertised;
    /// The server's binding for the current secure channel, which must be present if PLUS is advertised.
    std::optional<channel_binding> binding;
};

/// The client's initial wire message and the SASL mechanism it selected.
struct client_first_message
{
    /// Selected mechanism to pass to the SASL transport.
    mechanism selected;
    /// Client-first message bytes.
    std::string message;
};

/// Inline, reusable storage for the client's expected server signature.
using client_exchange_storage = key_buffer_storage<expected_server_signature_tag>;
/// Writable view of caller-owned storage for the client's expected server signature.
using client_exchange_out = key_out<expected_server_signature_tag>;

/// Client-side SCRAM-SHA-256 or SCRAM-SHA-256-PLUS exchange using the authentication identity for authorization.
/// @details Call start(), respond(), then finish(). Any failed or out-of-order operation closes the exchange.
/// A successful finish() also closes it. Call reset() before using it again.
class client_exchange
{
    enum class phase
    {
        idle,
        server_first,
        server_final,
        closed,
    };

    iteration_policy policy_;
    phase phase_ = phase::idle;
    std::string first_bare_;
    std::string nonce_;
    std::string binding_;
    client_exchange_storage owned_storage_{for_overwrite};
    client_exchange_out expected_signature_{owned_storage_};

    void close() noexcept;
    std::unexpected<errc> fail(errc error = errc::crypto_failed) noexcept;
    std::expected<client_first_message, errc> start_impl(std::string_view username, client_negotiation negotiation) noexcept;
    std::expected<std::string, errc> respond_impl(std::string_view message, std::variant<std::string_view, cached_client_credentials> source) noexcept;
    std::expected<void, errc> finish_impl(std::string_view message) noexcept;

public:
    /// Construct an idle client with inline confidential state.
    explicit client_exchange(iteration_policy policy = {}) noexcept;
    /// Construct an idle client with caller-owned confidential state.
    /// @pre The storage remains alive and reserved for this exchange until destruction.
    explicit client_exchange(client_exchange_out storage, iteration_policy policy = {}) noexcept;
    /// Wipe the expected server signature.
    ~client_exchange();

    /// Abandon any exchange and retain its storage for a fresh nonce and exchange.
    void reset() noexcept;

    /// Create the client-first wire message for a client without channel binding.
    /// @pre The username is UTF-8 prepared with SASLprep as a query string, or is unchanged by that preparation.
    template <detail::text Username>
    [[nodiscard]] std::expected<std::string, errc> start(Username const& username, std::nothrow_t) noexcept
    {
        return start(username, client_negotiation{}, std::nothrow).transform([](client_first_message&& first) noexcept { return std::move(first.message); });
    }

    /// Create the client-first wire message or throw.
    /// @see start
    template <detail::text Username>
    [[nodiscard]] std::string start(Username const& username)
    {
        return internal::unwrap(start(username, std::nothrow));
    }

    /// Select a mechanism and create its client-first wire message.
    /// @pre The username is UTF-8 prepared with SASLprep as a query string, or is unchanged by that preparation.
    template <detail::text Username>
    [[nodiscard]] std::expected<client_first_message, errc> start(Username const& username, client_negotiation negotiation, std::nothrow_t) noexcept
    {
        return start_impl(detail::as_string_view(username), negotiation);
    }

    /// Select a mechanism and create its client-first wire message or throw.
    template <detail::text Username>
    [[nodiscard]] client_first_message start(Username const& username, client_negotiation negotiation)
    {
        return internal::unwrap(start(username, negotiation, std::nothrow));
    }

    /// Validate the server-first wire message and create the client-final wire message.
    /// @pre The password is UTF-8 prepared with SASLprep as a stored string, or is unchanged by that preparation.
    template <detail::text Message, detail::text Password>
    [[nodiscard]] std::expected<std::string, errc> respond(Message const& server_first, Password const& password, std::nothrow_t) noexcept
    {
        return respond_impl(detail::as_string_view(server_first), detail::as_string_view(password));
    }

    /// Create the client-final wire message from a password or throw.
    /// @see respond
    template <detail::text Message, detail::text Password>
    [[nodiscard]] std::string respond(Message const& server_first, Password const& password)
    {
        return internal::unwrap(respond(server_first, password, std::nothrow));
    }

    /// Create the client-final wire message with cached keys after checking the salt and iteration count.
    /// @pre The cached keys belong to the intended service and authentication identity.
    template <detail::text Message>
    [[nodiscard]] std::expected<std::string, errc> respond(Message const& server_first, cached_client_credentials cached, std::nothrow_t) noexcept
    {
        return respond_impl(detail::as_string_view(server_first), cached);
    }

    /// Create the client-final wire message from cached keys or throw.
    /// @see respond
    template <detail::text Message>
    [[nodiscard]] std::string respond(Message const& server_first, cached_client_credentials cached)
    {
        return internal::unwrap(respond(server_first, cached, std::nothrow));
    }

    /// Authenticate the server-final wire message and close the exchange.
    template <detail::text Message>
    [[nodiscard]] std::expected<void, errc> finish(Message const& server_final, std::nothrow_t) noexcept
    {
        return finish_impl(detail::as_string_view(server_final));
    }

    /// Authenticate the server-final wire message or throw.
    template <detail::text Message>
    void finish(Message const& server_final)
    {
        internal::unwrap(finish(server_final, std::nothrow));
    }
};

/// Server-side SCRAM-SHA-256 or SCRAM-SHA-256-PLUS exchange using the authentication identity for authorization.
/// @details Call receive_client_first(), challenge(), then finish(). Any failed or out-of-order operation closes the exchange.
/// A successful finish() also closes it. Call reset() before using it again.
class server_exchange
{
    enum class phase
    {
        idle,
        verifier,
        client_final,
        closed,
    };

    phase phase_ = phase::idle;
    std::string first_bare_;
    std::string nonce_;
    std::string server_first_;
    std::string binding_;
    server_verifier_storage owned_storage_{for_overwrite};
    server_verifier_out verifier_{owned_storage_};

    void close() noexcept;
    std::unexpected<errc> fail(errc error = errc::crypto_failed) noexcept;
    std::expected<std::string, errc> receive_client_first_impl(std::string_view message, server_negotiation negotiation) noexcept;
    std::expected<std::string, errc> finish_impl(std::string_view message) noexcept;

public:
    /// Construct an idle server with inline confidential state.
    server_exchange() noexcept = default;
    /// Construct an idle server with caller-owned confidential state for a verifier copy.
    /// @pre The storage remains alive and reserved for this exchange until destruction.
    explicit server_exchange(server_verifier_out storage) noexcept;
    /// Wipe the verifier copy.
    ~server_exchange();

    /// Abandon any exchange and retain its storage for a fresh nonce and exchange.
    void reset() noexcept;

    /// Validate the client-first wire message and return the unescaped username for account lookup.
    /// @pre The caller uses SASLprep-aware account lookup as specified by RFC 5802.
    /// @pre The server lacks channel-binding support on this connection.
    template <detail::text Message>
    [[nodiscard]] std::expected<std::string, errc> receive_client_first(Message const& client_first, std::nothrow_t) noexcept
    {
        return receive_client_first(client_first, server_negotiation{}, std::nothrow);
    }

    /// Parse the client-first wire message or throw.
    /// @see receive_client_first
    template <detail::text Message>
    [[nodiscard]] std::string receive_client_first(Message const& client_first)
    {
        return internal::unwrap(receive_client_first(client_first, std::nothrow));
    }

    /// Verify the client GS2 header against the negotiated mechanism and return the unescaped username.
    /// @pre The caller uses SASLprep-aware account lookup as specified by RFC 5802.
    template <detail::text Message>
    [[nodiscard]] std::expected<std::string, errc> receive_client_first(Message const& client_first, server_negotiation negotiation, std::nothrow_t) noexcept
    {
        return receive_client_first_impl(detail::as_string_view(client_first), negotiation);
    }

    /// Verify the GS2 header and parse the client-first wire message or throw.
    template <detail::text Message>
    [[nodiscard]] std::string receive_client_first(Message const& client_first, server_negotiation negotiation)
    {
        return internal::unwrap(receive_client_first(client_first, negotiation, std::nothrow));
    }

    /// Bind the account's verifier and generate the server-first wire message.
    /// @pre The verifier, salt, and iteration count are from the selected account or its synthetic record.
    /// @pre The verifier and salt are disjoint from the exchange's confidential storage.
    [[nodiscard]] std::expected<std::string, errc> challenge(server_verifier_ref account, std::span<std::byte const> salt, std::uint32_t iterations, std::nothrow_t) noexcept;

    /// Create the server-first wire message or throw.
    /// @see challenge
    [[nodiscard]] std::string challenge(server_verifier_ref account, std::span<std::byte const> salt, std::uint32_t iterations);

    /// Authenticate the client-final wire message and return a server-final wire message on success.
    template <detail::text Message>
    [[nodiscard]] std::expected<std::string, errc> finish(Message const& client_final, std::nothrow_t) noexcept
    {
        return finish_impl(detail::as_string_view(client_final));
    }

    /// Authenticate the client-final wire message or throw.
    template <detail::text Message>
    [[nodiscard]] std::string finish(Message const& client_final)
    {
        return internal::unwrap(finish(client_final, std::nothrow));
    }
};
}  // namespace potassium::contrib::scram_sha256

/// @cond INTERNAL
namespace potassium::contrib::scram_sha256::detail
{
void server_signature_into(client_credentials_ref credentials, auth_message transcript, std::span<std::byte, key_size> out) noexcept;
}

/// @endcond
