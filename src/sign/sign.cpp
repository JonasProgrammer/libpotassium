// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

/// @brief Ed25519 signatures and incremental Ed25519ph signatures.
export module potassium.sign;

export import potassium.core;
import std;

export namespace potassium::sign
{
/// Ed25519 signature algorithm and signing key-pair tag.
struct ed25519;
/// Ed25519ph signature algorithm tag for multipart messages.
struct ed25519ph;
/// Confidential Ed25519 signing key purpose.
struct signing_key_tag;
/// Confidential Ed25519 key-pair seed purpose.
struct seed_tag;
}  // namespace potassium::sign

export namespace potassium
{
/// Encoded Ed25519 key and signature lengths.
template <>
struct algorithm_traits<sign::ed25519>
{
    /// Encoded verification key length in bytes.
    static constexpr std::size_t public_key_size = crypto_sign_ed25519_PUBLICKEYBYTES;
    /// Encoded signing key length in bytes.
    static constexpr std::size_t secret_key_size = crypto_sign_ed25519_SECRETKEYBYTES;
    /// Key-pair seed length in bytes.
    static constexpr std::size_t seed_size = crypto_sign_ed25519_SEEDBYTES;
    /// Detached signature length in bytes.
    static constexpr std::size_t signature_size = crypto_sign_ed25519_BYTES;
    /// Maximum message length for one-shot signing.
    static constexpr std::size_t messagebytes_max = crypto_sign_ed25519_MESSAGEBYTES_MAX;
};

/// Encoded Ed25519ph signature length.
template <>
struct algorithm_traits<sign::ed25519ph>
{
    /// Detached signature length in bytes.
    static constexpr std::size_t signature_size = crypto_sign_ed25519_BYTES;
};

/// Storage extent for an Ed25519 signing key.
template <>
struct key_traits<sign::signing_key_tag>
{
    /// Signing key length in bytes.
    static constexpr std::size_t size = algorithm_traits<sign::ed25519>::secret_key_size;
};

/// Storage extent and random generator for an Ed25519 seed.
template <>
struct key_traits<sign::seed_tag>
{
    /// Generator for a fresh seed.
    using generator = random_key_generator;
    /// Seed length in bytes.
    static constexpr std::size_t size = algorithm_traits<sign::ed25519>::seed_size;
};
}  // namespace potassium

/// Ed25519 key-pair generation, signing, and verification.
export namespace potassium::sign
{
/// Borrowed private signing key.
using signing_key_ref = key_ref<signing_key_tag>;
/// Borrowed public verification key.
using verification_key_ref = public_key_ref<ed25519>;

/// Copyable wire representation of a signature for algorithm A.
template <class A>
struct signature_buffer
{
    /// Signature bytes in transmission order.
    std::array<std::byte, algorithm_traits<A>::signature_size> storage{};

    /// @return Writable bytes for importing a signature from the wire.
    constexpr std::span<std::byte, algorithm_traits<A>::signature_size> bytes() & noexcept { return storage; }

    /// @return Read-only signature bytes.
    constexpr std::span<std::byte const, algorithm_traits<A>::signature_size> bytes() const& noexcept { return storage; }

    /// Borrowing requires a live lvalue owner.
    std::span<std::byte const, algorithm_traits<A>::signature_size> bytes() const&& = delete;
};

/// A one-shot Ed25519 signature.
using signature = signature_buffer<ed25519>;
/// A multipart Ed25519ph signature verified with prehash.
using prehash_signature = signature_buffer<ed25519ph>;

/// Matching verification key and guarded signing key.
struct keypair
{
    /// Publishable verification key.
    potassium::public_key<ed25519> public_key;
    /// Private signing key in guarded memory.
    potassium::secret_key<signing_key_tag> secret_key;

    /// Generate a random key pair directly in its final storage.
    /// @throws std::bad_alloc If allocation fails.
    /// @throws crypto_error If key generation fails.
    keypair();

    /// @pre Populate both halves with a matching pair before use.
    explicit keypair(for_overwrite_t);
};

/// Generate a random key pair into caller-owned storage.
/// @pre The destinations are disjoint.
std::expected<void, errc> generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret, std::nothrow_t) noexcept;
/// @overload
void generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret);

/// Derive a key pair from a confidential seed into caller-owned storage.
/// @pre The destinations are disjoint from one another and from the seed.
std::expected<void, errc> generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret, key_ref<seed_tag> seed, std::nothrow_t) noexcept;
/// @overload
void generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret, key_ref<seed_tag> seed);

/// Generate a random key pair with a guarded signing key.
std::expected<keypair, errc> generate_keypair(std::nothrow_t) noexcept;
/// @overload
keypair generate_keypair();

/// Derive a guarded key pair from a confidential seed.
std::expected<keypair, errc> generate_keypair(key_ref<seed_tag> seed, std::nothrow_t) noexcept;
/// @overload
keypair generate_keypair(key_ref<seed_tag> seed);

/// Extract the public key encoded in an Ed25519 signing key.
std::expected<public_key<ed25519>, errc> public_key_from_secret_key(signing_key_ref key, std::nothrow_t) noexcept;
/// @overload
public_key<ed25519> public_key_from_secret_key(signing_key_ref key);

/// Extract the seed encoded in an Ed25519 signing key.
/// @pre The output is disjoint from the signing key.
std::expected<void, errc> seed_from_secret_key_into(signing_key_ref key, key_out<seed_tag> out, std::nothrow_t) noexcept;
/// @overload
void seed_from_secret_key_into(signing_key_ref key, key_out<seed_tag> out);

/// Extract the seed encoded in an Ed25519 signing key into guarded storage.
std::expected<secret_key<seed_tag>, errc> seed_from_secret_key(signing_key_ref key, std::nothrow_t) noexcept;
/// @overload
secret_key<seed_tag> seed_from_secret_key(signing_key_ref key);

/// Write the Ed25519 signature followed by the message bytes.
/// @pre The message length is at most algorithm_traits<ed25519>::messagebytes_max.
/// @pre Output is disjoint from all inputs and holds message.size() plus signature_size bytes.
std::expected<void, errc> sign_into(signing_key_ref key, std::span<std::byte const> message, std::span<std::byte> out, std::nothrow_t) noexcept;
/// @overload
void sign_into(signing_key_ref key, std::span<std::byte const> message, std::span<std::byte> out);

/// Return the Ed25519 signature followed by the message bytes.
/// @pre The message length is at most algorithm_traits<ed25519>::messagebytes_max.
std::expected<std::vector<std::byte>, errc> sign(signing_key_ref key, std::span<std::byte const> message, std::nothrow_t) noexcept;
/// @overload
std::vector<std::byte> sign(signing_key_ref key, std::span<std::byte const> message);

/// Verify an Ed25519 signed message and copy the message to the destination.
/// @pre Output is disjoint from all inputs and, for a complete signed message, holds signed_message.size() minus signature_size bytes.
/// @note Verification failure may clear the output.
std::expected<void, errc> open_into(verification_key_ref key, std::span<std::byte const> signed_message, std::span<std::byte> out, std::nothrow_t) noexcept;
/// @overload
void open_into(verification_key_ref key, std::span<std::byte const> signed_message, std::span<std::byte> out);

/// Verify an Ed25519 signed message and return the message in guarded storage.
std::expected<secure_buffer, errc> open(verification_key_ref key, std::span<std::byte const> signed_message, std::nothrow_t) noexcept;
/// @overload
secure_buffer open(verification_key_ref key, std::span<std::byte const> signed_message);

/// Sign a message and return a separate Ed25519 signature.
/// @pre The message length is at most algorithm_traits<ed25519>::messagebytes_max.
std::expected<signature, errc> sign_detached(signing_key_ref key, std::span<std::byte const> message, std::nothrow_t) noexcept;
/// @overload
signature sign_detached(signing_key_ref key, std::span<std::byte const> message);

/// Verify a detached Ed25519 signature against its message.
std::expected<void, errc> verify_detached(verification_key_ref key, std::span<std::byte const> message, signature const& sig, std::nothrow_t) noexcept;
/// @overload
void verify_detached(verification_key_ref key, std::span<std::byte const> message, signature const& sig);

/// Backend state type for caller-provided Ed25519ph storage.
using state_type = crypto_sign_ed25519ph_state;

/// Immobile, inline storage that can back an Ed25519ph operation.
class inplace_state
{
public:
    inplace_state() = default;
    inplace_state(inplace_state const&) = delete;
    inplace_state& operator=(inplace_state const&) = delete;
    ~inplace_state();

    /// @return State to lend to a state_storage handle.
    state_type& get() & noexcept { return state_; }

private:
    state_type state_{};
};

/// Move-only handle to idle Ed25519ph state storage.
class state_storage
{
public:
    /// Allocate state in guarded memory.
    state_storage();

    /// Wipe and borrow preallocated state from inline storage or a custom owner.
    /// @pre The state outlives the handle and any operation that takes ownership of it.
    /// @pre The state is reserved for exclusive use by this handle and its successors.
    explicit state_storage(state_type& state) noexcept;

    /// Transfer storage and empty the source handle.
    state_storage(state_storage&& other) noexcept;
    /// Release the current storage and take storage from the source handle.
    state_storage& operator=(state_storage&& other) noexcept;

    /// @return Whether this handle holds storage for a new operation.
    [[nodiscard]] explicit operator bool() const noexcept;

private:
    friend class prehash;
    using guarded_state = std::indirect<state_type, allocator<state_type>>;
    std::variant<std::monostate, guarded_state, std::reference_wrapper<state_type>> storage_;

    state_type& get() noexcept;
};

/// Move-only Ed25519ph operation for signing or verifying a multipart message.
class prehash
{
public:
    /// Transfer state and close the source.
    prehash(prehash&& other) noexcept;
    /// Wipe the previous state and take the source state.
    prehash& operator=(prehash&& other) noexcept;
    ~prehash();

    /// Add the next chunk to an active operation.
    /// @pre The chunk is disjoint from the operation state.
    std::expected<void, errc> update(std::span<std::byte const> chunk, std::nothrow_t) noexcept;
    /// @overload
    void update(std::span<std::byte const> chunk);

    /// Sign the accumulated message and wipe its state.
    /// @pre The signing key is disjoint from the operation state.
    std::expected<prehash_signature, errc> finish_sign(signing_key_ref key, std::nothrow_t) noexcept;
    /// @overload
    prehash_signature finish_sign(signing_key_ref key);

    /// Verify the accumulated message and wipe its state, including on verification failure.
    /// @pre The verification key and signature are disjoint from the operation state.
    std::expected<void, errc> finish_verify(verification_key_ref key, prehash_signature const& sig, std::nothrow_t) noexcept;
    /// @overload
    void finish_verify(verification_key_ref key, prehash_signature const& sig);

    /// Close the operation, wipe its state and return the storage for another operation.
    /// Also works after finalization.
    [[nodiscard]] state_storage close_for_reuse() && noexcept;

private:
    friend std::expected<prehash, errc> start_prehash(state_storage&& storage, std::nothrow_t) noexcept;
    explicit prehash(state_storage&& storage) noexcept;
    void close() noexcept;

    state_storage storage_;
    bool active_ = true;
};

/// Start an Ed25519ph operation with guarded storage.
std::expected<prehash, errc> start_prehash(std::nothrow_t) noexcept;
/// @overload
prehash start_prehash();

/// Start an Ed25519ph operation, consuming the supplied storage handle.
std::expected<prehash, errc> start_prehash(state_storage&& storage, std::nothrow_t) noexcept;
/// @overload
prehash start_prehash(state_storage&& storage);
}  // namespace potassium::sign
