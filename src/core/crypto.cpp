// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

export module potassium.core:crypto;
import :memory;
import std;

namespace potassium::detail
{
template <class Traits>
concept AuthenticatedEncryptionTraits = requires {
    typename std::integral_constant<std::size_t, Traits::nonce_size>;
    typename std::integral_constant<std::size_t, Traits::mac_size>;
    typename std::integral_constant<std::size_t, Traits::messagebytes_max>;
};
}  // namespace potassium::detail

export namespace potassium
{
/// Operational failures returned by the nonthrowing API.
enum class errc
{
    /// Encryption or authentication failed.
    crypto_failed,
    /// The requested output storage could not be allocated.
    allocation_failed,
};

/// Exception raised when a cryptographic operation fails, including authentication failure.
class crypto_error : public std::runtime_error
{
public:
    /// Constructs an exception with a generic diagnostic.
    crypto_error();
};

/// @param error Failure reported by a nonthrowing operation.
/// @throws std::bad_alloc For errc::allocation_failed.
/// @throws crypto_error For errc::crypto_failed.
[[noreturn]] void throw_error(errc error);
/// @param[out] bytes Destination to fill with cryptographically secure random bytes.
void random_fill(std::span<std::byte> bytes) noexcept;
/// @param[out] bytes Storage to securely overwrite with zeros.
void wipe(std::span<std::byte> bytes) noexcept;
/// Compile-time dimensions and limits of an algorithm.
/// @tparam A Algorithm identity tag.
template <class A>
struct algorithm_traits;

/// Traits providing compile-time byte sizes and the message limit for secret-key authenticated encryption.
template <class Traits>
concept SecretKeyAlgorithmTraits = detail::AuthenticatedEncryptionTraits<Traits> && requires { typename std::integral_constant<std::size_t, Traits::key_size>; };

/// Traits providing compile-time byte sizes and the message limit for public-key authenticated encryption.
template <class Traits>
concept PublicKeyAlgorithmTraits = detail::AuthenticatedEncryptionTraits<Traits> && requires {
    typename std::integral_constant<std::size_t, Traits::public_key_size>;
    typename std::integral_constant<std::size_t, Traits::secret_key_size>;
    typename std::integral_constant<std::size_t, Traits::seed_size>;
    typename std::integral_constant<std::size_t, Traits::precomputed_key_size>;
};

/// Algorithm tag whose @ref algorithm_traits satisfy either authenticated-encryption trait contract.
template <class A>
concept Algorithm = SecretKeyAlgorithmTraits<algorithm_traits<A>> || PublicKeyAlgorithmTraits<algorithm_traits<A>>;

/// Specialize for each confidential key purpose with a static constexpr std::size_t size in bytes.
/// @tparam KeyTag Tag identifying the purpose of the key.
template <class KeyTag>
struct key_traits;

/// Read-only borrowed key. @pre The source storage outlives every use.
template <class KeyTag>
class key_ref
{
public:
    /// Fixed-size read-only view of the underlying bytes.
    using span_type = std::span<std::byte const, key_traits<KeyTag>::size>;

    /// @param bytes Caller-owned key material.
    /// @pre The key storage outlives every use of the view.
    explicit constexpr key_ref(span_type bytes) noexcept
        : bytes_(bytes)
    {
    }

    /// @return The borrowed byte range.
    constexpr span_type bytes() const noexcept { return bytes_; }

private:
    span_type bytes_;
};

/// Read-only borrowed nonce. @pre The source storage outlives every use.
template <Algorithm A>
class nonce_ref
{
public:
    /// Fixed-size read-only view of the underlying bytes.
    using span_type = std::span<std::byte const, algorithm_traits<A>::nonce_size>;

    /// @param bytes Caller-owned nonce bytes.
    /// @pre The nonce storage outlives every use of the view.
    explicit constexpr nonce_ref(span_type bytes) noexcept
        : bytes_(bytes)
    {
    }

    /// @return The borrowed byte range.
    constexpr span_type bytes() const noexcept { return bytes_; }

private:
    span_type bytes_;
};

/// Fixed-length guarded storage. The allocator wipes released bytes.
class secure_buffer
{
    std::vector<std::byte, allocator<std::byte>> storage_;

public:
    /// @param size Number of zero-initialized bytes in the guarded allocation.
    explicit secure_buffer(std::size_t size);
    /// Transfers ownership of the guarded storage.
    secure_buffer(secure_buffer&&) noexcept = default;
    /// Releases the current storage and takes ownership of the source storage.
    secure_buffer& operator=(secure_buffer&&) noexcept = default;

    /// @return Writable bytes in the guarded allocation.
    std::span<std::byte> bytes() & noexcept { return storage_; }

    /// @return Read-only bytes in the guarded allocation.
    std::span<std::byte const> bytes() const& noexcept { return storage_; }

    std::span<std::byte const> bytes() const&& = delete;
};

/// Copyable public nonce. Default initialization yields zero bytes.
template <Algorithm A>
class nonce_buffer
{
public:
    /// Nonce bytes in transmission order.
    std::array<std::byte, algorithm_traits<A>::nonce_size> storage{};

    /// @pre The owner remains alive while the view is in use.
    nonce_ref<A> ref() const& noexcept { return nonce_ref<A>{storage}; }

    nonce_ref<A> ref() && = delete;
    nonce_ref<A> ref() const&& = delete;

    /// @return A read-only view valid for the lifetime of this nonce.
    operator nonce_ref<A>() const& noexcept { return ref(); }

    operator nonce_ref<A>() && = delete;
    operator nonce_ref<A>() const&& = delete;
};

/// Read-only borrowed public key. @pre The source storage outlives every use.
template <class A>
    requires PublicKeyAlgorithmTraits<algorithm_traits<A>>
class public_key_ref
{
public:
    /// Fixed-size read-only view of the underlying bytes.
    using span_type = std::span<std::byte const, algorithm_traits<A>::public_key_size>;

    /// @param bytes Caller-owned public key bytes.
    /// @pre The public key storage outlives every use of the view.
    explicit constexpr public_key_ref(span_type bytes) noexcept
        : bytes_(bytes)
    {
    }

    /// @return The borrowed byte range.
    constexpr span_type bytes() const noexcept { return bytes_; }

private:
    span_type bytes_;
};

/// Copyable public key. Default initialization yields zero bytes.
template <class A>
    requires PublicKeyAlgorithmTraits<algorithm_traits<A>>
class public_key
{
public:
    /// Public key bytes in transmission order.
    std::array<std::byte, algorithm_traits<A>::public_key_size> storage{};

    /// @pre The owner remains alive while the view is in use.
    public_key_ref<A> ref() const& noexcept { return public_key_ref<A>{storage}; }

    public_key_ref<A> ref() && = delete;
    public_key_ref<A> ref() const&& = delete;

    /// @return A read-only view valid for the lifetime of this public key.
    operator public_key_ref<A>() const& noexcept { return ref(); }

    operator public_key_ref<A>() && = delete;
    operator public_key_ref<A>() const&& = delete;
};

/// Immobile stack key, generated on construction and wiped on destruction.
template <class KeyTag>
class key_buffer_storage
{
    std::array<std::byte, key_traits<KeyTag>::size> storage_{};

public:
    /// Writable destination for key generation or derivation.
    std::span<std::byte, key_traits<KeyTag>::size> writable_bytes() & noexcept { return storage_; }

    /// Generates a fresh key in the stack buffer.
    key_buffer_storage() { random_fill(storage_); }

    /// Wipes the key bytes before releasing the buffer.
    ~key_buffer_storage() { wipe(storage_); }

    key_buffer_storage(key_buffer_storage const&) = delete;
    key_buffer_storage& operator=(key_buffer_storage const&) = delete;

    /// @pre The owner remains alive while the view is in use.
    key_ref<KeyTag> ref() const& noexcept { return key_ref<KeyTag>{storage_}; }

    /// Borrowing from a temporary owner would allow a dangling key view.
    key_ref<KeyTag> ref() && = delete ("A key view can dangle when borrowed from a temporary owner");
    /// Borrowing from a temporary owner would allow a dangling key view.
    key_ref<KeyTag> ref() const&& = delete ("A key view can dangle when borrowed from a temporary owner");

    /// @return A borrowed view of this key.
    /// @see ref()
    operator key_ref<KeyTag>() const& noexcept { return ref(); }

    /// Borrowing from a temporary owner would allow a dangling key view.
    operator key_ref<KeyTag>() && = delete ("A key view can dangle when borrowed from a temporary owner");
    /// Borrowing from a temporary owner would allow a dangling key view.
    operator key_ref<KeyTag>() const&& = delete ("A key view can dangle when borrowed from a temporary owner");
};

/// Move-only guarded key, generated directly in its allocation.
template <class KeyTag>
class secret_key
{
    using key_bytes = std::array<std::byte, key_traits<KeyTag>::size>;
    std::indirect<key_bytes, allocator<key_bytes>> storage_;

public:
    /// Generates a fresh key directly in guarded storage.
    secret_key() { random_fill(writable_bytes()); }

    secret_key(secret_key const&) = delete;
    secret_key& operator=(secret_key const&) = delete;

    /// Transfers ownership of the guarded allocation.
    secret_key(secret_key&&) noexcept = default;
    /// Releases the current allocation and takes ownership of the source allocation.
    secret_key& operator=(secret_key&&) noexcept = default;

    /// Writable destination for key generation or derivation.
    /// @pre The owner has a live allocation and retains it while the span is in use.
    std::span<std::byte, key_traits<KeyTag>::size> writable_bytes() & noexcept { return *storage_; }

    /// @pre The owner has a live allocation and retains it while the view is in use.
    key_ref<KeyTag> ref() const& noexcept { return key_ref<KeyTag>{*storage_}; }

    /// Borrowing from a temporary owner would allow a dangling key view.
    key_ref<KeyTag> ref() && = delete ("A key view can dangle when borrowed from a temporary owner");
    /// Borrowing from a temporary owner would allow a dangling key view.
    key_ref<KeyTag> ref() const&& = delete ("A key view can dangle when borrowed from a temporary owner");

    /// @return A borrowed view of this key.
    /// @see ref()
    /// @pre The owner has a live allocation and retains it while the view is in use.
    operator key_ref<KeyTag>() const& noexcept { return ref(); }

    /// Borrowing from a temporary owner would allow a dangling key view.
    operator key_ref<KeyTag>() && = delete ("A key view can dangle when borrowed from a temporary owner");
    /// Borrowing from a temporary owner would allow a dangling key view.
    operator key_ref<KeyTag>() const&& = delete ("A key view can dangle when borrowed from a temporary owner");
};

/// @tparam A Algorithm whose nonce size determines the number of random bytes.
/// @return A freshly generated nonce for A.
template <Algorithm A>
nonce_buffer<A> generate_nonce() noexcept
{
    nonce_buffer<A> nonce;
    random_fill(nonce.storage);
    return nonce;
}

}  // namespace potassium
