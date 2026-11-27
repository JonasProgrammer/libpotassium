// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

/// @brief X-Wing key encapsulation.
export module potassium.kem;

export import potassium.core;
import std;

export namespace potassium::kem
{
/// X-Wing key encapsulation algorithm tag.
struct xwing;
/// Confidential decapsulation key purpose.
struct decapsulation_key_tag;
/// Confidential key-pair seed purpose.
struct seed_tag;
/// Confidential shared secret purpose.
struct shared_secret_tag;
}  // namespace potassium::kem

export namespace potassium
{
/// Encoded key and ciphertext dimensions for X-Wing.
template <>
struct algorithm_traits<kem::xwing>
{
    /// Encoded encapsulation key length in bytes.
    static constexpr std::size_t public_key_size = crypto_kem_PUBLICKEYBYTES;
    /// Encoded decapsulation key length in bytes.
    static constexpr std::size_t secret_key_size = crypto_kem_SECRETKEYBYTES;
    /// Key-pair seed length in bytes.
    static constexpr std::size_t seed_size = crypto_kem_SEEDBYTES;
    /// Encapsulation ciphertext length in bytes.
    static constexpr std::size_t ciphertext_size = crypto_kem_CIPHERTEXTBYTES;
    /// Shared secret length in bytes.
    static constexpr std::size_t shared_secret_size = crypto_kem_SHAREDSECRETBYTES;
};

/// Storage extent for a private X-Wing decapsulation key.
template <>
struct key_traits<kem::decapsulation_key_tag>
{
    /// Decapsulation key length in bytes.
    static constexpr std::size_t size = algorithm_traits<kem::xwing>::secret_key_size;
};

/// Storage extent and random generator for an X-Wing seed.
template <>
struct key_traits<kem::seed_tag>
{
    /// Generator for a fresh seed.
    using generator = random_key_generator;
    /// Seed length in bytes.
    static constexpr std::size_t size = algorithm_traits<kem::xwing>::seed_size;
};

/// Storage extent for a shared X-Wing secret.
template <>
struct key_traits<kem::shared_secret_tag>
{
    /// Shared secret length in bytes.
    static constexpr std::size_t size = algorithm_traits<kem::xwing>::shared_secret_size;
};
}  // namespace potassium

/// X-Wing key generation, encapsulation, and decapsulation.
export namespace potassium::kem
{
/// Borrowed public encapsulation key.
using encapsulation_key_ref = public_key_ref<xwing>;
/// Borrowed private decapsulation key.
using decapsulation_key_ref = key_ref<decapsulation_key_tag>;

/// Public encapsulation key and guarded decapsulation key.
struct keypair
{
    /// Publishable encapsulation key.
    potassium::public_key<xwing> public_key;
    /// Private decapsulation key in guarded memory.
    potassium::secret_key<decapsulation_key_tag> secret_key;

    /// Generate a random key pair directly in its final storage.
    /// @throws std::bad_alloc If allocation fails.
    /// @throws crypto_error If key generation fails.
    keypair();

    /// @pre Populate both halves with a matching pair before use.
    explicit keypair(for_overwrite_t);
};

/// Copyable public X-Wing ciphertext.
struct ciphertext_buffer
{
    /// Ciphertext bytes in transmission order.
    std::array<std::byte, algorithm_traits<xwing>::ciphertext_size> storage{};

    /// @return Writable bytes for importing ciphertext from the wire.
    constexpr std::span<std::byte, algorithm_traits<xwing>::ciphertext_size> bytes() & noexcept { return storage; }

    /// @return Read-only ciphertext bytes.
    constexpr std::span<std::byte const, algorithm_traits<xwing>::ciphertext_size> bytes() const& noexcept { return storage; }

    /// Borrowing requires a live lvalue owner.
    std::span<std::byte const, algorithm_traits<xwing>::ciphertext_size> bytes() const&& = delete;
};

/// X-Wing ciphertext and the associated guarded shared secret.
struct encapsulation
{
    /// Public ciphertext to send to the recipient.
    ciphertext_buffer ciphertext;
    /// Derived shared secret in guarded memory.
    secret_key<shared_secret_tag> shared_secret;
};

/// Generate a random key pair into the caller's storage.
/// @pre The destinations are disjoint.
std::expected<void, errc> generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret, std::nothrow_t) noexcept;
/// @overload
void generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret);

/// Derive a key pair from a confidential seed into the caller's storage.
/// @pre The destinations are disjoint from one another and from the seed.
std::expected<void, errc> generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret, key_ref<seed_tag> seed, std::nothrow_t) noexcept;
/// @overload
void generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret, key_ref<seed_tag> seed);

/// Generate a random key pair with a guarded decapsulation key.
std::expected<keypair, errc> generate_keypair(std::nothrow_t) noexcept;
/// @overload
keypair generate_keypair();

/// Derive a guarded key pair from a confidential seed.
std::expected<keypair, errc> generate_keypair(key_ref<seed_tag> seed, std::nothrow_t) noexcept;
/// @overload
keypair generate_keypair(key_ref<seed_tag> seed);

/// Encapsulate a fresh shared secret into the caller's storage.
/// @pre The destinations are disjoint from one another and from the public key.
/// @note Cryptographic failure wipes the shared secret destination.
std::expected<void, errc> encapsulate_into(encapsulation_key_ref key, ciphertext_buffer& ciphertext, key_out<shared_secret_tag> shared_secret, std::nothrow_t) noexcept;
/// @overload
void encapsulate_into(encapsulation_key_ref key, ciphertext_buffer& ciphertext, key_out<shared_secret_tag> shared_secret);

/// Encapsulate a fresh guarded shared secret for the recipient public key.
std::expected<encapsulation, errc> encapsulate(encapsulation_key_ref key, std::nothrow_t) noexcept;
/// @overload
encapsulation encapsulate(encapsulation_key_ref key);

/// Decapsulate into the caller's storage, preserving X-Wing's implicit rejection behavior.
/// @pre The destination is disjoint from all inputs.
/// @note Invalid ciphertext length or backend failure wipes the destination.
/// @note Some invalid ciphertexts yield a fallback secret and report success.
std::expected<void, errc> decapsulate_into(decapsulation_key_ref key, std::span<std::byte const> ciphertext, key_out<shared_secret_tag> shared_secret, std::nothrow_t) noexcept;
/// @overload
void decapsulate_into(decapsulation_key_ref key, std::span<std::byte const> ciphertext, key_out<shared_secret_tag> shared_secret);

/// Return the decapsulated secret in guarded storage.
/// @note Some invalid ciphertexts yield a fallback secret and report success.
std::expected<secret_key<shared_secret_tag>, errc> decapsulate(decapsulation_key_ref key, std::span<std::byte const> ciphertext, std::nothrow_t) noexcept;
/// @overload
secret_key<shared_secret_tag> decapsulate(decapsulation_key_ref key, std::span<std::byte const> ciphertext);
}  // namespace potassium::kem
