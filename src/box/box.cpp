// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

/// @brief Public-key authenticated encryption using Curve25519 with XSalsa20-Poly1305 or XChaCha20-Poly1305.
/// @details Import @c potassium.box to use the key-pair and message operations in @ref potassium::box.
export module potassium.box;
import potassium.core;
import std;

/// @brief Seal and open messages using a local private key and a peer public key.
/// @details For repeated messages with one peer, use @c precompute once and pass the shared key to @c seal or @c open.
/// Establish the peer's identity before using its public key.
/// Both participants can produce valid ciphertext and derive the same key in either direction.
/// Coordinate explicit nonces across both directions, or let seal generate a random nonce.
/// Static key pairs provide no forward secrecy after private-key compromise.
export namespace potassium::box
{

/// Curve25519 with XSalsa20-Poly1305.
struct curve25519xsalsa20poly1305;

/// Curve25519 with XChaCha20-Poly1305.
struct curve25519xchacha20poly1305;

/// Default algorithm for key-pair generation.
using box_default = curve25519xsalsa20poly1305;

/// Confidential local key used in key agreement.
template <class A>
struct private_key_tag;

/// Confidential pairwise key derived by precompute.
template <class A>
struct precomputed_key_tag;

/// Result of sealing with a generated nonce.
/// @tparam A Box algorithm used to seal the message.
template <class A>
struct seal_result
{
    /// Authentication tag followed by encrypted message bytes.
    std::vector<std::byte> ciphertext;
    /// Nonce required to authenticate and decrypt the ciphertext.
    nonce_buffer<A> nonce;
};

/// Local identity for sender-authenticated encryption.
template <class A>
struct keypair
{
    /// Public key to distribute to peers.
    potassium::public_key<A> public_key;
    /// Local private key in guarded storage.
    potassium::secret_key<private_key_tag<A>> secret_key;

    /// Generate a matching pair directly in its final storage.
    keypair()
        requires std::default_initializable<typename key_traits<keypair>::generator> && KeyPairGenerator<typename key_traits<keypair>::generator, A>
        : keypair(typename key_traits<keypair>::generator{})
    {
    }

    /// Invoke generate once on both destinations and propagate any exception.
    template <KeyPairGenerator<A> G>
    explicit keypair(G&& generate)
        : keypair(for_overwrite)
    {
        std::forward<G>(generate)(public_key, secret_key.writable_bytes());
    }

    /// @warning Both halves contain publicly known all-zero bytes.
    explicit keypair(zero_t)
        : public_key{}
        , secret_key(zero)
    {
    }

    /// @pre Populate both halves with a matching pair before cryptographic use.
    explicit keypair(for_overwrite_t)
        : secret_key(for_overwrite)
    {
    }

    /// Adopt a pair from existing owners.
    /// @pre The public key corresponds to the private key.
    keypair(potassium::public_key<A> pub, potassium::secret_key<private_key_tag<A>>&& secret) noexcept
        : public_key(pub)
        , secret_key(std::move(secret))
    {
    }
};

}  // namespace potassium::box

export namespace potassium
{

/// Byte dimensions and plaintext limit for @c box::curve25519xsalsa20poly1305.
template <>
struct algorithm_traits<box::curve25519xsalsa20poly1305>
{
    /// Encoded public key length in bytes.
    static constexpr std::size_t public_key_size = crypto_box_PUBLICKEYBYTES;
    /// Local private key length in bytes.
    static constexpr std::size_t secret_key_size = crypto_box_SECRETKEYBYTES;
    /// Key-pair seed length in bytes.
    static constexpr std::size_t seed_size = crypto_box_SEEDBYTES;
    /// Shared key length in bytes.
    static constexpr std::size_t precomputed_key_size = crypto_box_BEFORENMBYTES;
    /// Nonce length in bytes.
    static constexpr std::size_t nonce_size = crypto_box_NONCEBYTES;
    /// Authentication tag length in bytes.
    static constexpr std::size_t mac_size = crypto_box_MACBYTES;
    /// Maximum plaintext length in bytes.
    static constexpr std::size_t messagebytes_max = crypto_box_MESSAGEBYTES_MAX;
};

/// Byte dimensions and plaintext limit for @c box::curve25519xchacha20poly1305.
template <>
struct algorithm_traits<box::curve25519xchacha20poly1305>
{
    /// Encoded public key length in bytes.
    static constexpr std::size_t public_key_size = crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES;
    /// Local private key length in bytes.
    static constexpr std::size_t secret_key_size = crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES;
    /// Key-pair seed length in bytes.
    static constexpr std::size_t seed_size = crypto_box_curve25519xchacha20poly1305_SEEDBYTES;
    /// Shared key length in bytes.
    static constexpr std::size_t precomputed_key_size = crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES;
    /// Nonce length in bytes.
    static constexpr std::size_t nonce_size = crypto_box_curve25519xchacha20poly1305_NONCEBYTES;
    /// Authentication tag length in bytes.
    static constexpr std::size_t mac_size = crypto_box_curve25519xchacha20poly1305_MACBYTES;
    /// Maximum plaintext length in bytes.
    static constexpr std::size_t messagebytes_max = crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX;
};

/// Storage extent for a local private key.
template <class A>
struct key_traits<box::private_key_tag<A>>
{
    /// Default generator for this key purpose.
    using generator = random_key_generator;

    /// Confidential key length in bytes.
    static constexpr std::size_t size = algorithm_traits<A>::secret_key_size;
};

/// Storage extent for a shared key.
template <class A>
struct key_traits<box::precomputed_key_tag<A>>
{
    /// Confidential key length in bytes.
    static constexpr std::size_t size = algorithm_traits<A>::precomputed_key_size;
};
}  // namespace potassium

export namespace potassium::box
{

/// @name Curve25519 with XSalsa20-Poly1305 - keys
/// @{

/// Borrowed local private key.
using xsalsa_private_ref = key_ref<private_key_tag<curve25519xsalsa20poly1305>>;
/// Borrowed shared key for a peer.
using xsalsa_precomputed_ref = key_ref<precomputed_key_tag<curve25519xsalsa20poly1305>>;

/// Generate a key pair directly in caller-owned storage.
/// @param[out] pub Public key to distribute to peers.
/// @param[out] secret Private key bytes. The caller protects and wipes this storage.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Public and secret destinations are disjoint.
/// @return Empty success, or errc::crypto_failed if key generation fails.
std::expected<void, errc> generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, std::span<std::byte, 32> secret, std::nothrow_t tag) noexcept;

/// Generate a key pair directly in caller-owned storage.
/// @param[out] pub Public key to distribute to peers.
/// @param[out] secret Private key bytes. The caller protects and wipes this storage.
/// @pre Public and secret destinations are disjoint.
/// @throws crypto_error If key generation fails.
void generate_keypair_into(public_key<curve25519xsalsa20poly1305>& pub, std::span<std::byte, 32> secret);

/// Derive a guarded shared key for repeated communication with a peer.
/// @param key Local private key.
/// @param peer Public key of the peer.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Shared key, or errc::crypto_failed for a rejected peer key or errc::allocation_failed if allocation fails.
std::expected<secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>>, errc> precompute(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::nothrow_t tag) noexcept;

/// Derive a guarded shared key for repeated communication with a peer.
/// @param key Local private key.
/// @param peer Public key of the peer.
/// @return Shared key usable for sealing and opening.
/// @throws crypto_error If the backend rejects the peer key.
/// @throws std::bad_alloc If allocation fails.
secret_key<precomputed_key_tag<curve25519xsalsa20poly1305>> precompute(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer);

/// @}

/// @name Curve25519 with XSalsa20-Poly1305 - direct operations
/// @{

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @throws crypto_error If encryption fails.
void seal_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return An empty success value, or errc::crypto_failed on encryption failure.
std::expected<void, errc> seal_into(xsalsa_private_ref key,
                                    public_key_ref<curve25519xsalsa20poly1305> peer,
                                    std::span<std::byte const> plaintext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xsalsa20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @throws crypto_error If authentication fails.
void open_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @return An empty success value, or errc::crypto_failed on authentication failure.
std::expected<void, errc> open_into(xsalsa_private_ref key,
                                    public_key_ref<curve25519xsalsa20poly1305> peer,
                                    std::span<std::byte const> ciphertext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xsalsa20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce.
/// @throws crypto_error If encryption fails.
nonce_buffer<curve25519xsalsa20poly1305> seal_into(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce, or errc::crypto_failed on encryption failure.
std::expected<nonce_buffer<curve25519xsalsa20poly1305>, errc> seal_into(xsalsa_private_ref key,
                                                                        public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                        std::span<std::byte const> plaintext,
                                                                        std::span<std::byte> out,
                                                                        std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
std::vector<std::byte> seal(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<std::vector<std::byte>, errc> seal(xsalsa_private_ref key,
                                                 public_key_ref<curve25519xsalsa20poly1305> peer,
                                                 std::span<std::byte const> plaintext,
                                                 nonce_ref<curve25519xsalsa20poly1305> nonce,
                                                 std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
seal_result<curve25519xsalsa20poly1305> seal(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> plaintext);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<seal_result<curve25519xsalsa20poly1305>, errc> seal(xsalsa_private_ref key,
                                                                  public_key_ref<curve25519xsalsa20poly1305> peer,
                                                                  std::span<std::byte const> plaintext,
                                                                  std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xsalsa_private_ref key,
                                        public_key_ref<curve25519xsalsa20poly1305> peer,
                                        std::span<std::byte const> ciphertext,
                                        nonce_ref<curve25519xsalsa20poly1305> nonce,
                                        std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param sealed Combined ciphertext and its nonce.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, seal_result<curve25519xsalsa20poly1305> const& sealed);

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param sealed Combined ciphertext and its nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xsalsa_private_ref key, public_key_ref<curve25519xsalsa20poly1305> peer, seal_result<curve25519xsalsa20poly1305> const& sealed, std::nothrow_t tag) noexcept;

/// @}

/// @name Curve25519 with XSalsa20-Poly1305 - precomputed operations
/// @{

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @throws crypto_error If encryption fails.
void seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return An empty success value, or errc::crypto_failed on encryption failure.
std::expected<void, errc> seal_into(xsalsa_precomputed_ref key,
                                    std::span<std::byte const> plaintext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xsalsa20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @throws crypto_error If authentication fails.
void open_into(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @return An empty success value, or errc::crypto_failed on authentication failure.
std::expected<void, errc> open_into(xsalsa_precomputed_ref key,
                                    std::span<std::byte const> ciphertext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xsalsa20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce.
/// @throws crypto_error If encryption fails.
nonce_buffer<curve25519xsalsa20poly1305> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce, or errc::crypto_failed on encryption failure.
std::expected<nonce_buffer<curve25519xsalsa20poly1305>, errc> seal_into(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
std::vector<std::byte> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<std::vector<std::byte>, errc> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
seal_result<curve25519xsalsa20poly1305> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xsalsa20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<seal_result<curve25519xsalsa20poly1305>, errc> seal(xsalsa_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xsalsa_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xsalsa20poly1305> nonce, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param sealed Combined ciphertext and its nonce.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xsalsa_precomputed_ref key, seal_result<curve25519xsalsa20poly1305> const& sealed);

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param sealed Combined ciphertext and its nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xsalsa_precomputed_ref key, seal_result<curve25519xsalsa20poly1305> const& sealed, std::nothrow_t tag) noexcept;

/// @}

/// @name Curve25519 with XChaCha20-Poly1305 - keys
/// @{

/// Borrowed local private key.
using xchacha_private_ref = key_ref<private_key_tag<curve25519xchacha20poly1305>>;
/// Borrowed shared key for a peer.
using xchacha_precomputed_ref = key_ref<precomputed_key_tag<curve25519xchacha20poly1305>>;

/// Generate a key pair directly in caller-owned storage.
/// @param[out] pub Public key to distribute to peers.
/// @param[out] secret Private key bytes. The caller protects and wipes this storage.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Public and secret destinations are disjoint.
/// @return Empty success, or errc::crypto_failed if key generation fails.
std::expected<void, errc> generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub, std::span<std::byte, 32> secret, std::nothrow_t tag) noexcept;

/// Generate a key pair directly in caller-owned storage.
/// @param[out] pub Public key to distribute to peers.
/// @param[out] secret Private key bytes. The caller protects and wipes this storage.
/// @pre Public and secret destinations are disjoint.
/// @throws crypto_error If key generation fails.
void generate_keypair_into(public_key<curve25519xchacha20poly1305>& pub, std::span<std::byte, 32> secret);

/// Derive a guarded shared key for repeated communication with a peer.
/// @param key Local private key.
/// @param peer Public key of the peer.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Shared key, or errc::crypto_failed for a rejected peer key or errc::allocation_failed if allocation fails.
std::expected<secret_key<precomputed_key_tag<curve25519xchacha20poly1305>>, errc> precompute(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::nothrow_t tag) noexcept;

/// Derive a guarded shared key for repeated communication with a peer.
/// @param key Local private key.
/// @param peer Public key of the peer.
/// @return Shared key usable for sealing and opening.
/// @throws crypto_error If the backend rejects the peer key.
/// @throws std::bad_alloc If allocation fails.
secret_key<precomputed_key_tag<curve25519xchacha20poly1305>> precompute(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer);

/// @}

/// @name Curve25519 with XChaCha20-Poly1305 - direct operations
/// @{

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @throws crypto_error If encryption fails.
void seal_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return An empty success value, or errc::crypto_failed on encryption failure.
std::expected<void, errc> seal_into(xchacha_private_ref key,
                                    public_key_ref<curve25519xchacha20poly1305> peer,
                                    std::span<std::byte const> plaintext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @throws crypto_error If authentication fails.
void open_into(xchacha_private_ref key,
               public_key_ref<curve25519xchacha20poly1305> peer,
               std::span<std::byte const> ciphertext,
               std::span<std::byte> out,
               nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @return An empty success value, or errc::crypto_failed on authentication failure.
std::expected<void, errc> open_into(xchacha_private_ref key,
                                    public_key_ref<curve25519xchacha20poly1305> peer,
                                    std::span<std::byte const> ciphertext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce.
/// @throws crypto_error If encryption fails.
nonce_buffer<curve25519xchacha20poly1305> seal_into(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext, std::span<std::byte> out);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce, or errc::crypto_failed on encryption failure.
std::expected<nonce_buffer<curve25519xchacha20poly1305>, errc> seal_into(xchacha_private_ref key,
                                                                         public_key_ref<curve25519xchacha20poly1305> peer,
                                                                         std::span<std::byte const> plaintext,
                                                                         std::span<std::byte> out,
                                                                         std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
std::vector<std::byte> seal(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<std::vector<std::byte>, errc> seal(xchacha_private_ref key,
                                                 public_key_ref<curve25519xchacha20poly1305> peer,
                                                 std::span<std::byte const> plaintext,
                                                 nonce_ref<curve25519xchacha20poly1305> nonce,
                                                 std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
seal_result<curve25519xchacha20poly1305> seal(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> plaintext);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Local private key.
/// @param peer Recipient's public key.
/// @param plaintext Message bytes to encrypt.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<seal_result<curve25519xchacha20poly1305>, errc> seal(xchacha_private_ref key,
                                                                   public_key_ref<curve25519xchacha20poly1305> peer,
                                                                   std::span<std::byte const> plaintext,
                                                                   std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xchacha_private_ref key,
                                        public_key_ref<curve25519xchacha20poly1305> peer,
                                        std::span<std::byte const> ciphertext,
                                        nonce_ref<curve25519xchacha20poly1305> nonce,
                                        std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param sealed Combined ciphertext and its nonce.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, seal_result<curve25519xchacha20poly1305> const& sealed);

/// @brief Authenticate and decrypt a message.
/// @param key Local private key.
/// @param peer Sender's public key.
/// @param sealed Combined ciphertext and its nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xchacha_private_ref key, public_key_ref<curve25519xchacha20poly1305> peer, seal_result<curve25519xchacha20poly1305> const& sealed, std::nothrow_t tag) noexcept;

/// @}

/// @name Curve25519 with XChaCha20-Poly1305 - precomputed operations
/// @{

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @throws crypto_error If encryption fails.
void seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return An empty success value, or errc::crypto_failed on encryption failure.
std::expected<void, errc> seal_into(xchacha_precomputed_ref key,
                                    std::span<std::byte const> plaintext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @throws crypto_error If authentication fails.
void open_into(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @return An empty success value, or errc::crypto_failed on authentication failure.
std::expected<void, errc> open_into(xchacha_precomputed_ref key,
                                    std::span<std::byte const> ciphertext,
                                    std::span<std::byte> out,
                                    nonce_ref<curve25519xchacha20poly1305> nonce,
                                    std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce.
/// @throws crypto_error If encryption fails.
nonce_buffer<curve25519xchacha20poly1305> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce, or errc::crypto_failed on encryption failure.
std::expected<nonce_buffer<curve25519xchacha20poly1305>, errc> seal_into(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
std::vector<std::byte> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption by either participant with this key pair.
/// @return Combined ciphertext, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<std::vector<std::byte>, errc> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
seal_result<curve25519xchacha20poly1305> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext);
/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Shared key derived by precompute for this peer.
/// @param plaintext Message bytes to encrypt.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<curve25519xchacha20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<seal_result<curve25519xchacha20poly1305>, errc> seal(xchacha_precomputed_ref key, std::span<std::byte const> plaintext, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xchacha_precomputed_ref key, std::span<std::byte const> ciphertext, nonce_ref<curve25519xchacha20poly1305> nonce, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param sealed Combined ciphertext and its nonce.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xchacha_precomputed_ref key, seal_result<curve25519xchacha20poly1305> const& sealed);

/// @brief Authenticate and decrypt a message.
/// @param key Shared key derived by precompute for this peer.
/// @param sealed Combined ciphertext and its nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xchacha_precomputed_ref key, seal_result<curve25519xchacha20poly1305> const& sealed, std::nothrow_t tag) noexcept;

/// @}

}  // namespace potassium::box

export namespace potassium
{
/// Select the native Box generator for algorithms with a keypair backend.
template <class A>
    requires requires(public_key<A>& pub, std::span<std::byte, algorithm_traits<A>::secret_key_size> secret) { box::generate_keypair_into(pub, secret); }
struct key_traits<box::keypair<A>>
{
    struct generator
    {
        void operator()(public_key<A>& pub, std::span<std::byte, algorithm_traits<A>::secret_key_size> secret) const { box::generate_keypair_into(pub, secret); }
    };
};
}  // namespace potassium

export namespace potassium::box
{
/// @name Owning key-pair generation
/// @{

/// Generate a local key pair directly in its owning storage.
/// @tparam A Box algorithm, defaulting to box_default.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Key pair, or errc::crypto_failed on generation failure or errc::allocation_failed on allocation failure.
template <class A = box_default>
std::expected<keypair<A>, errc> generate_keypair(std::nothrow_t tag) noexcept
try
{
    keypair<A> pair{for_overwrite};
    auto status = generate_keypair_into(pair.public_key, pair.secret_key.writable_bytes(), std::nothrow);
    if (!status) return std::unexpected(status.error());
    return pair;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

/// Generate a local key pair directly in its owning storage.
/// @tparam A Box algorithm, defaulting to box_default.
/// @return Move-only key pair with a guarded private key.
/// @throws crypto_error If key generation fails.
/// @throws std::bad_alloc If allocation fails.
template <class A = box_default>
keypair<A> generate_keypair()
{
    auto result = generate_keypair<A>(std::nothrow);
    if (!result) throw_error(result.error());
    return std::move(*result);
}

/// @}

}  // namespace potassium::box
