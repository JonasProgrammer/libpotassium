// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

export module potassium.secretbox;

import potassium.core;
import std;

/// Symmetric authenticated encryption with a separate nonce.
export namespace potassium::secretbox
{

/// XSalsa20-Poly1305 SecretBox algorithm tag.
struct xsalsa20poly1305;

/// XChaCha20-Poly1305 SecretBox algorithm tag.
struct xchacha20poly1305;

/// Algorithm selected by default for SecretBox.
using secretbox_default = xsalsa20poly1305;

/// Result of sealing with a generated nonce.
/// @tparam A SecretBox algorithm used to seal the message.
template <class A>
struct seal_result
{
    /// Authentication tag followed by encrypted message bytes.
    std::vector<std::byte> ciphertext;
    /// Nonce required to authenticate and decrypt the ciphertext.
    nonce_buffer<A> nonce;
};
}  // namespace potassium::secretbox

export namespace potassium
{
/// Byte dimensions and message limit for XSalsa20-Poly1305.
template <>
struct algorithm_traits<secretbox::xsalsa20poly1305>
{
    /// Secret key length in bytes.
    static constexpr std::size_t key_size = crypto_secretbox_KEYBYTES;
    /// Nonce length in bytes.
    static constexpr std::size_t nonce_size = crypto_secretbox_NONCEBYTES;
    /// Authentication tag length in bytes.
    static constexpr std::size_t mac_size = crypto_secretbox_MACBYTES;
    /// Maximum plaintext length accepted by seal, in bytes.
    static constexpr std::size_t messagebytes_max = crypto_secretbox_MESSAGEBYTES_MAX;
};

/// Confidential key traits for XSalsa20-Poly1305 SecretBox.
template <>
struct key_traits<secretbox::xsalsa20poly1305>
{
    /// Default generator for this key purpose.
    using generator = random_key_generator;

    /// Secret key length in bytes.
    static constexpr std::size_t size = algorithm_traits<secretbox::xsalsa20poly1305>::key_size;
};

/// Byte dimensions and message limit for XChaCha20-Poly1305.
template <>
struct algorithm_traits<secretbox::xchacha20poly1305>
{
    /// Secret key length in bytes.
    static constexpr std::size_t key_size = crypto_secretbox_xchacha20poly1305_KEYBYTES;
    /// Nonce length in bytes.
    static constexpr std::size_t nonce_size = crypto_secretbox_xchacha20poly1305_NONCEBYTES;
    /// Authentication tag length in bytes.
    static constexpr std::size_t mac_size = crypto_secretbox_xchacha20poly1305_MACBYTES;
    /// Maximum plaintext length accepted by seal, in bytes.
    static constexpr std::size_t messagebytes_max = crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX;
};

/// Confidential key traits for XChaCha20-Poly1305 SecretBox.
template <>
struct key_traits<secretbox::xchacha20poly1305>
{
    /// Default generator for this key purpose.
    using generator = random_key_generator;

    /// Secret key length in bytes.
    static constexpr std::size_t size = algorithm_traits<secretbox::xchacha20poly1305>::key_size;
};
}  // namespace potassium

export namespace potassium::secretbox
{
/// @name XChaCha20-Poly1305
/// @{

/// Borrowed key for XChaCha20-Poly1305.
using xchacha_key_ref = key_ref<xchacha20poly1305>;
/// Borrowed nonce for XChaCha20-Poly1305.
using xchacha_nonce_ref = nonce_ref<xchacha20poly1305>;
/// Owning nonce for XChaCha20-Poly1305.
using xchacha_nonce_buffer = nonce_buffer<xchacha20poly1305>;
/// Combined ciphertext and generated nonce for XChaCha20-Poly1305.
using xchacha_seal_result = seal_result<xchacha20poly1305>;

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @throws crypto_error If encryption fails.
void seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xchacha_nonce_ref nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return An empty success value, or errc::crypto_failed on encryption failure.
std::expected<void, errc> seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xchacha_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @throws crypto_error If authentication fails.
void open_into(xchacha_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xchacha_nonce_ref nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @return An empty success value, or errc::crypto_failed on authentication failure.
std::expected<void, errc> open_into(xchacha_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xchacha_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce.
/// @throws crypto_error If encryption fails.
xchacha_nonce_buffer seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce, or errc::crypto_failed on encryption failure.
std::expected<xchacha_nonce_buffer, errc> seal_into(xchacha_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @return Combined ciphertext.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
std::vector<std::byte> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, xchacha_nonce_ref nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @return Combined ciphertext, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<std::vector<std::byte>, errc> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, xchacha_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
xchacha_seal_result seal(xchacha_key_ref key, std::span<std::byte const> plaintext);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xchacha20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<xchacha_seal_result, errc> seal(xchacha_key_ref key, std::span<std::byte const> plaintext, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xchacha_key_ref key, std::span<std::byte const> ciphertext, xchacha_nonce_ref nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xchacha_key_ref key, std::span<std::byte const> ciphertext, xchacha_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param sealed Combined ciphertext and its nonce.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xchacha_key_ref key, xchacha_seal_result const& sealed);

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param sealed Combined ciphertext and its nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xchacha_key_ref key, xchacha_seal_result const& sealed, std::nothrow_t tag) noexcept;

/// @}

/// @name XSalsa20-Poly1305
/// @{

/// Borrowed key for XSalsa20-Poly1305.
using xsalsa_key_ref = key_ref<xsalsa20poly1305>;
/// Borrowed nonce for XSalsa20-Poly1305.
using xsalsa_nonce_ref = nonce_ref<xsalsa20poly1305>;
/// Owning nonce for XSalsa20-Poly1305.
using xsalsa_nonce_buffer = nonce_buffer<xsalsa20poly1305>;
/// Combined ciphertext and generated nonce for XSalsa20-Poly1305.
using xsalsa_seal_result = seal_result<xsalsa20poly1305>;

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @throws crypto_error If encryption fails.
void seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xsalsa_nonce_ref nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return An empty success value, or errc::crypto_failed on encryption failure.
std::expected<void, errc> seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, xsalsa_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @throws crypto_error If authentication fails.
void open_into(xsalsa_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xsalsa_nonce_ref nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param[out] out Destination for authenticated plaintext.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Output is disjoint from all inputs.
/// @pre For ciphertext of at least 16 bytes, output length equals ciphertext length minus 16.
/// @return An empty success value, or errc::crypto_failed on authentication failure.
std::expected<void, errc> open_into(xsalsa_key_ref key, std::span<std::byte const> ciphertext, std::span<std::byte> out, xsalsa_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce.
/// @throws crypto_error If encryption fails.
xsalsa_nonce_buffer seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param[out] out Destination for the tag followed by encrypted bytes.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @pre Output is disjoint from all inputs.
/// @pre Output length equals plaintext length plus 16.
/// @return The generated nonce, or errc::crypto_failed on encryption failure.
std::expected<xsalsa_nonce_buffer, errc> seal_into(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::span<std::byte> out, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @return Combined ciphertext.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
std::vector<std::byte> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, xsalsa_nonce_ref nonce);

/// @brief Encrypt and authenticate a message.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param nonce Caller-supplied encryption nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @pre The nonce has never been used for encryption with this key.
/// @return Combined ciphertext, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<std::vector<std::byte>, errc> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, xsalsa_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce.
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
xsalsa_seal_result seal(xsalsa_key_ref key, std::span<std::byte const> plaintext);

/// @brief Encrypt and authenticate a message with a generated nonce.
/// @param key Secret key for encryption.
/// @param plaintext Message bytes to encrypt.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @pre Plaintext length is at most algorithm_traits<xsalsa20poly1305>::messagebytes_max.
/// @return Combined ciphertext and its generated nonce, or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
std::expected<xsalsa_seal_result, errc> seal(xsalsa_key_ref key, std::span<std::byte const> plaintext, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xsalsa_key_ref key, std::span<std::byte const> ciphertext, xsalsa_nonce_ref nonce);

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param ciphertext Authentication tag followed by encrypted message bytes.
/// @param nonce Nonce used to seal this message.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xsalsa_key_ref key, std::span<std::byte const> ciphertext, xsalsa_nonce_ref nonce, std::nothrow_t tag) noexcept;

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param sealed Combined ciphertext and its nonce.
/// @return Authenticated plaintext in guarded storage.
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
secure_buffer open(xsalsa_key_ref key, xsalsa_seal_result const& sealed);

/// @brief Authenticate and decrypt a message.
/// @param key Secret key used to seal the message.
/// @param sealed Combined ciphertext and its nonce.
/// @param tag Pass std::nothrow to receive errors in the result.
/// @return Authenticated plaintext in guarded storage, or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
std::expected<secure_buffer, errc> open(xsalsa_key_ref key, xsalsa_seal_result const& sealed, std::nothrow_t tag) noexcept;

/// @}

}  // namespace potassium::secretbox
