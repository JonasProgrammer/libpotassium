// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

/// @brief Authenticated encryption with associated data using ChaCha20-Poly1305.
export module potassium.aead;

export import potassium.core;
import potassium.internal;
import std;

/// ChaCha20-Poly1305 authenticated encryption with associated data.
export namespace potassium::aead
{
/// @struct potassium::aead::chacha20poly1305
/// @brief Original ChaCha20-Poly1305 with an 8-byte nonce.
struct chacha20poly1305;

/// @struct potassium::aead::chacha20poly1305_ietf
/// @brief IETF ChaCha20-Poly1305 with a 12-byte nonce.
struct chacha20poly1305_ietf;

/// @struct potassium::aead::xchacha20poly1305_ietf
/// @brief IETF XChaCha20-Poly1305 with a 24-byte nonce.
struct xchacha20poly1305_ietf;

/// Default AEAD construction, supporting generated nonces.
using default_algorithm = xchacha20poly1305_ietf;
}  // namespace potassium::aead

/// @cond INTERNAL
namespace potassium::aead::detail
{
template <std::size_t NonceSize, bool RandomNonce>
struct chacha_traits
{
    /// Secret key length in bytes.
    static constexpr std::size_t key_size = 32;
    /// Nonce length in bytes.
    static constexpr std::size_t nonce_size = NonceSize;
    /// Authentication tag length in bytes.
    static constexpr std::size_t mac_size = 16;
    /// Whether this construction supports randomly generated nonces.
    static constexpr bool random_nonce_enabled = RandomNonce;
    /// Maximum plaintext length accepted by the construction.
    static constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::uint64_t>::max()) - mac_size;
};

template <class A>
struct chacha_key_traits
{
    /// Default generator for this key purpose.
    using generator = random_key_generator;
    /// Key length in bytes.
    static constexpr std::size_t size = algorithm_traits<A>::key_size;
};
}  // namespace potassium::aead::detail

/// @endcond

export namespace potassium
{
/// Byte dimensions and message limit for original ChaCha20-Poly1305.
template <>
struct algorithm_traits<aead::chacha20poly1305> : aead::detail::chacha_traits<8, false>
{
};

/// Byte dimensions and message limit for IETF ChaCha20-Poly1305.
template <>
struct algorithm_traits<aead::chacha20poly1305_ietf> : aead::detail::chacha_traits<12, false>
{
    /// Maximum plaintext length allowed by the 32-bit block counter.
    static constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(chacha_traits::messagebytes_max, 64ull * (0xffffffffull));
};

/// Byte dimensions and message limit for IETF XChaCha20-Poly1305.
template <>
struct algorithm_traits<aead::xchacha20poly1305_ietf> : aead::detail::chacha_traits<24, true>
{
};

/// Confidential key traits for original ChaCha20-Poly1305.
template <>
struct key_traits<aead::chacha20poly1305> : aead::detail::chacha_key_traits<aead::chacha20poly1305>
{
};

/// Confidential key traits for IETF ChaCha20-Poly1305.
template <>
struct key_traits<aead::chacha20poly1305_ietf> : aead::detail::chacha_key_traits<aead::chacha20poly1305_ietf>
{
};

/// Confidential key traits for IETF XChaCha20-Poly1305.
template <>
struct key_traits<aead::xchacha20poly1305_ietf> : aead::detail::chacha_key_traits<aead::xchacha20poly1305_ietf>
{
};
}  // namespace potassium

/// @cond INTERNAL
namespace potassium::aead::detail
{
inline key_ref<chacha20poly1305> borrow_key(key_ref<chacha20poly1305> key) noexcept
{
    return key;
}

inline key_ref<chacha20poly1305_ietf> borrow_key(key_ref<chacha20poly1305_ietf> key) noexcept
{
    return key;
}

inline key_ref<xchacha20poly1305_ietf> borrow_key(key_ref<xchacha20poly1305_ietf> key) noexcept
{
    return key;
}

template <class A>
A identify_algorithm(key_ref<A>);

template <class K>
concept key = requires(K&& candidate) {
    { detail::borrow_key(std::forward<K>(candidate)) } noexcept;
};

template <class K>
using algorithm_for = decltype(detail::identify_algorithm(detail::borrow_key(std::declval<K>())));

template <class K>
using nonce_for = nonce_ref<algorithm_for<K>>;

template <class K>
concept random_nonce_key = key<K> && RandomNonceAlgorithm<algorithm_for<K>>;

template <class A>
struct backend
{
    static std::expected<void, errc> seal_into(key_ref<A> key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept;
    static std::expected<void, errc> open_into(key_ref<A> key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept;
    static std::expected<mac_buffer<A>, errc> seal_detached_into(key_ref<A> key,
                                                                 std::span<std::byte const> plaintext,
                                                                 std::span<std::byte const> ad,
                                                                 std::span<std::byte> out,
                                                                 nonce_ref<A> nonce) noexcept;
    static std::expected<void, errc> open_detached_into(key_ref<A> key,
                                                        std::span<std::byte const> ciphertext,
                                                        std::span<std::byte const> ad,
                                                        mac_buffer<A> const& mac,
                                                        std::span<std::byte> out,
                                                        nonce_ref<A> nonce) noexcept;
};
}  // namespace potassium::aead::detail

/// @endcond

export namespace potassium::aead
{
/// Combined ciphertext and its generated nonce.
template <Algorithm A = default_algorithm>
struct seal_result
{
    /// Encrypted message bytes followed by the MAC.
    std::vector<std::byte> ciphertext;
    /// Nonce required to open the ciphertext.
    nonce_buffer<A> nonce;
};

/// @name Message operations
/// Each operation authenticates the supplied associated data verbatim.
/// Pass an empty span when there is no associated data.
/// All encryption overloads require a message length of at most the algorithm's messagebytes_max.
/// @{

/// Encrypt a message and append its MAC in caller storage.
/// @pre Output is disjoint from all inputs and holds plaintext.size() plus mac_size bytes.
/// @pre The nonce has never been used for encryption with this key.
/// @return The result or errc::crypto_failed on encryption failure.
template <detail::key K>
std::expected<void, errc> seal_into(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, detail::nonce_for<K> nonce, std::nothrow_t) noexcept
{
    return detail::backend<detail::algorithm_for<K>>::seal_into(detail::borrow_key(std::forward<K>(key)), plaintext, ad, out, nonce);
}

/// @overload
/// @throws crypto_error If encryption fails.
template <detail::key K>
void seal_into(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::seal_into(std::forward<K>(key), plaintext, ad, out, nonce, std::nothrow));
}

/// Authenticate combined ciphertext and decrypt into caller storage.
/// @pre Output is disjoint from all inputs and, for ciphertext of at least mac_size bytes, holds ciphertext.size() minus mac_size bytes.
/// @note Authentication failure may clear the output.
/// @return The result or errc::crypto_failed on authentication failure.
template <detail::key K>
std::expected<void, errc> open_into(K&& key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, std::span<std::byte> out, detail::nonce_for<K> nonce, std::nothrow_t) noexcept
{
    return detail::backend<detail::algorithm_for<K>>::open_into(detail::borrow_key(std::forward<K>(key)), ciphertext, ad, out, nonce);
}

/// @overload
/// @throws crypto_error If authentication fails.
template <detail::key K>
void open_into(K&& key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, std::span<std::byte> out, detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::open_into(std::forward<K>(key), ciphertext, ad, out, nonce, std::nothrow));
}

/// Encrypt into caller storage and return the generated nonce.
/// @pre Output is disjoint from all inputs and holds plaintext.size() plus mac_size bytes.
/// @return The result or errc::crypto_failed on encryption failure.
template <detail::random_nonce_key K>
[[nodiscard("Retain the nonce to open the ciphertext")]] std::expected<nonce_buffer<detail::algorithm_for<K>>, errc> seal_into(K&& key,
                                                                                                                               std::span<std::byte const> plaintext,
                                                                                                                               std::span<std::byte const> ad,
                                                                                                                               std::span<std::byte> out,
                                                                                                                               std::nothrow_t) noexcept
{
    return internal::seal_into_with_nonce<detail::algorithm_for<K>>([&](auto& nonce) { return aead::seal_into(std::forward<K>(key), plaintext, ad, out, nonce, std::nothrow); });
}

/// @overload
/// @throws crypto_error If encryption fails.
template <detail::random_nonce_key K>
[[nodiscard("Retain the nonce to open the ciphertext")]] nonce_buffer<detail::algorithm_for<K>> seal_into(K&& key,
                                                                                                          std::span<std::byte const> plaintext,
                                                                                                          std::span<std::byte const> ad,
                                                                                                          std::span<std::byte> out)
{
    return internal::unwrap(aead::seal_into(std::forward<K>(key), plaintext, ad, out, std::nothrow));
}

/// Encrypt a message, returning encrypted bytes followed by their MAC.
/// @pre The nonce has never been used for encryption with this key.
/// @return The result or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
template <detail::key K>
std::expected<std::vector<std::byte>, errc> seal(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, detail::nonce_for<K> nonce, std::nothrow_t) noexcept
{
    return internal::allocate_ciphertext<detail::algorithm_for<K>>(plaintext.size(), [&](auto& out) { return aead::seal_into(std::forward<K>(key), plaintext, ad, out, nonce, std::nothrow); });
}

/// @overload
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::key K>
std::vector<std::byte> seal(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::seal(std::forward<K>(key), plaintext, ad, nonce, std::nothrow));
}

/// Encrypt a message and return combined ciphertext and its generated nonce.
/// @return The result or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
template <detail::random_nonce_key K>
std::expected<seal_result<detail::algorithm_for<K>>, errc> seal(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::nothrow_t) noexcept
{
    using A = detail::algorithm_for<K>;
    return internal::seal_with_nonce<A, seal_result<A>>([&](auto& nonce) { return aead::seal(std::forward<K>(key), plaintext, ad, nonce, std::nothrow); });
}

/// @overload
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::random_nonce_key K>
seal_result<detail::algorithm_for<K>> seal(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad)
{
    return internal::unwrap(aead::seal(std::forward<K>(key), plaintext, ad, std::nothrow));
}

/// Authenticate combined ciphertext and return plaintext in guarded storage.
/// @return The result or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
template <detail::key K>
std::expected<secure_buffer, errc> open(K&& key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, detail::nonce_for<K> nonce, std::nothrow_t) noexcept
{
    return internal::allocate_plaintext<detail::algorithm_for<K>>(ciphertext.size(),
                                                                  [&](auto& out) { return aead::open_into(std::forward<K>(key), ciphertext, ad, out.bytes(), nonce, std::nothrow); });
}

/// @overload
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::key K>
secure_buffer open(K&& key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::open(std::forward<K>(key), ciphertext, ad, nonce, std::nothrow));
}

/// Open combined ciphertext using the nonce returned when sealing.
/// @return The result or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
template <detail::key K>
std::expected<secure_buffer, errc> open(K&& key, seal_result<detail::algorithm_for<K>> const& sealed, std::span<std::byte const> ad, std::nothrow_t) noexcept
{
    return aead::open(std::forward<K>(key), sealed.ciphertext, ad, sealed.nonce, std::nothrow);
}

/// @overload
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::key K>
secure_buffer open(K&& key, seal_result<detail::algorithm_for<K>> const& sealed, std::span<std::byte const> ad)
{
    return internal::unwrap(aead::open(std::forward<K>(key), sealed, ad, std::nothrow));
}

/// Encrypt into caller storage and return a separate MAC.
/// @pre Output is disjoint from all inputs and has the same length as plaintext.
/// @pre The nonce has never been used for encryption with this key.
/// @return The result or errc::crypto_failed on encryption failure.
template <detail::key K>
[[nodiscard("Retain the MAC to open the ciphertext")]] std::expected<mac_buffer<detail::algorithm_for<K>>, errc> seal_detached_into(K&& key,
                                                                                                                                    std::span<std::byte const> plaintext,
                                                                                                                                    std::span<std::byte const> ad,
                                                                                                                                    std::span<std::byte> out,
                                                                                                                                    detail::nonce_for<K> nonce,
                                                                                                                                    std::nothrow_t) noexcept
{
    return detail::backend<detail::algorithm_for<K>>::seal_detached_into(detail::borrow_key(std::forward<K>(key)), plaintext, ad, out, nonce);
}

/// @overload
/// @throws crypto_error If encryption fails.
template <detail::key K>
[[nodiscard("Retain the MAC to open the ciphertext")]] mac_buffer<detail::algorithm_for<K>> seal_detached_into(K&& key,
                                                                                                               std::span<std::byte const> plaintext,
                                                                                                               std::span<std::byte const> ad,
                                                                                                               std::span<std::byte> out,
                                                                                                               detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::seal_detached_into(std::forward<K>(key), plaintext, ad, out, nonce, std::nothrow));
}

/// Authenticate detached ciphertext and decrypt into caller storage.
/// @pre Output is disjoint from all inputs and has the same length as ciphertext.
/// @note Authentication failure may clear the output.
/// @return The result or errc::crypto_failed on authentication failure.
template <detail::key K>
std::expected<void, errc> open_detached_into(K&& key,
                                             std::span<std::byte const> ciphertext,
                                             std::span<std::byte const> ad,
                                             mac_buffer<detail::algorithm_for<K>> const& mac,
                                             std::span<std::byte> out,
                                             detail::nonce_for<K> nonce,
                                             std::nothrow_t) noexcept
{
    return detail::backend<detail::algorithm_for<K>>::open_detached_into(detail::borrow_key(std::forward<K>(key)), ciphertext, ad, mac, out, nonce);
}

/// @overload
/// @throws crypto_error If authentication fails.
template <detail::key K>
void open_detached_into(K&& key,
                        std::span<std::byte const> ciphertext,
                        std::span<std::byte const> ad,
                        mac_buffer<detail::algorithm_for<K>> const& mac,
                        std::span<std::byte> out,
                        detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::open_detached_into(std::forward<K>(key), ciphertext, ad, mac, out, nonce, std::nothrow));
}

/// Encrypt into caller storage and return the separate MAC and generated nonce.
/// @pre Output is disjoint from all inputs and has the same length as plaintext.
/// @return The result or errc::crypto_failed on encryption failure.
template <detail::random_nonce_key K>
[[nodiscard("Retain the MAC and nonce to open the ciphertext")]] std::expected<detached_mac_nonce<detail::algorithm_for<K>>, errc> seal_detached_into(K&& key,
                                                                                                                                                      std::span<std::byte const> plaintext,
                                                                                                                                                      std::span<std::byte const> ad,
                                                                                                                                                      std::span<std::byte> out,
                                                                                                                                                      std::nothrow_t) noexcept
{
    using A = detail::algorithm_for<K>;
    auto nonce = generate_nonce<A>();
    return aead::seal_detached_into(std::forward<K>(key), plaintext, ad, out, nonce, std::nothrow).transform([&](auto mac) { return detached_mac_nonce<A>{mac, nonce}; });
}

/// @overload
/// @throws crypto_error If encryption fails.
template <detail::random_nonce_key K>
[[nodiscard("Retain the MAC and nonce to open the ciphertext")]] detached_mac_nonce<detail::algorithm_for<K>> seal_detached_into(K&& key,
                                                                                                                                 std::span<std::byte const> plaintext,
                                                                                                                                 std::span<std::byte const> ad,
                                                                                                                                 std::span<std::byte> out)
{
    return internal::unwrap(aead::seal_detached_into(std::forward<K>(key), plaintext, ad, out, std::nothrow));
}

/// Encrypt a message, returning encrypted bytes and a separate MAC.
/// @pre The nonce has never been used for encryption with this key.
/// @return The result or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
template <detail::key K>
std::expected<detached_ciphertext<detail::algorithm_for<K>>, errc> seal_detached(K&& key,
                                                                                 std::span<std::byte const> plaintext,
                                                                                 std::span<std::byte const> ad,
                                                                                 detail::nonce_for<K> nonce,
                                                                                 std::nothrow_t) noexcept
{
    return internal::allocate_detached_ciphertext<detail::algorithm_for<K>>(plaintext.size(),
                                                                            [&](auto& out) { return aead::seal_detached_into(std::forward<K>(key), plaintext, ad, out, nonce, std::nothrow); });
}

/// @overload
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::key K>
detached_ciphertext<detail::algorithm_for<K>> seal_detached(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::seal_detached(std::forward<K>(key), plaintext, ad, nonce, std::nothrow));
}

/// Encrypt a message and return detached ciphertext, its MAC and generated nonce.
/// @return The result or errc::crypto_failed on encryption failure or errc::allocation_failed on allocation failure.
template <detail::random_nonce_key K>
std::expected<detached_seal_result<detail::algorithm_for<K>>, errc> seal_detached(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::nothrow_t) noexcept
{
    using A = detail::algorithm_for<K>;
    auto nonce = generate_nonce<A>();
    return aead::seal_detached(std::forward<K>(key), plaintext, ad, nonce, std::nothrow)
            .transform([&](auto&& result) { return detached_seal_result<A>{std::move(result.ciphertext), result.mac, nonce}; });
}

/// @overload
/// @throws crypto_error If encryption fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::random_nonce_key K>
detached_seal_result<detail::algorithm_for<K>> seal_detached(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad)
{
    return internal::unwrap(aead::seal_detached(std::forward<K>(key), plaintext, ad, std::nothrow));
}

/// Authenticate detached ciphertext and return plaintext in guarded storage.
/// @return The result or errc::crypto_failed on authentication failure or errc::allocation_failed on allocation failure.
template <detail::key K>
std::expected<secure_buffer, errc> open_detached(K&& key,
                                                 std::span<std::byte const> ciphertext,
                                                 std::span<std::byte const> ad,
                                                 mac_buffer<detail::algorithm_for<K>> const& mac,
                                                 detail::nonce_for<K> nonce,
                                                 std::nothrow_t) noexcept
{
    return internal::allocate_detached_plaintext<detail::algorithm_for<K>>(
            ciphertext.size(), [&](auto& out) { return aead::open_detached_into(std::forward<K>(key), ciphertext, ad, mac, out.bytes(), nonce, std::nothrow); });
}

/// @overload
/// @throws crypto_error If authentication fails.
/// @throws std::bad_alloc If allocation fails.
template <detail::key K>
secure_buffer open_detached(K&& key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, mac_buffer<detail::algorithm_for<K>> const& mac, detail::nonce_for<K> nonce)
{
    return internal::unwrap(aead::open_detached(std::forward<K>(key), ciphertext, ad, mac, nonce, std::nothrow));
}

/// @}
}  // namespace potassium::aead
