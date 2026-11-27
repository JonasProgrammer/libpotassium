// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium/crypto_aead_aes256gcm.h>

/// @brief Authenticated encryption with associated data.
export module potassium.aead;

export import potassium.core;
import potassium.internal;
import std;

/// ChaCha20-Poly1305, AEGIS and AES-GCM authenticated encryption.
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

/// @struct potassium::aead::aegis128l
/// @brief AEGIS-128L with a 16-byte key and nonce.
struct aegis128l;

/// @struct potassium::aead::aegis256
/// @brief AEGIS-256 with a 32-byte key and nonce.
struct aegis256;

/// @struct potassium::aead::aes256gcm
/// @brief AES256-GCM with a 12-byte nonce.
struct aes256gcm;

/// Default AEAD construction, supporting generated nonces.
using default_algorithm = xchacha20poly1305_ietf;

/// Whether the current CPU supports the libsodium AES256-GCM implementation.
[[nodiscard]] bool aes256gcm_available() noexcept;

/// Aligned backend state for caller-provided AES256-GCM precomputation storage.
using aes256gcm_state_type = crypto_aead_aes256gcm_state;

class aes256gcm_state_storage;
class aes256gcm_precomputed;
}  // namespace potassium::aead

/// @cond INTERNAL
namespace potassium::aead::detail
{
template <std::size_t KeySize, std::size_t NonceSize, std::size_t MacSize, bool RandomNonce>
struct aead_traits
{
    /// Secret key length in bytes.
    static constexpr std::size_t key_size = KeySize;
    /// Nonce length in bytes.
    static constexpr std::size_t nonce_size = NonceSize;
    /// Authentication tag length in bytes.
    static constexpr std::size_t mac_size = MacSize;
    /// Whether this construction supports randomly generated nonces.
    static constexpr bool random_nonce_enabled = RandomNonce;
    /// Maximum plaintext length accepted by the construction.
    static constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::uint64_t>::max()) - mac_size;
};

template <std::size_t NonceSize, bool RandomNonce>
using chacha_traits = aead_traits<32, NonceSize, 16, RandomNonce>;

template <std::size_t KeySize>
struct aegis_traits : aead_traits<KeySize, KeySize, 32, true>
{
    /// Maximum plaintext length in bytes.
    static constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(aead_traits<KeySize, KeySize, 32, true>::messagebytes_max, (1ull << 61) - 1);
};

template <class A>
struct aead_key_traits
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
    static constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(aead_traits::messagebytes_max, 64ull * (0xffffffffull));
};

/// Byte dimensions and message limit for IETF XChaCha20-Poly1305.
template <>
struct algorithm_traits<aead::xchacha20poly1305_ietf> : aead::detail::chacha_traits<24, true>
{
};

/// Byte dimensions and message limit for AEGIS-128L.
template <>
struct algorithm_traits<aead::aegis128l> : aead::detail::aegis_traits<16>
{
};

/// Byte dimensions and message limit for AEGIS-256.
template <>
struct algorithm_traits<aead::aegis256> : aead::detail::aegis_traits<32>
{
};

/// Byte dimensions and message limit for AES256-GCM.
template <>
struct algorithm_traits<aead::aes256gcm> : aead::detail::aead_traits<32, 12, 16, false>
{
    /// Maximum plaintext length allowed by the 32-bit block counter.
    static constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(aead_traits::messagebytes_max, 16ull * ((1ull << 32) - 2));
};

/// Confidential key traits for original ChaCha20-Poly1305.
template <>
struct key_traits<aead::chacha20poly1305> : aead::detail::aead_key_traits<aead::chacha20poly1305>
{
};

/// Confidential key traits for IETF ChaCha20-Poly1305.
template <>
struct key_traits<aead::chacha20poly1305_ietf> : aead::detail::aead_key_traits<aead::chacha20poly1305_ietf>
{
};

/// Confidential key traits for IETF XChaCha20-Poly1305.
template <>
struct key_traits<aead::xchacha20poly1305_ietf> : aead::detail::aead_key_traits<aead::xchacha20poly1305_ietf>
{
};

/// Confidential key traits for AEGIS-128L.
template <>
struct key_traits<aead::aegis128l> : aead::detail::aead_key_traits<aead::aegis128l>
{
};

/// Confidential key traits for AEGIS-256.
template <>
struct key_traits<aead::aegis256> : aead::detail::aead_key_traits<aead::aegis256>
{
};

/// Confidential key traits for AES256-GCM.
template <>
struct key_traits<aead::aes256gcm> : aead::detail::aead_key_traits<aead::aes256gcm>
{
};
}  // namespace potassium

/// @cond INTERNAL
namespace potassium::aead::detail
{
struct aes256gcm_state_ref
{
    aes256gcm_state_type const* state;
};

aes256gcm_state_ref borrow_key(aes256gcm_precomputed const& state) noexcept;
aes256gcm_state_ref borrow_key(aes256gcm_precomputed const&&) = delete ("Precomputed state must be used through a live owner");

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

inline key_ref<aegis128l> borrow_key(key_ref<aegis128l> key) noexcept
{
    return key;
}

inline key_ref<aegis256> borrow_key(key_ref<aegis256> key) noexcept
{
    return key;
}

inline key_ref<aes256gcm> borrow_key(key_ref<aes256gcm> key) noexcept
{
    return key;
}

template <class A>
A identify_algorithm(key_ref<A>);

aes256gcm identify_algorithm(aes256gcm_state_ref);

template <class K>
concept key = requires(K&& candidate) {
    { detail::borrow_key(std::forward<K>(candidate)) } noexcept;
};

template <class K>
using key_ref_for = decltype(detail::borrow_key(std::declval<K>()));

template <class K>
using algorithm_for = decltype(detail::identify_algorithm(std::declval<key_ref_for<K>>()));

template <class K>
using nonce_for = nonce_ref<algorithm_for<K>>;

template <class K>
concept random_nonce_key = key<K> && RandomNonceAlgorithm<algorithm_for<K>>;

template <class K>
bool key_available(K&& key) noexcept
{
    if constexpr (std::same_as<key_ref_for<K>, key_ref<aes256gcm>>) return aes256gcm_available();
    if constexpr (std::same_as<key_ref_for<K>, aes256gcm_state_ref>) return detail::borrow_key(std::forward<K>(key)).state != nullptr;
    return true;
}

inline bool key_available(aes256gcm_state_ref state) noexcept
{
    return state.state != nullptr;
}

template <class K>
struct backend
{
    using A = decltype(detail::identify_algorithm(std::declval<K>()));
    static std::expected<void, errc> seal_into(K key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept;
    static std::expected<void, errc> open_into(K key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept;
    static std::expected<mac_buffer<A>, errc> seal_detached_into(K key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept;
    static std::expected<void, errc> open_detached_into(K key,
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
/// @name AES256-GCM precomputation
/// @{

/// Immobile, inline storage for an AES256-GCM key schedule.
class aes256gcm_inplace_state
{
public:
    aes256gcm_inplace_state() = default;
    aes256gcm_inplace_state(aes256gcm_inplace_state const&) = delete;
    aes256gcm_inplace_state& operator=(aes256gcm_inplace_state const&) = delete;
    /// Wipe the state before releasing its storage.
    ~aes256gcm_inplace_state();

    /// @return State to lend to an aes256gcm_state_storage handle.
    aes256gcm_state_type& get() & noexcept { return state_; }

private:
    aes256gcm_state_type state_{};
};

/// Expand a key directly in existing state storage.
/// @pre Key bytes are disjoint from the state storage.
/// @return The precomputed key or errc::crypto_failed if storage is empty, AES256-GCM is unavailable or precomputation fails.
/// @note On failure the caller retains its storage, with no key material in it.
std::expected<aes256gcm_precomputed, errc> precompute_into(key_ref<aes256gcm> key, aes256gcm_state_storage&& storage, std::nothrow_t) noexcept;

/// Move-only handle to idle storage for AES256-GCM precomputation.
class aes256gcm_state_storage
{
public:
    /// Allocate state in guarded memory.
    /// @throws std::bad_alloc If allocation fails.
    aes256gcm_state_storage();

    /// Wipe and borrow state from inline storage or a custom owner.
    /// @pre The state outlives the handle and any precomputation or handle it is moved into.
    /// @pre The state is reserved for exclusive use by this handle and its successors.
    explicit aes256gcm_state_storage(aes256gcm_state_type& state) noexcept;

    /// Transfer storage, leaving the source empty.
    aes256gcm_state_storage(aes256gcm_state_storage&&) noexcept = default;
    /// Release the previous storage and transfer storage from the source.
    aes256gcm_state_storage& operator=(aes256gcm_state_storage&&) noexcept = default;

    /// @return Whether the handle holds storage.
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(state_); }

private:
    friend class aes256gcm_precomputed;
    friend std::expected<aes256gcm_precomputed, errc> precompute_into(key_ref<aes256gcm>, aes256gcm_state_storage&&, std::nothrow_t) noexcept;

    struct state_deleter
    {
        bool guarded;
        void operator()(aes256gcm_state_type* state) const noexcept;
    };

    std::unique_ptr<aes256gcm_state_type, state_deleter> state_;

    void clear() noexcept;
};

/// Move-only AES256-GCM key schedule usable with the message operations.
class aes256gcm_precomputed
{
public:
    /// Transfer the schedule, leaving the source closed.
    aes256gcm_precomputed(aes256gcm_precomputed&&) noexcept = default;
    /// Wipe the previous schedule and transfer the new one, leaving the source closed.
    aes256gcm_precomputed& operator=(aes256gcm_precomputed&&) noexcept = default;

    /// @return Whether the schedule is usable.
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(storage_); }

    /// Wipe the schedule immediately and return its storage for a new key.
    [[nodiscard]] aes256gcm_state_storage close_for_reuse() && noexcept;

private:
    friend detail::aes256gcm_state_ref detail::borrow_key(aes256gcm_precomputed const&) noexcept;
    friend std::expected<aes256gcm_precomputed, errc> precompute_into(key_ref<aes256gcm>, aes256gcm_state_storage&&, std::nothrow_t) noexcept;

    explicit aes256gcm_precomputed(aes256gcm_state_storage&& storage) noexcept;

    aes256gcm_state_type const* state() const noexcept { return storage_.state_.get(); }

    aes256gcm_state_storage storage_;
};

/// @overload
/// @throws crypto_error If precomputation fails.
aes256gcm_precomputed precompute_into(key_ref<aes256gcm> key, aes256gcm_state_storage&& storage);

/// Expand a key in newly allocated guarded state.
/// @return The precomputed key, errc::crypto_failed on precomputation failure or errc::allocation_failed on allocation failure.
std::expected<aes256gcm_precomputed, errc> precompute(key_ref<aes256gcm> key, std::nothrow_t) noexcept;

/// @overload
/// @throws crypto_error If precomputation fails.
/// @throws std::bad_alloc If allocation fails.
aes256gcm_precomputed precompute(key_ref<aes256gcm> key);

/// @}

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
/// @pre For encryption, plaintext length is at most algorithm_traits<A>::messagebytes_max.
/// @pre For encryption, associated data fits a 64-bit byte count, or a 64-bit bit count for AES256-GCM and AEGIS.
/// AES256-GCM returns errc::crypto_failed when unsupported or given a closed precomputed key.
/// @{

/// Encrypt a message and append its MAC in caller storage.
/// @pre Output is disjoint from all inputs and holds plaintext.size() plus mac_size bytes.
/// @pre The nonce has never been used for encryption with this key.
/// @return The result or errc::crypto_failed on encryption failure.
template <detail::key K>
std::expected<void, errc> seal_into(K&& key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, detail::nonce_for<K> nonce, std::nothrow_t) noexcept
{
    return detail::backend<detail::key_ref_for<K>>::seal_into(detail::borrow_key(std::forward<K>(key)), plaintext, ad, out, nonce);
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
    return detail::backend<detail::key_ref_for<K>>::open_into(detail::borrow_key(std::forward<K>(key)), ciphertext, ad, out, nonce);
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
    if (!detail::key_available(std::forward<K>(key))) return std::unexpected(errc::crypto_failed);
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
    if (!detail::key_available(std::forward<K>(key))) return std::unexpected(errc::crypto_failed);
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
    return detail::backend<detail::key_ref_for<K>>::seal_detached_into(detail::borrow_key(std::forward<K>(key)), plaintext, ad, out, nonce);
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
    return detail::backend<detail::key_ref_for<K>>::open_detached_into(detail::borrow_key(std::forward<K>(key)), ciphertext, ad, mac, out, nonce);
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
    if (!detail::key_available(std::forward<K>(key))) return std::unexpected(errc::crypto_failed);
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
    if (!detail::key_available(std::forward<K>(key))) return std::unexpected(errc::crypto_failed);
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
