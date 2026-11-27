// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

#ifdef POTASSIUM_HASH_ASSERTS
#include <cassert>
#endif

/// @brief Fixed-output hashes and keyed digest streams, including HMAC.
/// @see potassium::hash
export module potassium.hash;
export import potassium.core;
export import :hmac;
import std;

/// @brief Digest algorithms, one-shot hashes, and reusable keyed and unkeyed streams.
/// @details Unkeyed choices include @ref potassium::hash::blake2b, @ref potassium::hash::sha256,
/// @ref potassium::hash::sha512, @ref potassium::hash::sha3_256, and @ref potassium::hash::sha3_512.
/// Keyed streams support BLAKE2b and the HMAC algorithms in @ref potassium::auth.
export namespace potassium::hash
{
/// BLAKE2b parameterized by its digest size in bytes.
template <std::size_t N = 32>
    requires(N >= 16 && N <= 64)
struct blake2b;

/// @struct potassium::hash::sha256
/// @brief SHA-2 with a 256-bit digest.
struct sha256;

/// @struct potassium::hash::sha512
/// @brief SHA-2 with a 512-bit digest.
struct sha512;

/// @struct potassium::hash::sha3_256
/// @brief SHA-3 with a 256-bit digest.
struct sha3_256;

/// @struct potassium::hash::sha3_512
/// @brief SHA-3 with a 512-bit digest.
struct sha3_512;

/// Stable default digest construction.
using default_algorithm = blake2b<>;

/// Confidential BLAKE2b key purpose, independent of digest length.
template <std::size_t K = crypto_generichash_blake2b_KEYBYTES>
    requires(K >= crypto_generichash_blake2b_KEYBYTES_MIN && K <= crypto_generichash_blake2b_KEYBYTES_MAX)
struct blake2b_key_tag;
}  // namespace potassium::hash

export namespace potassium
{
/// Dimensions of a confidential BLAKE2b key.
template <std::size_t K>
struct key_traits<hash::blake2b_key_tag<K>>
{
    /// Default generator for this key purpose.
    using generator = random_key_generator;

    /// Key length in bytes.
    static constexpr std::size_t size = K;
};
}  // namespace potassium

namespace potassium::hash::detail
{
bool equal(std::span<std::byte const>, std::span<std::byte const>) noexcept;
void check_status(int status) noexcept;

template <class State>
void erase(State& state) noexcept
{
    wipe(std::as_writable_bytes(std::span{&state, 1}));
}

template <class StorageType>
constexpr bool always_holds_value = false;

template <typename E, std::size_t N>
    requires std::is_trivial_v<E>
constexpr bool always_holds_value<std::array<E, N>> = true;

}  // namespace potassium::hash::detail

export namespace potassium::hash
{
/// Immobile state, erased before its storage is released.
template <class State>
    requires detail::always_holds_value<State>
class inplace_hash_state
{
    State state_{};

public:
    /// Value-initialize the inline backend state.
    inplace_hash_state() = default;
    /// Prevent copying potentially key-derived stream state.
    inplace_hash_state(inplace_hash_state const&) = delete;
    /// Prevent copying potentially key-derived stream state.
    inplace_hash_state& operator=(inplace_hash_state const&) = delete;

    /// Wipe the state before releasing its storage.
    ~inplace_hash_state() { detail::erase(state_); }

    /// Return the owned state.
    State& get() & noexcept { return state_; }

    /// Move-only token for reuse of this storage policy.
    class transfer_token
    {
        friend class inplace_hash_state;
        transfer_token() = default;

    public:
        /// Transfer permission to restart in-place storage.
        transfer_token(transfer_token&&) noexcept = default;
        /// Accept a token for in-place reuse.
        transfer_token& operator=(transfer_token&&) noexcept = default;
    };

    /// Whether get() can access the state.
    bool has_value() const noexcept { return true; }

    /// Issue a reuse token. @pre This owner holds a state.
    [[nodiscard]] transfer_token make_token() & noexcept { return transfer_token{}; }

    /// Provide storage for a fresh computation. @pre The token is unconsumed.
    void assign_token(transfer_token&&) & noexcept {}
};

/// Guarded state whose allocation transfers intact across moves.
template <class State>
class guarded_hash_state
{
    std::indirect<State, allocator<State>> state_;

public:
    /// Allocate the backend state in guarded memory.
    /// @throws std::bad_alloc If the allocation fails.
    guarded_hash_state() = default;
    /// Prevent copying potentially key-derived stream state.
    guarded_hash_state(guarded_hash_state const&) = delete;
    /// Prevent copying potentially key-derived stream state.
    guarded_hash_state& operator=(guarded_hash_state const&) = delete;
    /// Transfer ownership of the live state.
    guarded_hash_state(guarded_hash_state&&) noexcept = default;
    /// Wipe and release the previous allocation and take ownership of the source state.
    guarded_hash_state& operator=(guarded_hash_state&&) noexcept = default;

    /// @pre This owner holds a live allocation.
    State& get() & noexcept { return *state_; }

    /// Move-only token for reuse of this storage policy.
    class transfer_token
    {
        friend class guarded_hash_state;
        decltype(state_) allocation_;

        explicit transfer_token(decltype(state_)&& allocation) noexcept
            : allocation_(std::move(allocation))
        {
        }

    public:
        /// Take ownership of the wiped guarded allocation.
        transfer_token(transfer_token&&) noexcept = default;
        /// Release the previous allocation and take ownership of the source allocation.
        transfer_token& operator=(transfer_token&&) noexcept = default;
    };

    /// Whether get() can access the state.
    bool has_value() const noexcept { return !state_.valueless_after_move(); }

    /// Issue a reuse token. @pre This owner holds a state.
    [[nodiscard]] transfer_token make_token() & noexcept { return transfer_token{std::move(state_)}; }

    /// Provide storage for a fresh computation. @pre The token is unconsumed.
    void assign_token(transfer_token&& token) & noexcept { state_ = std::move(token.allocation_); }
};

/// Storage owns a state, erases it on release, and transfers ownership on any move.
template <class Storage, class State>
concept hash_state_storage =
        std::default_initializable<Storage> && !std::is_copy_constructible_v<Storage> && !std::is_copy_assignable_v<Storage> && requires(Storage& s, typename Storage::transfer_token&& token)
        {
            { s.get() } noexcept -> std::same_as<State&>;
            requires std::is_nothrow_move_constructible_v<typename Storage::transfer_token>;
            requires std::is_nothrow_destructible_v<typename Storage::transfer_token>;
            requires(!std::is_copy_constructible_v<typename Storage::transfer_token> && !std::is_copy_assignable_v<typename Storage::transfer_token>);
            { std::as_const(s).has_value() } noexcept -> std::same_as<bool>;
            { s.make_token() } noexcept -> std::same_as<typename Storage::transfer_token>;
            { s.assign_token(std::move(token)) } noexcept -> std::same_as<void>;
        };
/// State, output size, and default storage for an unkeyed digest.
template <class A>
struct hash_traits;
/// State, tag size, key sizes, and default storage for a keyed digest.
template <class A>
struct keyed_hash_traits;
}  // namespace potassium::hash

namespace potassium::hash::detail
{
/// Shared dimensions and storage for an unkeyed construction.
template <class State, std::size_t N>
struct traits
{
    /// Concrete backend state.
    using state_type = State;
    /// Digest length in bytes.
    static constexpr std::size_t digest_size = N;
    /// Store unkeyed state inline.
    using default_storage = inplace_hash_state<State>;
};

/// @cond INTERNAL
template <class A>
struct ops;

struct blake2b_ops
{
    /// Concrete BLAKE2b state.
    using state_type = crypto_generichash_blake2b_state;
    static void init(state_type&, std::size_t, std::span<std::byte const> key = {}) noexcept;
    static void update(state_type&, std::span<std::byte const>) noexcept;
    static void final(state_type&, std::span<std::byte>) noexcept;
    static void one_shot(std::span<std::byte>, std::span<std::byte const>, std::span<std::byte const> key = {}) noexcept;
};

template <std::size_t N>
struct ops<blake2b<N>> : blake2b_ops
{
    static void init(state_type& state) noexcept { blake2b_ops::init(state, N); }

    static void init(state_type& state, std::span<std::byte const> key) noexcept { blake2b_ops::init(state, N, key); }
};

template <auth::hmac_algorithm A>
struct ops<A> : auth::detail::hmac_ops<A>
{
};

/// @endcond
}  // namespace potassium::hash::detail

export namespace potassium::hash
{

template <>
constexpr bool detail::always_holds_value<crypto_generichash_blake2b_state> = true;

/// Backend state and output size for @c blake2b<N>.
template <std::size_t N>
struct hash_traits<blake2b<N>> : detail::traits<crypto_generichash_blake2b_state, N>
{
};

template <>
constexpr bool detail::always_holds_value<crypto_auth_hmacsha256_state> = true;

template <>
constexpr bool detail::always_holds_value<crypto_auth_hmacsha512_state> = true;

/// HMAC accepts an explicit key of any length for streaming.
template <auth::hmac_algorithm A>
struct keyed_hash_traits<A>
{
    /// Backend state for the selected HMAC construction.
    using state_type = typename auth::auth_traits<A>::state_type;
    /// Guarded storage for the key-derived state.
    using default_storage = guarded_hash_state<state_type>;
    /// View of the default fixed-size key.
    using key_type = key_ref<auth::hmac_key_tag<A>>;
    /// Tag size in bytes.
    static constexpr std::size_t digest_size = auth::auth_traits<A>::tag_size;
    /// Minimum streaming key size in bytes, including explicit empty keys.
    static constexpr std::size_t min_key_size = 0;
    /// Size in bytes of a generated key.
    static constexpr std::size_t default_key_size = auth::auth_traits<A>::key_size;
    /// Largest key size representable by a byte span.
    static constexpr std::size_t max_key_size = std::numeric_limits<std::size_t>::max();
};

/// Native keyed BLAKE2b dimensions and protected storage.
template <std::size_t N>
struct keyed_hash_traits<blake2b<N>>
{
    /// Read-only view of the default BLAKE2b key.
    using key_type = key_ref<blake2b_key_tag<>>;
    /// Tag length in bytes for this BLAKE2b construction.
    static constexpr std::size_t digest_size = N;
    /// Concrete BLAKE2b state.
    using state_type = crypto_generichash_blake2b_state;
    /// Allocate keyed state in guarded memory.
    using default_storage = guarded_hash_state<state_type>;
    /// Shortest supported key in bytes.
    static constexpr std::size_t min_key_size = crypto_generichash_blake2b_KEYBYTES_MIN;
    /// Longest supported key in bytes.
    static constexpr std::size_t max_key_size = crypto_generichash_blake2b_KEYBYTES_MAX;
    /// Default key length in bytes.
    static constexpr std::size_t default_key_size = crypto_generichash_blake2b_KEYBYTES;
};

template <>
constexpr bool detail::always_holds_value<crypto_hash_sha256_state> = true;

/// Backend state and output size for @c sha256.
template <>
struct hash_traits<sha256> : detail::traits<crypto_hash_sha256_state, crypto_hash_sha256_BYTES>
{
};

template <>
constexpr bool detail::always_holds_value<crypto_hash_sha512_state> = true;

/// Backend state and output size for @c sha512.
template <>
struct hash_traits<sha512> : detail::traits<crypto_hash_sha512_state, crypto_hash_sha512_BYTES>
{
};

template <>
constexpr bool detail::always_holds_value<crypto_hash_sha3256_state> = true;

/// Backend state and output size for @c sha3_256.
template <>
struct hash_traits<sha3_256> : detail::traits<crypto_hash_sha3256_state, crypto_hash_sha3256_BYTES>
{
};

template <>
constexpr bool detail::always_holds_value<crypto_hash_sha3512_state> = true;

/// Backend state and output size for @c sha3_512.
template <>
struct hash_traits<sha3_512> : detail::traits<crypto_hash_sha3512_state, crypto_hash_sha3512_BYTES>
{
};
}  // namespace potassium::hash

namespace potassium::hash::detail
{
/// @cond INTERNAL
template <>
struct ops<sha256>
{
    using state_type = hash_traits<sha256>::state_type;
    using output_type = std::span<std::byte, hash_traits<sha256>::digest_size>;
    static void init(state_type&) noexcept;
    static void update(state_type&, std::span<std::byte const>) noexcept;
    static void final(state_type&, output_type) noexcept;
    static void one_shot(output_type, std::span<std::byte const>) noexcept;
};

template <>
struct ops<sha512>
{
    using state_type = hash_traits<sha512>::state_type;
    using output_type = std::span<std::byte, hash_traits<sha512>::digest_size>;
    static void init(state_type&) noexcept;
    static void update(state_type&, std::span<std::byte const>) noexcept;
    static void final(state_type&, output_type) noexcept;
    static void one_shot(output_type, std::span<std::byte const>) noexcept;
};

template <>
struct ops<sha3_256>
{
    using state_type = hash_traits<sha3_256>::state_type;
    using output_type = std::span<std::byte, hash_traits<sha3_256>::digest_size>;
    static void init(state_type&) noexcept;
    static void update(state_type&, std::span<std::byte const>) noexcept;
    static void final(state_type&, output_type) noexcept;
    static void one_shot(output_type, std::span<std::byte const>) noexcept;
};

template <>
struct ops<sha3_512>
{
    using state_type = hash_traits<sha3_512>::state_type;
    using output_type = std::span<std::byte, hash_traits<sha3_512>::digest_size>;
    static void init(state_type&) noexcept;
    static void update(state_type&, std::span<std::byte const>) noexcept;
    static void final(state_type&, output_type) noexcept;
    static void one_shot(output_type, std::span<std::byte const>) noexcept;
};

/// @endcond
}  // namespace potassium::hash::detail

export namespace potassium::hash
{
/// Traits describing a fixed-size unkeyed digest and its storage policy.
template <class T>
concept hash_traits_type = requires
{
    typename std::integral_constant<std::size_t, T::digest_size>;
    requires T::digest_size > 0;
    requires hash_state_storage<typename T::default_storage, typename T::state_type>;
};
/// Traits describing the key-size range and storage policy for a keyed digest.
template <class T>
concept keyed_hash_traits_type = requires
{
    typename std::integral_constant<std::size_t, T::min_key_size>;
    typename std::integral_constant<std::size_t, T::max_key_size>;
    typename std::integral_constant<std::size_t, T::default_key_size>;
    requires(T::min_key_size <= T::default_key_size && T::default_key_size <= T::max_key_size);
    requires hash_state_storage<typename T::default_storage, typename T::state_type>;
};
/// Algorithm supporting unkeyed hashing.
template <class A>
concept SimpleDigest = hash_traits_type<hash_traits<A>> && requires(typename hash_traits<A>::state_type& state, std::span<std::byte const> input, std::span<std::byte, hash_traits<A>::digest_size> out)
{
    { detail::ops<A>::init(state) } noexcept -> std::same_as<void>;
    { detail::ops<A>::update(state, input) } noexcept -> std::same_as<void>;
    { detail::ops<A>::final(state, out) } noexcept -> std::same_as<void>;
};

/// Algorithm supporting keyed digest streams.
template <class A>
concept KeyedDigest = keyed_hash_traits_type<keyed_hash_traits<A>> &&
                      requires(typename keyed_hash_traits<A>::state_type& state, std::span<std::byte const> input, std::span<std::byte, keyed_hash_traits<A>::digest_size> out)
                      {
                          typename keyed_hash_traits<A>::key_type;
                          { detail::ops<A>::init(state, input) } noexcept -> std::same_as<void>;
                          { detail::ops<A>::update(state, input) } noexcept -> std::same_as<void>;
                          { detail::ops<A>::final(state, out) } noexcept -> std::same_as<void>;
                      };

/// Compatibility spelling for SimpleDigest.
template <class A>
concept hash_algorithm = SimpleDigest<A>;
/// Compatibility spelling for KeyedDigest.
template <class A>
concept keyed_hash_algorithm = KeyedDigest<A>;

namespace detail
{
struct digest_kind;
struct tag_kind;

/// Copyable public digest. Equality compares every byte.
template <class A, class Kind, std::size_t Size>
struct hash_output
{
    /// Digest bytes in wire order.
    std::array<std::byte, Size> storage{};

    /// Borrow the bytes for the lifetime of this digest.
    std::span<std::byte const, Size> bytes() const& noexcept { return storage; }

    /// Borrowing bytes requires a live lvalue result.
    auto bytes() const&& = delete;

    /// Compare digests in constant time.
    bool operator==(hash_output const& other) const noexcept { return detail::equal(storage, other.storage); }
};
}  // namespace detail

/// Fixed-size unkeyed digest with constant-time equality.
template <hash_algorithm A>
using digest_buffer = detail::hash_output<A, detail::digest_kind, hash_traits<A>::digest_size>;

/// Authentication tag produced by keyed hashing.
template <keyed_hash_algorithm A>
using tag_buffer = detail::hash_output<A, detail::tag_kind, keyed_hash_traits<A>::digest_size>;
}  // namespace potassium::hash

namespace potassium::hash::detail
{
template <std::size_t K>
auto key_view(key_ref<blake2b_key_tag<K>> key) noexcept
{
    return key;
}

template <std::size_t K>
auto key_view(secret_key<blake2b_key_tag<K>> const& key) noexcept
{
    return key.ref();
}

template <std::size_t K>
void key_view(secret_key<blake2b_key_tag<K>> const&&) = delete;

template <std::size_t K>
auto key_view(key_buffer_storage<blake2b_key_tag<K>> const& key) noexcept
{
    return key.ref();
}

template <std::size_t K>
void key_view(key_buffer_storage<blake2b_key_tag<K>> const&&) = delete;
template <class K>
concept compatible_key = requires(K&& key) { detail::key_view(std::forward<K>(key)); };

template <class A>
concept blake2b_algorithm = SimpleDigest<A> && std::derived_from<ops<A>, blake2b_ops>;

template <blake2b_algorithm A, compatible_key K>
std::span<std::byte const> key_bytes(K&& key) noexcept
{
    return key_view(std::forward<K>(key)).bytes();
}

template <auth::hmac_algorithm A>
std::span<std::byte const> key_bytes(key_ref<auth::hmac_key_tag<A>> key) noexcept
{
    return key.bytes();
}

template <auth::hmac_algorithm A>
std::span<std::byte const> key_bytes(std::span<std::byte const> key) noexcept
{
    return key;
}

template <class K, class A>
concept stream_key = requires(K&& key)
{
    { key_bytes<A>(std::forward<K>(key)) } noexcept;
};
}  // namespace potassium::hash::detail

export namespace potassium::hash
{
/// Write a digest directly into an exactly sized output.
template <hash_algorithm A>
void hash_into(std::span<std::byte const> message, std::span<std::byte, hash_traits<A>::digest_size> output) noexcept
{
    detail::ops<A>::one_shot(output, message);
}

/// Compute an unkeyed digest without allocating.
template <hash_algorithm A>
[[nodiscard]] digest_buffer<A> hash(std::span<std::byte const> message) noexcept
{
    digest_buffer<A> result;
    hash_into<A>(message, result.storage);
    return result;
}

/// Write a keyed BLAKE2b digest into an exactly sized output.
template <detail::blake2b_algorithm A, detail::compatible_key K>
void hash_into(K&& key, std::span<std::byte const> message, std::span<std::byte, hash_traits<A>::digest_size> output) noexcept
{
    detail::ops<A>::one_shot(output, message, detail::key_view(std::forward<K>(key)).bytes());
}

/// Compute a keyed digest without allocating guarded stream state.
template <detail::blake2b_algorithm A, detail::compatible_key K>
[[nodiscard]] tag_buffer<A> hash(K&& key, std::span<std::byte const> message) noexcept
{
    tag_buffer<A> result;
    hash_into<A>(std::forward<K>(key), message, result.storage);
    return result;
}
}  // namespace potassium::hash

namespace potassium::hash::detail
{

/// Common ownership and consumption rules for streaming hashes.
template <class A, class Storage, class Result>
class stream_state
{
    Storage storage_;
#ifdef POTASSIUM_HASH_ASSERTS
    bool active_ = false;
#endif

public:
    /// Fixed-size digest or authentication tag.
    using result_type = Result;
    /// Move-only handle used to restart a stream in wiped storage.
    using token_type = typename Storage::transfer_token;

protected:
    stream_state() = default;

    ~stream_state()
    {
        if (storage_.has_value()) erase(storage_.get());
    }

    /// Transfer ownership and invalidate the source.
    stream_state(stream_state&& other) noexcept
        requires std::is_nothrow_move_constructible_v<Storage>
        : storage_(std::move(other.storage_))
#ifdef POTASSIUM_HASH_ASSERTS
        , active_(std::exchange(other.active_, false))
#endif
    {
    }

    /// Release the previous state and transfer ownership.
    stream_state& operator=(stream_state&& other) noexcept
        requires std::is_nothrow_move_assignable_v<Storage>
    {
        if (this != &other)
        {
            storage_ = std::move(other.storage_);
#ifdef POTASSIUM_HASH_ASSERTS
            active_ = std::exchange(other.active_, false);
#endif
        }
        return *this;
    }

    /// Initialize a fresh or wiped state.
    template <class... Key>
    void initialize(Key... key) noexcept
    {
        ops<A>::init(storage_.get(), key...);
#ifdef POTASSIUM_HASH_ASSERTS
        active_ = true;
#endif
    }

    /// Discard pending input. @pre The stream is active.
    template <class... Key>
    void reset(Key... key) noexcept
    {
#ifdef POTASSIUM_HASH_ASSERTS
        assert(active_);
#endif
        erase(storage_.get());
        initialize(key...);
    }

    /// Start a computation using a live token, including on a moved-from stream.
    template <class... Key>
    void reset_with_token(typename Storage::transfer_token&& token, Key... key) noexcept
    {
        if (storage_.has_value()) erase(storage_.get());
        storage_.assign_token(std::move(token));
        initialize(key...);
    }

public:
    /// Absorb a chunk. @pre The stream is active.
    void update(std::span<std::byte const> message) & noexcept
    {
#ifdef POTASSIUM_HASH_ASSERTS
        assert(active_);
#endif
        ops<A>::update(storage_.get(), message);
    }

    /// Finish the digest and erase the state. @pre The stream is active.
    [[nodiscard]] Result finalize() && noexcept
    {
#ifdef POTASSIUM_HASH_ASSERTS
        assert(active_);
        active_ = false;
#endif
        Result result;
        ops<A>::final(storage_.get(), result.storage);
        erase(storage_.get());
        return result;
    }

    /// Finish and hand the wiped storage to the caller. @pre The stream is active.
    [[nodiscard]] std::pair<Result, token_type> finalize_for_reuse() && noexcept { return {std::move(*this).finalize(), storage_.make_token()}; }

    /// Consume a mutable rvalue to finalize the stream.
    Result finalize() & = delete ("finalize() consumes the hasher: use std::move(hasher).finalize()");
    /// Consume a mutable rvalue to finalize the stream.
    Result finalize() const& = delete ("finalize() requires a mutable hasher: use std::move(hasher).finalize()");
    /// Consume a mutable rvalue to finalize the stream.
    Result finalize() const&& = delete ("finalize() requires a mutable rvalue hasher");

    /// Consume a mutable rvalue to finalize the stream.
    std::pair<Result, token_type> finalize_for_reuse() & = delete ("finalize_for_reuse() consumes the hasher: use std::move(hasher).finalize_for_reuse()");
    /// Consume a mutable rvalue to finalize the stream.
    std::pair<Result, token_type> finalize_for_reuse() const& = delete ("finalize_for_reuse() requires a mutable rvalue hasher");
    /// Consume a mutable rvalue to finalize the stream.
    std::pair<Result, token_type> finalize_for_reuse() const&& = delete ("finalize_for_reuse() requires a mutable rvalue hasher");
};
}  // namespace potassium::hash::detail

#if __has_cpp_attribute(clang::reinitializes)
#define LIBPOTASSIUM_MOVE_RESET [[clang::reinitializes]]
#else
#define LIBPOTASSIUM_MOVE_RESET
#endif

export namespace potassium::hash
{
/// Incremental unkeyed digest with immobile, in-place state by default.
/// @tparam A Unkeyed digest algorithm.
/// @tparam Storage State owner satisfying hash_state_storage.
template <hash_algorithm A, class Storage = typename hash_traits<A>::default_storage>
    requires hash_state_storage<Storage, typename hash_traits<A>::state_type>
class hasher : public detail::stream_state<A, Storage, digest_buffer<A>>
{
    using base = detail::stream_state<A, Storage, digest_buffer<A>>;

public:
    /// Start an empty digest with the selected storage policy.
    hasher() noexcept(std::is_nothrow_default_constructible_v<Storage>) { base::initialize(); }

    /// Discard any partial input and start again. @pre The stream is active.
    void reset() & noexcept { base::reset(); }

    /// Start again from any stream state. @pre The token is unconsumed.
    LIBPOTASSIUM_MOVE_RESET void reset(typename Storage::transfer_token&& token) & noexcept { base::reset_with_token(std::move(token)); }
};

/// Incremental keyed BLAKE2b or HMAC with guarded state by default.
/// @tparam A Keyed digest algorithm, such as auth::hmac_sha256 or blake2b<>.
/// @tparam Storage State owner, such as guarded_hash_state or inplace_hash_state.
/// @details Finalization consumes the stream and immediately wipes its state.
/// Use finalize_for_reuse() to retain a token for allocation-free reset.
template <keyed_hash_algorithm A, class Storage = typename keyed_hash_traits<A>::default_storage>
    requires hash_state_storage<Storage, typename keyed_hash_traits<A>::state_type>
class keyed_hasher : public detail::stream_state<A, Storage, tag_buffer<A>>
{
    using base = detail::stream_state<A, Storage, tag_buffer<A>>;

public:
    /// Representative key view accepted by construction and reset.
    using key_type = typename keyed_hash_traits<A>::key_type;

    /// Construct directly in the result, including for immobile storage.
    /// @return An initialized stream or errc::allocation_failed.
    template <detail::stream_key<A> K = std::span<std::byte const>>
    static std::expected<keyed_hasher, errc> create(K&& key, std::nothrow_t) noexcept
    try
    {
        return std::expected<keyed_hasher, errc>{std::in_place, std::forward<K>(key)};
    }
    catch (std::bad_alloc const&)
    {
        return std::unexpected(errc::allocation_failed);
    }

    /// Construct a keyed stream or throw on allocation failure.
    template <detail::stream_key<A> K = std::span<std::byte const>>
    static keyed_hasher create(K&& key) noexcept(std::is_nothrow_default_constructible_v<Storage>)
    {
        if constexpr (std::move_constructible<keyed_hasher>)
        {
            auto result = create(std::forward<K>(key), std::nothrow);
            if (!result) throw_error(result.error());
            return std::move(*result);
        }
        else
            return keyed_hasher(std::forward<K>(key));
    }

    /// Initialize from a borrowed key without retaining the reference.
    template <detail::stream_key<A> K = std::span<std::byte const>>
    explicit keyed_hasher(K&& key) noexcept(std::is_nothrow_default_constructible_v<Storage>)
    {
        base::initialize(detail::key_bytes<A>(std::forward<K>(key)));
    }

    /// Restart under the supplied key. @pre The stream is active.
    template <detail::stream_key<A> K = std::span<std::byte const>>
    void reset(K&& key) & noexcept
    {
        base::reset(detail::key_bytes<A>(std::forward<K>(key)));
    }

    /// Start under the supplied key from any stream state. @pre The token is unconsumed.
    template <detail::stream_key<A> K = std::span<std::byte const>>
    LIBPOTASSIUM_MOVE_RESET void reset(K&& key, typename Storage::transfer_token&& token) & noexcept
    {
        base::reset_with_token(std::move(token), detail::key_bytes<A>(std::forward<K>(key)));
    }
};

/// Initialized stream with nonthrowing update and consuming finalizers.
template <class S>
concept Hasher = requires(S& stream, std::span<std::byte const> chunk)
{
    { stream.update(chunk) } noexcept -> std::same_as<void>;
    { std::move(stream).finalize() } noexcept -> std::same_as<typename S::result_type>;
    { std::move(stream).finalize_for_reuse() } noexcept -> std::same_as<std::pair<typename S::result_type, typename S::token_type>>;
    requires(!requires { stream.finalize(); } && !requires { stream.finalize_for_reuse(); });
    requires(!requires { std::as_const(stream).finalize(); } && !requires { std::as_const(stream).finalize_for_reuse(); });
    requires(!requires { std::move(std::as_const(stream)).finalize(); } && !requires { std::move(std::as_const(stream)).finalize_for_reuse(); });
};

/// Stream supporting keyless construction and reset.
template <class S>
concept SimpleHasher = Hasher<S> && std::default_initializable<S> && requires(S& stream, typename S::token_type token)
{
    { stream.reset() } noexcept -> std::same_as<void>;
    { stream.reset(std::move(token)) } noexcept -> std::same_as<void>;
};

/// Stream supporting construction and reset with its associated key view.
template <class S>
concept KeyedHasher = Hasher<S> && std::constructible_from<S, typename S::key_type> && requires(S& stream, typename S::key_type key, typename S::token_type token)
{
    { stream.reset(key) } noexcept -> std::same_as<void>;
    { stream.reset(key, std::move(token)) } noexcept -> std::same_as<void>;
};

/// Construct an unkeyed stream in place, including with custom allocating storage.
template <hash_algorithm A, class Storage = typename hash_traits<A>::default_storage>
std::expected<hasher<A, Storage>, errc> make_hasher(std::nothrow_t) noexcept
try
{
    return std::expected<hasher<A, Storage>, errc>{std::in_place};
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

/// Construct in the result's storage, translating allocation failure.
template <keyed_hash_algorithm A, class Storage = typename keyed_hash_traits<A>::default_storage, detail::stream_key<A> K>
std::expected<keyed_hasher<A, Storage>, errc> make_keyed_hasher(K&& key, std::nothrow_t) noexcept
{
    return keyed_hasher<A, Storage>::create(std::forward<K>(key), std::nothrow);
}

/// Construct a keyed stream or throw on allocation failure.
template <keyed_hash_algorithm A, class Storage = typename keyed_hash_traits<A>::default_storage, detail::stream_key<A> K>
keyed_hasher<A, Storage> make_keyed_hasher(K&& key)
{
    return keyed_hasher<A, Storage>::create(std::forward<K>(key));
}
}  // namespace potassium::hash
