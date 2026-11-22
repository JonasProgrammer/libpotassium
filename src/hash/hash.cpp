// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

/// @brief Fixed-output one-shot and streaming hashes.
export module potassium.hash;
export import potassium.core;
import std;

export namespace potassium::hash
{
/// BLAKE2b parameterized by its digest size in bytes.
template <std::size_t N = 32>
    requires(N >= 16 && N <= 64)
struct blake2b;

/// SHA-2 with a 256-bit digest.
struct sha256;

/// SHA-2 with a 512-bit digest.
struct sha512;

/// SHA-3 with a 256-bit digest.
struct sha3_256;

/// SHA-3 with a 512-bit digest.
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

template <class State>
void erase(State& state) noexcept
{
    wipe(std::as_writable_bytes(std::span{&state, 1}));
}
}  // namespace potassium::hash::detail

export namespace potassium::hash
{
/// Immobile state, erased before its storage is released.
template <class State>
class inplace_hash_state
{
    State state_{};

public:
    inplace_hash_state() = default;
    inplace_hash_state(inplace_hash_state const&) = delete;
    inplace_hash_state& operator=(inplace_hash_state const&) = delete;

    ~inplace_hash_state() { detail::erase(state_); }

    /// Return the owned state.
    State& get() & noexcept { return state_; }
};

/// Guarded state whose allocation transfers intact across moves.
template <class State>
class guarded_hash_state
{
    std::indirect<State, allocator<State>> state_;

public:
    guarded_hash_state() = default;
    guarded_hash_state(guarded_hash_state const&) = delete;
    guarded_hash_state& operator=(guarded_hash_state const&) = delete;
    /// Transfer ownership of the live state.
    guarded_hash_state(guarded_hash_state&&) noexcept = default;
    /// Wipe and release the previous allocation and take ownership of the source state.
    guarded_hash_state& operator=(guarded_hash_state&&) noexcept = default;

    /// @pre This owner holds a live allocation.
    State& get() & noexcept { return *state_; }
};

/// Storage owns a state, erases it on release, and transfers ownership on any move.
template <class Storage, class State>
concept hash_state_storage = std::default_initializable<Storage> && !std::is_copy_constructible_v<Storage> && !std::is_copy_assignable_v<Storage> && requires(Storage& s) {
    { s.get() } noexcept -> std::same_as<State&>;
};
template <class A>
struct hash_traits;
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
};

/// @endcond
}  // namespace potassium::hash::detail

export namespace potassium::hash
{
template <std::size_t N>
struct hash_traits<blake2b<N>> : detail::traits<crypto_generichash_blake2b_state, N>
{
};

/// Native keyed BLAKE2b dimensions and protected storage.
template <std::size_t N>
struct keyed_hash_traits<blake2b<N>>
{
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
struct hash_traits<sha256> : detail::traits<crypto_hash_sha256_state, crypto_hash_sha256_BYTES>
{
};

template <>
struct hash_traits<sha512> : detail::traits<crypto_hash_sha512_state, crypto_hash_sha512_BYTES>
{
};

template <>
struct hash_traits<sha3_256> : detail::traits<crypto_hash_sha3256_state, crypto_hash_sha3256_BYTES>
{
};

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
template <class T>
concept hash_traits_type = requires {
    typename std::integral_constant<std::size_t, T::digest_size>;
    requires T::digest_size > 0;
    requires hash_state_storage<typename T::default_storage, typename T::state_type>;
};
template <class T>
concept keyed_hash_traits_type = requires {
    typename std::integral_constant<std::size_t, T::min_key_size>;
    typename std::integral_constant<std::size_t, T::max_key_size>;
    typename std::integral_constant<std::size_t, T::default_key_size>;
    requires(0 < T::min_key_size && T::min_key_size <= T::default_key_size && T::default_key_size <= T::max_key_size);
    requires hash_state_storage<typename T::default_storage, typename T::state_type>;
};
template <class A>
concept hash_algorithm = requires { sizeof(detail::ops<A>); } && hash_traits_type<hash_traits<A>>;
template <class A>
concept keyed_hash_algorithm = hash_algorithm<A> && std::derived_from<detail::ops<A>, detail::blake2b_ops> && keyed_hash_traits_type<keyed_hash_traits<A>>;

namespace detail
{
struct digest_kind;
struct tag_kind;

/// Copyable public digest. Equality compares every byte.
template <hash_algorithm A, class Kind>
struct hash_output
{
    /// Digest bytes in wire order.
    std::array<std::byte, hash_traits<A>::digest_size> storage{};

    /// Borrow the bytes for the lifetime of this digest.
    std::span<std::byte const, hash_traits<A>::digest_size> bytes() const& noexcept { return storage; }

    auto bytes() const&& = delete;

    /// Compare digests in constant time.
    bool operator==(hash_output const& other) const noexcept { return detail::equal(storage, other.storage); }
};
}  // namespace detail

template <hash_algorithm A>
using digest_buffer = detail::hash_output<A, detail::digest_kind>;

/// Authentication tag produced by keyed hashing.
template <keyed_hash_algorithm A>
using tag_buffer = detail::hash_output<A, detail::tag_kind>;
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
template <keyed_hash_algorithm A, detail::compatible_key K>
void hash_into(K&& key, std::span<std::byte const> message, std::span<std::byte, hash_traits<A>::digest_size> output) noexcept
{
    detail::ops<A>::one_shot(output, message, detail::key_view(std::forward<K>(key)).bytes());
}

/// Compute a keyed digest without allocating guarded stream state.
template <keyed_hash_algorithm A, detail::compatible_key K>
[[nodiscard]] tag_buffer<A> hash(K&& key, std::span<std::byte const> message) noexcept
{
    tag_buffer<A> result;
    hash_into<A>(std::forward<K>(key), message, result.storage);
    return result;
}
}  // namespace potassium::hash

namespace potassium::hash::detail
{
// Inactive finalized streams still own storage. A moved-from stream has none.
enum class phase
{
    active,
    finalized,
    moved_from,
};

/// Common ownership and consumption rules for streaming hashes.
template <class A, class Storage>
class stream_state
{
    Storage storage_;
    phase phase_ = phase::finalized;

public:
    stream_state() = default;

    ~stream_state()
    {
        if (phase_ == phase::active) erase(storage_.get());
    }

    /// Transfer ownership and invalidate the source.
    stream_state(stream_state&& other) noexcept
        requires std::is_nothrow_move_constructible_v<Storage>
        : storage_(std::move(other.storage_))
        , phase_(std::exchange(other.phase_, phase::moved_from))
    {
    }

    /// Release the previous state and transfer ownership.
    stream_state& operator=(stream_state&& other) noexcept
        requires std::is_nothrow_move_assignable_v<Storage>
    {
        if (this != &other)
        {
            storage_ = std::move(other.storage_);
            phase_ = std::exchange(other.phase_, phase::moved_from);
        }
        return *this;
    }

    /// Erase any pending input and return storage for initialization.
    auto& restart() noexcept
    {
        if (phase_ == phase::moved_from) std::terminate();
        auto& state = storage_.get();
        if (phase_ == phase::active) erase(state);
        phase_ = phase::active;
        return state;
    }

    /// Absorb a chunk. @pre The stream is active.
    void update(std::span<std::byte const> message) & noexcept
    {
        if (phase_ != phase::active) std::terminate();
        ops<A>::update(storage_.get(), message);
    }

    /// Finish the digest and erase the state. @pre The stream is active.
    template <class Result>
    [[nodiscard]] Result finish() noexcept
    {
        if (phase_ != phase::active) std::terminate();
        Result result;
        ops<A>::final(storage_.get(), result.storage);
        erase(storage_.get());
        phase_ = phase::finalized;
        return result;
    }
};
}  // namespace potassium::hash::detail

#if __has_cpp_attribute(clang::reinitializes)
#define LIBPOTASSIUM_MOVE_RESET [[clang::reinitializes]]
#else
#define LIBPOTASSIUM_MOVE_RESET
#endif

export namespace potassium::hash
{
/// Unkeyed stream with immobile, in-place state by default.
template <hash_algorithm A, class Storage = typename hash_traits<A>::default_storage>
    requires hash_state_storage<Storage, typename hash_traits<A>::state_type>
class hasher
{
    detail::stream_state<A, Storage> state_;

public:
    hasher() noexcept(std::is_nothrow_default_constructible_v<Storage>) { reset(); }

    /// Absorb a chunk. @pre The stream is active.
    void update(std::span<std::byte const> message) & noexcept { state_.update(message); }

    /// Finish the digest and wipe the state. @pre The stream is active.
    [[nodiscard]] digest_buffer<A> finalize() && noexcept { return state_.template finish<digest_buffer<A>>(); }

    /// A named stream must explicitly be consumed.
    digest_buffer<A> finalize() & = delete ("finalize() consumes the hasher: use std::move(hasher).finalize()");
    /// Finalization requires a mutable stream.
    digest_buffer<A> finalize() const& = delete ("finalize() requires a mutable hasher: use std::move(hasher).finalize()");
    /// Finalization requires a mutable stream.
    digest_buffer<A> finalize() const&& = delete ("finalize() requires a mutable rvalue hasher");

    /// Discard any partial input and start again. @pre The stream owns its storage.
    void reset() & noexcept LIBPOTASSIUM_MOVE_RESET
    {
        if constexpr (keyed_hash_algorithm<A>)
            detail::ops<A>::init(state_.restart(), hash_traits<A>::digest_size);
        else
            detail::ops<A>::init(state_.restart());
    }
};

/// Keyed BLAKE2b stream with move-only guarded state by default.
template <keyed_hash_algorithm A, class Storage = typename keyed_hash_traits<A>::default_storage>
    requires hash_state_storage<Storage, typename hash_traits<A>::state_type>
class keyed_hasher
{
    detail::stream_state<A, Storage> state_;

public:
    /// Initialize from a borrowed key without retaining the reference.
    template <detail::compatible_key K>
    explicit keyed_hasher(K&& key) noexcept(std::is_nothrow_default_constructible_v<Storage>)
    {
        reset(std::forward<K>(key));
    }

    /// Absorb a chunk. @pre The stream is active.
    void update(std::span<std::byte const> message) & noexcept { state_.update(message); }

    /// Finish the digest and wipe the state. @pre The stream is active.
    [[nodiscard]] tag_buffer<A> finalize() && noexcept { return state_.template finish<tag_buffer<A>>(); }

    /// A named stream must explicitly be consumed.
    tag_buffer<A> finalize() & = delete ("finalize() consumes the hasher: use std::move(hasher).finalize()");
    /// Finalization requires a mutable stream.
    tag_buffer<A> finalize() const& = delete ("finalize() requires a mutable hasher: use std::move(hasher).finalize()");
    /// Finalization requires a mutable stream.
    tag_buffer<A> finalize() const&& = delete ("finalize() requires a mutable rvalue hasher");

    /// Restart under the supplied key. @pre The stream owns its storage.
    template <detail::compatible_key K>
    void reset(K&& key) & noexcept
    {
        detail::ops<A>::init(state_.restart(), hash_traits<A>::digest_size, detail::key_view(std::forward<K>(key)).bytes());
    }
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
template <keyed_hash_algorithm A, class Storage = typename keyed_hash_traits<A>::default_storage, detail::compatible_key K>
std::expected<keyed_hasher<A, Storage>, errc> make_keyed_hasher(K&& key, std::nothrow_t) noexcept
try
{
    return std::expected<keyed_hasher<A, Storage>, errc>{std::in_place, std::forward<K>(key)};
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

/// Construct a movable stream or throw on allocation failure.
template <keyed_hash_algorithm A, class Storage = typename keyed_hash_traits<A>::default_storage, detail::compatible_key K>
    requires std::move_constructible<keyed_hasher<A, Storage>>
keyed_hasher<A, Storage> make_keyed_hasher(K&& key)
{
    auto result = make_keyed_hasher<A, Storage>(std::forward<K>(key), std::nothrow);
    if (!result) throw_error(result.error());
    return std::move(*result);
}
}  // namespace potassium::hash
