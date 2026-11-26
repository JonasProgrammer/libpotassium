// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

/// @brief Authenticated encryption of ordered records with XChaCha20-Poly1305.
export module potassium.secretstream;

export import potassium.core;
import std;

/// Stateful authenticated encryption of ordered records.
export namespace potassium::secretstream
{
/// @struct potassium::secretstream::key_tag
/// @brief Confidential key purpose for secretstream.
struct key_tag;

/// Length in bytes of the public stream header.
inline constexpr std::size_t header_size = 24;

/// Extra bytes in each encrypted record.
inline constexpr std::size_t record_overhead = 17;

/// Maximum plaintext length for an individual record.
inline constexpr std::size_t messagebytes_max = std::min<std::uintmax_t>(std::numeric_limits<std::size_t>::max() - record_overhead, 64ull * (0xffffffffull - 1));
}  // namespace potassium::secretstream

export namespace potassium
{
/// Confidential key traits for secretstream.
template <>
struct key_traits<secretstream::key_tag>
{
    /// Default generator for this key purpose.
    using generator = random_key_generator;

    /// Key length in bytes.
    static constexpr std::size_t size = 32;
};
}  // namespace potassium

namespace potassium::secretstream::detail
{
class stream_state;
}  // namespace potassium::secretstream::detail

export namespace potassium::secretstream
{
/// Borrowed key for stream initialization.
using stream_key_ref = key_ref<key_tag>;

/// Backend state type for caller-provided storage.
using state_type = crypto_secretstream_xchacha20poly1305_state;

/// Immobile, inline storage that can back a sender or receiver.
class inplace_state
{
public:
    /// Value-initialize the backend state.
    inplace_state() = default;
    inplace_state(inplace_state const&) = delete;
    inplace_state& operator=(inplace_state const&) = delete;
    /// Wipe the state before releasing its storage.
    ~inplace_state();

    /// @return State to lend to a state_storage handle.
    state_type& get() & noexcept { return state_; }

private:
    state_type state_{};
};

/// Move-only handle to idle storage for a sender or receiver.
class state_storage
{
public:
    /// Allocate state in guarded memory.
    /// @throws std::bad_alloc If allocation fails.
    state_storage();

    /// Wipe and borrow preallocated state from inline storage or a custom owner.
    /// @pre The state outlives the handle and any stream or handle it is moved into.
    /// @pre The state is reserved for exclusive use by this handle and its successors.
    explicit state_storage(state_type& state) noexcept;

    /// Transfer the storage and empty the source handle.
    state_storage(state_storage&& other) noexcept;
    /// Release the previous storage, transfer the new storage and empty the source handle.
    state_storage& operator=(state_storage&& other) noexcept;

    /// @return Whether this handle holds storage for a new stream.
    [[nodiscard]] explicit operator bool() const noexcept;

private:
    friend class detail::stream_state;
    using guarded_state = std::indirect<state_type, allocator<state_type>>;
    std::variant<std::monostate, guarded_state, std::reference_wrapper<state_type>> storage_;

    state_type& get() noexcept;
};

/// Copyable public header sent ahead of the first encrypted record.
struct stream_header
{
    /// Header bytes in transmission order.
    std::array<std::byte, header_size> storage{};

    /// @return Writable bytes for importing a header from the wire.
    constexpr std::span<std::byte, header_size> bytes() & noexcept { return storage; }

    /// @return Read-only header bytes.
    constexpr std::span<std::byte const, header_size> bytes() const& noexcept { return storage; }

    /// Borrowing requires a live lvalue owner.
    std::span<std::byte const, header_size> bytes() const&& = delete;
};

/// Authenticated type of a stream record.
enum class record_tag : unsigned char
{
    /// An ordinary record.
    message = 0,
    /// The end of an application-defined group of records.
    push = 1,
    /// Rekey both peers after processing this record.
    rekey = 2,
    /// Finish the stream after processing this record.
    final = 3,
};

/// Authenticated plaintext and record tag.
struct pull_result
{
    /// Plaintext in guarded storage.
    secure_buffer plaintext;
    /// Tag authenticated with the record.
    record_tag tag;
};

class sender;
class receiver;

/// Initialize a sender in guarded storage and generate its public header.
/// @return A sender, errc::allocation_failed, or errc::crypto_failed.
std::expected<sender, errc> start_push(stream_key_ref key, std::nothrow_t) noexcept;

/// Initialize a sender in guarded storage and generate its public header.
/// @throws std::bad_alloc If allocation fails.
/// @throws crypto_error If initialization fails.
sender start_push(stream_key_ref key);

/// Initialize a sender using storage supplied by the caller.
/// @param storage Storage consumed by initialization.
/// @return A sender or errc::crypto_failed if the handle is empty or initialization fails.
std::expected<sender, errc> start_push(stream_key_ref key, state_storage&& storage, std::nothrow_t) noexcept;

/// @overload
/// @throws crypto_error If the handle is empty or initialization fails.
sender start_push(stream_key_ref key, state_storage&& storage);

/// Initialize a receiver in guarded storage using the sender's header.
/// @note Record authentication uses the key and header supplied here.
/// @return A receiver, errc::allocation_failed, or errc::crypto_failed.
std::expected<receiver, errc> start_pull(stream_key_ref key, stream_header const& header, std::nothrow_t) noexcept;

/// Initialize a receiver in guarded storage using the sender's header.
/// @throws std::bad_alloc If allocation fails.
/// @throws crypto_error If initialization fails.
receiver start_pull(stream_key_ref key, stream_header const& header);

/// Initialize a receiver using storage supplied by the caller and the sender's header.
/// @param storage Storage consumed by initialization.
/// @return A receiver or errc::crypto_failed if the handle is empty or initialization fails.
std::expected<receiver, errc> start_pull(stream_key_ref key, stream_header const& header, state_storage&& storage, std::nothrow_t) noexcept;

/// @overload
/// @throws crypto_error If the handle is empty or initialization fails.
receiver start_pull(stream_key_ref key, stream_header const& header, state_storage&& storage);
}  // namespace potassium::secretstream

/// @cond INTERNAL
namespace potassium::secretstream::detail
{
class stream_state
{
public:
    explicit stream_state(state_storage&& storage) noexcept;
    stream_state(stream_state&& other) noexcept;
    stream_state& operator=(stream_state&& other) noexcept;
    ~stream_state();

    explicit operator bool() const noexcept { return active_; }

    state_type& get() noexcept { return storage_.get(); }

    void close() noexcept;
    state_storage release() noexcept;

private:
    state_storage storage_;
    bool active_ = true;
};
}  // namespace potassium::secretstream::detail

/// @endcond

export namespace potassium::secretstream
{
/// Move-only state for sealing an ordered stream of records.
class sender
{
public:
    /// Transfer the stream state, leaving the source closed.
    sender(sender&&) noexcept = default;
    /// Wipe the previous state and take the source state.
    sender& operator=(sender&&) noexcept = default;

    /// @return A copy of the public header.
    [[nodiscard]] stream_header header() const noexcept { return header_; }

    /// Close the sender, wipe its state and return storage for a new stream.
    /// Also works after sending a final record.
    /// @return An empty handle if the storage was already moved out.
    [[nodiscard]] state_storage close_for_reuse() && noexcept { return state_.release(); }

    /// Seal a record with optional associated data.
    /// @return A record, errc::allocation_failed, or errc::crypto_failed.
    std::expected<std::vector<std::byte>, errc> push(std::span<std::byte const> message, std::span<std::byte const> ad, record_tag tag, std::nothrow_t) noexcept;

    /// @overload
    /// @throws std::bad_alloc If allocation fails.
    /// @throws crypto_error If the stream is closed or sealing fails.
    std::vector<std::byte> push(std::span<std::byte const> message, std::span<std::byte const> ad, record_tag tag = record_tag::message);

    /// Seal a record into caller storage.
    /// @pre Output is disjoint from all inputs and holds message.size() plus record_overhead bytes.
    /// @return Success or errc::crypto_failed.
    std::expected<void, errc> push_into(std::span<std::byte const> message, std::span<std::byte const> ad, std::span<std::byte> out, record_tag tag, std::nothrow_t) noexcept;

    /// @overload
    /// @throws crypto_error If the stream is closed or sealing fails.
    void push_into(std::span<std::byte const> message, std::span<std::byte const> ad, std::span<std::byte> out, record_tag tag = record_tag::message);

    /// Rekey the sender between records.
    /// @pre The receiver rekeys at the same position in the stream.
    /// @return Success or errc::crypto_failed if the stream is closed.
    std::expected<void, errc> rekey(std::nothrow_t) noexcept;

    /// @overload
    /// @throws crypto_error If the stream is closed.
    void rekey();

private:
    friend std::expected<sender, errc> start_push(stream_key_ref key, state_storage&& storage, std::nothrow_t) noexcept;
    explicit sender(state_storage&& storage) noexcept;
    std::expected<void, errc> push_record(std::span<std::byte const> message, std::span<std::byte const> ad, std::span<std::byte> out, record_tag tag) noexcept;

    detail::stream_state state_;
    stream_header header_;
};

/// Move-only state for opening an ordered stream of records.
class receiver
{
public:
    /// Transfer the stream state and final authentication result, leaving the source closed.
    receiver(receiver&& other) noexcept;
    /// Wipe the previous state and take the source state and final authentication result.
    receiver& operator=(receiver&& other) noexcept;

    /// @return Whether this stream successfully authenticated a final record.
    [[nodiscard]] bool finished() const noexcept { return finished_; }

    /// Close the receiver, wipe its state and return storage for a new stream.
    /// Also works after authenticating a final record or closing on an error.
    /// @return An empty handle if the storage was already moved out.
    [[nodiscard]] state_storage close_for_reuse() && noexcept { return state_.release(); }

    /// Open a record with optional associated data.
    /// @return Guarded plaintext and tag, errc::allocation_failed, or errc::crypto_failed.
    std::expected<pull_result, errc> pull(std::span<std::byte const> record, std::span<std::byte const> ad, std::nothrow_t) noexcept;

    /// @overload
    /// @throws std::bad_alloc If allocation fails.
    /// @throws crypto_error If the stream is closed or opening fails.
    pull_result pull(std::span<std::byte const> record, std::span<std::byte const> ad);

    /// Open a record into caller storage and return its authenticated tag.
    /// @pre Output is disjoint from all inputs and, for a record of at least record_overhead bytes, holds record.size() minus record_overhead bytes.
    /// @note Authentication failure may clear the output.
    /// @return The authenticated tag or errc::crypto_failed.
    std::expected<record_tag, errc> pull_into(std::span<std::byte const> record, std::span<std::byte const> ad, std::span<std::byte> out, std::nothrow_t) noexcept;

    /// @overload
    /// @throws crypto_error If the stream is closed or opening fails.
    record_tag pull_into(std::span<std::byte const> record, std::span<std::byte const> ad, std::span<std::byte> out);

    /// Rekey the receiver between records.
    /// @pre The sender rekeys at the same position in the stream.
    /// @return Success or errc::crypto_failed if the stream is closed.
    std::expected<void, errc> rekey(std::nothrow_t) noexcept;

    /// @overload
    /// @throws crypto_error If the stream is closed.
    void rekey();

private:
    friend std::expected<receiver, errc> start_pull(stream_key_ref key, stream_header const& header, state_storage&& storage, std::nothrow_t) noexcept;
    explicit receiver(state_storage&& storage) noexcept;
    std::expected<std::size_t, errc> plaintext_size(std::size_t record_size, std::size_t ad_size) noexcept;
    std::expected<record_tag, errc> pull_record(std::span<std::byte const> record, std::span<std::byte const> ad, std::span<std::byte> out) noexcept;

    detail::stream_state state_;
    bool finished_ = false;
};
}  // namespace potassium::secretstream
