// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

module potassium.secretstream;

import potassium.internal;
import std;

namespace potassium::secretstream
{
namespace
{
using internal::sodium_bytes;
using internal::unwrap;

static_assert(key_traits<key_tag>::size == crypto_secretstream_xchacha20poly1305_KEYBYTES);
static_assert(header_size == crypto_secretstream_xchacha20poly1305_HEADERBYTES);
static_assert(record_overhead == crypto_secretstream_xchacha20poly1305_ABYTES);
static_assert(messagebytes_max == crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
static_assert(std::to_underlying(record_tag::message) == crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
static_assert(std::to_underlying(record_tag::push) == crypto_secretstream_xchacha20poly1305_TAG_PUSH);
static_assert(std::to_underlying(record_tag::rekey) == crypto_secretstream_xchacha20poly1305_TAG_REKEY);
static_assert(std::to_underlying(record_tag::final) == crypto_secretstream_xchacha20poly1305_TAG_FINAL);

void erase_state(state_type& state) noexcept
{
    wipe(std::as_writable_bytes(std::span{&state, 1}));
}

bool valid_tag(record_tag tag) noexcept
{
    return tag <= record_tag::final;
}

bool valid_lengths(std::size_t message_size, std::size_t ad_size) noexcept
{
    return message_size <= messagebytes_max && std::in_range<std::uint64_t>(ad_size);
}
}  // namespace

inplace_state::~inplace_state()
{
    erase_state(state_);
}

state_storage::state_storage()
    : storage_(std::in_place_type<guarded_state>)
{
}

state_storage::state_storage(state_type& state) noexcept
    : storage_(std::ref(state))
{
    erase_state(state);
}

state_storage::state_storage(state_storage&& other) noexcept
    : storage_(std::exchange(other.storage_, std::monostate{}))
{
}

state_storage& state_storage::operator=(state_storage&& other) noexcept
{
    if (this != &other) storage_ = std::exchange(other.storage_, std::monostate{});
    return *this;
}

state_storage::operator bool() const noexcept
{
    return !std::holds_alternative<std::monostate>(storage_);
}

state_type& state_storage::get() noexcept
{
    if (auto* guarded = std::get_if<guarded_state>(&storage_)) return **guarded;
    return std::get<std::reference_wrapper<state_type>>(storage_).get();
}

detail::stream_state::stream_state(state_storage&& storage) noexcept
    : storage_(std::move(storage))
{
}

detail::stream_state::stream_state(stream_state&& other) noexcept
    : storage_(std::move(other.storage_))
    , active_(std::exchange(other.active_, false))
{
}

detail::stream_state& detail::stream_state::operator=(stream_state&& other) noexcept
{
    if (this != &other)
    {
        close();
        storage_ = std::move(other.storage_);
        active_ = std::exchange(other.active_, false);
    }
    return *this;
}

detail::stream_state::~stream_state()
{
    close();
}

void detail::stream_state::close() noexcept
{
    if (std::exchange(active_, false)) erase_state(get());
}

state_storage detail::stream_state::release() noexcept
{
    close();
    return std::move(storage_);
}

sender::sender(state_storage&& storage) noexcept
    : state_(std::move(storage))
{
}

receiver::receiver(state_storage&& storage) noexcept
    : state_(std::move(storage))
{
}

std::expected<sender, errc> start_push(stream_key_ref key, state_storage&& storage, std::nothrow_t) noexcept
{
    if (!storage) return std::unexpected(errc::crypto_failed);
    sender stream{std::move(storage)};
    if (crypto_secretstream_xchacha20poly1305_init_push(&stream.state_.get(), sodium_bytes(stream.header_.bytes().data()), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return stream;
}

std::expected<sender, errc> start_push(stream_key_ref key, std::nothrow_t) noexcept
try
{
    return start_push(key, state_storage{}, std::nothrow);
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

sender start_push(stream_key_ref key)
{
    return unwrap(start_push(key, std::nothrow));
}

sender start_push(stream_key_ref key, state_storage&& storage)
{
    return unwrap(start_push(key, std::move(storage), std::nothrow));
}

std::expected<receiver, errc> start_pull(stream_key_ref key, stream_header const& header, state_storage&& storage, std::nothrow_t) noexcept
{
    if (!storage) return std::unexpected(errc::crypto_failed);
    receiver stream{std::move(storage)};
    if (crypto_secretstream_xchacha20poly1305_init_pull(&stream.state_.get(), sodium_bytes(header.bytes().data()), sodium_bytes(key.bytes().data())) != 0) return std::unexpected(errc::crypto_failed);
    return stream;
}

std::expected<receiver, errc> start_pull(stream_key_ref key, stream_header const& header, std::nothrow_t) noexcept
try
{
    return start_pull(key, header, state_storage{}, std::nothrow);
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

receiver start_pull(stream_key_ref key, stream_header const& header)
{
    return unwrap(start_pull(key, header, std::nothrow));
}

receiver start_pull(stream_key_ref key, stream_header const& header, state_storage&& storage)
{
    return unwrap(start_pull(key, header, std::move(storage), std::nothrow));
}

std::expected<void, errc> sender::push_record(std::span<std::byte const> message, std::span<std::byte const> ad, std::span<std::byte> out, record_tag tag) noexcept
{
    unsigned char const empty{};
    if (crypto_secretstream_xchacha20poly1305_push(&state_.get(),
                                                   sodium_bytes(out.data()),
                                                   nullptr,
                                                   message.empty() ? &empty : sodium_bytes(message.data()),
                                                   message.size(),
                                                   sodium_bytes(ad.data()),
                                                   ad.size(),
                                                   std::to_underlying(tag)) != 0)
    {
        state_.close();
        return std::unexpected(errc::crypto_failed);
    }
    if (tag == record_tag::final) state_.close();
    return {};
}

std::expected<std::vector<std::byte>, errc> sender::push(std::span<std::byte const> message, std::span<std::byte const> ad, record_tag tag, std::nothrow_t) noexcept
{
    if (!state_ || !valid_tag(tag) || !valid_lengths(message.size(), ad.size())) return std::unexpected(errc::crypto_failed);
    return internal::allocate_and_transform<std::vector<std::byte>>(message.size() + record_overhead, [&](auto& out) { return push_record(message, ad, out, tag); });
}

std::vector<std::byte> sender::push(std::span<std::byte const> message, std::span<std::byte const> ad, record_tag tag)
{
    return unwrap(push(message, ad, tag, std::nothrow));
}

std::expected<void, errc> sender::push_into(std::span<std::byte const> message, std::span<std::byte const> ad, std::span<std::byte> out, record_tag tag, std::nothrow_t) noexcept
{
    if (!state_ || !valid_tag(tag) || !valid_lengths(message.size(), ad.size()) || out.size() != message.size() + record_overhead) return std::unexpected(errc::crypto_failed);
    return push_record(message, ad, out, tag);
}

void sender::push_into(std::span<std::byte const> message, std::span<std::byte const> ad, std::span<std::byte> out, record_tag tag)
{
    unwrap(push_into(message, ad, out, tag, std::nothrow));
}

std::expected<void, errc> sender::rekey(std::nothrow_t) noexcept
{
    if (!state_) return std::unexpected(errc::crypto_failed);
    crypto_secretstream_xchacha20poly1305_rekey(&state_.get());
    return {};
}

void sender::rekey()
{
    unwrap(rekey(std::nothrow));
}

receiver::receiver(receiver&& other) noexcept
    : state_(std::move(other.state_))
    , finished_(std::exchange(other.finished_, false))
{
}

receiver& receiver::operator=(receiver&& other) noexcept
{
    if (this != &other)
    {
        state_ = std::move(other.state_);
        finished_ = std::exchange(other.finished_, false);
    }
    return *this;
}

std::expected<std::size_t, errc> receiver::plaintext_size(std::size_t record_size, std::size_t ad_size) noexcept
{
    if (!state_) return std::unexpected(errc::crypto_failed);
    if (record_size < record_overhead || !valid_lengths(record_size - record_overhead, ad_size))
    {
        state_.close();
        return std::unexpected(errc::crypto_failed);
    }
    return record_size - record_overhead;
}

std::expected<record_tag, errc> receiver::pull_record(std::span<std::byte const> record, std::span<std::byte const> ad, std::span<std::byte> out) noexcept
{
    unsigned char empty{};
    unsigned char tag_byte{};
    auto status = crypto_secretstream_xchacha20poly1305_pull(
            &state_.get(), out.empty() ? &empty : sodium_bytes(out.data()), nullptr, &tag_byte, sodium_bytes(record.data()), record.size(), sodium_bytes(ad.data()), ad.size());
    auto tag = static_cast<record_tag>(tag_byte);
    if (status != 0 || !valid_tag(tag))
    {
        // Libsodium can open authenticated records with tags outside the public choices.
        wipe(out);
        state_.close();
        return std::unexpected(errc::crypto_failed);
    }
    if (tag == record_tag::final)
    {
        finished_ = true;
        state_.close();
    }
    return tag;
}

std::expected<pull_result, errc> receiver::pull(std::span<std::byte const> record, std::span<std::byte const> ad, std::nothrow_t) noexcept
try
{
    auto size = plaintext_size(record.size(), ad.size());
    if (!size) return std::unexpected(size.error());
    secure_buffer plaintext(*size);
    auto tag = pull_record(record, ad, plaintext.bytes());
    if (!tag) return std::unexpected(tag.error());
    return pull_result{std::move(plaintext), *tag};
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}
catch (std::length_error const&)
{
    return std::unexpected(errc::allocation_failed);
}

pull_result receiver::pull(std::span<std::byte const> record, std::span<std::byte const> ad)
{
    return unwrap(pull(record, ad, std::nothrow));
}

std::expected<record_tag, errc> receiver::pull_into(std::span<std::byte const> record, std::span<std::byte const> ad, std::span<std::byte> out, std::nothrow_t) noexcept
{
    auto size = plaintext_size(record.size(), ad.size());
    if (!size) return std::unexpected(size.error());
    if (out.size() != *size) return std::unexpected(errc::crypto_failed);
    return pull_record(record, ad, out);
}

record_tag receiver::pull_into(std::span<std::byte const> record, std::span<std::byte const> ad, std::span<std::byte> out)
{
    return unwrap(pull_into(record, ad, out, std::nothrow));
}

std::expected<void, errc> receiver::rekey(std::nothrow_t) noexcept
{
    if (!state_) return std::unexpected(errc::crypto_failed);
    crypto_secretstream_xchacha20poly1305_rekey(&state_.get());
    return {};
}

void receiver::rekey()
{
    unwrap(rekey(std::nothrow));
}
}  // namespace potassium::secretstream
