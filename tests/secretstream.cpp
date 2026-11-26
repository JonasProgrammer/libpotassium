// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <sodium.h>
#include <catch2/catch_test_macros.hpp>

import potassium.aead;
import potassium.secretbox;
import potassium.secretstream;
import std;

namespace
{
using namespace potassium;
namespace ss = potassium::secretstream;
using ss::record_tag;
using byte_view = std::span<std::byte const>;

template <class K>
concept StartsSender = requires(K&& key) {
    { ss::start_push(std::forward<K>(key), std::nothrow) } noexcept -> std::same_as<std::expected<ss::sender, errc>>;
};

static_assert(std::movable<ss::sender> && !std::copy_constructible<ss::sender>);
static_assert(std::movable<ss::receiver> && !std::copy_constructible<ss::receiver>);
static_assert(std::is_nothrow_move_constructible_v<ss::sender> && std::is_nothrow_move_assignable_v<ss::sender>);
static_assert(std::is_nothrow_move_constructible_v<ss::receiver> && std::is_nothrow_move_assignable_v<ss::receiver>);
static_assert(!std::default_initializable<ss::sender> && !std::default_initializable<ss::receiver>);
static_assert(std::movable<ss::state_storage> && !std::copy_constructible<ss::state_storage>);
static_assert(!std::movable<ss::inplace_state>);
static_assert(std::copyable<ss::stream_header>);
static_assert(std::same_as<decltype(std::declval<ss::stream_header const&>().bytes()), std::span<std::byte const, ss::header_size>>);
static_assert(std::same_as<decltype(std::declval<ss::stream_header&>().bytes()), std::span<std::byte, ss::header_size>>);
static_assert(StartsSender<secret_key<ss::key_tag>&> && StartsSender<key_buffer_storage<ss::key_tag> const&>);
static_assert(!StartsSender<secret_key<ss::key_tag>>);
static_assert(!StartsSender<secret_key<aead::default_algorithm>&> && !StartsSender<secret_key<secretbox::xchacha20poly1305>&>);

auto native_bytes(byte_view bytes)
{
    return reinterpret_cast<unsigned char const*>(bytes.data());
}

bool is_wiped(ss::state_type const& state)
{
    return std::ranges::all_of(std::as_bytes(std::span{&state, 1}), [](std::byte byte) { return byte == std::byte{}; });
}

constexpr std::array message{std::byte{0xc2}, std::byte{0x2e}, std::byte{0}, std::byte{0xff}};
constexpr std::array metadata{std::byte{0xa8}, std::byte{0}, std::byte{0x34}};
constexpr std::array tags{record_tag::message, record_tag::push, record_tag::rekey, record_tag::final};

std::vector<unsigned char> native_push(crypto_secretstream_xchacha20poly1305_state& state, byte_view plaintext, byte_view ad, unsigned char tag)
{
    std::vector<unsigned char> record(plaintext.size() + ss::record_overhead);
    unsigned long long length{};
    unsigned char const empty{};
    REQUIRE(crypto_secretstream_xchacha20poly1305_push(&state, record.data(), &length, plaintext.empty() ? &empty : native_bytes(plaintext), plaintext.size(), native_bytes(ad), ad.size(), tag) == 0);
    REQUIRE(length == record.size());
    return record;
}
}  // namespace

TEST_CASE("Secretstream reuses preallocated guarded storage", "[secretstream]")
{
    secret_key<ss::key_tag> key;
    ss::state_storage push_storage;
    ss::state_storage pull_storage;

    for (int round = 0; round != 2; ++round)
    {
        auto sender = ss::start_push(key, std::move(push_storage), std::nothrow);
        REQUIRE(sender);
        CHECK_FALSE(push_storage);
        auto receiver = ss::start_pull(key, sender->header(), std::move(pull_storage));
        CHECK_FALSE(pull_storage);
        auto sealed = sender->push(message, metadata, record_tag::final);
        auto opened = receiver.pull(sealed, metadata);
        CHECK(opened.tag == record_tag::final);
        CHECK(std::ranges::equal(opened.plaintext.bytes(), message));
        CHECK(receiver.finished());

        push_storage = std::move(*sender).close_for_reuse();
        pull_storage = std::move(receiver).close_for_reuse();
        CHECK(push_storage);
        CHECK(pull_storage);
        CHECK_FALSE(std::move(receiver).close_for_reuse());
        CHECK(ss::start_push(key, std::move(*sender).close_for_reuse(), std::nothrow) == std::unexpected(errc::crypto_failed));
    }
}

TEST_CASE("Secretstream wipes caller state as soon as it closes", "[secretstream]")
{
    secret_key<ss::key_tag> key;
    ss::inplace_state inline_state;
    ss::state_type custom_state{};
    std::array<std::byte, message.size() + ss::record_overhead> record{};
    std::array<std::byte, message.size()> clear{};

    auto sender = ss::start_push(key, ss::state_storage{inline_state.get()});
    auto receiver = ss::start_pull(key, sender.header(), ss::state_storage{custom_state});
    REQUIRE_FALSE(is_wiped(inline_state.get()));
    REQUIRE_FALSE(is_wiped(custom_state));

    sender.push_into(message, metadata, record, record_tag::final);
    CHECK(is_wiped(inline_state.get()));
    record.back() ^= std::byte{1};
    CHECK(receiver.pull_into(record, metadata, clear, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(is_wiped(custom_state));
    CHECK_FALSE(receiver.finished());

    sender = ss::start_push(key, std::move(sender).close_for_reuse());
    receiver = ss::start_pull(key, sender.header(), std::move(receiver).close_for_reuse());
    sender.push_into(message, metadata, record, record_tag::final);
    CHECK(receiver.pull_into(record, metadata, clear) == record_tag::final);
    CHECK(clear == message);
    CHECK(receiver.finished());
    CHECK(is_wiped(custom_state));

    sender = ss::start_push(key, std::move(sender).close_for_reuse());
    auto storage = std::move(sender).close_for_reuse();
    CHECK(is_wiped(inline_state.get()));
    {
        auto active = ss::start_push(key, std::move(storage));
        auto replacement = ss::start_push(key, std::move(receiver).close_for_reuse());
        active = std::move(replacement);
        CHECK(is_wiped(inline_state.get()));
        CHECK_FALSE(is_wiped(custom_state));
    }
    CHECK(is_wiped(custom_state));
}

TEST_CASE("Libsodium opens potassium secretstream records", "[secretstream][interop]")
{
    secret_key<ss::key_tag> key;
    auto started = ss::start_push(key, std::nothrow);
    REQUIRE(started);
    auto& sender = *started;
    auto header = sender.header();
    crypto_secretstream_xchacha20poly1305_state native{};
    REQUIRE(crypto_secretstream_xchacha20poly1305_init_pull(&native, native_bytes(header.bytes()), native_bytes(key.ref().bytes())) == 0);

    for (auto tag : tags)
    {
        CAPTURE(std::to_underlying(tag));
        auto plaintext = tag == record_tag::push ? byte_view{} : byte_view{message};
        auto ad = tag == record_tag::message || tag == record_tag::rekey ? byte_view{metadata} : byte_view{};
        std::vector<std::byte> record;
        if (tag == record_tag::push || tag == record_tag::rekey)
        {
            record.resize(plaintext.size() + ss::record_overhead);
            sender.push_into(plaintext, ad, record, tag);
        }
        else
        {
            auto sealed = sender.push(plaintext, ad, tag, std::nothrow);
            REQUIRE(sealed);
            record = std::move(*sealed);
        }
        REQUIRE(record.size() == plaintext.size() + ss::record_overhead);
        std::array<unsigned char, message.size()> clear{};
        unsigned long long length{};
        unsigned char native_tag{};
        REQUIRE(crypto_secretstream_xchacha20poly1305_pull(&native, clear.data(), &length, &native_tag, native_bytes(record), record.size(), native_bytes(ad), ad.size()) == 0);
        REQUIRE(length == plaintext.size());
        CHECK(native_tag == std::to_underlying(tag));
        CHECK(std::ranges::equal(std::as_bytes(std::span{clear}.first(length)), plaintext));

        if (tag == record_tag::push)
        {
            REQUIRE(sender.rekey(std::nothrow));
            crypto_secretstream_xchacha20poly1305_rekey(&native);
        }
    }

    CHECK(sender.push({}, {}, record_tag::final, std::nothrow) == std::unexpected(errc::crypto_failed));
    std::array<std::byte, ss::record_overhead> out{};
    CHECK(sender.push_into({}, {}, out, record_tag::message, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_THROWS_AS(sender.rekey(), crypto_error);
    CHECK(std::ranges::equal(sender.header().storage, header.storage));
}

TEST_CASE("Potassium opens libsodium secretstream records", "[secretstream][interop]")
{
    key_buffer_storage<ss::key_tag> key;
    crypto_secretstream_xchacha20poly1305_state native{};
    std::array<unsigned char, ss::header_size> native_header{};
    REQUIRE(crypto_secretstream_xchacha20poly1305_init_push(&native, native_header.data(), native_bytes(key.ref().bytes())) == 0);
    ss::stream_header header;
    std::ranges::copy(std::as_bytes(std::span{native_header}), header.bytes().begin());
    auto started = ss::start_pull(key, header, std::nothrow);
    REQUIRE(started);
    auto& receiver = *started;
    CHECK_FALSE(receiver.finished());
    std::vector<unsigned char> record;

    for (auto tag : tags)
    {
        CAPTURE(std::to_underlying(tag));
        auto plaintext = tag == record_tag::final ? byte_view{} : byte_view{message};
        auto ad = tag == record_tag::push || tag == record_tag::final ? byte_view{metadata} : byte_view{};
        record = native_push(native, plaintext, ad, std::to_underlying(tag));
        auto ciphertext = std::as_bytes(std::span{record});
        CHECK_FALSE(receiver.finished());
        if (tag == record_tag::message || tag == record_tag::rekey)
        {
            auto [opened, opened_tag] = receiver.pull(ciphertext, ad);
            CHECK(opened_tag == tag);
            CHECK(std::ranges::equal(opened.bytes(), plaintext));
        }
        else
        {
            std::array<std::byte, message.size()> clear{};
            auto out = std::span{clear}.first(plaintext.size());
            auto opened = receiver.pull_into(ciphertext, ad, out, std::nothrow);
            REQUIRE(opened);
            CHECK(*opened == tag);
            CHECK(std::ranges::equal(out, plaintext));
        }

        if (tag == record_tag::push)
        {
            crypto_secretstream_xchacha20poly1305_rekey(&native);
            receiver.rekey();
        }
    }

    CHECK(receiver.finished());
    CHECK_THROWS_AS(receiver.pull(std::as_bytes(std::span{record}), metadata), crypto_error);
    auto trailing = native_push(native, message, {}, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
    CHECK(receiver.pull(std::as_bytes(std::span{trailing}), {}, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(receiver.rekey(std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(receiver.finished());
}

TEST_CASE("Invalid secretstream records close the receiver", "[secretstream]")
{
    secret_key<ss::key_tag> key;
    secret_key<ss::key_tag> wrong_key;
    auto sender = ss::start_push(key);
    auto header = sender.header();
    auto wrong_header = header;
    wrong_header.storage.front() ^= std::byte{1};
    auto first = sender.push(message, metadata);
    auto last = sender.push(message, metadata, record_tag::final);
    auto tampered = first;
    tampered.front() ^= std::byte{1};
    auto wrong_ad = metadata;
    wrong_ad.back() ^= std::byte{1};

    auto check_closed = [&](ss::receiver& receiver)
    {
        CHECK_FALSE(receiver.finished());
        CHECK(receiver.pull(first, metadata, std::nothrow) == std::unexpected(errc::crypto_failed));
        CHECK_THROWS_AS(receiver.rekey(), crypto_error);
    };
    auto check_failure = [&](ss::stream_key_ref candidate_key, ss::stream_header const& candidate_header, byte_view record, byte_view ad)
    {
        auto receiver = ss::start_pull(candidate_key, candidate_header);
        std::array<std::byte, message.size()> clear;
        std::ranges::fill(clear, std::byte{0x55});
        auto out = std::span{clear}.first(record.size() >= ss::record_overhead ? record.size() - ss::record_overhead : 0);
        CHECK_THROWS_AS(receiver.pull_into(record, ad, out), crypto_error);
        CHECK(std::ranges::all_of(clear, [](auto byte) { return byte == std::byte{} || byte == std::byte{0x55}; }));
        check_closed(receiver);
    };

    check_failure(wrong_key, header, first, metadata);
    check_failure(key, wrong_header, first, metadata);
    check_failure(key, header, first, wrong_ad);
    check_failure(key, header, tampered, metadata);
    check_failure(key, header, std::span{first}.first(ss::record_overhead - 1), metadata);
    check_failure(key, header, std::span{first}.first(first.size() - 1), metadata);
    check_failure(key, header, last, metadata);

    auto duplicate = ss::start_pull(key, header);
    REQUIRE(duplicate.pull(first, metadata, std::nothrow));
    CHECK(duplicate.pull(first, metadata, std::nothrow) == std::unexpected(errc::crypto_failed));
    check_closed(duplicate);
}

TEST_CASE("Secretstream rejects unsupported record tags", "[secretstream]")
{
    constexpr unsigned char unsupported = 7;
    secret_key<ss::key_tag> key;
    crypto_secretstream_xchacha20poly1305_state native{};
    std::array<unsigned char, ss::header_size> native_header{};
    REQUIRE(crypto_secretstream_xchacha20poly1305_init_push(&native, native_header.data(), native_bytes(key.ref().bytes())) == 0);
    auto record = native_push(native, message, {}, unsupported);
    auto next = native_push(native, message, {}, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    ss::stream_header header;
    std::ranges::copy(std::as_bytes(std::span{native_header}), header.bytes().begin());
    auto receiver = ss::start_pull(key, header);
    std::array<std::byte, message.size()> clear;
    std::ranges::fill(clear, std::byte{0x55});
    CHECK(receiver.pull_into(std::as_bytes(std::span{record}), {}, clear, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(std::ranges::all_of(clear, [](auto byte) { return byte == std::byte{}; }));
    CHECK_FALSE(receiver.finished());
    CHECK(receiver.pull(std::as_bytes(std::span{next}), {}, std::nothrow) == std::unexpected(errc::crypto_failed));

    auto sender = ss::start_push(key);
    CHECK(sender.push(message, {}, static_cast<record_tag>(unsupported), std::nothrow) == std::unexpected(errc::crypto_failed));
    auto valid_receiver = ss::start_pull(key, sender.header());
    auto final = sender.push(message, {}, record_tag::final);
    CHECK(valid_receiver.pull(final, {}).tag == record_tag::final);
}

TEST_CASE("Secretstream moves transfer active state and final authentication", "[secretstream]")
{
    secret_key<ss::key_tag> key;
    auto sender = ss::start_push(key);
    auto header = sender.header();
    auto receiver = ss::start_pull(key, header);
    auto first = sender.push(message, metadata);
    REQUIRE(receiver.pull(first, metadata, std::nothrow));
    CHECK_FALSE(receiver.finished());

    auto moved_sender = std::move(sender);
    auto moved_receiver = std::move(receiver);
    CHECK(sender.push(message, {}, record_tag::message, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(receiver.pull(first, metadata, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_FALSE(receiver.finished());
    CHECK_FALSE(moved_receiver.finished());

    auto replacement_sender = ss::start_push(key);
    auto replacement_receiver = ss::start_pull(key, replacement_sender.header());
    replacement_sender = std::move(moved_sender);
    replacement_receiver = std::move(moved_receiver);
    CHECK(moved_sender.rekey(std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(moved_receiver.rekey(std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK(std::ranges::equal(replacement_sender.header().storage, header.storage));

    std::array<std::byte, message.size() + ss::record_overhead> final{};
    REQUIRE(replacement_sender.push_into(message, {}, final, record_tag::final, std::nothrow));
    std::array<std::byte, message.size()> clear{};
    CHECK(replacement_receiver.pull_into(final, {}, clear) == record_tag::final);
    CHECK(std::ranges::equal(clear, message));
    CHECK(replacement_receiver.finished());

    auto finished = std::move(replacement_receiver);
    CHECK(finished.finished());
    CHECK_FALSE(replacement_receiver.finished());
    auto destination = ss::start_pull(key, header);
    destination = std::move(finished);
    CHECK(destination.finished());
    CHECK_FALSE(finished.finished());
    CHECK(destination.pull(final, {}, std::nothrow) == std::unexpected(errc::crypto_failed));
    destination = ss::start_pull(key, header);
    CHECK_FALSE(destination.finished());
    REQUIRE(destination.pull(first, metadata, std::nothrow));
}

TEST_CASE("Secretstream requires an authenticated final record at EOF", "[secretstream]")
{
    key_buffer_storage<ss::key_tag> key;
    auto sender = ss::start_push(key);
    auto header = sender.header();
    auto receiver = ss::start_pull(key, header);
    CHECK_FALSE(receiver.finished());
    auto final = sender.push({}, {}, record_tag::final);
    CHECK(final.size() == ss::record_overhead);
    auto [clear, tag] = receiver.pull(final, {});
    CHECK(clear.bytes().empty());
    CHECK(tag == record_tag::final);
    CHECK(receiver.finished());

    auto tampered = ss::start_pull(key, header);
    final.back() ^= std::byte{1};
    CHECK(tampered.pull(final, {}, std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_FALSE(tampered.finished());
}
