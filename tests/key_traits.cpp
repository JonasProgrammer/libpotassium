// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_test_macros.hpp>

import potassium.core;
import std;

namespace
{
struct PrivateKeyTag;
struct SharedKeyTag;
}  // namespace

template <>
struct potassium::key_traits<PrivateKeyTag>
{
    static constexpr std::size_t size = 48;
};

template <>
struct potassium::key_traits<SharedKeyTag>
{
    static constexpr std::size_t size = 48;
};

// Compile the owner constructors and borrowing bodies with no algorithm traits.
template class potassium::secret_key<PrivateKeyTag>;
template class potassium::key_buffer_storage<PrivateKeyTag>;

namespace
{
using RawKey = std::span<std::byte const, 48>;
using PrivateRef = potassium::key_ref<PrivateKeyTag>;
using SharedRef = potassium::key_ref<SharedKeyTag>;
using SecretKey = potassium::secret_key<PrivateKeyTag>;

static_assert(std::same_as<PrivateRef::span_type, RawKey>);
static_assert(std::same_as<SharedRef::span_type, RawKey>);
static_assert(std::same_as<decltype(std::declval<PrivateRef const&>().bytes()), RawKey>);
static_assert(std::constructible_from<PrivateRef, RawKey>);
static_assert(!std::convertible_to<RawKey, PrivateRef>);
static_assert(!std::convertible_to<PrivateRef, SharedRef>);
static_assert(!std::convertible_to<SharedRef, PrivateRef>);

template <class Owner>
concept CanBorrow = requires(Owner&& key) { std::forward<Owner>(key).ref(); };

template <class Owner>
concept CanWrite = requires(Owner&& key) { std::forward<Owner>(key).writable_bytes(); };

template <class Owner>
consteval bool check_owner()
{
    static_assert(std::convertible_to<Owner&, PrivateRef>);
    static_assert(std::convertible_to<Owner const&, PrivateRef>);
    static_assert(!std::convertible_to<Owner&&, PrivateRef>);
    static_assert(!std::convertible_to<Owner const&&, PrivateRef>);
    static_assert(!std::convertible_to<Owner&, SharedRef>);
    static_assert(CanBorrow<Owner&> && CanBorrow<Owner const&>);
    static_assert(!CanBorrow<Owner> && !CanBorrow<Owner const>);
    static_assert(std::same_as<decltype(std::declval<Owner&>().writable_bytes()), std::span<std::byte, 48>>);
    static_assert(!CanWrite<Owner const&> && !CanWrite<Owner> && !CanWrite<Owner const>);
    return true;
}

static_assert(check_owner<SecretKey>());
static_assert(check_owner<potassium::key_buffer_storage<PrivateKeyTag>>());
static_assert(!std::is_copy_constructible_v<SecretKey>);
static_assert(!std::is_copy_assignable_v<SecretKey>);
static_assert(std::is_nothrow_move_constructible_v<SecretKey>);
static_assert(std::is_nothrow_move_assignable_v<SecretKey>);
}  // namespace

TEST_CASE("Guarded key moves transfer the fixed-size allocation", "[memory]")
{
    SecretKey original;
    std::array<std::byte, 48> const expected{std::byte{0x42}, std::byte{0x17}};
    auto const writable = original.writable_bytes();
    std::ranges::copy(expected, writable.begin());
    auto const* address = writable.data();
    CHECK(original.ref().bytes().data() == address);
    CHECK(std::ranges::equal(original.ref().bytes(), expected));

    SecretKey moved{std::move(original)};
    CHECK(moved.writable_bytes().data() == address);
    CHECK(std::ranges::equal(moved.ref().bytes(), expected));

    SecretKey replacement;
    REQUIRE(replacement.writable_bytes().data() != address);
    replacement = std::move(moved);
    CHECK(replacement.writable_bytes().data() == address);
    CHECK(std::ranges::equal(replacement.ref().bytes(), expected));
}
