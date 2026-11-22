// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_test_macros.hpp>

import potassium.box;
import potassium.core;
import potassium.secretbox;
import std;

namespace
{
struct PrivateKeyTag;
struct SharedKeyTag;
template <class Error>
struct FailingKeyTag;
struct RuntimeNonceSize;
}  // namespace

template <>
struct potassium::algorithm_traits<RuntimeNonceSize>
{
    static constexpr std::size_t key_size = 32;
    static std::size_t nonce_size;
    static constexpr std::size_t mac_size = 16;
    static constexpr std::size_t messagebytes_max = 4096;
};

template <>
struct potassium::key_traits<PrivateKeyTag>
{
    static constexpr std::size_t size = 48;

    struct generator
    {
        void operator()(std::span<std::byte, size> out) && { std::ranges::fill(out, std::byte{0x42}); }
    };
};

template <>
struct potassium::key_traits<SharedKeyTag>
{
    static constexpr std::size_t size = 48;
};

template <class Error>
struct potassium::key_traits<FailingKeyTag<Error>>
{
    static constexpr std::size_t size = 32;

    struct generator
    {
        void operator()(std::span<std::byte, size> out) const
        {
            out.front() = std::byte{1};
            throw Error{};
        }
    };
};

TEST_CASE("Guarded key factories translate generator failures", "[keys]")
{
    using namespace potassium;
    CHECK(make_secret_key<FailingKeyTag<std::bad_alloc>>(std::nothrow) == std::unexpected(errc::allocation_failed));
    CHECK(make_secret_key<FailingKeyTag<crypto_error>>(std::nothrow) == std::unexpected(errc::crypto_failed));
    CHECK_THROWS_AS(make_secret_key<FailingKeyTag<std::bad_alloc>>(), std::bad_alloc);
    CHECK_THROWS_AS(make_secret_key<FailingKeyTag<crypto_error>>(), crypto_error);
}

// Compile the owner constructors and borrowing bodies with no algorithm traits.
template class potassium::secret_key<PrivateKeyTag>;
template class potassium::key_buffer_storage<PrivateKeyTag>;

namespace
{
using SecretBoxAlgorithm = potassium::secretbox::secretbox_default;
using BoxAlgorithm = potassium::box::box_default;

static_assert(potassium::SecretKeyAlgorithmTraits<potassium::algorithm_traits<SecretBoxAlgorithm>>);
static_assert(!potassium::PublicKeyAlgorithmTraits<potassium::algorithm_traits<SecretBoxAlgorithm>>);
static_assert(potassium::PublicKeyAlgorithmTraits<potassium::algorithm_traits<BoxAlgorithm>>);
static_assert(!potassium::SecretKeyAlgorithmTraits<potassium::algorithm_traits<BoxAlgorithm>>);
static_assert(potassium::Algorithm<SecretBoxAlgorithm>);
static_assert(potassium::Algorithm<BoxAlgorithm>);
static_assert(!potassium::Algorithm<PrivateKeyTag>);
static_assert(!potassium::Algorithm<RuntimeNonceSize>);

template <class Ref>
consteval bool borrows_only_live_arrays()
{
    using Array = std::array<std::byte, Ref::span_type::extent>;
    using ConstElements = std::array<std::byte const, Ref::span_type::extent>;
    using Raw = std::byte[Ref::span_type::extent];
    static_assert(std::constructible_from<Ref, Raw&> && !std::constructible_from<Ref, Raw&&>);
    static_assert(std::constructible_from<Ref, ConstElements&> && !std::constructible_from<Ref, ConstElements&&>);
    return std::constructible_from<Ref, Array&> && std::constructible_from<Ref, Array const&> && !std::constructible_from<Ref, Array&&> && !std::constructible_from<Ref, Array const&&> &&
           std::constructible_from<Ref, typename Ref::span_type>;
}

static_assert(borrows_only_live_arrays<potassium::key_ref<PrivateKeyTag>>());
static_assert(borrows_only_live_arrays<potassium::nonce_ref<BoxAlgorithm>>());
static_assert(borrows_only_live_arrays<potassium::public_key_ref<BoxAlgorithm>>());

using RawKey = std::span<std::byte const, 48>;
using PrivateRef = potassium::key_ref<PrivateKeyTag>;
using SharedRef = potassium::key_ref<SharedKeyTag>;
using SecretKey = potassium::secret_key<PrivateKeyTag>;
using Generator = potassium::key_traits<PrivateKeyTag>::generator;

static_assert(potassium::KeyGenerator<Generator, PrivateKeyTag>);
static_assert(!potassium::KeyGenerator<Generator&, PrivateKeyTag>);

static_assert(std::same_as<PrivateRef::span_type, RawKey>);
static_assert(std::same_as<SharedRef::span_type, RawKey>);
static_assert(std::same_as<decltype(std::declval<PrivateRef const&>().bytes()), RawKey>);
static_assert(std::constructible_from<PrivateRef, RawKey>);
static_assert(!std::convertible_to<RawKey, PrivateRef>);
static_assert(!std::convertible_to<PrivateRef, SharedRef>);
static_assert(!std::convertible_to<SharedRef, PrivateRef>);
static_assert(!std::default_initializable<potassium::secret_key<SharedKeyTag>>);
static_assert(!std::default_initializable<potassium::key_buffer_storage<SharedKeyTag>>);

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
    potassium::key_buffer_storage<PrivateKeyTag> stack;
    CHECK(std::ranges::all_of(original.ref().bytes(), [](auto b) { return b == std::byte{0x42}; }));
    CHECK(std::ranges::equal(stack.ref().bytes(), original.ref().bytes()));
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
