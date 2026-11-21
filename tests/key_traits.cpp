// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

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

static_assert(std::same_as<PrivateRef::span_type, RawKey>);
static_assert(std::same_as<SharedRef::span_type, RawKey>);
static_assert(std::constructible_from<PrivateRef, RawKey>);
static_assert(!std::convertible_to<RawKey, PrivateRef>);
static_assert(!std::convertible_to<PrivateRef, SharedRef>);
static_assert(!std::convertible_to<SharedRef, PrivateRef>);

template <class Owner>
concept CanBorrow = requires(Owner&& key) { std::forward<Owner>(key).ref(); };

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
    return true;
}

static_assert(check_owner<potassium::secret_key<PrivateKeyTag>>());
static_assert(check_owner<potassium::key_buffer_storage<PrivateKeyTag>>());
}  // namespace
