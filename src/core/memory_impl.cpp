// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
#include <cassert>

module potassium.core;
import std;

static_assert(std::is_trivial_v<potassium::raw_allocator>);

namespace potassium
{

void* raw_allocator::allocate_raw(size_type bytes)
{
    auto const ret = allocate_raw(bytes, std::nothrow);
    if (!ret) throw std::bad_alloc{};
    return ret;
}

void* raw_allocator::allocate_raw(size_type count, size_type element_size)
{
    auto const ret = allocate_raw(count, element_size, std::nothrow);
    if (!ret) throw std::bad_alloc{};
    return ret;
}

void* raw_allocator::allocate_raw(size_type bytes, std::nothrow_t const&) noexcept
{
    return sodium_malloc(bytes);
}

void* raw_allocator::allocate_raw(size_type count, size_type element_size, std::nothrow_t const&) noexcept
{
    return sodium_allocarray(count, element_size);
}

void raw_allocator::deallocate(void* ptr, size_type) noexcept
{
    sodium_free(ptr);
}

mlock_guard::mlock_guard(void* address, std::size_t len)
    : addr_(address)
    , len_(len)
{
    assert(address && len);
    if (sodium_mlock(address, len) == -1) throw std::runtime_error{"cannot mlock"};
}

mlock_guard::~mlock_guard()
{
    if (addr_) sodium_munlock(addr_, len_);
}

void* memory_resource::do_allocate(std::size_t bytes, std::size_t alignment)
{
    assert(std::has_single_bit(alignment));
    if (alignment > alignof(std::max_align_t)) throw std::bad_alloc{};

    auto const remainder = bytes % alignment;
    auto const padding = remainder == 0 ? 0 : alignment - remainder;
    if (bytes > std::numeric_limits<std::size_t>::max() - padding) throw std::bad_alloc{};

    auto const ret = raw_allocator::allocate_raw(bytes + padding);
    assert(reinterpret_cast<std::uintptr_t>(ret) % alignment == 0);
    return ret;
}

void memory_resource::do_deallocate(void* ptr, std::size_t bytes, std::size_t)
{
    raw_allocator::deallocate(ptr, bytes);
}

bool memory_resource::do_is_equal(std::pmr::memory_resource const& other) const noexcept
{
    return dynamic_cast<memory_resource const*>(&other) != nullptr;
}

}  // namespace potassium

namespace
{
template <typename A>
using ByteAllocator = std::allocator_traits<A>::template rebind_alloc<std::byte>;

// Check the allocator interface and rebinding used by standard containers.
template <typename A>
concept Allocator = std::copyable<A> && std::equality_comparable<A> && requires(A a, typename std::allocator_traits<A>::pointer ptr, typename std::allocator_traits<A>::size_type count)
{
    { a.allocate(count) } -> std::same_as<typename std::allocator_traits<A>::pointer>;
    { a.deallocate(ptr, count) } noexcept -> std::same_as<void>;
    typename ByteAllocator<A>;
    requires std::same_as<typename std::allocator_traits<ByteAllocator<A>>::value_type, std::byte>;
    requires std::is_nothrow_constructible_v<ByteAllocator<A>, A const&>;
    requires std::is_nothrow_constructible_v<A, ByteAllocator<A> const&>;
    requires std::same_as<typename std::allocator_traits<ByteAllocator<A>>::template rebind_alloc<typename A::value_type>, A>;
};

static_assert(Allocator<potassium::allocator<int>>);
static_assert(Allocator<potassium::allocator<std::byte>>);
}  // namespace
