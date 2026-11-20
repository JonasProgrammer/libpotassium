// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import libpotassium;
import std;

namespace
{
struct ThreeBytes
{
    std::byte bytes[3];
};

struct PaddedFields
{
    char prefix;
    int value;
    char suffix;
};

struct alignas(std::max_align_t) AlignedPayload
{
    std::byte bytes[37];
};

struct PageCrossingPayload
{
    int value;
    std::byte bytes[4097];
};

struct alignas(2 * alignof(std::max_align_t)) OveralignedPayload
{
    int value;
};

template <typename T>
concept SupportsGuardedAllocator = requires { typename potassium::allocator<T>; };

static_assert(SupportsGuardedAllocator<std::max_align_t>);
static_assert(!SupportsGuardedAllocator<OveralignedPayload>);

static_assert(!std::is_copy_constructible_v<potassium::mlock_guard>);
static_assert(!std::is_copy_assignable_v<potassium::mlock_guard>);
static_assert(std::is_nothrow_move_constructible_v<potassium::mlock_guard>);
static_assert(std::is_nothrow_move_assignable_v<potassium::mlock_guard>);
}  // namespace

TEMPLATE_TEST_CASE("Allocators satisfy the same object alignment", "[memory]", char, int, double, std::max_align_t, ThreeBytes, PaddedFields, AlignedPayload, PageCrossingPayload)
{
    constexpr auto size = sizeof(TestType);
    constexpr auto alignment = alignof(TestType);
    CAPTURE(size, alignment);

    std::unique_ptr<void, decltype(&std::free)> const malloc_storage{std::malloc(size), std::free};
    std::allocator<TestType> allocator;
    auto const deallocate = [&allocator](TestType* pointer)
    {
        allocator.deallocate(pointer, 1);
    };
    std::unique_ptr<TestType, decltype(deallocate)> const allocator_storage{allocator.allocate(1), deallocate};
    potassium::allocator<TestType> guarded_allocator;
    auto const guarded_deallocate = [&guarded_allocator](TestType* pointer)
    {
        guarded_allocator.deallocate(pointer, 1);
    };
    std::unique_ptr<TestType, decltype(guarded_deallocate)> const guarded_storage{guarded_allocator.allocate(1), guarded_deallocate};

    REQUIRE(malloc_storage.get() != nullptr);
    REQUIRE(allocator_storage.get() != nullptr);
    REQUIRE(guarded_storage.get() != nullptr);
    CHECK(reinterpret_cast<std::uintptr_t>(malloc_storage.get()) % alignment == 0);
    CHECK(reinterpret_cast<std::uintptr_t>(allocator_storage.get()) % alignment == 0);
    CHECK(reinterpret_cast<std::uintptr_t>(guarded_storage.get()) % alignment == 0);
}

TEMPLATE_TEST_CASE("Allocators provide storage for multiple objects", "[memory]", std::allocator<PaddedFields>, potassium::allocator<PaddedFields>)
{
    constexpr auto values = std::array{12, 34, 56, 78, 90};
    constexpr auto count = values.size();
    TestType allocator;
    auto const deallocate = [&allocator](PaddedFields* pointer)
    {
        allocator.deallocate(pointer, count);
    };
    std::unique_ptr<PaddedFields[], decltype(deallocate)> const storage{allocator.allocate(count), deallocate};
    REQUIRE(storage.get() != nullptr);
    REQUIRE(reinterpret_cast<std::uintptr_t>(storage.get()) % alignof(PaddedFields) == 0);

    for (std::size_t i = 0; i < count; ++i) std::construct_at(storage.get() + i, PaddedFields{'a', values[i], 'z'});

    for (std::size_t i = 0; i < count; ++i)
    {
        CAPTURE(i);
        CHECK(storage[i].value == values[i]);
    }
    std::destroy_n(storage.get(), count);
}

TEST_CASE("Guarded allocator supports container rebinding", "[memory]")
{
    potassium::allocator<int> allocator;
    potassium::allocator<std::string> const rebound{allocator};
    CHECK(allocator == rebound);

    std::list<std::string, potassium::allocator<std::string>> values{rebound};
    values.emplace_back(40, 'x');
    CHECK(values.front() == std::string(40, 'x'));
}

TEST_CASE("Guarded allocator rejects overflowing sizes and accepts zero counts", "[memory]")
{
    auto const oversized_count = std::numeric_limits<std::size_t>::max();
    potassium::allocator<int> ordinary;
    CHECK_THROWS_AS(static_cast<void>(ordinary.allocate(oversized_count)), std::bad_alloc);
    ordinary.deallocate(ordinary.allocate(0), 0);
}

TEST_CASE("Raw allocator provides nothrow allocation", "[memory]")
{
    using potassium::raw_allocator;
    static_assert(noexcept(raw_allocator::allocate_raw(16, std::nothrow)));
    static_assert(noexcept(raw_allocator::allocate_raw(2, 16, std::nothrow)));
    auto* single = raw_allocator::allocate_raw(16, std::nothrow);
    REQUIRE(single != nullptr);
    raw_allocator::deallocate(single, 16);
    auto* array = raw_allocator::allocate_raw(2, 16, std::nothrow);
    REQUIRE(array != nullptr);
    raw_allocator::deallocate(array, 2);
    CHECK(raw_allocator::allocate_raw(std::numeric_limits<std::size_t>::max(), 2, std::nothrow) == nullptr);
}

TEST_CASE("Guarded memory resources compare equal only to each other", "[memory]")
{
    potassium::memory_resource first;
    potassium::memory_resource second;
    std::pmr::memory_resource& resource = first;
    CHECK(resource.is_equal(first));
    REQUIRE(resource.is_equal(second));
    CHECK_FALSE(resource.is_equal(*std::pmr::new_delete_resource()));

    constexpr std::size_t bytes = 1;
    constexpr auto alignment = alignof(std::max_align_t);
    auto* ptr = resource.allocate(bytes, alignment);
    CHECK(reinterpret_cast<std::uintptr_t>(ptr) % alignment == 0);
    second.deallocate(ptr, bytes, alignment);
}

TEST_CASE("Guarded memory resource rejects unsupported or overflowing requests", "[memory]")
{
    potassium::memory_resource resource;
    CHECK_THROWS_AS(static_cast<void>(resource.allocate(1, alignof(OveralignedPayload))), std::bad_alloc);
    CHECK_THROWS_AS(static_cast<void>(resource.allocate(std::numeric_limits<std::size_t>::max(), alignof(std::max_align_t))), std::bad_alloc);
}

TEST_CASE("Moving a memory lock guard keeps the buffer intact until release", "[memory]")
{
    constexpr std::array contents{std::byte{1}, std::byte{2}};
    auto buffer = contents;
    std::optional<potassium::mlock_guard> original;
    try
    {
        original.emplace(buffer.data(), buffer.size());
    }
    catch (std::runtime_error const& error)
    {
        SKIP(error.what());
    }

    {
        potassium::mlock_guard owner{std::move(*original)};
        CHECK_FALSE(static_cast<bool>(*original));
        CHECK(original->address() == nullptr);

        potassium::mlock_guard empty{std::move(*original)};
        CHECK_FALSE(static_cast<bool>(empty));
        original.reset();

        auto& alias = owner;
        owner = std::move(alias);
        CHECK(owner.address() == buffer.data());

        owner = std::move(empty);
        CHECK_FALSE(static_cast<bool>(owner));
        CHECK(static_cast<bool>(empty));
        CHECK(empty.address() == buffer.data());
        CHECK(buffer == contents);
    }
    CHECK(std::ranges::all_of(buffer, [](std::byte value) { return value == std::byte{}; }));
}
