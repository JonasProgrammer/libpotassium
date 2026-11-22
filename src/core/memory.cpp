// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

export module potassium.core:memory;

import std;

namespace potassium
{

namespace detail
{
inline constexpr std::size_t safe_alignment = 1024;
}

/// @brief Guarded heap storage for sensitive data.
/// Libsodium attempts to lock pages and wipes the storage on release.
/// Each allocation has page-level overhead.
/// For page-backed allocations, a byte count divisible by the required alignment
/// gives an aligned address when the alignment also divides the page size.
export struct raw_allocator
{
    /// All instances can release each other's allocations.
    using is_always_equal = std::true_type;
    /// Type for allocation sizes and element counts.
    using size_type = std::size_t;

    /// @brief Allocates raw storage.
    /// @throws std::bad_alloc If allocation fails.
    /// @see allocate_raw(size_type, std::nothrow_t const&)
    /// @see deallocate_raw(void*)
    [[nodiscard]] static void* allocate_raw(size_type bytes);

    /// @brief Allocates raw storage, returning nullptr on failure.
    /// @see allocate_raw(size_type)
    /// @see deallocate_raw(void*)
    [[nodiscard]] static void* allocate_raw(size_type bytes, std::nothrow_t const&) noexcept;

    /// @brief Allocates raw storage for an array.
    /// @param count Number of array elements.
    /// @param element_size Number of bytes per element.
    /// @throws std::bad_alloc If the total byte count overflows or allocation fails.
    /// @see allocate_raw(size_type, size_type, std::nothrow_t const&)
    /// @see deallocate_raw(void*)
    [[nodiscard]] static void* allocate_raw(size_type count, size_type element_size);

    /// @brief Allocates array storage, returning nullptr on overflow or failure.
    /// @see allocate_raw(size_type, size_type)
    /// @see deallocate_raw(void*)
    [[nodiscard]] static void* allocate_raw(size_type count, size_type element_size, std::nothrow_t const&) noexcept;

    /// @brief Wipes and releases storage.
    /// @param ptr Pointer to release, or null.
    /// @param count Unused.
    /// @pre A non-null @p ptr points to a live allocation from @c allocate_raw.
    static void deallocate(void* ptr, size_type count) noexcept;
};

/// @brief Stateless standard-container allocator for sensitive elements.
/// Page-backed allocations support alignments that divide the page size.
export template <typename T>
struct allocator : raw_allocator
{
    /// Element type.
    using value_type = T;

    constexpr allocator() noexcept = default;

    /// Constructs an allocator from another element type.
    template <typename U>
    constexpr allocator(allocator<U> const&) noexcept
    {
    }

    /// @brief Allocates storage for elements without constructing them.
    /// @throws std::bad_alloc If the total byte count overflows or aligned allocation fails.
    [[nodiscard]] static T* allocate(size_type count)
    {
        constexpr auto object_size = std::max(sizeof(T), alignof(T));
        void* raw;
        if constexpr (object_size == 1)
            raw = allocate_raw(count);
        else
            raw = allocate_raw(count, object_size);

        if constexpr (alignof(T) > detail::safe_alignment)
        {
            if (reinterpret_cast<std::uintptr_t>(raw) % alignof(T) != 0) [[unlikely]]
            {
                raw_allocator::deallocate(raw, count);
                throw std::bad_alloc{};
            }
        }

        return std::start_lifetime_as_array<T>(raw, count);
    }

    /// @brief Wipes and releases storage.
    /// @param ptr Pointer returned by @c allocate.
    /// @param count Element count passed to @c allocate.
    /// @pre The allocation is live and any constructed elements have been destroyed.
    static void deallocate(T* ptr, size_type count) noexcept { raw_allocator::deallocate(ptr, count); }

    /// @return Always true because allocator instances share the same heap.
    template <typename U>
    constexpr bool operator==(allocator<U> const&) const noexcept
    {
        return true;
    }
};

/// @brief Move-only guard for a lock on caller-owned memory.
/// Disjoint byte ranges can share a page and its lock.
///
/// @code{.cpp}
/// import potassium.core;
/// import std;
///
/// int main()
/// {
///     potassium::init();
///     constexpr std::size_t size = 32;
///     auto buffer = std::make_unique<std::byte[]>(size);
///     potassium::mlock_guard guard{buffer.get(), size};
///     // Read sensitive data directly into buffer and use it here.
/// }
/// @endcode
export class mlock_guard final
{
    void* addr_;
    std::size_t len_;

public:
    /// @brief Locks a region of writable memory.
    /// @pre @p address is non-null and points to a writable region of at least @p len bytes.
    /// @pre @p len is greater than zero.
    /// @pre The region remains alive, writable, and at the same address until the lock is released.
    /// @pre The guard has exclusive control of locking on every page touched by the region.
    /// @throws std::runtime_error If libsodium reports that the lock failed.
    mlock_guard(void* address, std::size_t len);

    /// Transfers the lock and leaves @p other empty.
    mlock_guard(mlock_guard&& other) noexcept
        : addr_(std::exchange(other.addr_, nullptr))
        , len_(std::exchange(other.len_, 0))
    {
    }

    /// Wipes the guarded bytes and attempts to unlock their pages, if the guard owns a lock.
    /// Unlock errors are ignored.
    ~mlock_guard();

    /// Exchanges locks with @p other, including empty states.
    /// Self-move assignment leaves the guard unchanged.
    mlock_guard& operator=(mlock_guard&& other) noexcept
    {
        std::swap(addr_, other.addr_);
        std::swap(len_, other.len_);
        return *this;
    }

    /// @return Whether the guard owns a lock.
    [[nodiscard]] explicit operator bool() const noexcept { return addr_ != nullptr; }

    /// @return The start of the guarded region, or null if empty.
    [[nodiscard]] void* address() const noexcept { return addr_; }
};

/// @brief Guarded heap resource for PMR containers and other byte allocations.
/// Allocation sizes are rounded up to the requested alignment.
/// Supports alignments up to 1024 bytes.
/// Throws std::bad_alloc if the requested alignment exceeds this limit.
/// Each allocation has page-level overhead.
export class memory_resource final : public std::pmr::memory_resource
{
    [[nodiscard]] void* do_allocate(std::size_t bytes, std::size_t alignment) override;
    void do_deallocate(void* ptr, std::size_t bytes, std::size_t alignment) override;
    [[nodiscard]] bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override;
};

}  // namespace potassium
