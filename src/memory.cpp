// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

export module libpotassium:memory;

import std;

namespace potassium
{

/// @brief Guarded heap storage for sensitive data.
/// Libsodium attempts to lock pages and wipes the storage on release.
/// Each allocation has page-level overhead.
export struct raw_allocator
{
    /// All instances can release each other's allocations.
    using is_always_equal = std::true_type;
    /// Type for allocation sizes and element counts.
    using size_type = std::size_t;

    /// @brief Allocates raw storage.
    /// @param bytes Number of bytes to allocate.
    /// @pre @p bytes is a multiple of the required fundamental alignment.
    /// @return Pointer to the allocated storage.
    /// @throws std::bad_alloc If allocation fails.
    [[nodiscard]] static void* allocate_raw(size_type bytes);

    /// @brief Allocates raw storage for an array.
    /// @param count Number of elements.
    /// @param element_size Number of bytes per element.
    /// @pre The total byte count is a multiple of the required fundamental alignment.
    /// @return Pointer to the allocated storage.
    /// @throws std::bad_alloc If the total byte count overflows or allocation fails.
    [[nodiscard]] static void* allocate_raw(size_type count, size_type element_size);

    /// @brief Wipes and releases storage.
    /// @param ptr Pointer to release, or null.
    /// @param count Unused.
    /// @pre A non-null @p ptr points to a live allocation from @c allocate_raw.
    static void deallocate(void* ptr, size_type count) noexcept;
};

/// @brief Stateless standard-container allocator for sensitive elements.
/// Supports complete types with fundamental alignment.
export template <typename T>
    requires(alignof(T) <= alignof(std::max_align_t))
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
    /// @param count Number of elements.
    /// @return Pointer to the allocated storage.
    /// @throws std::bad_alloc If the total byte count overflows or allocation fails.
    [[nodiscard]] static T* allocate(size_type count)
    {
        void* raw;
        if constexpr (sizeof(T) == 1)
            raw = allocate_raw(count);
        else
            raw = allocate_raw(count, sizeof(T));
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

}  // namespace potassium
