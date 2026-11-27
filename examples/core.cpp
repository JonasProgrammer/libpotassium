// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.core;
import std;

struct session_key_tag;

template <>
struct potassium::key_traits<session_key_tag>
{
    using generator = potassium::random_key_generator;
    static constexpr std::size_t size = 32;
};

int main()
{
    // Applications can choose the nonthrowing initialization path.
    if (!potassium::init(std::nothrow))
    {
        std::println(std::cerr, "libsodium initialization failed");
        return 1;
    }

    auto guarded_key = potassium::make_secret_key<session_key_tag>(std::nothrow);
    if (!guarded_key)
    {
        std::println(std::cerr, "Could not generate a guarded key");
        return 1;
    }

    // Generate directly into an inline key via a typed output view.
    potassium::key_buffer_storage<session_key_tag> inline_key{potassium::for_overwrite};
    potassium::key_out<session_key_tag> destination = inline_key;
    potassium::random_fill(destination.bytes());

    // Inline keys erase their bytes on destruction; key_ref borrows either owner.
    potassium::key_ref<session_key_tag> guarded_view = guarded_key->ref();
    potassium::key_ref<session_key_tag> inline_view = inline_key.ref();
    std::println("Generated a {}-byte guarded key and a {}-byte inline key", guarded_view.bytes().size(), inline_view.bytes().size());

    // Fill and wipe byte storage directly.
    potassium::secure_buffer scratch{64};
    potassium::random_fill(scratch.bytes());
    potassium::wipe(scratch.bytes());

    // Container allocations are guarded and wiped on release.
    std::vector<std::byte, potassium::allocator<std::byte>> guarded_bytes(64);
    potassium::random_fill(guarded_bytes);
    potassium::memory_resource resource;
    std::pmr::vector<std::byte> pmr_bytes(64, &resource);
    potassium::random_fill(pmr_bytes);

    void* raw = potassium::raw_allocator::allocate_raw(64, std::nothrow);
    if (!raw)
    {
        std::println(std::cerr, "Could not allocate guarded raw storage");
        return 1;
    }
    potassium::random_fill({static_cast<std::byte*>(raw), 64});
    potassium::raw_allocator::deallocate(raw, 64);

    // Lock caller-owned memory for the lifetime of the guard.
    auto buffer = std::make_unique<std::byte[]>(64);
    try
    {
        potassium::mlock_guard lock{buffer.get(), 64};
        potassium::random_fill({buffer.get(), 64});
    }
    catch (std::runtime_error const& error)
    {
        std::println(std::cerr, "Memory locking unavailable: {}", error.what());
    }
}
