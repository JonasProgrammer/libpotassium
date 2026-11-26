// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <cassert>

/// @brief Internal adapters for libsodium operations.
/// @private Only for internal use, not guaranteed to be stable.
export module potassium.internal;

import potassium.core;
import std;

export namespace potassium::internal
{
/// View writable bytes as a libsodium output pointer.
/// @private Only for internal use, not guaranteed to be stable.
inline unsigned char* sodium_bytes(void* data) noexcept
{
    return static_cast<unsigned char*>(data);
}

/// View read-only bytes as a libsodium input pointer.
/// @private Only for internal use, not guaranteed to be stable.
inline unsigned char const* sodium_bytes(void const* data) noexcept
{
    return static_cast<unsigned char const*>(data);
}

template <class T>
T unwrap(std::expected<T, errc> result)
{
    if (!result) throw_error(result.error());
    if constexpr (!std::is_void_v<T>) return std::move(*result);
}

template <class Buffer, class Operation>
std::expected<Buffer, errc> allocate_and_transform(std::size_t size, Operation operation) noexcept
try
{
    Buffer out(size);
    auto result = operation(out);
    if (!result) return std::unexpected(result.error());
    return out;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}
catch (std::length_error const&)
{
    return std::unexpected(errc::allocation_failed);
}

enum class direction
{
    seal,
    open,
};

template <direction Mode, class Function, class A, class... Keys>
std::expected<void, errc> transform(Function function, std::span<std::byte const> input, std::span<std::byte> out, nonce_ref<A> nonce, Keys... keys) noexcept
{
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    if constexpr (Mode == direction::open)
        assert(input.size() < mac_size || out.size() == input.size() - mac_size);
    else
        assert(out.size() >= mac_size && out.size() - mac_size == input.size());
    unsigned char empty{};
    if (function(out.empty() ? &empty : sodium_bytes(out.data()),
                 input.empty() ? &empty : sodium_bytes(input.data()),
                 input.size(),
                 sodium_bytes(nonce.bytes().data()),
                 sodium_bytes(keys.bytes().data())...) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class A, class Operation>
std::expected<std::vector<std::byte>, errc> allocate_ciphertext(std::size_t plaintext_size, Operation operation) noexcept
{
    return allocate_and_transform<std::vector<std::byte>>(plaintext_size + algorithm_traits<A>::mac_size, operation);
}

template <class A, class Operation>
std::expected<secure_buffer, errc> allocate_plaintext(std::size_t ciphertext_size, Operation operation) noexcept
{
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    if (ciphertext_size < mac_size) return std::unexpected(errc::crypto_failed);
    return allocate_and_transform<secure_buffer>(ciphertext_size - mac_size, operation);
}

template <class A, class Operation>
std::expected<detached_ciphertext<A>, errc> allocate_detached_ciphertext(std::size_t plaintext_size, Operation operation) noexcept
try
{
    if (plaintext_size > algorithm_traits<A>::messagebytes_max) return std::unexpected(errc::crypto_failed);
    std::vector<std::byte> ciphertext(plaintext_size);
    auto mac = operation(ciphertext);
    if (!mac) return std::unexpected(mac.error());
    return detached_ciphertext<A>{std::move(ciphertext), *mac};
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}
catch (std::length_error const&)
{
    return std::unexpected(errc::allocation_failed);
}

template <class A, class Operation>
std::expected<secure_buffer, errc> allocate_detached_plaintext(std::size_t ciphertext_size, Operation operation) noexcept
{
    if (ciphertext_size > algorithm_traits<A>::messagebytes_max) return std::unexpected(errc::crypto_failed);
    return allocate_and_transform<secure_buffer>(ciphertext_size, operation);
}

template <class A, class Operation>
std::expected<nonce_buffer<A>, errc> seal_into_with_nonce(Operation operation) noexcept
{
    auto nonce = generate_nonce<A>();
    return operation(nonce).transform([&] { return nonce; });
}

template <class A, class Result, class Operation>
std::expected<Result, errc> seal_with_nonce(Operation operation) noexcept
{
    auto nonce = generate_nonce<A>();
    return operation(nonce).transform([&](auto&& ciphertext) { return Result{std::move(ciphertext), nonce}; });
}
}  // namespace potassium::internal
