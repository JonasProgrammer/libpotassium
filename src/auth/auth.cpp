// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

/// @brief One-shot HMAC computation and constant-time verification.
/// @see potassium::auth, potassium::hash::keyed_hasher
export module potassium.auth;

export import potassium.hash;
import potassium.internal;
import std;

/// @cond INTERNAL
namespace potassium::auth::detail
{
template <class A>
using key_type = std::type_identity_t<key_ref<hmac_key_tag<A>>>;

template <class A, class Byte>
using tag_span = std::span<Byte, auth_traits<A>::tag_size>;
}  // namespace potassium::auth::detail

/// @endcond

/// @brief HMAC algorithms, typed keys, and one-shot message authentication.
/// @details Choose @ref potassium::auth::hmac_sha256, @ref potassium::auth::hmac_sha512,
/// or @ref potassium::auth::hmac_sha512256 (the default).
/// Use @ref potassium::hash::keyed_hasher for incremental messages.
export namespace potassium::auth
{
/// Public fixed-size HMAC tag with constant-time equality for tags of the same algorithm.
template <hmac_algorithm A = default_algorithm>
using tag_buffer = hash::tag_buffer<A>;

/// Write a tag into an exactly sized destination.
/// @param key Fixed-size authentication key for A.
/// @param message Bytes to authenticate, possibly empty.
/// @param[out] out Destination for the tag bytes in wire order.
/// @pre Output is disjoint from all inputs.
template <hmac_algorithm A = default_algorithm>
void authenticate_into(detail::key_type<A> key, std::span<std::byte const> message, detail::tag_span<A, std::byte> out) noexcept
{
    detail::hmac_ops<A>::authenticate(key, message, out);
}

/// Compute a tag without allocating.
/// @return Authentication tag for the supplied key and message.
template <hmac_algorithm A = default_algorithm>
[[nodiscard]] tag_buffer<A> authenticate(detail::key_type<A> key, std::span<std::byte const> message) noexcept
{
    tag_buffer<A> tag;
    authenticate_into<A>(key, message, tag.storage);
    return tag;
}

/// Verify a tag in constant time, returning errc::crypto_failed on mismatch.
template <hmac_algorithm A = default_algorithm>
std::expected<void, errc> verify(detail::key_type<A> key, std::span<std::byte const> message, detail::tag_span<A, std::byte const> tag, std::nothrow_t) noexcept
{
    if (!detail::hmac_ops<A>::verify(key, message, tag)) return std::unexpected(errc::crypto_failed);
    return {};
}

/// Verify a tag in constant time.
/// @throws crypto_error If the tag does not match.
template <hmac_algorithm A = default_algorithm>
void verify(detail::key_type<A> key, std::span<std::byte const> message, detail::tag_span<A, std::byte const> tag)
{
    internal::unwrap(verify<A>(key, message, tag, std::nothrow));
}

/// Compatibility alias for the keyed HMAC stream.
/// @details The default specialization is @c potassium::hash::keyed_hasher<potassium::auth::default_algorithm>.
/// @deprecated Use @ref potassium::hash::keyed_hasher with the HMAC algorithm tag and storage policy.
template <hmac_algorithm A = default_algorithm, class Storage = typename hash::keyed_hash_traits<A>::default_storage>
using authenticator [[deprecated("Use potassium::hash::keyed_hasher<A, Storage> for streaming HMAC")]] = hash::keyed_hasher<A, Storage>;
}  // namespace potassium::auth
