// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>
#include <cassert>

module potassium.aead;

import potassium.internal;
import std;

namespace potassium::aead
{
namespace
{
void wipe_state(aes256gcm_state_type& state) noexcept
{
    wipe(std::as_writable_bytes(std::span{&state, 1}));
}
}  // namespace

bool aes256gcm_available() noexcept
{
    return crypto_aead_aes256gcm_is_available() != 0;
}

aes256gcm_inplace_state::~aes256gcm_inplace_state()
{
    wipe_state(state_);
}

aes256gcm_state_storage::aes256gcm_state_storage()
    : state_(allocator<aes256gcm_state_type>::allocate(1), state_deleter{true})
{
    clear();
}

aes256gcm_state_storage::aes256gcm_state_storage(aes256gcm_state_type& state) noexcept
    : state_(&state, state_deleter{false})
{
    clear();
}

void aes256gcm_state_storage::state_deleter::operator()(aes256gcm_state_type* state) const noexcept
{
    if (guarded)
        allocator<aes256gcm_state_type>::deallocate(state, 1);
    else
        wipe_state(*state);
}

void aes256gcm_state_storage::clear() noexcept
{
    if (state_) wipe_state(*state_);
}

aes256gcm_precomputed::aes256gcm_precomputed(aes256gcm_state_storage&& storage) noexcept
    : storage_(std::move(storage))
{
}

aes256gcm_state_storage aes256gcm_precomputed::close_for_reuse() && noexcept
{
    storage_.clear();
    return std::move(storage_);
}

std::expected<aes256gcm_precomputed, errc> precompute_into(key_ref<aes256gcm> key, aes256gcm_state_storage&& storage, std::nothrow_t) noexcept
{
    if (!storage || !aes256gcm_available()) return std::unexpected(errc::crypto_failed);
    if (crypto_aead_aes256gcm_beforenm(storage.state_.get(), internal::sodium_bytes(key.bytes().data())) != 0)
    {
        storage.clear();
        return std::unexpected(errc::crypto_failed);
    }
    return aes256gcm_precomputed{std::move(storage)};
}

aes256gcm_precomputed precompute_into(key_ref<aes256gcm> key, aes256gcm_state_storage&& storage)
{
    return internal::unwrap(precompute_into(key, std::move(storage), std::nothrow));
}

std::expected<aes256gcm_precomputed, errc> precompute(key_ref<aes256gcm> key, std::nothrow_t) noexcept
try
{
    if (!aes256gcm_available()) return std::unexpected(errc::crypto_failed);
    return precompute_into(key, aes256gcm_state_storage{}, std::nothrow);
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

aes256gcm_precomputed precompute(key_ref<aes256gcm> key)
{
    return internal::unwrap(precompute(key, std::nothrow));
}
}  // namespace potassium::aead

namespace potassium::aead::detail
{
aes256gcm_state_ref borrow_key(aes256gcm_precomputed const& state) noexcept
{
    return {state.state()};
}

namespace
{
using internal::sodium_bytes;

template <class K>
struct sodium_aead;

template <>
struct sodium_aead<key_ref<chacha20poly1305>>
{
    static constexpr auto encrypt = crypto_aead_chacha20poly1305_encrypt;
    static constexpr auto decrypt = crypto_aead_chacha20poly1305_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_chacha20poly1305_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_chacha20poly1305_decrypt_detached;
};

template <>
struct sodium_aead<key_ref<chacha20poly1305_ietf>>
{
    static constexpr auto encrypt = crypto_aead_chacha20poly1305_ietf_encrypt;
    static constexpr auto decrypt = crypto_aead_chacha20poly1305_ietf_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_chacha20poly1305_ietf_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_chacha20poly1305_ietf_decrypt_detached;
};

template <>
struct sodium_aead<key_ref<xchacha20poly1305_ietf>>
{
    static constexpr auto encrypt = crypto_aead_xchacha20poly1305_ietf_encrypt;
    static constexpr auto decrypt = crypto_aead_xchacha20poly1305_ietf_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
};

template <>
struct sodium_aead<key_ref<aegis128l>>
{
    static constexpr auto encrypt = crypto_aead_aegis128l_encrypt;
    static constexpr auto decrypt = crypto_aead_aegis128l_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_aegis128l_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_aegis128l_decrypt_detached;
};

template <>
struct sodium_aead<key_ref<aegis256>>
{
    static constexpr auto encrypt = crypto_aead_aegis256_encrypt;
    static constexpr auto decrypt = crypto_aead_aegis256_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_aegis256_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_aegis256_decrypt_detached;
};

template <>
struct sodium_aead<key_ref<aes256gcm>>
{
    static constexpr auto encrypt = crypto_aead_aes256gcm_encrypt;
    static constexpr auto decrypt = crypto_aead_aes256gcm_decrypt;
    static constexpr auto encrypt_detached = crypto_aead_aes256gcm_encrypt_detached;
    static constexpr auto decrypt_detached = crypto_aead_aes256gcm_decrypt_detached;
};

template <>
struct sodium_aead<aes256gcm_state_ref>
{
    static constexpr auto encrypt = crypto_aead_aes256gcm_encrypt_afternm;
    static constexpr auto decrypt = crypto_aead_aes256gcm_decrypt_afternm;
    static constexpr auto encrypt_detached = crypto_aead_aes256gcm_encrypt_detached_afternm;
    static constexpr auto decrypt_detached = crypto_aead_aes256gcm_decrypt_detached_afternm;
};

template <class A>
auto native_key(key_ref<A> key) noexcept
{
    return sodium_bytes(key.bytes().data());
}

auto native_key(aes256gcm_state_ref state) noexcept
{
    return state.state;
}

template <class A>
consteval bool matches_backend(std::size_t key, std::size_t nonce, std::size_t mac, std::size_t messagebytes_max)
{
    using traits = algorithm_traits<A>;
    return traits::key_size == key && traits::nonce_size == nonce && traits::mac_size == mac && traits::messagebytes_max == messagebytes_max;
}

static_assert(matches_backend<chacha20poly1305>(crypto_aead_chacha20poly1305_KEYBYTES,
                                                crypto_aead_chacha20poly1305_NPUBBYTES,
                                                crypto_aead_chacha20poly1305_ABYTES,
                                                crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX));
static_assert(matches_backend<chacha20poly1305_ietf>(crypto_aead_chacha20poly1305_ietf_KEYBYTES,
                                                     crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                                     crypto_aead_chacha20poly1305_ietf_ABYTES,
                                                     crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX));
static_assert(matches_backend<xchacha20poly1305_ietf>(crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                                                      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                                      crypto_aead_xchacha20poly1305_ietf_ABYTES,
                                                      crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX));
static_assert(matches_backend<aegis128l>(crypto_aead_aegis128l_KEYBYTES, crypto_aead_aegis128l_NPUBBYTES, crypto_aead_aegis128l_ABYTES, crypto_aead_aegis128l_MESSAGEBYTES_MAX));
static_assert(matches_backend<aegis256>(crypto_aead_aegis256_KEYBYTES, crypto_aead_aegis256_NPUBBYTES, crypto_aead_aegis256_ABYTES, crypto_aead_aegis256_MESSAGEBYTES_MAX));
static_assert(matches_backend<aes256gcm>(crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_NPUBBYTES, crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_MESSAGEBYTES_MAX));

template <class A>
bool valid_lengths(std::size_t message, std::size_t ad) noexcept
{
    if constexpr (std::same_as<A, aegis128l> || std::same_as<A, aegis256> || std::same_as<A, aes256gcm>) return message <= algorithm_traits<A>::messagebytes_max && ad <= (1ull << 61) - 1;
    return message <= algorithm_traits<A>::messagebytes_max && std::in_range<std::uint64_t>(ad);
}
}  // namespace

template <class K>
std::expected<void, errc> backend<K>::seal_into(K key, std::span<std::byte const> plaintext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept
{
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    assert(valid_lengths<A>(plaintext.size(), ad.size()));
    assert(out.size() >= mac_size && out.size() - mac_size == plaintext.size());
    if (!key_available(key)) return std::unexpected(errc::crypto_failed);

    if (sodium_aead<K>::encrypt(sodium_bytes(out.data()),
                                nullptr,
                                sodium_bytes(plaintext.data()),
                                plaintext.size(),
                                sodium_bytes(ad.data()),
                                ad.size(),
                                nullptr,
                                sodium_bytes(nonce.bytes().data()),
                                native_key(key)) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class K>
std::expected<void, errc> backend<K>::open_into(K key, std::span<std::byte const> ciphertext, std::span<std::byte const> ad, std::span<std::byte> out, nonce_ref<A> nonce) noexcept
{
    constexpr auto mac_size = algorithm_traits<A>::mac_size;
    if (!key_available(key) || ciphertext.size() < mac_size || !valid_lengths<A>(ciphertext.size() - mac_size, ad.size())) return std::unexpected(errc::crypto_failed);
    assert(out.size() == ciphertext.size() - mac_size);

    if (sodium_aead<K>::decrypt(sodium_bytes(out.data()),
                                nullptr,
                                nullptr,
                                sodium_bytes(ciphertext.data()),
                                ciphertext.size(),
                                sodium_bytes(ad.data()),
                                ad.size(),
                                sodium_bytes(nonce.bytes().data()),
                                native_key(key)) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template <class K>
std::expected<mac_buffer<typename backend<K>::A>, errc> backend<K>::seal_detached_into(K key,
                                                                                       std::span<std::byte const> plaintext,
                                                                                       std::span<std::byte const> ad,
                                                                                       std::span<std::byte> out,
                                                                                       nonce_ref<A> nonce) noexcept
{
    assert(valid_lengths<A>(plaintext.size(), ad.size()));
    assert(out.size() == plaintext.size());
    if (!key_available(key)) return std::unexpected(errc::crypto_failed);
    mac_buffer<A> mac;
    unsigned char empty{};
    if (sodium_aead<K>::encrypt_detached(out.empty() ? &empty : sodium_bytes(out.data()),
                                         sodium_bytes(mac.bytes().data()),
                                         nullptr,
                                         sodium_bytes(plaintext.data()),
                                         plaintext.size(),
                                         sodium_bytes(ad.data()),
                                         ad.size(),
                                         nullptr,
                                         sodium_bytes(nonce.bytes().data()),
                                         native_key(key)) != 0)
        return std::unexpected(errc::crypto_failed);
    return mac;
}

template <class K>
std::expected<void, errc> backend<K>::open_detached_into(K key,
                                                         std::span<std::byte const> ciphertext,
                                                         std::span<std::byte const> ad,
                                                         mac_buffer<A> const& mac,
                                                         std::span<std::byte> out,
                                                         nonce_ref<A> nonce) noexcept
{
    if (!key_available(key) || !valid_lengths<A>(ciphertext.size(), ad.size())) return std::unexpected(errc::crypto_failed);
    assert(out.size() == ciphertext.size());
    unsigned char empty{};
    if (sodium_aead<K>::decrypt_detached(sodium_bytes(out.data()),
                                         nullptr,
                                         ciphertext.empty() ? &empty : sodium_bytes(ciphertext.data()),
                                         ciphertext.size(),
                                         sodium_bytes(mac.bytes().data()),
                                         sodium_bytes(ad.data()),
                                         ad.size(),
                                         sodium_bytes(nonce.bytes().data()),
                                         native_key(key)) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

template struct backend<key_ref<chacha20poly1305>>;
template struct backend<key_ref<chacha20poly1305_ietf>>;
template struct backend<key_ref<xchacha20poly1305_ietf>>;
template struct backend<key_ref<aegis128l>>;
template struct backend<key_ref<aegis256>>;
template struct backend<key_ref<aes256gcm>>;
template struct backend<aes256gcm_state_ref>;
}  // namespace potassium::aead::detail
