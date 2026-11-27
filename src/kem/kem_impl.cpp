// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;

#include <sodium.h>
#include <cassert>

module potassium.kem;

import potassium.internal;
import std;

namespace potassium::kem
{
namespace
{
using internal::disjoint_bytes;
using internal::sodium_bytes;
using internal::unwrap;

static_assert(std::string_view{crypto_kem_PRIMITIVE} == "xwing");

template <class Operation>
std::expected<keypair, errc> allocate_keypair(Operation generate) noexcept
try
{
    keypair pair{for_overwrite};
    auto result = generate(pair);
    if (!result) return std::unexpected(result.error());
    return pair;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}
}  // namespace

keypair::keypair()
    : keypair(for_overwrite)
{
    generate_keypair_into(public_key, secret_key);
}

keypair::keypair(for_overwrite_t)
    : secret_key(for_overwrite)
{
}

std::expected<void, errc> generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret, std::nothrow_t) noexcept
{
    assert(disjoint_bytes(pub.storage, secret.bytes()));
    if (crypto_kem_keypair(sodium_bytes(pub.storage.data()), sodium_bytes(secret.bytes().data())) != 0)
    {
        wipe(secret.bytes());
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret)
{
    unwrap(generate_keypair_into(pub, secret, std::nothrow));
}

std::expected<void, errc> generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret, key_ref<seed_tag> seed, std::nothrow_t) noexcept
{
    assert(disjoint_bytes(pub.storage, secret.bytes()));
    assert(disjoint_bytes(pub.storage, seed.bytes()));
    assert(disjoint_bytes(secret.bytes(), seed.bytes()));
    if (crypto_kem_seed_keypair(sodium_bytes(pub.storage.data()), sodium_bytes(secret.bytes().data()), sodium_bytes(seed.bytes().data())) != 0)
    {
        wipe(secret.bytes());
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void generate_keypair_into(public_key<xwing>& pub, key_out<decapsulation_key_tag> secret, key_ref<seed_tag> seed)
{
    unwrap(generate_keypair_into(pub, secret, seed, std::nothrow));
}

std::expected<keypair, errc> generate_keypair(std::nothrow_t) noexcept
{
    return allocate_keypair([](auto& pair) { return generate_keypair_into(pair.public_key, pair.secret_key, std::nothrow); });
}

keypair generate_keypair()
{
    return unwrap(generate_keypair(std::nothrow));
}

std::expected<keypair, errc> generate_keypair(key_ref<seed_tag> seed, std::nothrow_t) noexcept
{
    return allocate_keypair([&](auto& pair) { return generate_keypair_into(pair.public_key, pair.secret_key, seed, std::nothrow); });
}

keypair generate_keypair(key_ref<seed_tag> seed)
{
    return unwrap(generate_keypair(seed, std::nothrow));
}

std::expected<void, errc> encapsulate_into(encapsulation_key_ref key, ciphertext_buffer& ciphertext, key_out<shared_secret_tag> shared_secret, std::nothrow_t) noexcept
{
    auto secret = shared_secret.bytes();
    assert(disjoint_bytes(ciphertext.bytes(), secret));
    assert(disjoint_bytes(ciphertext.bytes(), key.bytes()));
    assert(disjoint_bytes(secret, key.bytes()));
    if (crypto_kem_enc(sodium_bytes(ciphertext.bytes().data()), sodium_bytes(secret.data()), sodium_bytes(key.bytes().data())) != 0)
    {
        wipe(secret);
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void encapsulate_into(encapsulation_key_ref key, ciphertext_buffer& ciphertext, key_out<shared_secret_tag> shared_secret)
{
    unwrap(encapsulate_into(key, ciphertext, shared_secret, std::nothrow));
}

std::expected<encapsulation, errc> encapsulate(encapsulation_key_ref key, std::nothrow_t) noexcept
try
{
    encapsulation result{ciphertext_buffer{}, secret_key<shared_secret_tag>{for_overwrite}};
    auto status = encapsulate_into(key, result.ciphertext, result.shared_secret, std::nothrow);
    if (!status) return std::unexpected(status.error());
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

encapsulation encapsulate(encapsulation_key_ref key)
{
    return unwrap(encapsulate(key, std::nothrow));
}

std::expected<void, errc> decapsulate_into(decapsulation_key_ref key, std::span<std::byte const> ciphertext, key_out<shared_secret_tag> shared_secret, std::nothrow_t) noexcept
{
    auto secret = shared_secret.bytes();
    assert(disjoint_bytes(secret, ciphertext));
    assert(disjoint_bytes(secret, key.bytes()));
    if (ciphertext.size() != algorithm_traits<xwing>::ciphertext_size || crypto_kem_dec(sodium_bytes(secret.data()), sodium_bytes(ciphertext.data()), sodium_bytes(key.bytes().data())) != 0)
    {
        wipe(secret);
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void decapsulate_into(decapsulation_key_ref key, std::span<std::byte const> ciphertext, key_out<shared_secret_tag> shared_secret)
{
    unwrap(decapsulate_into(key, ciphertext, shared_secret, std::nothrow));
}

std::expected<secret_key<shared_secret_tag>, errc> decapsulate(decapsulation_key_ref key, std::span<std::byte const> ciphertext, std::nothrow_t) noexcept
try
{
    if (ciphertext.size() != algorithm_traits<xwing>::ciphertext_size) return std::unexpected(errc::crypto_failed);
    secret_key<shared_secret_tag> result{for_overwrite};
    auto status = decapsulate_into(key, ciphertext, result, std::nothrow);
    if (!status) return std::unexpected(status.error());
    return result;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

secret_key<shared_secret_tag> decapsulate(decapsulation_key_ref key, std::span<std::byte const> ciphertext)
{
    return unwrap(decapsulate(key, ciphertext, std::nothrow));
}
}  // namespace potassium::kem
