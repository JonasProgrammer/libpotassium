// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;

#include <sodium.h>
#include <cassert>

module potassium.sign;

import potassium.internal;
import std;

namespace potassium::sign
{
namespace
{
using internal::disjoint_bytes;
using internal::sodium_bytes;
using internal::unwrap;
using traits = algorithm_traits<ed25519>;

static_assert(std::string_view{crypto_sign_PRIMITIVE} == "ed25519");

std::span<std::byte> state_bytes(state_type& state) noexcept
{
    return std::as_writable_bytes(std::span{&state, 1});
}

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

std::expected<void, errc> generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret, std::nothrow_t) noexcept
{
    assert(disjoint_bytes(pub.storage, secret.bytes()));
    if (crypto_sign_ed25519_keypair(sodium_bytes(pub.storage.data()), sodium_bytes(secret.bytes().data())) != 0)
    {
        wipe(secret.bytes());
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret)
{
    unwrap(generate_keypair_into(pub, secret, std::nothrow));
}

std::expected<void, errc> generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret, key_ref<seed_tag> seed, std::nothrow_t) noexcept
{
    assert(disjoint_bytes(pub.storage, secret.bytes()));
    assert(disjoint_bytes(pub.storage, seed.bytes()));
    assert(disjoint_bytes(secret.bytes(), seed.bytes()));
    if (crypto_sign_ed25519_seed_keypair(sodium_bytes(pub.storage.data()), sodium_bytes(secret.bytes().data()), sodium_bytes(seed.bytes().data())) != 0)
    {
        wipe(secret.bytes());
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void generate_keypair_into(public_key<ed25519>& pub, key_out<signing_key_tag> secret, key_ref<seed_tag> seed)
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

std::expected<public_key<ed25519>, errc> public_key_from_secret_key(signing_key_ref key, std::nothrow_t) noexcept
{
    public_key<ed25519> pub;
    if (crypto_sign_ed25519_sk_to_pk(sodium_bytes(pub.storage.data()), sodium_bytes(key.bytes().data())) != 0) return std::unexpected(errc::crypto_failed);
    return pub;
}

public_key<ed25519> public_key_from_secret_key(signing_key_ref key)
{
    return unwrap(public_key_from_secret_key(key, std::nothrow));
}

std::expected<void, errc> seed_from_secret_key_into(signing_key_ref key, key_out<seed_tag> out, std::nothrow_t) noexcept
{
    assert(disjoint_bytes(out.bytes(), key.bytes()));
    if (crypto_sign_ed25519_sk_to_seed(sodium_bytes(out.bytes().data()), sodium_bytes(key.bytes().data())) != 0)
    {
        wipe(out.bytes());
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void seed_from_secret_key_into(signing_key_ref key, key_out<seed_tag> out)
{
    unwrap(seed_from_secret_key_into(key, out, std::nothrow));
}

std::expected<secret_key<seed_tag>, errc> seed_from_secret_key(signing_key_ref key, std::nothrow_t) noexcept
try
{
    secret_key<seed_tag> seed{for_overwrite};
    auto result = seed_from_secret_key_into(key, seed, std::nothrow);
    if (!result) return std::unexpected(result.error());
    return seed;
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

secret_key<seed_tag> seed_from_secret_key(signing_key_ref key)
{
    return unwrap(seed_from_secret_key(key, std::nothrow));
}

std::expected<void, errc> sign_into(signing_key_ref key, std::span<std::byte const> message, std::span<std::byte> out, std::nothrow_t) noexcept
{
    assert(message.size() <= traits::messagebytes_max);
    assert(out.size() == message.size() + traits::signature_size);
    assert(disjoint_bytes(out, key.bytes()));
    assert(disjoint_bytes(out, message));
    unsigned char empty{};
    if (crypto_sign_ed25519(sodium_bytes(out.data()), nullptr, message.empty() ? &empty : sodium_bytes(message.data()), message.size(), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

void sign_into(signing_key_ref key, std::span<std::byte const> message, std::span<std::byte> out)
{
    unwrap(sign_into(key, message, out, std::nothrow));
}

std::expected<std::vector<std::byte>, errc> sign(signing_key_ref key, std::span<std::byte const> message, std::nothrow_t) noexcept
{
    assert(message.size() <= traits::messagebytes_max);
    return internal::allocate_and_transform<std::vector<std::byte>>(message.size() + traits::signature_size, [&](auto& out) { return sign_into(key, message, out, std::nothrow); });
}

std::vector<std::byte> sign(signing_key_ref key, std::span<std::byte const> message)
{
    return unwrap(sign(key, message, std::nothrow));
}

std::expected<void, errc> open_into(verification_key_ref key, std::span<std::byte const> signed_message, std::span<std::byte> out, std::nothrow_t) noexcept
{
    if (signed_message.size() < traits::signature_size || signed_message.size() - traits::signature_size > traits::messagebytes_max) return std::unexpected(errc::crypto_failed);
    assert(out.size() == signed_message.size() - traits::signature_size);
    assert(disjoint_bytes(out, key.bytes()));
    assert(disjoint_bytes(out, signed_message));
    unsigned char empty{};
    if (crypto_sign_ed25519_open(out.empty() ? &empty : sodium_bytes(out.data()), nullptr, sodium_bytes(signed_message.data()), signed_message.size(), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

void open_into(verification_key_ref key, std::span<std::byte const> signed_message, std::span<std::byte> out)
{
    unwrap(open_into(key, signed_message, out, std::nothrow));
}

std::expected<secure_buffer, errc> open(verification_key_ref key, std::span<std::byte const> signed_message, std::nothrow_t) noexcept
{
    if (signed_message.size() < traits::signature_size || signed_message.size() - traits::signature_size > traits::messagebytes_max) return std::unexpected(errc::crypto_failed);
    return internal::allocate_and_transform<secure_buffer>(signed_message.size() - traits::signature_size, [&](auto& out) { return open_into(key, signed_message, out.bytes(), std::nothrow); });
}

secure_buffer open(verification_key_ref key, std::span<std::byte const> signed_message)
{
    return unwrap(open(key, signed_message, std::nothrow));
}

std::expected<signature, errc> sign_detached(signing_key_ref key, std::span<std::byte const> message, std::nothrow_t) noexcept
{
    assert(message.size() <= traits::messagebytes_max);
    signature sig;
    unsigned char empty{};
    if (crypto_sign_ed25519_detached(sodium_bytes(sig.bytes().data()), nullptr, message.empty() ? &empty : sodium_bytes(message.data()), message.size(), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return sig;
}

signature sign_detached(signing_key_ref key, std::span<std::byte const> message)
{
    return unwrap(sign_detached(key, message, std::nothrow));
}

std::expected<void, errc> verify_detached(verification_key_ref key, std::span<std::byte const> message, signature const& sig, std::nothrow_t) noexcept
{
    if (message.size() > traits::messagebytes_max) return std::unexpected(errc::crypto_failed);
    unsigned char empty{};
    if (crypto_sign_ed25519_verify_detached(sodium_bytes(sig.bytes().data()), message.empty() ? &empty : sodium_bytes(message.data()), message.size(), sodium_bytes(key.bytes().data())) != 0)
        return std::unexpected(errc::crypto_failed);
    return {};
}

void verify_detached(verification_key_ref key, std::span<std::byte const> message, signature const& sig)
{
    unwrap(verify_detached(key, message, sig, std::nothrow));
}

inplace_state::~inplace_state()
{
    wipe(state_bytes(state_));
}

state_storage::state_storage()
    : storage_(std::in_place_type<guarded_state>)
{
}

state_storage::state_storage(state_type& state) noexcept
    : storage_(std::ref(state))
{
    wipe(state_bytes(state));
}

state_storage::state_storage(state_storage&& other) noexcept
    : storage_(std::exchange(other.storage_, std::monostate{}))
{
}

state_storage& state_storage::operator=(state_storage&& other) noexcept
{
    if (this != &other) storage_ = std::exchange(other.storage_, std::monostate{});
    return *this;
}

state_storage::operator bool() const noexcept
{
    return !std::holds_alternative<std::monostate>(storage_);
}

state_type& state_storage::get() noexcept
{
    if (auto* guarded = std::get_if<guarded_state>(&storage_)) return **guarded;
    return std::get<std::reference_wrapper<state_type>>(storage_).get();
}

prehash::prehash(state_storage&& storage) noexcept
    : storage_(std::move(storage))
{
    if (crypto_sign_ed25519ph_init(&storage_.get()) != 0) close();
}

prehash::prehash(prehash&& other) noexcept
    : storage_(std::move(other.storage_))
    , active_(std::exchange(other.active_, false))
{
}

prehash& prehash::operator=(prehash&& other) noexcept
{
    if (this != &other)
    {
        close();
        storage_ = std::move(other.storage_);
        active_ = std::exchange(other.active_, false);
    }
    return *this;
}

prehash::~prehash()
{
    close();
}

void prehash::close() noexcept
{
    if (std::exchange(active_, false)) wipe(state_bytes(storage_.get()));
}

state_storage prehash::close_for_reuse() && noexcept
{
    close();
    return std::move(storage_);
}

std::expected<void, errc> prehash::update(std::span<std::byte const> chunk, std::nothrow_t) noexcept
{
    if (!active_) return std::unexpected(errc::crypto_failed);
    auto& state = storage_.get();
    assert(disjoint_bytes(state_bytes(state), chunk));
    unsigned char empty{};
    if (crypto_sign_ed25519ph_update(&state, chunk.empty() ? &empty : sodium_bytes(chunk.data()), chunk.size()) != 0)
    {
        close();
        return std::unexpected(errc::crypto_failed);
    }
    return {};
}

void prehash::update(std::span<std::byte const> chunk)
{
    unwrap(update(chunk, std::nothrow));
}

std::expected<prehash_signature, errc> prehash::finish_sign(signing_key_ref key, std::nothrow_t) noexcept
{
    if (!active_) return std::unexpected(errc::crypto_failed);
    auto& state = storage_.get();
    assert(disjoint_bytes(state_bytes(state), key.bytes()));
    prehash_signature sig;
    auto status = crypto_sign_ed25519ph_final_create(&state, sodium_bytes(sig.bytes().data()), nullptr, sodium_bytes(key.bytes().data()));
    close();
    if (status != 0) return std::unexpected(errc::crypto_failed);
    return sig;
}

prehash_signature prehash::finish_sign(signing_key_ref key)
{
    return unwrap(finish_sign(key, std::nothrow));
}

std::expected<void, errc> prehash::finish_verify(verification_key_ref key, prehash_signature const& sig, std::nothrow_t) noexcept
{
    if (!active_) return std::unexpected(errc::crypto_failed);
    auto& state = storage_.get();
    assert(disjoint_bytes(state_bytes(state), key.bytes()));
    assert(disjoint_bytes(state_bytes(state), sig.bytes()));
    auto status = crypto_sign_ed25519ph_final_verify(&state, sodium_bytes(sig.bytes().data()), sodium_bytes(key.bytes().data()));
    close();
    if (status != 0) return std::unexpected(errc::crypto_failed);
    return {};
}

void prehash::finish_verify(verification_key_ref key, prehash_signature const& sig)
{
    unwrap(finish_verify(key, sig, std::nothrow));
}

std::expected<prehash, errc> start_prehash(std::nothrow_t) noexcept
try
{
    return start_prehash(state_storage{}, std::nothrow);
}
catch (std::bad_alloc const&)
{
    return std::unexpected(errc::allocation_failed);
}

prehash start_prehash()
{
    return unwrap(start_prehash(std::nothrow));
}

std::expected<prehash, errc> start_prehash(state_storage&& storage, std::nothrow_t) noexcept
{
    if (!storage) return std::unexpected(errc::crypto_failed);
    prehash operation{std::move(storage)};
    if (!operation.active_) return std::unexpected(errc::crypto_failed);
    return operation;
}

prehash start_prehash(state_storage&& storage)
{
    return unwrap(start_prehash(std::move(storage), std::nothrow));
}
}  // namespace potassium::sign
