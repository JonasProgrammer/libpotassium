// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.box;
import std;

namespace box = potassium::box;

namespace
{
constexpr std::array input{'d', 'a', 't', 'a'};

template <class A>
bool owning_boxes()
{
    auto message = std::as_bytes(std::span{input});
    auto alice = box::generate_keypair<A>();
    potassium::key_buffer_storage<box::seed_tag<A>> bob_seed;
    auto bob = box::generate_keypair<A>(bob_seed);

    // Alice and Bob must already trust each other's public keys.
    auto sealed = box::seal(alice.secret_key, bob.public_key, message);
    auto opened = box::open(bob.secret_key, alice.public_key, sealed);
    if (!std::ranges::equal(opened.bytes(), message)) return false;

    auto detached = box::seal_detached(alice.secret_key, bob.public_key, message);
    auto detached_plaintext = box::open_detached(bob.secret_key, alice.public_key, detached.ciphertext, detached.mac, detached.nonce);
    if (!std::ranges::equal(detached_plaintext.bytes(), message)) return false;

    // A precomputed key can also own guarded storage.
    auto sending_key = box::precompute(alice.secret_key, bob.public_key);
    auto receiving_key = box::precompute(bob.secret_key, alice.public_key);
    auto nonce = potassium::generate_nonce<A>();
    auto ciphertext = box::seal(sending_key, message, nonce);
    auto plaintext = box::open(receiving_key, ciphertext, nonce);
    if (!std::ranges::equal(plaintext.bytes(), message)) return false;

    // An anonymous sealed box needs only Bob's public key and gives no sender identity.
    auto anonymous = box::seal_anonymous(bob.public_key, message);
    auto anonymous_plaintext = box::open_anonymous(bob.secret_key, bob.public_key, anonymous);
    return std::ranges::equal(anonymous_plaintext.bytes(), message);
}

template <class A>
bool caller_owned_boxes()
{
    auto message = std::as_bytes(std::span{input});
    potassium::public_key<A> alice_public;
    potassium::public_key<A> bob_public;
    potassium::key_buffer_storage<box::private_key_tag<A>> alice_private{potassium::for_overwrite};
    potassium::key_buffer_storage<box::private_key_tag<A>> bob_private{potassium::for_overwrite};
    potassium::key_buffer_storage<box::seed_tag<A>> bob_seed;
    box::generate_keypair_into(alice_public, alice_private.writable_bytes());
    box::generate_keypair_into(bob_public, bob_private, bob_seed);

    std::array<std::byte, input.size() + potassium::algorithm_traits<A>::mac_size> combined{};
    std::array<std::byte, input.size()> plaintext{};
    auto nonce = box::seal_into(alice_private, bob_public, message, combined);
    box::open_into(bob_private, alice_public, combined, plaintext, nonce);
    if (!std::ranges::equal(plaintext, message)) return false;

    std::array<std::byte, input.size()> ciphertext{};
    auto detached = box::seal_detached_into(alice_private, bob_public, message, ciphertext);
    box::open_detached_into(bob_private, alice_public, ciphertext, detached.mac, plaintext, detached.nonce);
    if (!std::ranges::equal(plaintext, message)) return false;

    // Precompute the same pairwise key at both ends and reuse it for messages.
    potassium::key_buffer_storage<box::precomputed_key_tag<A>> sending_key{potassium::for_overwrite};
    potassium::key_buffer_storage<box::precomputed_key_tag<A>> receiving_key{potassium::for_overwrite};
    box::precompute_into(alice_private, bob_public, sending_key);
    box::precompute_into(bob_private, alice_public, receiving_key);

    auto precomputed_nonce = box::seal_into(sending_key, message, combined);
    box::open_into(receiving_key, combined, plaintext, precomputed_nonce);
    if (!std::ranges::equal(plaintext, message)) return false;

    auto precomputed_detached = box::seal_detached_into(sending_key, message, ciphertext);
    auto opened = box::open_detached_into(receiving_key, ciphertext, precomputed_detached.mac, plaintext, precomputed_detached.nonce, std::nothrow);
    if (!opened || !std::ranges::equal(plaintext, message)) return false;

    std::array<std::byte, input.size() + potassium::algorithm_traits<A>::sealed_overhead> anonymous{};
    box::seal_anonymous_into(bob_public, message, anonymous);
    box::open_anonymous_into(bob_private, bob_public, anonymous, plaintext);
    return std::ranges::equal(plaintext, message);
}
}  // namespace

int main()
{
    potassium::init();
    if (!owning_boxes<box::box_default>() || !owning_boxes<box::curve25519xchacha20poly1305>() || !caller_owned_boxes<box::box_default>() || !caller_owned_boxes<box::curve25519xchacha20poly1305>())
    {
        std::println(std::cerr, "Box round trip failed");
        return 1;
    }
    std::println("Direct, precomputed, and anonymous Box round trips succeeded");
}
