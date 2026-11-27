// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.aead;
import std;

namespace aead = potassium::aead;

namespace
{
constexpr std::array input{'d', 'a', 't', 'a'};
constexpr std::array metadata{'v', '1'};

template <class A>
bool encrypt_message()
{
    auto message = std::as_bytes(std::span{input});
    auto ad = std::as_bytes(std::span{metadata});
    std::array<std::byte, input.size()> plaintext{};
    potassium::secret_key<A> key;

    if constexpr (potassium::RandomNonceAlgorithm<A>)
    {
        auto sealed = aead::seal(key, message, ad);
        auto opened = aead::open(key, sealed, ad);
        if (!std::ranges::equal(opened.bytes(), message)) return false;

        auto detached = aead::seal_detached(key, message, ad);
        auto detached_plaintext = aead::open_detached(key, detached.ciphertext, ad, detached.mac, detached.nonce);
        if (!std::ranges::equal(detached_plaintext.bytes(), message)) return false;

        // Caller buffers can also be paired with library-generated nonces.
        std::array<std::byte, input.size() + potassium::algorithm_traits<A>::mac_size> combined{};
        auto nonce = aead::seal_into(key, message, ad, combined);
        aead::open_into(key, combined, ad, plaintext, nonce);
        if (!std::ranges::equal(plaintext, message)) return false;
    }
    else
    {
        // Short-nonce algorithms require an explicit nonce. Use zero once with this fresh key.
        std::array<std::byte, potassium::algorithm_traits<A>::nonce_size> counter{};
        potassium::nonce_buffer<A> nonce{counter};
        auto sealed = aead::seal(key, message, ad, nonce);
        auto opened = aead::open(key, sealed, ad, nonce);
        if (!std::ranges::equal(opened.bytes(), message)) return false;
    }

    // A fresh inline key and caller buffers make this path allocation-free.
    potassium::key_buffer_storage<A> inline_key;
    std::array<std::byte, input.size()> ciphertext{};
    std::array<std::byte, potassium::algorithm_traits<A>::nonce_size> counter{};
    // This example encrypts once with this key, using counter value zero.
    // For more messages, advance the counter for every encryption with the key.
    potassium::nonce_buffer<A> nonce{counter};
    auto mac = aead::seal_detached_into(inline_key, message, ad, ciphertext, nonce);
    aead::open_detached_into(inline_key, ciphertext, ad, mac, plaintext, nonce);
    if (!std::ranges::equal(plaintext, message)) return false;

    // Associated data must match the bytes authenticated by the sender.
    auto rejected = aead::open_detached_into(inline_key, ciphertext, {}, mac, plaintext, nonce, std::nothrow);
    return rejected == std::unexpected(potassium::errc::crypto_failed);
}

bool aes256gcm_precomputation()
{
    if (!aead::aes256gcm_available())
    {
        std::println("Skipping AES256-GCM because the CPU does not support it");
        return true;
    }

    using algorithm = aead::aes256gcm;
    auto message = std::as_bytes(std::span{input});
    auto ad = std::as_bytes(std::span{metadata});
    std::array<std::byte, input.size() + potassium::algorithm_traits<algorithm>::mac_size> ciphertext{};
    std::array<std::byte, input.size()> plaintext{};
    std::array<std::byte, potassium::algorithm_traits<algorithm>::nonce_size> counter{};

    potassium::key_buffer_storage<algorithm> key;
    auto guarded_schedule = aead::precompute(key);
    // A single key schedule can serve multiple messages with distinct nonces.
    for (auto value : {std::byte{0}, std::byte{1}})
    {
        counter.back() = value;
        potassium::nonce_buffer<algorithm> nonce{counter};
        aead::seal_into(guarded_schedule, message, ad, ciphertext, nonce);
        aead::open_into(key, ciphertext, ad, plaintext, nonce);  // Direct and precomputed calls share a wire format.
        if (!std::ranges::equal(plaintext, message)) return false;
    }

    // Return the guarded allocation and expand a different key in place.
    auto storage = std::move(guarded_schedule).close_for_reuse();
    potassium::key_buffer_storage<algorithm> next_key;
    auto next_schedule = aead::precompute_into(next_key, std::move(storage));
    counter.back() = std::byte{2};
    potassium::nonce_buffer<algorithm> nonce{counter};
    aead::seal_into(next_schedule, message, ad, ciphertext, nonce);

    // Borrow inline storage to avoid allocating a schedule at all.
    aead::aes256gcm_inplace_state inline_state;
    auto receiver = aead::precompute_into(next_key, aead::aes256gcm_state_storage{inline_state.get()});
    aead::open_into(receiver, ciphertext, ad, plaintext, nonce);
    return std::ranges::equal(plaintext, message);
}
}  // namespace

int main()
{
    potassium::init();
    if (!encrypt_message<aead::default_algorithm>() || !encrypt_message<aead::chacha20poly1305>() || !encrypt_message<aead::chacha20poly1305_ietf>() || !encrypt_message<aead::aegis128l>() ||
        !encrypt_message<aead::aegis256>() || !aes256gcm_precomputation())
    {
        std::println(std::cerr, "AEAD round trip or authentication check failed");
        return 1;
    }
    std::println("AEAD ciphertext and associated data verified");
}
