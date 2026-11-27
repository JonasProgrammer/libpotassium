// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.secretbox;
import std;

namespace box = potassium::secretbox;

namespace
{
template <class A>
bool encrypt_message()
{
    constexpr std::array input{'d', 'a', 't', 'a'};
    auto message = std::as_bytes(std::span{input});

    // Owning results carry the nonce and decrypt into guarded memory.
    potassium::secret_key<A> key;
    auto sealed = box::seal(key, message);
    auto plaintext = box::open(key, sealed);
    if (!std::ranges::equal(plaintext.bytes(), message)) return false;

    auto detached = box::seal_detached(key, message);
    auto detached_plaintext = box::open_detached(key, detached.ciphertext, detached.mac, detached.nonce);
    if (!std::ranges::equal(detached_plaintext.bytes(), message)) return false;

    // Inline key and caller buffers give an allocation-free path.
    potassium::key_buffer_storage<A> inline_key;
    std::array<std::byte, input.size() + potassium::algorithm_traits<A>::mac_size> combined{};
    std::array<std::byte, input.size()> output{};
    auto nonce = box::seal_into(inline_key, message, combined);
    box::open_into(inline_key, combined, output, nonce);
    if (!std::ranges::equal(output, message)) return false;

    // Supply a fresh nonce explicitly and reuse the plaintext buffer.
    std::array<std::byte, input.size()> ciphertext{};
    auto detached_nonce = potassium::generate_nonce<A>();
    auto mac = box::seal_detached_into(inline_key, message, ciphertext, detached_nonce);
    auto opened = box::open_detached_into(inline_key, ciphertext, mac, output, detached_nonce, std::nothrow);
    if (!opened || !std::ranges::equal(output, message)) return false;

    ciphertext.front() ^= std::byte{1};
    auto rejected = box::open_detached_into(inline_key, ciphertext, mac, output, detached_nonce, std::nothrow);
    return rejected == std::unexpected(potassium::errc::crypto_failed);
}
}  // namespace

int main()
{
    potassium::init();
    if (!encrypt_message<box::secretbox_default>() || !encrypt_message<box::xchacha20poly1305>())
    {
        std::println(std::cerr, "SecretBox round trip or authentication check failed");
        return 1;
    }
    std::println("Combined and detached SecretBox ciphertexts verified");
}
