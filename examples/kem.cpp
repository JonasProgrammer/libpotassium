// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.kem;
import std;

namespace kem = potassium::kem;

namespace
{
bool guarded_encapsulation()
{
    auto recipient = kem::generate_keypair();
    // The sender needs only the recipient's public key.
    auto sent = kem::encapsulate(recipient.public_key);
    auto received = kem::decapsulate(recipient.secret_key, sent.ciphertext.bytes());
    // Check the two ends of this local example without displaying the secret.
    return std::ranges::equal(sent.shared_secret.ref().bytes(), received.ref().bytes());
}

bool caller_owned_encapsulation()
{
    potassium::key_buffer_storage<kem::seed_tag> seed;
    potassium::public_key<kem::xwing> public_key;
    potassium::key_buffer_storage<kem::decapsulation_key_tag> private_key{potassium::for_overwrite};
    kem::generate_keypair_into(public_key, private_key, seed);

    kem::ciphertext_buffer ciphertext;
    potassium::key_buffer_storage<kem::shared_secret_tag> sent{potassium::for_overwrite};
    potassium::key_buffer_storage<kem::shared_secret_tag> received{potassium::for_overwrite};

    // Each encapsulation creates a fresh secret and overwrites the same buffers.
    for (int exchange = 0; exchange != 2; ++exchange)
    {
        kem::encapsulate_into(public_key, ciphertext, sent);
        auto result = kem::decapsulate_into(private_key, ciphertext.bytes(), received, std::nothrow);
        if (!result || !std::ranges::equal(sent.ref().bytes(), received.ref().bytes())) return false;
    }

    // Wrong wire length is an explicit error. Some malformed full-length
    // ciphertexts instead produce a fallback secret under implicit rejection.
    auto truncated = ciphertext.bytes().first(ciphertext.bytes().size() - 1);
    auto rejected = kem::decapsulate_into(private_key, truncated, received, std::nothrow);
    return rejected == std::unexpected(potassium::errc::crypto_failed);
}
}  // namespace

int main()
{
    potassium::init();
    if (!guarded_encapsulation() || !caller_owned_encapsulation())
    {
        std::println(std::cerr, "X-Wing encapsulation round trip or length check failed");
        return 1;
    }
    std::println("X-Wing encapsulation and decapsulation derived matching secrets");
}
