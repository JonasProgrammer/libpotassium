// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.sign;
import std;

namespace sign = potassium::sign;

namespace
{
constexpr std::array input{'d', 'a', 't', 'a'};

bool signed_messages()
{
    auto message = std::as_bytes(std::span{input});
    auto keys = sign::generate_keypair();
    auto signed_message = sign::sign(keys.secret_key, message);
    auto opened = sign::open(keys.public_key, signed_message);
    if (!std::ranges::equal(opened.bytes(), message)) return false;

    auto signature = sign::sign_detached(keys.secret_key, message);
    sign::verify_detached(keys.public_key, message, signature);
    auto rejected = sign::verify_detached(keys.public_key, message.first<2>(), signature, std::nothrow);
    return rejected == std::unexpected(potassium::errc::crypto_failed);
}

bool caller_owned_signing()
{
    auto message = std::as_bytes(std::span{input});
    potassium::key_buffer_storage<sign::seed_tag> seed;
    potassium::public_key<sign::ed25519> public_key;
    potassium::key_buffer_storage<sign::signing_key_tag> signing_key{potassium::for_overwrite};
    sign::generate_keypair_into(public_key, signing_key, seed);

    // Recover the encoded public key and seed from a signing key.
    auto extracted_public = sign::public_key_from_secret_key(signing_key);
    potassium::key_buffer_storage<sign::seed_tag> extracted_seed{potassium::for_overwrite};
    sign::seed_from_secret_key_into(signing_key, extracted_seed);
    if (!std::ranges::equal(extracted_public.ref().bytes(), public_key.ref().bytes()) || !std::ranges::equal(extracted_seed.ref().bytes(), seed.ref().bytes())) return false;

    constexpr auto signature_size = potassium::algorithm_traits<sign::ed25519>::signature_size;
    std::array<std::byte, input.size() + signature_size> signed_message{};
    std::array<std::byte, input.size()> opened{};
    sign::sign_into(signing_key, message, signed_message);
    sign::open_into(public_key, signed_message, opened);
    if (!std::ranges::equal(opened, message)) return false;

    // Ed25519ph signs and verifies chunks through a separate signature type.
    // Borrow inline state and reuse the same wiped bytes for verification.
    sign::inplace_state state;
    auto signer = sign::start_prehash(sign::state_storage{state.get()});
    signer.update(message.first<2>());
    signer.update(message.last<2>());
    auto signature = signer.finish_sign(signing_key);
    auto verifier = sign::start_prehash(std::move(signer).close_for_reuse());
    verifier.update(message);
    return verifier.finish_verify(public_key, signature, std::nothrow).has_value();
}

void guarded_prehash()
{
    auto message = std::as_bytes(std::span{input});
    auto keys = sign::generate_keypair();
    auto signer = sign::start_prehash();
    signer.update(message);
    auto signature = signer.finish_sign(keys.secret_key);

    // Reuse the original guarded allocation instead of allocating again.
    auto verifier = sign::start_prehash(std::move(signer).close_for_reuse());
    verifier.update(message.first<2>());
    verifier.update(message.last<2>());
    verifier.finish_verify(keys.public_key, signature);
}
}  // namespace

int main()
{
    potassium::init();
    if (!signed_messages() || !caller_owned_signing())
    {
        std::println(std::cerr, "Ed25519 signing or verification check failed");
        return 1;
    }
    guarded_prehash();
    std::println("Ed25519 and Ed25519ph signatures verified");
}
