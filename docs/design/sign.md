<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# Ed25519 signatures

Import `potassium.sign` to use `potassium::sign`, the core public-key and confidential-key owners, and `potassium::init()`.

## Key operations

`generate_keypair()` produces a 32-byte public key and a 64-byte guarded signing key, and `generate_keypair(seed)` derives both from a confidential 32-byte `seed_tag` key.
Both operations have `generate_keypair_into` forms that accept caller-owned public and signing-key storage, including a stack `key_buffer_storage<signing_key_tag>`.
`public_key_from_secret_key` extracts the encoded public key, while `seed_from_secret_key` and `seed_from_secret_key_into` extract the confidential seed.
Treat the extracted seed as a signing secret because it can recreate the signing key.

## One-shot messages

`sign` and `sign_into` produce a signed message consisting of a 64-byte Ed25519 signature followed by the message bytes.
`open` verifies that format and returns the message in guarded storage, and `open_into` writes the verified message to a disjoint destination.
Signed messages expose their entire contents to anyone who receives them.

`sign_detached` returns a fixed-size `signature` with no heap allocation.
`verify_detached` checks that signature against the separately supplied message.
Check the wire length before importing a detached signature into its writable byte span.
Invalid signed messages and failed verification report `errc::crypto_failed`.

## Multipart messages

`start_prehash()` creates an Ed25519ph operation with guarded state.
Call `update` for each chunk, then `finish_sign` with the signing key or `finish_verify` with the public key and a `prehash_signature`.
Both final operations wipe the state, including on a verification failure.
A one-shot Ed25519 signature and an Ed25519ph signature use distinct types and different verification operations.

Pass `state_storage{state.get()}` for an `inplace_state`, or lend a `state_type` from custom storage.
The borrowed object must outlive the operation and any state handle that holds it.
The operation is move-only and wipes active state on destruction.
Use `std::move(operation).close_for_reuse()` before or after finalization to obtain wiped storage for a new operation without reallocating state.

[libsodium public-key signature documentation](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
