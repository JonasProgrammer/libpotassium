<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# X-Wing key encapsulation

Import `potassium.kem` to use `potassium::kem`, the core key storage types, and `potassium::init()`.
The libpotassium operations map to libsodium's `crypto_kem_*` family, which selects the X-Wing hybrid of ML-KEM768 and X25519.

`generate_keypair()` creates an encapsulation public key and a guarded decapsulation key.
`generate_keypair(seed)` derives the pair from a confidential `seed_tag` key.
`generate_keypair_into` accepts caller-owned public and private destinations for either form of generation.
The key-pair dimensions are 1216 public-key bytes, 32 private-key bytes and 32 seed bytes.

`encapsulate` takes the recipient's public key and returns a 1120-byte `ciphertext_buffer` and a guarded 32-byte `shared_secret`.
Send the ciphertext to the recipient, who passes its bytes and their private key to `decapsulate`.
Use the resulting shared secret as input to the key schedule of the surrounding protocol.
`encapsulate_into` and `decapsulate_into` support caller-owned secret storage, including `key_buffer_storage<shared_secret_tag>`.

```cpp
auto recipient = potassium::kem::generate_keypair();
auto sent = potassium::kem::encapsulate(recipient.public_key);
auto received = potassium::kem::decapsulate(recipient.secret_key, sent.ciphertext.bytes());
```

Wrong-length ciphertext and explicit backend rejection return `errc::crypto_failed`.
The decapsulation operation preserves libsodium's implicit rejection for invalid ML-KEM components by returning the resulting fallback shared secret.
X25519 can still explicitly reject a low-order ciphertext component.
The protocol uses authenticated data or a key-confirmation step to establish that the parties derived matching secrets.

[libsodium X-Wing implementation](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_kem/xwing/kem_xwing.c)
