<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# ChaCha authenticated encryption with associated data

Import `potassium.aead` for independent messages that need both encryption and authentication of protocol data.
The module follows the [core key, error and buffer contracts](core.md).

| Tag in `potassium::aead` | libsodium function family | Nonce bytes | Nonce selection |
| --- | --- | --- | --- |
| `chacha20poly1305` | `crypto_aead_chacha20poly1305_*` | 8 | Caller supplied |
| `chacha20poly1305_ietf` | `crypto_aead_chacha20poly1305_ietf_*` | 12 | Caller supplied |
| `xchacha20poly1305_ietf` (`default_algorithm`) | `crypto_aead_xchacha20poly1305_ietf_*` | 24 | Caller supplied or generated |

All three constructions use 32-byte keys and 16-byte MACs.
Each tag identifies a distinct `key_ref`, `nonce_ref` and `mac_buffer` specialization.
XChaCha20-Poly1305-IETF has its own key, nonce and MAC types and wire format distinct from [XChaCha20-Poly1305 SecretBox](secretbox.md).
The `algorithm_traits<A>::messagebytes_max` limit matches the corresponding libsodium backend and platform.
The IETF ChaCha20 variant has a 32-bit block counter and a per-message limit of at most `64 * (2^32 - 1)` bytes.

Pass an explicit unique nonce for every encryption with either short-nonce construction.
Coordinate nonce uniqueness under each key across all senders and across restarts.
These constructions expose neither generated-nonce sealing overloads nor `generate_nonce<A>()`.
The XChaCha20 variant supports both explicit and generated nonces.
See the [libsodium AEAD construction limits](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#limitations).

## Operations and wire format

The associated-data span goes immediately after the plaintext or ciphertext, before any MAC, output buffer or nonce argument.
Pass an empty span when the message has no associated data.
The receiver supplies the exact same bytes used by the sender.
The ciphertext carries no copy of the associated data.

```cpp
import potassium.aead;
import std;

void example(std::span<std::byte const> message, std::span<std::byte const> associated_data)
{
    using namespace potassium;
    secret_key<aead::default_algorithm> key;
    auto sealed = aead::seal(key, message, associated_data);
    auto plaintext = aead::open(key, sealed, associated_data);
}
```

Combined ciphertext consists of encrypted message bytes followed by the MAC, in [libsodium's native AEAD format](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#supported-constructions).
Detached mode stores the same encrypted bytes and MAC separately.
Empty messages produce a 16-byte combined ciphertext or a zero-length detached ciphertext with a 16-byte MAC.
The nonce travels separately in either format.

`seal_into`, `open_into`, `seal_detached_into` and `open_detached_into` take exact-size caller buffers disjoint from all inputs.
The allocating open overloads return authenticated plaintext in guarded storage.
Caller-buffer opens may clear the destination on authentication failure.
Applications must provide their own framing, ordering and replay handling when using independent messages.
