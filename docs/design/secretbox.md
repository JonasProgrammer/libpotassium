<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# SecretBox

`potassium.secretbox` authenticates and encrypts independent messages using one symmetric key shared by sender and recipient.
It provides combined and detached operations under the [core contracts](core.md#message-and-operation-conventions).
The interface takes a whole message and authenticates its encrypted bytes.

Import `potassium.secretbox` to access the construction, its core key types, and `potassium::init()`.

## Algorithms and keys

| Tag in `potassium::secretbox` | libsodium combined seal / open | libsodium detached seal / open |
| --- | --- | --- |
| `xsalsa20poly1305` (`secretbox_default`) | `crypto_secretbox_easy` / `crypto_secretbox_open_easy` | `crypto_secretbox_detached` / `crypto_secretbox_open_detached` |
| `xchacha20poly1305` | `crypto_secretbox_xchacha20poly1305_easy` / `crypto_secretbox_xchacha20poly1305_open_easy` | `crypto_secretbox_xchacha20poly1305_detached` / `crypto_secretbox_xchacha20poly1305_open_detached` |

Each algorithm tag doubles as its confidential key tag, preserving the spelling `key_ref<A>` for existing callers.
Its `key_traits<A>::size` equals `algorithm_traits<A>::key_size`.
Both constructions use a 32-byte key, a 24-byte nonce and a 16-byte MAC.
Each publishes its backend's platform-specific `messagebytes_max`.

Both `secret_key<A>` and `key_buffer_storage<A>` default to `key_traits<A>::generator`, which fills the final storage with secure random bytes for both SecretBox algorithms.
An explicit generator receives a writable fixed-extent byte span, fills all bytes on success, and returns `void`.
If the generator throws, construction propagates the exception and the owner wipes the secret storage during cleanup.
Use `make_secret_key<A>(std::nothrow)` to generate a guarded key with allocation and cryptographic failures reported through the result.
Guarded allocation can also throw `std::bad_alloc` before the generator runs.
Use `potassium::for_overwrite` to construct a destination for key import and fill every byte before use.
Use `potassium::zero` when a known all-zero key is intentional.

## Operations and interoperability

All message operations take the shared key as their first argument.

```cpp
auto sealed = secretbox::seal(key, plaintext);
auto opened = secretbox::open(key, sealed.ciphertext, sealed.nonce);
```

Combined ciphertext is a 16-byte MAC followed by the encrypted bytes for both algorithms.
Use detached mode when the protocol stores the MAC in a separate field.

```cpp
auto [ciphertext, mac, nonce] = secretbox::seal_detached(key, plaintext);
auto opened = secretbox::open_detached(key, ciphertext, mac, nonce);
```

Both sealing families support a caller-supplied unique nonce or a generated nonce.
The detached ciphertext matches the plaintext length, and `seal_detached_into` writes it directly to a caller buffer of that length and returns the MAC.
`open_detached_into` writes to a separate caller buffer of the same length after authentication succeeds.
An empty message produces zero encrypted bytes and a 16-byte MAC.
The MAC is typed to the algorithm, and its public fixed-size storage supports wire import and export.

The generic libsodium easy and detached functions select XSalsa20-Poly1305.
The XChaCha variant has a separate wire format from IETF AEAD and uses the [XChaCha SecretBox symbols](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretbox_xchacha20poly1305.h).
Backend assertions check `crypto_secretbox_PRIMITIVE` against `"xsalsa20poly1305"` and compare both sets of public traits with their libsodium constants.
For each algorithm, interoperability covers opening libsodium ciphertext in SecretBox and opening SecretBox ciphertext in libsodium in both modes.

[libsodium SecretBox documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox)
