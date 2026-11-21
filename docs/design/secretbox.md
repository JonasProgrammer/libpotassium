<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# SecretBox

`potassium.secretbox` authenticates and encrypts independent messages using one symmetric key shared by sender and recipient.
It uses the combined message format and operation contracts defined in [core](core.md).
The interface covers whole messages without associated data, detached tags or stream state.

## Algorithms and keys

| Tag in `potassium::secretbox` | libsodium seal / open functions |
| --- | --- |
| `xsalsa20poly1305` (`secretbox_default`) | `crypto_secretbox_easy` / `crypto_secretbox_open_easy` |
| `xchacha20poly1305` | `crypto_secretbox_xchacha20poly1305_easy` / `crypto_secretbox_xchacha20poly1305_open_easy` |

Each algorithm tag doubles as its confidential key tag, preserving the spelling `key_ref<A>` for existing callers.
Its `key_traits<A>::size` equals `algorithm_traits<A>::key_size`.
Both constructions use a 32-byte key, a 24-byte nonce and a 16-byte MAC.
Each publishes its backend's platform-specific `messagebytes_max`.

## Operations and interoperability

All message operations take the shared key as their first argument.

```cpp
auto sealed = secretbox::seal(key, plaintext);
auto opened = secretbox::open(key, sealed.ciphertext, sealed.nonce);
```

The generic easy functions supply combined XSalsa20-Poly1305 encryption, while the explicitly named XSalsa interface uses legacy padding.
The XChaCha variant requires the XChaCha SecretBox symbols and is distinct from the IETF AEAD construction.
Backend assertions check `crypto_secretbox_PRIMITIVE` against `"xsalsa20poly1305"` and compare both sets of public traits with their libsodium constants.
For each algorithm, interoperability covers opening libsodium ciphertext in SecretBox and opening SecretBox ciphertext in libsodium.

[libsodium SecretBox documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox)
