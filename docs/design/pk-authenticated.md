<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# Public-key authenticated encryption

The proposed `potassium.box` module provides sender-authenticated encryption between a local key holder and a peer.
Both direct and precomputed operations follow the [core key, nonce, buffer and error contracts](core.md).

Import `potassium.box` to access the construction, its core key types, and `potassium::init()`.

## Algorithms and key pairs

| Tag in `potassium::box` | libsodium function prefix |
| --- | --- |
| `curve25519xsalsa20poly1305` (`box_default`) | `crypto_box_` |
| `curve25519xchacha20poly1305` | `crypto_box_curve25519xchacha20poly1305_` |

For both algorithms, `public_key_size`, `secret_key_size`, `precomputed_key_size` and `seed_size` are 32 bytes, `nonce_size` is 24 bytes and `mac_size` is 16 bytes.
Each specialization publishes the backend's platform-specific `messagebytes_max`.
Backend assertions verify these dimensions and the default `crypto_box_PRIMITIVE` value of `"curve25519xsalsa20poly1305"`.
The XChaCha variant requires its named backend symbols.

For algorithm `A`, both `keypair<A>{}` and `generate_keypair<A>()` produce a matching public key and guarded private key in a move-only owner.
Default construction selects `key_traits<keypair<A>>::generator`.
A custom generator passed to the explicit constructor receives the public owner by mutable reference and the private destination as a fixed-extent writable byte span.
The constructor forwards the generator in its original value category and calls it once.
The generator must populate both halves with a matching pair on success and may throw on failure.
Use `keypair<A>{potassium::for_overwrite}` when importing or deriving both halves, or `keypair<A>{potassium::zero}` for explicitly all-zero storage.
The existing `generate_keypair<A>(std::nothrow)` factory reports allocation and backend failures through its result.
Pass a mutable private-key owner directly to `generate_keypair_into` and a precomputed-key owner to `precompute_into`.
Key generation writes directly into the final destinations, including caller-owned storage in the corresponding generation-into operation.
Deterministic key generation is a possible extension and would treat its seed as confidential.

## Direct and precomputed operations

The first argument is the local private key and the second is the peer public key.
Their roles reverse when the recipient opens the message.

```cpp
auto sealed = box::seal(alice.secret_key, bob.public_key, plaintext);
auto opened = box::open(bob.secret_key, alice.public_key, sealed.ciphertext, sealed.nonce);
```

Direct operations use the backend's `easy` and `open_easy` functions.
The name `box::seal` denotes sender-authenticated encryption here, whereas libsodium reserves `crypto_box_seal` for anonymous sealed boxes.

For repeated messages, `box::precompute(local.secret_key, peer.public_key)` uses `beforenm` to derive a confidential owner tagged with `precomputed_key_tag<A>`.
Precomputed key owners require derivation or explicit initialization.
The shared-key overloads take this one key in place of the direct key arguments and call `easy_afternm` or `open_easy_afternm`.
Private, precomputed and SecretBox keys cannot implicitly convert between roles.
With matching keys, plaintext and nonce, direct and precomputed encryption produce identical ciphertext.
Interoperability tests exercise both directions between these modes and with libsodium for both algorithms.
Rejection of an externally supplied peer key, including a small-order input rejected during precomputation, is a recoverable `crypto_failed`.

## Protocol responsibilities

The application independently establishes whose public key it uses.
Either participant can produce a valid ciphertext, so successful authentication supplies no third-party proof of authorship.
Static key pairs provide no forward secrecy after private-key compromise.

The same pair derives the same shared key in both directions.
Independent counters starting at zero would therefore reuse a nonce on the first exchange.
Use the random-nonce overload or coordinate explicit nonces across both directions, for example by assigning disjoint counter ranges.

[libsodium authenticated public-key encryption documentation](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption)
