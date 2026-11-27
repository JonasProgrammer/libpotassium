<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# libpotassium coverage of libsodium

This comparison follows the [libsodium manual](https://libsodium.gitbook.io/doc) and its [table of contents](https://github.com/jedisct1/libsodium-doc/blob/master/SUMMARY.md).
Coverage describes operations available through the [public potassium module](src/libpotassium.cpp).

| Coverage | Meaning |
| --- | --- |
| ✅ Supported | Callers can perform the listed operation. |
| 🟡 Partial | The wrapper exposes a subset of the operation or its options. |
| ❌ Unwrapped | No public wrapper exists. |
| 🚫 Omitted by design | The wrapper deliberately excludes this interface. |
| 📖 Guidance | The upstream topic describes application responsibilities. |

## Introduction, installation and usage

The introduction, installation, quickstart and FAQ, projects, commercial support and language bindings are informational chapters.
For the C++ build requirements and module imports, see the [project README](README.md).

| Upstream topic | Coverage | C++ interface or gap |
| --- | --- | --- |
| Usage and initialization | ✅ Supported | Call `potassium::init()` or check the Boolean result of `init(std::nothrow)`. |
| Version information | 🟡 Partial | `sodium_version_string` identifies the build-time headers, alongside the wrapper's own version strings. |
| Runtime configuration | ❌ Unwrapped | No public misuse-handler registration or CPU feature queries. |

## Helpers, padding, secure memory and generating random data

The [core design](docs/design/core.md) describes ownership and wiping, and the [hash design](docs/design/hash.md) specifies constant-time comparison for typed results.

| Upstream topic | Coverage | C++ interface or gap |
| --- | --- | --- |
| Constant-time comparison | 🟡 Partial | Digests and tags of matching type provide constant-time equality, with no general byte-span comparison API. |
| Other helpers | ❌ Unwrapped | Hex and Base64 codecs, little-endian comparison, increment, addition, subtraction, zero testing and stack clearing. |
| Padding | ❌ Unwrapped | No general-purpose block padding or unpadding (`sodium_pad`, `sodium_unpad`). |
| Memory wiping and locking | ✅ Supported | `wipe` erases a byte span and `mlock_guard` locks caller-owned storage and wipes it on release. |
| Guarded heap | ✅ Supported | `raw_allocator`, `allocator<T>` and the PMR `memory_resource` expose guarded allocation, also used by confidential owners. |
| Page protection changes | ❌ Unwrapped | No public transitions to read-only, read/write or inaccessible pages. |
| Random data | 🟡 Partial | `random_fill` fills a span, and typed key and nonce generation also draw secure bytes. |
| Other RNG operations | ❌ Unwrapped | Random integers, bounded uniform sampling, deterministic buffers and generator lifecycle controls. |

## Secret-key cryptography

See the [SecretBox design](docs/design/secretbox.md), [AEAD design](docs/design/aead.md), [secretstream design](docs/design/secretstream.md) and [authentication design](docs/design/hash.md#hmac-authentication) for the supported interfaces and wire formats.

| Upstream topic | Coverage | C++ interface or gap |
| --- | --- | --- |
| Authenticated encryption, combined mode | ✅ Supported | `secretbox::seal` and `open` use XSalsa20-Poly1305 by default and also support XChaCha20-Poly1305. |
| Detached SecretBox | ✅ Supported | `secretbox::seal_detached`, `open_detached` and their caller-buffer forms support both SecretBox algorithms with separate typed MACs. |
| Original NaCl SecretBox | 🚫 Omitted by design | The easy interface accepts ordinary plaintext and produces a MAC followed by encrypted bytes, eliminating the legacy caller-supplied zero prefixes. |
| Encrypted streams and file encryption | ✅ Supported | `secretstream::start_push` and `start_pull` manage guarded state, authenticated record tags, finalization and rekeying. |
| Encrypting related messages | 📖 Guidance | Applications frame ordered secretstream records, or manage ordering, replay and nonces when using independent boxes. |
| Authentication | ✅ Supported | `auth::authenticate`, `authenticate_into` and `verify` cover `crypto_auth`, including its default truncated HMAC-SHA-512 tag. |
| AEAD, ChaCha family | ✅ Supported | `aead` wraps the original and IETF ChaCha20-Poly1305 variants and defaults to IETF XChaCha20-Poly1305, each in combined and detached mode with associated data. |
| AEAD, AEGIS and AES | ✅ Supported | `aead` provides combined and detached AEGIS-128L, AEGIS-256 and AES256-GCM, including runtime AES256-GCM availability and reusable precomputation. |
| IP address encryption | ❌ Unwrapped | No address-encryption or decryption API. |

## Public-key cryptography

The [public-key authenticated encryption design](docs/design/pk-authenticated.md) specifies key roles and precomputation.
Both box modules follow the [core message contract](docs/design/core.md#message-and-operation-conventions), so callers can supply a nonce or receive a generated nonce alongside the ciphertext.
The allocating open operations return guarded plaintext, and the caller-buffer operations require disjoint input and output.

| Upstream topic | Coverage | C++ interface or gap |
| --- | --- | --- |
| Authenticated encryption | ✅ Supported | `box::seal` and `open` support Curve25519 with XSalsa20-Poly1305 or XChaCha20-Poly1305, directly or with a key from `box::precompute`. |
| Key pairs | 🟡 Partial | Random key-pair generation is exposed, including generation into caller storage, while deterministic generation from a seed is unwrapped. |
| Detached Box | ❌ Unwrapped | Only the combined MAC and ciphertext format is exposed. |
| Original NaCl Box | 🚫 Omitted by design | Direct and precomputed operations use the easy format, eliminating the zero-padding contract of the legacy Box calls. |
| Signatures | ❌ Unwrapped | No Ed25519 key pairs, signed messages, detached signatures or multipart Ed25519ph. |
| Sealed boxes | ❌ Unwrapped | Upstream `crypto_box_seal` uses an anonymous sender, while `box::seal` requires a sender private key or a precomputed shared key. |
| Key encapsulation | ❌ Unwrapped | No X-Wing key generation, encapsulation or decapsulation. |

## Hashing

The [hash design](docs/design/hash.md) describes one-shot calls, streaming state, digest sizes and typed keys.

| Upstream topic | Coverage | C++ interface or gap |
| --- | --- | --- |
| Generic hashing | ✅ Supported | Keyed and unkeyed BLAKE2b support one-shot and multipart input with 16 to 64 output bytes (default 32). |
| BLAKE2b parameters | 🟡 Partial | Digest and key lengths are type parameters, with no salt or personalization interface. |
| Short-input hashing | ❌ Unwrapped | No SipHash interface. |
| Extendable output functions | ❌ Unwrapped | No SHAKE or TurboSHAKE, including incremental output. |

HMAC and keyed BLAKE2b deliberately share the keyed streaming interface `hash::keyed_hasher<A>`.
The algorithm tag selects the construction and types the resulting authentication tag.
For one-shot calls, keyed BLAKE2b uses `hash::hash` and HMAC uses `auth::authenticate`, with `auth::verify` for constant-time wire-tag verification.
HMAC one-shot keys are 32 bytes, while a stream accepts an explicit key span of any length.
See [HMAC authentication](docs/design/hash.md#hmac-authentication).

## Password hashing, key derivation and key exchange

| Upstream chapter | Coverage | C++ interface or gap |
| --- | --- | --- |
| Password hashing | ❌ Unwrapped | No Argon2 password-based key derivation, encoded password hashes, verification or rehash checks. |
| Key derivation | ❌ Unwrapped | No `crypto_kdf` context and subkey-ID API. |
| HKDF | ❌ Unwrapped | No extract or expand API. |
| Key exchange | ❌ Unwrapped | No `crypto_kx` client/server directional session keys. |

## Advanced

The [hash design](docs/design/hash.md#choosing-the-construction) lists the supported SHA and HMAC tags, output lengths and state types.

| Upstream topic | Coverage | C++ interface or gap |
| --- | --- | --- |
| SHA-2 | ✅ Supported | SHA-256 and SHA-512, one-shot and streaming. |
| SHA-3 | ✅ Supported | SHA3-256 and SHA3-512, one-shot and streaming. |
| ML-KEM768 | ❌ Unwrapped | No standalone post-quantum KEM. |
| HMAC-SHA-2 | ✅ Supported | HMAC-SHA-256, HMAC-SHA-512 and HMAC-SHA-512 truncated to 256 bits, one-shot and streaming. |
| Scrypt | ❌ Unwrapped | No high-level password interface or low-level scrypt derivation. |
| Point/scalar multiplication | ❌ Unwrapped | Box uses Curve25519 internally, with no standalone X25519 scalar multiplication API. |
| One-time authentication | ❌ Unwrapped | No standalone Poly1305 computation or verification. |
| Stream ciphers | ❌ Unwrapped | No raw keystream or XOR operations for ChaCha20, XChaCha20, Salsa20 or XSalsa20. |
| Ed25519 to Curve25519 | ❌ Unwrapped | No public or secret key conversion. |
| Finite field arithmetic and Ristretto | ❌ Unwrapped | No public Ed25519 or Ristretto255 point and scalar operations. |
| Keccak-f[1600] | ❌ Unwrapped | No public permutation or low-level state operations. |
| Custom RNG | ❌ Unwrapped | No registration of a process-wide randombytes implementation. |

## Internals and roadmap

These upstream chapters describe implementation choices and future work.
The tables record the current public interface and make no commitment about future wrappers.
