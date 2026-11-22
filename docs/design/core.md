<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# Core types and authenticated-encryption contracts

`potassium.core` defines the types used by [SecretBox](secretbox.md) and [public-key authenticated encryption](pk-authenticated.md).
Each construction supplies its own algorithm tags, trait specializations and operations.

## Key and nonce types

| Material | Owner | Read-only view | Extent in bytes |
| --- | --- | --- | --- |
| Confidential key | `secret_key<KeyTag>` or caller-selected storage | `key_ref<KeyTag>` | `key_traits<KeyTag>::size` |
| Public key | `public_key<A>` | `public_key_ref<A>` | `algorithm_traits<A>::public_key_size` |
| Nonce | `nonce_buffer<A>` | `nonce_ref<A>` | `algorithm_traits<A>::nonce_size` |

A confidential key tag identifies its cryptographic purpose and needs only a `key_traits` specialization.
An algorithm tag identifies a construction, and its `algorithm_traits` specialization supplies the dimensions and message limit applicable to that construction.
Distinct key purposes and algorithms remain distinct types even when their byte lengths match.

Each view takes an explicit `std::span<const std::byte, N>` and borrows the underlying bytes.
A matching owner converts implicitly to its view on lvalues only.
Both mutable and const rvalues must reject borrowing, including through named view accessors.
The caller keeps the backing storage alive for every use of the view and controls the protection and wiping of externally owned secrets.

Public keys and nonces are ordinary copyable, movable values with fixed-size inline byte storage.
A public key carries the full algorithm identity, so reusing the same encoding across protocols requires explicit adaptation.
Constructing a public-key view establishes its extent and declared type only.
Peer identity and acceptance of the encoded key are separate questions.

## Confidential storage

Operations borrow confidential keys independently of the storage policy.
The default heap owner stores a key-sized byte array in `std::indirect` using the guarded allocator.
Moving the owner transfers the allocation without copying key bytes.
Move assignment wipes and releases the destination's previous allocation.
Borrowing requires a live allocation, so a moved-from owner must receive a new allocation before it can be borrowed from.
A stack-local `key_buffer_storage<KeyTag>` owns a fixed-size buffer, disallows copying and moving, and wipes its contents on destruction.
Generate or derive keys directly in their final writable storage and make any duplication explicit.
Default construction of either confidential owner requires a default-constructible `key_traits<KeyTag>::generator` satisfying `KeyGenerator<G, KeyTag>`.
Size-only key traits support explicit generator, `zero`, and `for_overwrite` construction.

Guarded allocation attempts page locking on a best-effort basis.
Stack storage does not acquire a lock automatically because disjoint objects may occupy the same page.
Callers requiring strict locking can guard a contiguous aggregate with `mlock_guard` when they control all affected pages.

Decrypted plaintext uses a move-only `secure_buffer` backed by guarded allocation.
Destruction, shrinking and reallocation must wipe secret bytes before their storage becomes unused or is released.

## Message and operation conventions

Inputs use `std::span<const std::byte>` and caller-owned destinations use `std::span<std::byte>`.
Combined ciphertext is exactly `MAC || encrypted plaintext`, with length equal to the plaintext length plus `mac_size`.
Applications transport the nonce separately and define framing, versioning, replay detection and ordering.

| Operation after the key arguments | Result |
| --- | --- |
| `seal(plaintext)` | A construction-specific aggregate with `std::vector<std::byte> ciphertext` followed by `nonce_buffer<A> nonce` |
| `seal(plaintext, nonce)` | Ciphertext vector |
| `open(ciphertext, nonce)` or `open(sealed_result)` | Authenticated plaintext in a `secure_buffer` |
| `seal_into(plaintext, out)` | Generated nonce |
| `seal_into(plaintext, out, nonce)` | Writes combined ciphertext |
| `open_into(ciphertext, out, nonce)` | Writes authenticated plaintext |

Sealing without an explicit nonce uses the secure RNG, also available through `generate_nonce<A>()`.
To import a nonce, explicitly construct its owner from a fixed-extent byte span.
An explicit nonce must be unique for each encryption under the same key across participants, processes and restarts.

Encryption requires plaintext length at most `algorithm_traits<A>::messagebytes_max`.
For the allocation-free message operations, output must be disjoint from every input and sized exactly for the result.
Opening rejects ciphertext shorter than `mac_size` before subtracting the overhead to determine the output size.
Failed authentication must never expose unauthenticated plaintext.

## Failures and implementation boundaries

The default overloads throw `crypto_error` for cryptographic failure and `std::bad_alloc` for allocation failure.
A final `std::nothrow_t` selects a nonthrowing overload returning `std::expected<T, errc>`, including `T = void`.
Malformed ciphertext and backend rejection map to `errc::crypto_failed` without guessing whether the key, nonce or message was wrong.
Allocation failures in ordinary and guarded storage map to `errc::allocation_failed`.

Core owns the shared RNG, wiping, guarded memory, byte-pointer adapters and error translation.
The design keeps libsodium headers, dispatch and backend assertions in private implementation units, with exported interfaces limited to declarations, layouts, constants and short template definitions.
Concrete algorithm overloads allow an owner to convert to a view during overload resolution, since template deduction through that conversion would fail.

Shared contract tests cover explicit raw-span construction, lvalue-only borrowing, tag isolation, owner copy and move semantics, and wiping.
Each construction exercises both nonce modes, exact output sizes, empty and binary messages, authentication failures and short ciphertext in both error interfaces, including allocation failure where injection is practical.
