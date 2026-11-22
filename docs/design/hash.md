<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# Hashing with potassium.hash

Import `potassium.hash` for hashing, or `potassium` for the complete API, including initialization and confidential key owners.
Call `potassium::init()` once before using either interface.

```cpp
import potassium;
import std;

namespace h = potassium::hash;

void example(std::span<std::byte const> message)
{
    auto checksum = h::hash<h::sha256>(message);

    potassium::secret_key<h::blake2b_key_tag<>> key;
    auto tag = h::hash<h::default_algorithm>(key, message);

    h::hasher<h::sha256> stream;
    stream.update(message);
    auto same_checksum = std::move(stream).finalize();
    stream.reset();

    h::keyed_hasher<h::default_algorithm> keyed(key);
    keyed.update(message);
    auto same_tag = std::move(keyed).finalize();
    keyed.reset(key);
}
```

## Choosing the construction

| Algorithm tag | Digest bytes | Key bytes |
| --- | --- | --- |
| `blake2b<N>` | 16 through 64, default 32 | Unkeyed or 16 through 64, default 32 |
| `sha256`, `sha3_256` | 32 | Unkeyed |
| `sha512`, `sha3_512` | 64 | Unkeyed |

The stable `default_algorithm` alias selects `blake2b<32>`.
BLAKE2b incorporates the output length during initialization, so truncating a 64-byte digest produces a different construction from requesting 32 bytes.
The type `digest_buffer<A>` records that choice and distinguishes algorithms with equal output lengths.
Digests, including keyed authentication tags, are copyable values in ordinary memory.
Compare two digests of the same type with `==` or `!=`, which use libsodium's constant-time comparison.
Use the fixed-extent span from `digest.bytes()` while the digest lives, or copy received bytes into its fixed-size `storage` array.

The `keyed_hash_algorithm` concept limits keyed operations to native keyed BLAKE2b.
Its key length is an independent initialization parameter, so a single `blake2b_key_tag<K>` applies across digest lengths.
The purpose tag prevents accidental substitution of a SecretBox key or Box private key of the same size.
A `secret_key` or `key_buffer_storage` generates the key directly in its final storage.
Pass a live lvalue owner, or explicitly construct a matching `potassium::key_ref` from a fixed-extent span and keep the referenced bytes alive through the call.

Choose SHA-2 or SHA-3 when a format or protocol specifies it.
An unkeyed digest alone cannot authenticate the sender.
In particular, prefixing a message with a secret before SHA-256 or SHA-512 permits length-extension attacks.
Use a dedicated password-hashing construction for passwords because all five hash families are designed to run quickly.

## One-shot and streaming state

`hash<A>(message)` and unkeyed stream finalization return `digest_buffer<A>`.
Keyed calls and keyed stream finalization return `tag_buffer<A>`, a distinct fixed-size value with the same byte access and constant-time equality.
Use `hash_into<A>(message, output)` or `hash_into<A>(key, message, output)` with writable storage of exactly `hash_traits<A>::digest_size` bytes.
These calls go directly to the matching libsodium one-shot function, avoiding stream construction and guarded allocation.
The module pins BLAKE2b to the explicit `crypto_generichash_blake2b` family and requires libsodium 1.0.22 or newer for SHA-3.

An unkeyed `hasher<A>` stores the actual aligned libsodium state in place, avoiding a heap allocation.
It erases the state because even unkeyed hashes may buffer fragments of the input.
A `keyed_hasher<A>` requires a key at construction and defaults to the guarded allocator because the derived state can authenticate further input.
Its move-only storage wraps `std::indirect<State, potassium::allocator<State>>`, so the allocator manages the state allocation and moves transfer ownership without copying state bytes.
Guarded allocation attempts page locking and wipes memory on release.
Initialization consumes the key bytes synchronously, so the caller can release the key afterward.
Separate types give each mode its own storage default and make a missing key a compile-time error.

The optional second template argument controls ownership and protection independently of the algorithm.
For example, choose `hasher<A, guarded_hash_state<typename hash_traits<A>::state_type>>` to protect an unkeyed computation.
A custom policy owns a fully constructed, correctly aligned state, exposes it by mutable lvalue reference through a nonthrowing `get()`, and securely erases released storage.
It must prohibit copying and transfer ownership without duplicating state bytes if it supports moving.
When using a nonthrowing factory, a custom policy must report construction failure through `std::bad_alloc`.
Traits describe sizes and storage defaults, while compile-time selection calls typed backend functions implemented outside the module interface.
This preserves the actual state layout and keeps the libsodium calls out of the consumer's BMI without runtime dispatch.

## Finalization, reuse and errors

`update(chunk)` consumes the bytes during the call and accepts empty chunks.
On a named stream, use `std::move(stream).finalize()` to finish the active computation and immediately wipe its state.
Only mutable rvalues can finalize, including temporaries and streams whose in-place storage prohibits move construction.
The C++26 deleted lvalue overloads explain how to express consumption, and the deleted const overloads explain the mutability requirement.
With GCC 16.2, the diagnostic for an imported module shows the reason in the declaration excerpt and omits it from the primary error line.
Disabling source excerpts on that compiler hides the reason.
The cast alone transfers no ownership, and compilers need not warn about later uses of the named object.

After finalization the stream still owns its storage.
Use `reset()` or `reset(key)` to start again, including when abandoning partial input.
Reset wipes any active state and reuses the existing storage without allocating or retaining an old key.
Moving a guarded stream transfers the allocation, leaving the source available for destruction or move assignment.
Updating or finalizing an inactive stream, or resetting a moved-from stream, violates a precondition and terminates the program.

Guarded construction can throw `std::bad_alloc`.
Use `make_keyed_hasher<A>(key, std::nothrow)` or `make_hasher<A, Storage>(std::nothrow)` to receive `std::expected` with `potassium::errc::allocation_failed` on allocation failure.
One-shot hashing, updating, resetting and finalizing valid inputs have no recoverable backend error.
