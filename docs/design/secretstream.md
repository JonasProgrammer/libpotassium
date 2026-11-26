<!-- SPDX-FileCopyrightText: 2026 libpotassium team -->
<!-- SPDX-License-Identifier: BSL-1.0 -->

# Secretstream

Import `potassium.secretstream` to encrypt and authenticate an ordered sequence of records.
Use a `potassium::secret_key<potassium::secretstream::key_tag>` or another owner of the same 32-byte key purpose.
`start_push(key)` creates a sender and generates its public 24-byte `stream_header`.
Send or store `sender.header()` before the first record.
The receiver imports exactly `header_size` bytes into a header's `storage` or writable `bytes()` span and calls `start_pull(key, header)`.
Successful initialization prepares the receiver to authenticate records under that key and header.

## Records and rekeying

`sender.push(message, ad, tag)` returns a native secretstream record.
`receiver.pull(record, ad)` returns guarded plaintext and the authenticated record tag.
`push_into` and `pull_into` take an exact-size destination immediately after the associated data.
Each record adds `record_overhead` bytes (17) to its plaintext length, including the encrypted record tag and MAC.
The message length must be at most `messagebytes_max`.
The output buffer must be disjoint from all inputs.
Send one record per call and use an empty associated-data span when there is no associated data.
The receiver needs the same associated-data bytes the sender used for that record.

| `record_tag` | Meaning |
| --- | --- |
| `message` | Ordinary record and default for sealing |
| `push` | End of an application-defined group of records |
| `rekey` | Advance both peers to fresh stream state after processing the record |
| `final` | Last record in the stream |

Libsodium rekeys automatically before its internal counter wraps and after a `rekey` record.
An application can also call `rekey()` at a shared boundary between records.
Both peers must perform such explicit rekeying at the same position.
The header and the opaque ciphertext records retain [libsodium's native wire format](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream#usage).

## State, errors and end of input

By default, a sender or receiver owns one guarded allocation.
Moves transfer the storage handle without copying confidential state and close the source.
Successful final processing wipes the state immediately.
The closed stream retains the wiped storage until it is destroyed, replaced or transferred for reuse.
Destruction or replacement of an active stream wipes its state as well.
Allocation happens before the backend processes a record, so an allocation failure leaves the stream ready to retry.

Authentication failure, a malformed record length or an unsupported authenticated tag closes and wipes the receiver.
A caller-buffer pull may clear the output in these cases.
Operations on closed or moved-from streams report `errc::crypto_failed` through a final `std::nothrow` overload or throw `crypto_error`.

The application provides transport framing and reads records in the original order.
At EOF, require `finished()` to confirm that a final record authenticated successfully.
An empty stream still contains one record with a `final` tag and empty plaintext.
Reject trailing input after the authenticated final record, including bytes insufficient to form another record.

```cpp
import potassium.secretstream;
import std;

struct framed_record
{
    std::span<std::byte const> ciphertext;
    std::span<std::byte const> associated_data;
};

void read_stream(potassium::secretstream::stream_key_ref key,
                 potassium::secretstream::stream_header const& header,
                 std::span<framed_record const> records, auto consume)
{
    auto receiver = potassium::secretstream::start_pull(key, header);
    for (auto const& record : records)
    {
        if (receiver.finished()) throw potassium::crypto_error{};
        auto [plaintext, tag] = receiver.pull(record.ciphertext, record.associated_data);
        consume(plaintext.bytes(), tag);
    }
    if (!receiver.finished()) throw potassium::crypto_error{};
}
```

Here the transport produces `records` through EOF and reports partial frames as errors.

## Preallocated state and reuse

Pass a `state_storage` handle to `start_push` or `start_pull` to use existing storage.
A default-constructed handle allocates guarded state in advance.
Construct a handle from `inplace_state::get()` or a `state_type&` supplied by a custom owner to borrow state without allocating.
Borrowed storage must outlive the stream and any handles obtained from it, and each state may back only one stream or handle at a time.
`close_for_reuse()` works on a mutable rvalue, wipes any active state and transfers the wiped storage.
It also works after a final record or an error has closed the stream.
A new sender still generates a fresh header, and a new receiver must use that header.

```cpp
import potassium.secretstream;
import std;

namespace ss = potassium::secretstream;

void send_two_streams(ss::stream_key_ref key, auto send)
{
    ss::inplace_state storage;
    auto sender = ss::start_push(key, ss::state_storage{storage.get()});
    send(sender.header(), sender.push({}, {}, ss::record_tag::final));

    auto reuse = std::move(sender).close_for_reuse();
    auto next = ss::start_push(key, std::move(reuse));
    send(next.header(), next.push({}, {}, ss::record_tag::final));
}
```
