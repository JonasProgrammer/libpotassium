// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.secretstream;
import std;

namespace stream = potassium::secretstream;

namespace
{
constexpr std::array input{'d', 'a', 't', 'a'};
constexpr std::array metadata{'v', '1'};

bool guarded_stream()
{
    potassium::secret_key<stream::key_tag> key;
    auto message = std::as_bytes(std::span{input});
    auto ad = std::as_bytes(std::span{metadata});

    auto sender = stream::start_push(key);
    // Send the public header before the records and preserve record boundaries.
    auto receiver = stream::start_pull(key, sender.header());
    auto first_record = sender.push(message, ad);
    auto first = receiver.pull(first_record, ad);
    if (first.tag != stream::record_tag::message || !std::ranges::equal(first.plaintext.bytes(), message) || receiver.finished()) return false;

    // End of input is valid only after authenticating a final record.
    auto final_record = sender.push({}, {}, stream::record_tag::final);
    auto final = receiver.pull(final_record, {});
    if (final.tag != stream::record_tag::final || !final.plaintext.bytes().empty() || !receiver.finished()) return false;

    // Keep both guarded allocations and initialize a new stream with a fresh header.
    auto send_storage = std::move(sender).close_for_reuse();
    auto receive_storage = std::move(receiver).close_for_reuse();
    auto next_sender = stream::start_push(key, std::move(send_storage));
    auto next_receiver = stream::start_pull(key, next_sender.header(), std::move(receive_storage));

    // Reuse the ciphertext vector's existing buffer as well.
    next_sender.push_into(message, ad, first_record, stream::record_tag::final);
    auto restarted = next_receiver.pull(first_record, ad);
    return restarted.tag == stream::record_tag::final && next_receiver.finished() && std::ranges::equal(restarted.plaintext.bytes(), message);
}

bool caller_owned_stream()
{
    potassium::key_buffer_storage<stream::key_tag> key;
    stream::inplace_state send_state;
    stream::state_type receive_state{};  // The caller can also supply backend storage.
    auto sender = stream::start_push(key, stream::state_storage{send_state.get()});
    auto receiver = stream::start_pull(key, sender.header(), stream::state_storage{receive_state});
    auto message = std::as_bytes(std::span{input});
    auto ad = std::as_bytes(std::span{metadata});
    std::array<std::byte, input.size() + stream::record_overhead> record{};
    std::array<std::byte, input.size()> plaintext{};

    // A rekey record updates both peers as they process it.
    sender.push_into(message, ad, record, stream::record_tag::rekey);
    auto rekey = receiver.pull_into(record, ad, plaintext);
    if (rekey != stream::record_tag::rekey || !std::ranges::equal(plaintext, message)) return false;

    // Explicit rekeying also works when both peers do it at the same boundary.
    sender.rekey();
    receiver.rekey();

    sender.push_into(message, ad, record, stream::record_tag::final);
    auto final = receiver.pull_into(record, ad, plaintext, std::nothrow);
    if (final != stream::record_tag::final || !receiver.finished() || !std::ranges::equal(plaintext, message)) return false;

    // Finalization wipes both states. Start a fresh stream with the same storage and a new header.
    sender = stream::start_push(key, std::move(sender).close_for_reuse());
    receiver = stream::start_pull(key, sender.header(), std::move(receiver).close_for_reuse());
    sender.push_into(message, ad, record, stream::record_tag::final);
    auto restarted = receiver.pull_into(record, ad, plaintext);
    return restarted == stream::record_tag::final && receiver.finished() && std::ranges::equal(plaintext, message);
}
}  // namespace

int main()
{
    potassium::init();
    if (!guarded_stream() || !caller_owned_stream())
    {
        std::println(std::cerr, "Secretstream round trip or final record check failed");
        return 1;
    }
    std::println("Secretstream records verified through the final record");
}
