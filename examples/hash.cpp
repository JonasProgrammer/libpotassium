// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.hash;
import std;

namespace hash = potassium::hash;

namespace
{
constexpr std::array input{'a', 'b', 'c', 'd'};

template <hash::hash_algorithm A>
bool unkeyed_digest()
{
    auto message = std::as_bytes(std::span{input});
    auto digest = hash::hash<A>(message);

    std::array<std::byte, hash::hash_traits<A>::digest_size> output{};
    hash::hash_into<A>(message, output);

    // Default unkeyed state lives inside the hasher.
    hash::hasher<A> stream;
    stream.update(message.first<2>());
    stream.reset();  // Discard buffered input before restarting.
    stream.update(message.first<2>());
    stream.update(message.last<2>());
    auto [streamed, storage] = std::move(stream).finalize_for_reuse();

    stream.reset(std::move(storage));
    stream.update(message);
    return digest == streamed && digest == std::move(stream).finalize() && std::ranges::equal(digest.bytes(), output);
}

bool keyed_blake2b()
{
    using algorithm = hash::blake2b<48>;
    using state_type = hash::keyed_hash_traits<algorithm>::state_type;
    auto message = std::as_bytes(std::span{input});

    potassium::key_buffer_storage<hash::blake2b_key_tag<>> key;
    auto tag = hash::hash<algorithm>(key, message);
    std::array<std::byte, hash::keyed_hash_traits<algorithm>::digest_size> output{};
    hash::hash_into<algorithm>(key, message, output);

    // The default keyed stream allocates guarded state once.
    auto stream = hash::make_keyed_hasher<algorithm>(key, std::nothrow);
    if (!stream) potassium::throw_error(stream.error());
    stream->update(message.first<2>());
    stream->update(message.last<2>());
    auto [streamed, storage] = std::move(*stream).finalize_for_reuse();

    // Transfer the wiped allocation back and start another message.
    stream->reset(key, std::move(storage));
    stream->update(message.first<2>());

    // Resetting an active stream discards the partial message and replaces its key in the same allocation.
    potassium::key_buffer_storage<hash::blake2b_key_tag<>> next_key;
    stream->reset(next_key);
    stream->update(message);
    auto restarted = std::move(*stream).finalize();

    // An explicit inline policy avoids allocating even at construction.
    hash::keyed_hasher<algorithm, hash::inplace_hash_state<state_type>> inline_stream{key};
    inline_stream.update(message);

    return tag == streamed && tag == std::move(inline_stream).finalize() && std::ranges::equal(tag.bytes(), output) && restarted == hash::hash<algorithm>(next_key, message);
}

bool guarded_unkeyed_digest()
{
    using algorithm = hash::sha256;
    using storage = hash::guarded_hash_state<hash::hash_traits<algorithm>::state_type>;
    auto stream = hash::make_hasher<algorithm, storage>(std::nothrow);
    if (!stream) potassium::throw_error(stream.error());
    auto message = std::as_bytes(std::span{input});
    stream->update(message);
    return std::move(*stream).finalize() == hash::hash<algorithm>(message);
}
}  // namespace

int main()
{
    potassium::init();
    if (!unkeyed_digest<hash::default_algorithm>() || !unkeyed_digest<hash::sha256>() || !unkeyed_digest<hash::sha512>() || !unkeyed_digest<hash::sha3_256>() || !unkeyed_digest<hash::sha3_512>() ||
        !keyed_blake2b() || !guarded_unkeyed_digest())
    {
        std::println(std::cerr, "Hash results differ across usage variants");
        return 1;
    }
    std::println("One-shot and incremental digests agree");
}
