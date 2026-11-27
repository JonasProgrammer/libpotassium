// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.auth;
import std;

namespace auth = potassium::auth;
namespace hash = potassium::hash;

namespace
{
template <auth::hmac_algorithm A>
bool authenticate_message()
{
    constexpr std::array input{'a', 'b', 'c', 'd'};
    auto message = std::as_bytes(std::span{input});
    potassium::key_buffer_storage<auth::hmac_key_tag<A>> key;

    // Both one-shot forms use fixed-size storage and allocate nothing.
    auto tag = auth::authenticate<A>(key, message);
    std::array<std::byte, auth::auth_traits<A>::tag_size> output{};
    auth::authenticate_into<A>(key, message, output);
    auth::verify<A>(key, message, output);

    // Reject a modified wire tag without throwing.
    output.front() ^= std::byte{1};
    auto rejected = auth::verify<A>(key, message, output, std::nothrow);
    if (rejected != std::unexpected(potassium::errc::crypto_failed)) return false;

    // Streaming HMAC lives in potassium.hash and can use inline state.
    using state_type = typename hash::keyed_hash_traits<A>::state_type;
    hash::keyed_hasher<A, hash::inplace_hash_state<state_type>> stream{key};
    stream.update(message.first<2>());
    stream.update(message.last<2>());
    auto [streamed, storage] = std::move(stream).finalize_for_reuse();

    // HMAC streaming also accepts raw key spans, including lengths other than the generated key size.
    stream.reset(key.ref().bytes(), std::move(storage));
    stream.update(message);
    return tag == streamed && tag == std::move(stream).finalize();
}
}  // namespace

int main()
{
    potassium::init();
    if (!authenticate_message<auth::default_algorithm>() || !authenticate_message<auth::hmac_sha256>() || !authenticate_message<auth::hmac_sha512>())
    {
        std::println(std::cerr, "HMAC verification or streaming comparison failed");
        return 1;
    }
    std::println("HMAC verified for all three algorithms");
}
