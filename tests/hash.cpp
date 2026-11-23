// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

import potassium.hash;
import std;

namespace
{
namespace h = potassium::hash;
using namespace std::string_view_literals;

using default_hash = h::default_algorithm;
using unkeyed_stream = h::hasher<default_hash>;
using keyed_stream = h::keyed_hasher<default_hash>;
using key_tag = h::blake2b_key_tag<>;
using key = potassium::secret_key<key_tag>;

static_assert(__cpp_deleted_function >= 202403L);
static_assert(std::same_as<default_hash, h::blake2b<32>>);

template <class S>
concept finalizable = requires(S&& s) { std::forward<S>(s).finalize(); };

template <class S>
concept finalizable_for_reuse = requires(S&& s) { std::forward<S>(s).finalize_for_reuse(); };

template <class S>
constexpr bool reuses_only_as_mutable_rvalue = finalizable_for_reuse<S> && !finalizable_for_reuse<S&> && !finalizable_for_reuse<S const&> && !finalizable_for_reuse<S const>;

static_assert(reuses_only_as_mutable_rvalue<unkeyed_stream> && reuses_only_as_mutable_rvalue<keyed_stream>);

using inplace_token = h::hash_traits<default_hash>::default_storage::transfer_token;
using guarded_token = h::keyed_hash_traits<default_hash>::default_storage::transfer_token;
static_assert(std::is_empty_v<inplace_token>);
static_assert(!std::default_initializable<inplace_token> && !std::default_initializable<guarded_token>);
static_assert(noexcept(std::declval<unkeyed_stream>().finalize_for_reuse()));
static_assert(noexcept(std::declval<keyed_stream>().finalize_for_reuse()));
static_assert(noexcept(std::declval<unkeyed_stream&>().reset(std::declval<inplace_token>())));
static_assert(noexcept(std::declval<keyed_stream&>().reset(std::declval<key&>(), std::declval<guarded_token>())));

template <class S>
constexpr bool finalizes_only_as_mutable_rvalue = finalizable<S> && !finalizable<S&> && !finalizable<S const&> && !finalizable<S const>;

static_assert(finalizes_only_as_mutable_rvalue<unkeyed_stream> && finalizes_only_as_mutable_rvalue<keyed_stream>);
static_assert(!std::move_constructible<unkeyed_stream> && !std::copy_constructible<unkeyed_stream>);
static_assert(std::movable<keyed_stream> && !std::copy_constructible<keyed_stream> && !std::default_initializable<keyed_stream>);

template <std::size_t N>
concept valid_output = requires { typename h::blake2b<N>; };

template <std::size_t N>
concept valid_key = requires { typename h::blake2b_key_tag<N>; };

static_assert(valid_key<16> && valid_key<32> && valid_key<64> && !valid_key<15> && !valid_key<65>);
static_assert(valid_output<16> && valid_output<64> && !valid_output<15> && !valid_output<65>);
static_assert(!h::hash_algorithm<int> && h::keyed_hash_algorithm<default_hash>);
static_assert(!h::keyed_hash_algorithm<h::sha256> && !h::keyed_hash_algorithm<h::sha512> && !h::keyed_hash_algorithm<h::sha3_256> && !h::keyed_hash_algorithm<h::sha3_512>);

using limits = h::keyed_hash_traits<default_hash>;
static_assert(limits::min_key_size == 16 && limits::default_key_size == 32 && limits::max_key_size == 64);

static_assert(sizeof(h::digest_buffer<default_hash>) == 32 && !std::same_as<h::digest_buffer<default_hash>, h::digest_buffer<h::sha256>>);
static_assert(!std::same_as<h::digest_buffer<h::sha256>, h::digest_buffer<h::sha3_256>>);

template <class A, class K>
concept accepts_key = requires(K&& k) { h::hash<A>(std::forward<K>(k), {}); };

template <class A, class Out>
concept accepts_output = requires(Out out) { h::hash_into<A>({}, out); };

static_assert(!accepts_output<default_hash, std::span<std::byte, 64>>);
static_assert(accepts_key<default_hash, key&> && accepts_key<default_hash, key const&> && !accepts_key<default_hash, key> && !accepts_key<default_hash, key const>);
static_assert(!accepts_key<h::sha256, key&> && !accepts_key<default_hash, std::span<std::byte const, 32>>);
static_assert(!std::constructible_from<keyed_stream, key&&>);

std::string hex(std::span<std::byte const> bytes)
{
    std::string result;
    for (auto b : bytes) result += std::format("{:02x}", std::to_integer<unsigned>(b));
    return result;
}

template <h::hash_algorithm A>
void check_vector(std::span<std::byte const> message, std::string_view expected)
{
    auto result = h::hash<A>(message);
    CAPTURE(expected);
    CHECK(hex(result.bytes()) == expected);

    h::digest_buffer<A> output;
    h::hash_into<A>(message, output.storage);
    CHECK(result == output);

    h::digest_buffer<A> imported;
    std::ranges::copy(result.bytes(), imported.storage.begin());
    CHECK(imported == output);

    output.storage.back() ^= std::byte{1};
    CHECK(result != output);

    h::hasher<A> stream;
    for (auto split : {0u, 1u, 63u, 64u, 65u, 127u, 128u, 129u, 135u, 136u})
    {
        auto n = std::min<std::size_t>(split, message.size());
        CAPTURE(n);

        stream.update(message.first(n));
        stream.update({});
        stream.update(message.subspan(n));

        auto [digest, reuse] = std::move(stream).finalize_for_reuse();
        CHECK(digest == result);
        stream.reset(std::move(reuse));
    }

    CHECK(std::move(stream).finalize() == h::hash<A>({}));
}

template <class A>
void check_vectors(std::string_view empty, std::string_view abc, std::string_view sequence)
{
    check_vector<A>({}, empty);
    check_vector<A>(std::as_bytes(std::span{"abc"sv}), abc);

    std::array<std::byte, 256> data;
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::byte>(i);

    check_vector<A>(data, sequence);
}
}  // namespace

TEST_CASE("Hash one-shot and chunked known-answer vectors", "[hash]")
{
    // Independent reference digests from Python hashlib for each input and output length.
    check_vectors<h::sha256>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                             "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");

    check_vectors<h::sha512>("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                             "1e7b80bc8edc552c8feeb2780e111477e5bc70465fac1a77b29b35980c3f0ce4a036a6c9462036824bd56801e62af7e9feba5c22ed8a5af877bf7de117dcac6d");

    check_vectors<h::sha3_256>("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                               "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                               "9b04c091da96b997afb8f2585d608aebe9c4a904f7d52c8f28c7e4d2dd9fba5f");

    check_vectors<h::sha3_512>("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                               "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                               "3a843af1f872928f0bbbb513207a1a8e14e3d911269fff521292d07dbd5e2e520d6c2634292801184ffa54fd5f1e992ccfdaff8162f5c5f6d1ea79dbcae97e1d");

    check_vectors<h::blake2b<16>>("cae66941d9efbd404e4d88758ea67670", "cf4ab791c62b8d2b2109c90275287816", "c2472c0ac37a8dbdb25f05ada0d82643");

    check_vectors<h::blake2b<32>>("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                                  "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
                                  "39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835");

    check_vectors<h::blake2b<64>>("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                                  "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                                  "1ecc896f34d3f9cac484c73f75f6a5fb58ee6784be41b35f46067b9c65c63a6794d3d744112c653f73dd7deb6666204c5a9bfa5b46081fc10fdbe7884fa5cbf8");
}

TEMPLATE_TEST_CASE("Resetting a hash stream produces the same digest as a fresh stream",
                   "[hash][reset]",
                   h::sha256,
                   h::sha512,
                   h::sha3_256,
                   h::sha3_512,
                   h::blake2b<16>,
                   h::blake2b<32>,
                   h::blake2b<64>)
{
    std::array<std::byte, 257> previous_message{};
    h::hasher<TestType> reused;
    reused.update(previous_message);

    SECTION("Reset with input still buffered")
    {
        reused.reset();
    }

    SECTION("Reset after finalizing the previous message")
    {
        auto [digest, reuse] = std::move(reused).finalize_for_reuse();
        REQUIRE(digest == h::hash<TestType>(previous_message));
        reused.reset(std::move(reuse));
    }

    auto message = std::as_bytes(std::span{"second message"sv});
    h::hasher<TestType> fresh;
    fresh.update(message);
    reused.update(message);

    CHECK(std::move(reused).finalize() == std::move(fresh).finalize());
}

TEMPLATE_TEST_CASE("Resetting a keyed BLAKE2b stream uses the replacement key", "[hash][reset]", h::blake2b<16>, h::blake2b<32>, h::blake2b<64>)
{
    key original_key;
    key replacement_key;
    auto previous_message = std::as_bytes(std::span{"first message"sv});
    h::keyed_hasher<TestType> reused(original_key);
    reused.update(previous_message);

    SECTION("Replace the key with input still buffered")
    {
        reused.reset(replacement_key);
    }

    SECTION("Replace the key after finalization")
    {
        auto [tag, reuse] = std::move(reused).finalize_for_reuse();
        REQUIRE(tag == h::hash<TestType>(original_key, previous_message));
        reused.reset(replacement_key, std::move(reuse));
    }

    auto message = std::as_bytes(std::span{"second message"sv});
    h::keyed_hasher<TestType> fresh(replacement_key);
    fresh.update(message);
    reused.update(message);

    CHECK(std::move(reused).finalize() == std::move(fresh).finalize());
}

namespace
{
using State = h::hash_traits<default_hash>::state_type;

class observed_storage : public h::inplace_hash_state<State>
{
public:
    static inline State* current;
    static inline bool clean_at_release;

    observed_storage() { current = &get(); }

    static bool erased()
    {
        return std::ranges::all_of(std::as_bytes(std::span{current, 1}), [](std::byte b) { return b == std::byte{}; });
    }

    void assign_token(transfer_token&& token) & noexcept
    {
        CHECK(erased());
        h::inplace_hash_state<State>::assign_token(std::move(token));
    }

    ~observed_storage()
    {
        clean_at_release = erased();
        current = nullptr;
    }
};

struct failing_storage : h::guarded_hash_state<State>
{
    failing_storage() { throw std::bad_alloc{}; }
};
}  // namespace

TEST_CASE("Keyed hash state is wiped on finalization and destruction", "[hash]")
{
    key secret;
    auto message = secret.ref().bytes();

    {
        h::keyed_hasher<default_hash, observed_storage> stream(secret);
        stream.update(message);

        auto [tag, reuse] = std::move(stream).finalize_for_reuse();
        CHECK(tag == h::hash<default_hash>(secret, message));
        CHECK(observed_storage::erased());

        stream.reset(secret, std::move(reuse));
    }

    CHECK(observed_storage::clean_at_release);
}

TEST_CASE("Unkeyed hash state is wiped on finalization and destruction", "[hash]")
{
    auto message = std::as_bytes(std::span{"abc"sv});

    {
        h::hasher<default_hash, observed_storage> stream;
        stream.update(message);
        stream.reset();

        auto [digest, reuse] = std::move(stream).finalize_for_reuse();
        CHECK(digest == h::hash<default_hash>({}));
        CHECK(observed_storage::erased());

        stream.reset(std::move(reuse));
        stream.update(message);
    }

    CHECK(observed_storage::clean_at_release);
}

TEST_CASE("An in-place token restarts an active destination after its source is destroyed", "[hash][reset]")
{
    auto [digest, reuse] = unkeyed_stream{}.finalize_for_reuse();
    CHECK(digest == h::hash<default_hash>({}));

    h::hasher<default_hash, observed_storage> destination;
    destination.update(std::as_bytes(std::span{"abandoned input"sv}));
    destination.reset(std::move(reuse));
    CHECK(std::move(destination).finalize() == h::hash<default_hash>({}));
}

TEST_CASE("Hash stream factories report allocation failure", "[hash]")
{
    key secret;

    auto failed_keyed = h::make_keyed_hasher<default_hash, failing_storage>(secret, std::nothrow);
    REQUIRE_FALSE(failed_keyed.has_value());
    CHECK(failed_keyed.error() == potassium::errc::allocation_failed);
    CHECK_THROWS_AS((h::make_keyed_hasher<default_hash, failing_storage>(secret)), std::bad_alloc);

    auto failed_unkeyed = h::make_hasher<default_hash, failing_storage>(std::nothrow);
    REQUIRE_FALSE(failed_unkeyed.has_value());
    CHECK(failed_unkeyed.error() == potassium::errc::allocation_failed);
}

TEST_CASE("Unkeyed hashing supports guarded state storage", "[hash]")
{
    auto guarded = h::make_hasher<default_hash, h::guarded_hash_state<State>>(std::nothrow);
    REQUIRE(guarded.has_value());
    CHECK(std::move(*guarded).finalize() == h::hash<default_hash>({}));
}

TEST_CASE("Guarded hash storage preserves alignment and address across moves", "[hash]")
{
    h::guarded_hash_state<State> storage;
    auto* address = &storage.get();
    CHECK(reinterpret_cast<std::uintptr_t>(address) % alignof(State) == 0);

    auto transferred = std::move(storage);
    CHECK(address == &transferred.get());

    h::guarded_hash_state<State> replacement;
    replacement = std::move(transferred);
    CHECK(address == &replacement.get());
}

TEST_CASE("Keyed BLAKE2b returns the original guarded allocation wiped after reuse", "[hash][reset]")
{
    h::guarded_hash_state<State> storage;
    auto* original = &storage.get();
    key first_key;
    key next_key;
    keyed_stream stream(first_key);
    auto message = std::as_bytes(std::span{"guarded reuse"sv});
    stream.update(message);

    stream.reset(next_key, storage.make_token());
    REQUIRE_FALSE(storage.has_value());
    stream.update(message);
    auto [tag, reuse] = std::move(stream).finalize_for_reuse();
    CHECK(tag == h::hash<default_hash>(next_key, message));

    storage.assign_token(std::move(reuse));
    REQUIRE(storage.has_value());
    REQUIRE(&storage.get() == original);
    CHECK(std::ranges::all_of(std::as_bytes(std::span{&storage.get(), 1}), [](std::byte b) { return b == std::byte{}; }));
}

TEST_CASE("A token restarts a moved-from keyed stream independently of its new owner", "[hash][reset]")
{
    key original;
    key replacement;
    auto message = std::as_bytes(std::span{"pending input"sv});
    keyed_stream stream(original);
    stream.update(message);
    auto owner = std::move(stream);

    auto [tag, reuse] = keyed_stream(replacement).finalize_for_reuse();
    CHECK(tag == h::hash<default_hash>(replacement, {}));
    stream.reset(replacement, std::move(reuse));
    stream.update(message);

    CHECK(std::move(owner).finalize() == h::hash<default_hash>(original, message));
    CHECK(std::move(stream).finalize() == h::hash<default_hash>(replacement, message));
}

TEST_CASE("Moving a keyed hash stream preserves its computation", "[hash]")
{
    key secret;
    auto stream = h::make_keyed_hasher<default_hash>(secret);
    stream.update(secret.ref().bytes());

    auto moved = std::move(stream);
    keyed_stream destination(secret);
    destination.update({});
    destination = std::move(moved);
    stream = std::move(destination);

    CHECK(std::move(stream).finalize() == h::hash<default_hash>(secret, secret.ref().bytes()));
}

TEST_CASE("BLAKE2b output length selects the construction", "[hash]")
{
    auto full = h::hash<h::blake2b<64>>({});
    auto shorter = h::hash<default_hash>({});
    CHECK_FALSE(std::ranges::equal(full.bytes().first<32>(), shorter.bytes()));
}
