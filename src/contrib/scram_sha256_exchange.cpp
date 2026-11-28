// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

module;
#include <sodium.h>

module potassium.contrib;

import potassium.internal;
import std;

namespace potassium::contrib::scram_sha256
{
namespace
{
constexpr std::string_view client_header = "n,,";
constexpr std::string_view unbound_header = "y,,";
constexpr auto gs2_plus_overhead = std::string_view{"p=,,"}.size();
constexpr auto base64_variant = sodium_base64_VARIANT_ORIGINAL;
constexpr auto client_final_overhead = std::string_view{"c=,r=,p="}.size() + sodium_base64_ENCODED_LEN(key_size, base64_variant) - 1;

bool valid_message(std::string_view message) noexcept
{
    return !message.empty() && message.size() <= max_message_size && message.back() != ',';
}

bool valid_nonce(std::string_view nonce) noexcept
{
    return !nonce.empty() && std::ranges::all_of(nonce, [](unsigned char ch) { return ch >= 0x21 && ch <= 0x7e && ch != ','; });
}

bool valid_channel_binding(channel_binding binding) noexcept
{
    if (binding.type.empty() || binding.type.size() > max_channel_binding_size - gs2_plus_overhead) return false;
    if (binding.data.empty() || binding.data.size() > max_channel_binding_size - gs2_plus_overhead - binding.type.size()) return false;
    if (binding.type == "tls-exporter" && binding.data.size() != 32) return false;
    return std::ranges::all_of(binding.type, [](char ch) { return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-'; });
}

bool valid_utf8(std::string_view text) noexcept
{
    while (!text.empty())
    {
        auto lead = static_cast<unsigned char>(text.front());
        text.remove_prefix(1);
        if (lead == 0) return false;
        if (lead <= 0x7f) continue;
        if (lead < 0xc2 || lead > 0xf4) return false;

        auto count = lead < 0xe0 ? 1u : lead < 0xf0 ? 2u : 3u;
        if (text.size() < count) return false;
        auto next = static_cast<unsigned char>(text.front());
        if ((lead == 0xe0 && next < 0xa0) || (lead == 0xed && next > 0x9f) || (lead == 0xf0 && next < 0x90) || (lead == 0xf4 && next > 0x8f)) return false;
        if (!std::ranges::all_of(text.substr(0, count), [](unsigned char ch) { return ch >= 0x80 && ch <= 0xbf; })) return false;
        text.remove_prefix(count);
    }
    return true;
}

std::optional<std::string_view> take_attribute(std::string_view& remaining, char name) noexcept
{
    if (remaining.size() < 3 || remaining[0] != name || remaining[1] != '=') return {};
    auto separator = remaining.find(',');
    if (separator == 2) return {};
    auto value = remaining.substr(2, separator == std::string_view::npos ? separator : separator - 2);
    remaining = separator == std::string_view::npos ? std::string_view{} : remaining.substr(separator + 1);
    return value;
}

bool valid_extensions(std::string_view remaining) noexcept
{
    constexpr std::string_view reserved = "acimnprsev";
    while (!remaining.empty())
    {
        auto name = remaining.front();
        if ((name < 'A' || name > 'Z') && (name < 'a' || name > 'z')) return false;
        if (reserved.contains(name)) return false;
        auto value = take_attribute(remaining, name);
        if (!value || !valid_utf8(*value)) return false;
    }
    return true;
}

void append_escaped(std::string& result, std::string_view username)
{
    for (auto ch : username)
    {
        if (ch == ',')
            result.append("=2C");
        else if (ch == '=')
            result.append("=3D");
        else
            result.push_back(ch);
    }
}

std::optional<std::string> unescape_username(std::string_view username)
{
    if (!valid_utf8(username)) return {};
    std::string result;
    result.reserve(username.size());
    for (std::size_t i = 0; i < username.size(); ++i)
    {
        auto ch = username[i];
        if (ch != '=')
        {
            result.push_back(ch);
            continue;
        }
        auto escape = username.substr(i, 3);
        if (escape == "=2C")
            result.push_back(',');
        else if (escape == "=3D")
            result.push_back('=');
        else
            return {};
        i += 2;
    }
    return result;
}

void append_base64(std::string& result, std::span<std::byte const> bytes)
{
    constexpr auto max_size = std::max(max_salt_size, max_channel_binding_size);
    std::array<char, sodium_base64_ENCODED_LEN(max_size, base64_variant)> encoded;
    auto size = sodium_base64_encoded_len(bytes.size(), base64_variant);
    sodium_bin2base64(encoded.data(), size, internal::sodium_bytes(bytes.data()), bytes.size(), base64_variant);
    result.append(encoded.data(), size - 1);
}

void encode_binding(std::string& out, std::string_view header, std::span<std::byte const> data)
{
    std::array<std::byte, max_channel_binding_size> input;
    auto after_header = std::ranges::copy(detail::as_bytes(header), input.begin()).out;
    auto end = std::ranges::copy(data, after_header).out;
    out.clear();
    append_base64(out, std::span{input.begin(), end});
}

template <std::size_t N>
std::optional<std::size_t> decode_base64(std::string_view encoded, std::array<std::byte, N>& decoded) noexcept
{
    std::array<char, sodium_base64_ENCODED_LEN(N, base64_variant)> canonical;
    if (encoded.empty() || encoded.size() >= canonical.size()) return {};
    std::size_t size = 0;
    if (sodium_base642bin(internal::sodium_bytes(decoded.data()), decoded.size(), encoded.data(), encoded.size(), nullptr, &size, nullptr, base64_variant) != 0) return {};
    sodium_bin2base64(canonical.data(), canonical.size(), internal::sodium_bytes(decoded.data()), size, base64_variant);
    if (encoded != canonical.data()) return {};
    return size;
}

void append_nonce(std::string& nonce)
{
    std::array<std::byte, 18> random;
    random_fill(random);
    append_base64(nonce, random);
}

struct parsed_challenge
{
    std::string_view nonce;
    std::array<std::byte, max_salt_size> salt{};
    std::size_t salt_size;
    std::uint32_t iterations;
};

bool parse_challenge(std::string_view remaining, std::string_view client_nonce, std::size_t max_nonce_size, iteration_policy policy, parsed_challenge& result) noexcept
{
    if (!valid_message(remaining)) return false;
    auto nonce = take_attribute(remaining, 'r');
    auto salt = take_attribute(remaining, 's');
    auto iterations = take_attribute(remaining, 'i');
    if (!nonce || !salt || !iterations || !valid_extensions(remaining)) return false;
    if (!valid_nonce(*nonce) || nonce->size() <= client_nonce.size() || !nonce->starts_with(client_nonce) || nonce->size() > max_nonce_size) return false;
    if (iterations->front() < '1' || iterations->front() > '9') return false;
    auto end = iterations->data() + iterations->size();
    auto parsed = std::from_chars(iterations->data(), end, result.iterations);
    if (parsed.ec != std::errc{} || parsed.ptr != end || result.iterations < policy.minimum || result.iterations > policy.maximum) return false;
    auto salt_size = decode_base64(*salt, result.salt);
    if (!salt_size || *salt_size == 0) return false;
    result.nonce = *nonce;
    result.salt_size = *salt_size;
    return true;
}
}  // namespace

client_exchange::client_exchange(iteration_policy policy) noexcept
    : policy_(policy)
{
}

client_exchange::client_exchange(client_exchange_out storage, iteration_policy policy) noexcept
    : policy_(policy)
    , expected_signature_(storage)
{
    wipe(expected_signature_.bytes());
}

client_exchange::~client_exchange()
{
    close();
}

void client_exchange::close() noexcept
{
    wipe(expected_signature_.bytes());
    first_bare_.clear();
    nonce_.clear();
    binding_.clear();
    phase_ = phase::closed;
}

std::unexpected<errc> client_exchange::fail(errc error) noexcept
{
    close();
    return std::unexpected(error);
}

void client_exchange::reset() noexcept
{
    close();
    phase_ = phase::idle;
}

std::expected<client_first_message, errc> client_exchange::start_impl(std::string_view username, client_negotiation negotiation) noexcept
try
{
    if (phase_ != phase::idle || policy_.minimum == 0 || policy_.maximum < policy_.minimum || username.empty() || username.size() > max_message_size || !valid_utf8(username)) return fail();
    if (negotiation.binding && !valid_channel_binding(*negotiation.binding)) return fail();
    bool use_plus = negotiation.offered.sha256_plus && negotiation.binding.has_value();
    if (!use_plus && (!negotiation.offered.sha256 || negotiation.require_channel_binding)) return fail();

    std::string result;
    std::span<std::byte const> binding_data;
    if (use_plus)
    {
        result.assign("p=").append(negotiation.binding->type).append(",,");
        binding_data = negotiation.binding->data;
    }
    else
    {
        result.assign(negotiation.binding ? unbound_header : client_header);
    }
    encode_binding(binding_, result, binding_data);

    append_nonce(nonce_);
    first_bare_.assign("n=");
    append_escaped(first_bare_, username);
    first_bare_.append(",r=").append(nonce_);
    result.append(first_bare_);
    if (result.size() > max_message_size) return fail();
    phase_ = phase::server_first;
    return client_first_message{use_plus ? mechanism::sha256_plus : mechanism::sha256, std::move(result)};
}
catch (std::bad_alloc const&)
{
    return fail(errc::allocation_failed);
}

std::expected<std::string, errc> client_exchange::respond_impl(std::string_view message, std::variant<std::string_view, cached_client_credentials> source) noexcept
try
{
    parsed_challenge challenge;
    auto max_nonce_size = max_message_size - client_final_overhead - binding_.size();
    if (phase_ != phase::server_first || !parse_challenge(message, nonce_, max_nonce_size, policy_, challenge)) return fail();
    auto salt = std::span{challenge.salt}.first(challenge.salt_size);
    client_credentials_storage derived{for_overwrite};
    auto* cached = std::get_if<cached_client_credentials>(&source);
    if (cached)
    {
        if (cached->iterations != challenge.iterations || !std::ranges::equal(cached->salt, salt)) return fail();
    }
    else
    {
        auto status = derive_client_credentials_into(std::get<std::string_view>(source), salt, challenge.iterations, derived, std::nothrow);
        if (!status) return fail(status.error());
    }
    auto credentials = cached ? cached->credentials : derived.ref();

    std::string result{"c="};
    result.append(binding_).append(",r=").append(challenge.nonce);

    auth_message transcript{first_bare_, message, result};
    auto proof = make_client_proof(credentials, transcript);
    detail::server_signature_into(credentials, transcript, expected_signature_.bytes());
    result.append(",p=");
    append_base64(result, proof.bytes());
    phase_ = phase::server_final;
    return result;
}
catch (std::bad_alloc const&)
{
    return fail(errc::allocation_failed);
}

std::expected<void, errc> client_exchange::finish_impl(std::string_view message) noexcept
{
    if (phase_ != phase::server_final || !valid_message(message)) return fail();
    auto encoded = take_attribute(message, 'v');
    if (!encoded || !valid_extensions(message)) return fail();
    server_signature signature;
    if (decode_base64(*encoded, signature.storage) != key_size || sodium_memcmp(expected_signature_.bytes().data(), signature.storage.data(), key_size) != 0) return fail();
    close();
    return {};
}

server_exchange::server_exchange(server_verifier_out storage) noexcept
    : verifier_(storage)
{
    wipe(verifier_.bytes());
}

server_exchange::~server_exchange()
{
    close();
}

void server_exchange::close() noexcept
{
    wipe(verifier_.bytes());
    first_bare_.clear();
    nonce_.clear();
    server_first_.clear();
    binding_.clear();
    phase_ = phase::closed;
}

std::unexpected<errc> server_exchange::fail(errc error) noexcept
{
    close();
    return std::unexpected(error);
}

void server_exchange::reset() noexcept
{
    close();
    phase_ = phase::idle;
}

std::expected<std::string, errc> server_exchange::receive_client_first_impl(std::string_view message, server_negotiation negotiation) noexcept
try
{
    if (phase_ != phase::idle || !valid_message(message)) return fail();
    if (negotiation.binding && !valid_channel_binding(*negotiation.binding)) return fail();
    if (negotiation.advertised.sha256_plus && !negotiation.binding) return fail();

    auto flag_end = message.find(',');
    if (flag_end == std::string_view::npos || flag_end + 1 >= message.size() || message[flag_end + 1] != ',') return fail();
    auto header = message.substr(0, flag_end + 2);
    std::span<std::byte const> binding_data;
    if (negotiation.selected == mechanism::sha256_plus)
    {
        auto flag = message.substr(0, flag_end);
        if (!negotiation.advertised.sha256_plus || !flag.starts_with("p=") || flag.substr(2) != negotiation.binding->type) return fail();
        binding_data = negotiation.binding->data;
    }
    else
    {
        if (negotiation.selected != mechanism::sha256 || !negotiation.advertised.sha256 || (header != client_header && (header != unbound_header || negotiation.binding))) return fail();
    }

    auto bare = message.substr(header.size());
    auto remaining = bare;
    auto username = take_attribute(remaining, 'n');
    auto nonce = take_attribute(remaining, 'r');
    if (!username || !nonce || !valid_nonce(*nonce) || !valid_extensions(remaining)) return fail();
    auto decoded_username = unescape_username(*username);
    if (!decoded_username) return fail();
    first_bare_.assign(bare);
    nonce_.assign(*nonce);
    encode_binding(binding_, header, binding_data);
    phase_ = phase::verifier;
    return std::move(*decoded_username);
}
catch (std::bad_alloc const&)
{
    return fail(errc::allocation_failed);
}

std::expected<std::string, errc> server_exchange::challenge(server_verifier_ref account, std::span<std::byte const> salt, std::uint32_t iterations, std::nothrow_t) noexcept
try
{
    if (phase_ != phase::verifier || salt.empty() || salt.size() > max_salt_size || iterations == 0) return fail();
    append_nonce(nonce_);
    if (nonce_.size() > max_message_size - client_final_overhead - binding_.size()) return fail();
    server_first_.assign("r=");
    server_first_.append(nonce_).append(",s=");
    append_base64(server_first_, salt);
    server_first_.append(",i=").append(std::to_string(iterations));
    if (server_first_.size() > max_message_size) return fail();

    std::string result = server_first_;
    std::ranges::copy(account.bytes(), verifier_.bytes().begin());
    phase_ = phase::client_final;
    return result;
}
catch (std::bad_alloc const&)
{
    return fail(errc::allocation_failed);
}

std::string server_exchange::challenge(server_verifier_ref account, std::span<std::byte const> salt, std::uint32_t iterations)
{
    return internal::unwrap(challenge(account, salt, iterations, std::nothrow));
}

std::expected<std::string, errc> server_exchange::finish_impl(std::string_view message) noexcept
try
{
    if (phase_ != phase::client_final || !valid_message(message)) return fail();
    auto proof_start = message.rfind(",p=");
    if (proof_start == std::string_view::npos) return fail();
    auto without_proof = message.substr(0, proof_start);
    if (!valid_message(without_proof)) return fail();
    auto remaining = without_proof;
    auto binding = take_attribute(remaining, 'c');
    auto nonce = take_attribute(remaining, 'r');
    if (binding != binding_ || nonce != nonce_ || !valid_extensions(remaining)) return fail();

    client_proof proof;
    if (decode_base64(message.substr(proof_start + 3), proof.storage) != key_size) return fail();
    auto signature = authenticate_client(server_verifier_ref{verifier_.bytes()}, auth_message{first_bare_, server_first_, without_proof}, proof.bytes(), std::nothrow);
    if (!signature) return fail(signature.error());
    close();

    std::string result{"v="};
    append_base64(result, signature->bytes());
    return result;
}
catch (std::bad_alloc const&)
{
    return fail(errc::allocation_failed);
}
}  // namespace potassium::contrib::scram_sha256
