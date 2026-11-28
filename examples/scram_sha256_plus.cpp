// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.contrib;
import std;

namespace scram = potassium::contrib::scram_sha256;

int main()
{
    potassium::init();

    // Store the verifier with the salt and iteration count at enrollment.
    std::array<std::byte, 16> salt;
    potassium::random_fill(salt);
    constexpr auto iterations = scram::recommended_min_iterations;
    auto verifier = scram::make_server_verifier("pencil", salt, iterations);

    // This demo uses a fixture for the exporter bytes each peer obtains independently from TLS.
    constexpr std::array<std::byte, 32> demo_exporter{};
    scram::channel_binding binding{"tls-exporter", demo_exporter};
    constexpr scram::mechanism_offer offered{.sha256 = true, .sha256_plus = true};

    scram::client_exchange client;
    scram::server_exchange server;
    auto client_first = client.start("user", {.offered = offered, .binding = binding, .require_channel_binding = true});
    auto username = server.receive_client_first(client_first.message, {.selected = client_first.selected, .advertised = offered, .binding = binding});
    if (username != "user") return 1;

    auto server_first = server.challenge(verifier, salt, iterations);
    auto client_final = client.respond(server_first, u8"pencil");
    auto server_final = server.finish(client_final);
    client.finish(server_final);
    std::println("{} authenticated the client and server", scram::mechanism_name(client_first.selected));
}
