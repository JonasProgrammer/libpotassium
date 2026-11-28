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

    scram::client_exchange client;
    scram::server_exchange server;
    auto client_first = client.start("user");
    auto username = server.receive_client_first(client_first);
    if (username != "user") return 1;

    auto server_first = server.challenge(verifier, salt, iterations);
    auto client_final = client.respond(server_first, u8"pencil");
    auto server_final = server.finish(client_final);
    client.finish(server_final);
    std::println("SCRAM-SHA-256 authenticated the client and server");
}
