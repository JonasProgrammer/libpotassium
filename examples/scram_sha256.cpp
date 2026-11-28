// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.contrib;
import std;

namespace scram = potassium::contrib::scram_sha256;

int main()
{
    potassium::init();

    // RFC 7677 sample salt and transcript. Use a fresh random salt for each enrollment.
    constexpr std::array salt{std::byte{0x5b},
                              std::byte{0x6d},
                              std::byte{0x99},
                              std::byte{0x68},
                              std::byte{0x9d},
                              std::byte{0x12},
                              std::byte{0x35},
                              std::byte{0x8e},
                              std::byte{0xec},
                              std::byte{0xa0},
                              std::byte{0x4b},
                              std::byte{0x14},
                              std::byte{0x12},
                              std::byte{0x36},
                              std::byte{0xfa},
                              std::byte{0x81}};
    constexpr std::uint32_t iterations = 4096;

    // Store the verifier with the salt and iteration count at enrollment.
    auto verifier = scram::make_server_verifier("pencil", salt, iterations);
    // The client can cache credentials as long as the salt and iteration count still match.
    auto credentials = scram::derive_client_credentials(u8"pencil", salt, iterations);

    scram::auth_message transcript{
            "n=user,r=rOprNGfwEbeRWgbNEkqO", "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"};

    auto proof = scram::make_client_proof(credentials, transcript);
    auto signature = scram::authenticate_client(verifier, transcript, proof.bytes());
    scram::authenticate_server(credentials, transcript, signature.bytes());
    std::println("SCRAM-SHA-256 authenticated the client and server");
}
