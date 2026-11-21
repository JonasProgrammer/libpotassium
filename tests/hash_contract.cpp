// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium;
import std;

// CTest expects failure only when the violated precondition calls terminate.
int main(int argc, char** argv)
{
    if (argc != 2) return 0;
    potassium::init();
    namespace h = potassium::hash;
    potassium::secret_key<h::blake2b_key_tag<>> key;
    h::keyed_hasher<h::default_algorithm> stream(key);
    std::set_terminate([] { std::_Exit(1); });
    std::string_view mode = argv[1];
    if (mode == "moved-reset")
    {
        auto owner = std::move(stream);
        stream.reset(key);
    }
    else
    {
        (void)std::move(stream).finalize();
        if (mode == "finalized-update") stream.update({});
        if (mode == "finalized-finalize") (void)std::move(stream).finalize();
    }
}
