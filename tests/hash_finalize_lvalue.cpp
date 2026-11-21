// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

import potassium.hash;

// Compiled only by the diagnostic test.
void finalize_named_hasher(potassium::hash::hasher<potassium::hash::sha256>& stream)
{
    (void)stream.finalize();
}
