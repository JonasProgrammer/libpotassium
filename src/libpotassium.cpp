// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

/// @mainpage potassium
/// @pre Call @c potassium::init() once successfully before using the module (and submodule) API.

/// @brief Complete libpotassium API, including version information.
export module potassium;

export import :base;

export import potassium.core;

export import potassium.aead;
export import potassium.auth;
export import potassium.box;
export import potassium.secretbox;

export import potassium.hash;
