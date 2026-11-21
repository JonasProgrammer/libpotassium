// SPDX-FileCopyrightText: 2026 libpotassium team
// SPDX-License-Identifier: BSL-1.0

#pragma once

#ifndef POTASSIUM_MUTABLE_BYTES
#define POTASSIUM_MUTABLE_BYTES(data) (static_cast<unsigned char*>(static_cast<void*>((data))))
#endif

#ifndef POTASSIUM_CONST_BYTES
#define POTASSIUM_CONST_BYTES(data) (static_cast<unsigned char const*>(static_cast<void const*>((data))))
#endif
