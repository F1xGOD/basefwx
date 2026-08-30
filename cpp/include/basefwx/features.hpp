/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

#pragma once

// CMake publishes this definition through the basefwxcpp target. Direct
// header consumers get the default core-only capability unless their
// compatibility build explicitly defines it.
#ifndef BASEFWX_HAS_RETIRED_MEDIA
#define BASEFWX_HAS_RETIRED_MEDIA 0
#endif
