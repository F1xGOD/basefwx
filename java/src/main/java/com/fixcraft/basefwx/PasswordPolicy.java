/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

/**
 * Password strength policy mirroring C++ {@code RequireStrongPasswordForEncryption}.
 */
public final class PasswordPolicy {
    private PasswordPolicy() {}

    public static void requireStrongPassword(byte[] password, String context) {
        if (password == null || password.length == 0) {
            return;
        }
        if (Constants.TEST_KDF_OVERRIDE) {
            return;
        }
        if (Constants.envEnabled("BASEFWX_ALLOW_WEAK_PASSWORD")) {
            return;
        }
        int minLen = Constants.MINIMUM_PASSWORD_LENGTH;
        String rawMin = System.getenv("BASEFWX_MIN_PASSWORD_LEN");
        if (rawMin != null && !rawMin.trim().isEmpty()) {
            try {
                int configured = Integer.parseInt(rawMin.trim());
                if (configured >= 0) {
                    minLen = configured;
                }
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (minLen == 0 || password.length >= minLen) {
            return;
        }
        String label = (context == null || context.isEmpty()) ? "Encryption" : context;
        throw new IllegalArgumentException(
                label + " requires a password of at least " + minLen
                        + " UTF-8 bytes (set BASEFWX_ALLOW_WEAK_PASSWORD=1 to override)");
    }

}
