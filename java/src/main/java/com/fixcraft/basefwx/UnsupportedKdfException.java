/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

/**
 * Thrown when the Java runtime is asked to operate on a blob that was
 * produced under a KDF the Java side does not implement (currently:
 * Argon2id). This is a deliberate platform choice — see basefwx
 * {@code SECURITY.md} and the project compatibility matrix in
 * {@code COMPATIBILITY.md}.
 *
 * <p>Callers that need to handle the cross-platform-only case (e.g.
 * routing Argon2-wrapped blobs to a native helper, or surfacing a
 * specific UI message) should catch this exception type explicitly
 * rather than the more generic {@link IllegalArgumentException}.
 */
public class UnsupportedKdfException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    private final String kdfLabel;

    public UnsupportedKdfException(String kdfLabel, String message) {
        super(message);
        this.kdfLabel = kdfLabel;
    }

    /** The KDF label that was requested (e.g. "argon2id"). Never null. */
    public String getKdfLabel() {
        return kdfLabel;
    }
}
