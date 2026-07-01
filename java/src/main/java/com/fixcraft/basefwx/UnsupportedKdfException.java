/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

/**
 * Thrown when the Java runtime is asked to operate on a blob that uses
 * an unrecognised KDF label. Note: Argon2id is supported since 3.7.0
 * (via BouncyCastle's {@code Argon2BytesGenerator}); this exception is
 * only raised for truly unknown labels, not for "argon2id" or "argon2".
 * See {@code SECURITY.md} and the project compatibility matrix in
 * {@code COMPATIBILITY.md}.
 *
 * <p>Callers that need to route unrecognised labels to a native helper
 * or surface a specific UI message should catch this exception type
 * explicitly rather than the more generic {@link IllegalArgumentException}.
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
