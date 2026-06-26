/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class FileCodecKdf {
    private FileCodecKdf() {}

static String resolveUserKdfLabel() {
        String raw = System.getenv("BASEFWX_USER_KDF");
        if (raw == null || raw.trim().isEmpty()) {
            return "pbkdf2";
        }
        return resolveKdfLabel(raw.trim().toLowerCase());
    }

static String resolveKdfLabel(String label) {
        if (label == null || label.isEmpty() || "auto".equalsIgnoreCase(label)) {
            return "pbkdf2";
        }
        String normalized = label.toLowerCase();
        if (normalized.startsWith("argon2")) {
            // 3.6.5: Java now supports Argon2id (via BouncyCastle); see KeyWrap.resolveKdfLabel.
            return "argon2id";
        }
        if (!"pbkdf2".equals(normalized)) {
            throw new UnsupportedKdfException(normalized,
                    "Unsupported KDF label: " + normalized);
        }
        return normalized;
    }

static int hardenPbkdf2Iterations(byte[] password, int iterations) {
        if (password == null || password.length == 0) {
            return iterations;
        }
        if (Constants.TEST_KDF_OVERRIDE) {
            return iterations;
        }
        if (password.length < Constants.SHORT_PASSWORD_MIN) {
            return Math.max(iterations, Constants.SHORT_PBKDF2_ITERS);
        }
        return iterations;
    }
}
