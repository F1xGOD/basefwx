/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.util.Arrays;

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
        if ("argon2".equals(normalized) || "argon2id".equals(normalized)) {
            // 3.7.0: Java now supports Argon2id (via BouncyCastle); see KeyWrap.resolveKdfLabel.
            return "argon2id";
        }
        if (!"pbkdf2".equals(normalized)) {
            throw new UnsupportedKdfException(normalized,
                    "Unsupported KDF label: " + normalized);
        }
        return normalized;
    }

    static String resolvePeerKdfLabel(String label) {
        if ("pbkdf2".equals(label)) {
            return label;
        }
        if ("argon2".equals(label) || "argon2id".equals(label)) {
            return "argon2id";
        }
        throw new UnsupportedKdfException(
                label == null ? "" : label,
                "Unsupported peer KDF label: " + label);
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

    static void requirePeerArgon2WithinLimits(
            Integer timeCost, Integer memoryKib, Integer parallelism) {
        if (timeCost != null && timeCost > Constants.ARGON2_TIME_COST_MAX) {
            throw new IllegalArgumentException(
                    "Peer ENC-ARGON2-TC exceeds maximum (" + Constants.ARGON2_TIME_COST_MAX + ")");
        }
        if (memoryKib != null && memoryKib > Constants.ARGON2_MEMORY_KIB_MAX) {
            throw new IllegalArgumentException(
                    "Peer ENC-ARGON2-MEM exceeds maximum (" + Constants.ARGON2_MEMORY_KIB_MAX + ")");
        }
        if (parallelism != null && parallelism > Constants.ARGON2_PARALLELISM_MAX) {
            throw new IllegalArgumentException(
                    "Peer ENC-ARGON2-PAR exceeds maximum (" + Constants.ARGON2_PARALLELISM_MAX + ")");
        }
        if (timeCost != null && timeCost <= 0) {
            throw new IllegalArgumentException("Peer ENC-ARGON2-TC must be positive");
        }
        if (memoryKib != null && memoryKib <= 0) {
            throw new IllegalArgumentException("Peer ENC-ARGON2-MEM must be positive");
        }
        if (parallelism != null && parallelism <= 0) {
            throw new IllegalArgumentException("Peer ENC-ARGON2-PAR must be positive");
        }
    }

    static void requirePeerPbkdf2WithinLimits(int iterations) {
        if (iterations <= 0) {
            throw new IllegalArgumentException(
                    "Peer PBKDF2 iteration count must be positive");
        }
        if (iterations > Constants.PEER_PBKDF2_ITERATIONS_MAX) {
            throw new IllegalArgumentException(
                    "Peer PBKDF2 iteration count exceeds maximum ("
                            + Constants.PEER_PBKDF2_ITERATIONS_MAX + ")");
        }
    }

    static byte[] deriveUserKey(
            byte[] password, byte[] salt, String label, KeyWrap.KdfOptions kdf) {
        if (salt.length < Constants.USER_KDF_SALT_SIZE) {
            throw new IllegalArgumentException("User key salt must be at least 16 bytes");
        }
        String resolved = resolveKdfLabel(label);
        if ("argon2id".equals(resolved) || "argon2".equals(resolved)) {
            int[] params = hardenArgon2Params(password, kdf);
            int time = params[0];
            int mem = params[1];
            int par = params[2];
            requirePeerArgon2WithinLimits(time, mem, par);
            return Crypto.argon2idHashRaw(password, salt, time, mem, par, 32);
        }
        if (!"pbkdf2".equals(resolved)) {
            throw new UnsupportedKdfException(resolved, "Unsupported KDF label: " + resolved);
        }
        int iters = hardenPbkdf2Iterations(password, kdf.pbkdf2Iterations);
        requirePeerPbkdf2WithinLimits(iters);
        return Crypto.pbkdf2HmacSha256(password, salt, iters, 32);
    }

    static int[] hardenArgon2Params(
            byte[] password, KeyWrap.KdfOptions kdf) {
        int time = kdf.argon2TimeCost;
        int mem = kdf.argon2MemoryKib;
        int par = kdf.argon2Parallelism;
        if (!Constants.TEST_KDF_OVERRIDE && password != null
                && password.length > 0
                && password.length < Constants.SHORT_PASSWORD_MIN) {
            time = Math.max(time, Constants.SHORT_ARGON2_TIME_COST);
            mem = Math.max(mem, Constants.SHORT_ARGON2_MEMORY_KIB);
            par = Math.max(par, Constants.SHORT_ARGON2_PARALLELISM);
        }
        return new int[] {time, mem, par};
    }

    static byte[] deriveKemKeyAndWipe(byte[] shared, byte[] info) {
        if (shared == null) {
            throw new IllegalArgumentException("KEM shared secret must not be null");
        }
        try {
            return Crypto.hkdfSha256(shared, info, 32);
        } finally {
            Arrays.fill(shared, (byte) 0);
        }
    }

    static byte[] recoverPqKemKey(byte[] ciphertext, byte[] info) throws Exception {
        byte[] privateKey = null;
        byte[] shared = null;
        try {
            privateKey = PQ.loadMasterPrivateKey();
            shared = PQ.kemDecrypt(privateKey, ciphertext);
            return Crypto.hkdfSha256(shared, info, 32);
        } finally {
            if (privateKey != null) {
                Arrays.fill(privateKey, (byte) 0);
            }
            if (shared != null) {
                Arrays.fill(shared, (byte) 0);
            }
        }
    }

    static byte[] recoverPayloadKey(byte[] userBlob,
                                    byte[] masterBlob,
                                    byte[] password,
                                    boolean useMaster,
                                    byte[] kemInfo,
                                    byte[] aad,
                                    String kdfLabel,
                                    KeyWrap.KdfOptions kdf) throws Exception {
        boolean masterPresent = masterBlob != null && masterBlob.length > 0;
        boolean userFallbackAvailable = userBlob != null
                && userBlob.length >= Constants.USER_KDF_SALT_SIZE
                        + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN
                && password != null && password.length > 0;
        if (masterPresent && useMaster) {
            try {
                if (EcKeys.isEcMasterBlob(masterBlob)) {
                    if (PQ.strictPqOnly()) {
                        throw new IllegalArgumentException(
                                "EC master blobs are disabled in PQ strict mode");
                    }
                    java.security.PrivateKey privateKey = EcKeys.loadMasterPrivate();
                    byte[] shared = EcKeys.kemDecrypt(masterBlob, privateKey);
                    return deriveKemKeyAndWipe(shared, kemInfo);
                }
                return recoverPqKemKey(masterBlob, kemInfo);
            } catch (Exception exc) {
                if (!userFallbackAvailable) {
                    throw exc;
                }
            }
        }
        if (masterPresent && !useMaster && !userFallbackAvailable) {
            throw new IllegalArgumentException("Master key required to decrypt this payload");
        }
        if (!userFallbackAvailable) {
            if (userBlob == null || userBlob.length == 0) {
                throw new IllegalArgumentException("Ciphertext missing key transport data");
            }
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("User password required to decrypt this payload");
            }
            throw new IllegalArgumentException(
                    "Corrupted user key blob: missing salt or AEAD data");
        }
        byte[] salt = Arrays.copyOfRange(userBlob, 0, Constants.USER_KDF_SALT_SIZE);
        byte[] wrapped = Arrays.copyOfRange(
                userBlob, Constants.USER_KDF_SALT_SIZE, userBlob.length);
        byte[] userKey = deriveUserKey(password, salt, kdfLabel, kdf);
        try {
            return Crypto.aesGcmDecrypt(userKey, wrapped, aad);
        } finally {
            Arrays.fill(userKey, (byte) 0);
        }
    }
}
