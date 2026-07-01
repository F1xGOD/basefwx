/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class KeyWrap {
    private KeyWrap() {}

    private static final byte[] HKDF_ZERO_SALT = new byte[32];

    public static MaskKeyResult prepareMaskKey(byte[] password,
                                               boolean useMaster,
                                               byte[] maskInfo,
                                               boolean requirePassword,
                                               byte[] aad,
                                               KdfOptions kdf) {
        if (requirePassword && (password == null || password.length == 0)) {
            throw new IllegalArgumentException("Password required for this mode");
        }
        boolean hasPassword = password != null && password.length > 0;
        boolean useMasterEffective = false;
        byte[] pqMasterBlob = null;
        byte[] pqShared = null;
        EcKeys.EcKemResult ecKem = null;
        if (useMaster) {
            if (PQ.isMasterPublicKeyConfigured()) {
                try {
                    byte[] pqPub = PQ.loadMasterPublicKey();
                    PQ.KemResult kem = PQ.kemEncrypt(pqPub);
                    pqMasterBlob = kem.ciphertext;
                    pqShared = kem.shared;
                    useMasterEffective = true;
                } catch (Exception exc) {
                    if (exc instanceof RuntimeException) {
                        throw (RuntimeException) exc;
                    }
                    throw new IllegalStateException("PQ master key wrap failed", exc);
                }
            } else if (!PQ.strictPqOnly()) {
                try {
                    java.security.PublicKey pub =
                            EcKeys.loadMasterPublic(EcKeys.masterEcAutoCreateEnabled());
                    if (pub != null) {
                        ecKem = EcKeys.kemEncrypt(pub);
                        useMasterEffective = true;
                    }
                } catch (Exception exc) {
                    useMasterEffective = false;
                }
            }
        }
        if (!hasPassword && !useMasterEffective) {
            throw new IllegalArgumentException("Password required when master key is unavailable");
        }

        MaskKeyResult result = new MaskKeyResult();
        result.usedMaster = useMasterEffective;
        if (useMasterEffective && pqShared != null) {
            result.masterBlob = pqMasterBlob;
            result.maskKey = Crypto.hkdfSha256(pqShared, maskInfo, 32);
            Arrays.fill(pqShared, (byte) 0);
        } else if (useMasterEffective && ecKem != null) {
            result.masterBlob = ecKem.masterBlob;
            result.maskKey = Crypto.hkdfSha256(ecKem.shared, maskInfo, 32);
            Arrays.fill(ecKem.shared, (byte) 0);
        } else {
            result.masterBlob = new byte[0];
            result.maskKey = Crypto.randomBytes(32);
        }

        result.userBlob = new byte[0];
        if (hasPassword) {
            KdfOptions kdfOpts = hardenKdfOptions(password, kdf);
            String label = resolveKdfLabel(kdfOpts.label);
            byte[] salt = Crypto.randomBytes(Constants.USER_KDF_SALT_SIZE);
            byte[] userKey = deriveUserKeyWithLabel(password, salt, label, kdfOpts);
            byte[] wrapped;
            try {
                wrapped = Crypto.aesGcmEncrypt(userKey, result.maskKey, aad);
            } finally {
                // userKey is PBKDF2-derived from the password; wipe before
                // it goes back to the free-list and waits for GC.
                Arrays.fill(userKey, (byte) 0);
            }
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            if (labelBytes.length > 255) {
                Arrays.fill(wrapped, (byte) 0);
                throw new IllegalArgumentException("KDF label too long");
            }
            int total = 1 + labelBytes.length + salt.length + wrapped.length;
            byte[] userBlob = new byte[total];
            userBlob[0] = (byte) labelBytes.length;
            System.arraycopy(labelBytes, 0, userBlob, 1, labelBytes.length);
            System.arraycopy(salt, 0, userBlob, 1 + labelBytes.length, salt.length);
            System.arraycopy(wrapped, 0, userBlob, 1 + labelBytes.length + salt.length, wrapped.length);
            // wrapped is also derived from the maskKey-encryption pass —
            // not as sensitive as userKey but still scrubbed for hygiene.
            Arrays.fill(wrapped, (byte) 0);
            result.userBlob = userBlob;
        }
        return result;
    }

    public static byte[] recoverMaskKey(byte[] userBlob,
                                        byte[] masterBlob,
                                        byte[] password,
                                        boolean useMaster,
                                        byte[] maskInfo,
                                        byte[] aad,
                                        KdfOptions kdf) {
        if (masterBlob != null && masterBlob.length > 0) {
            if (!useMaster) {
                throw new IllegalArgumentException("Master key required to decode this payload");
            }
            try {
                byte[] shared;
                if (startsWith(masterBlob, Constants.MASTER_EC_MAGIC)) {
                    if (PQ.strictPqOnly()) {
                        throw new IllegalArgumentException(
                                "EC master blobs are disabled in PQ strict mode");
                    }
                    java.security.PrivateKey priv = EcKeys.loadMasterPrivate();
                    shared = EcKeys.kemDecrypt(masterBlob, priv);
                } else {
                    byte[] priv = PQ.loadMasterPrivateKey();
                    try {
                        shared = PQ.kemDecrypt(priv, masterBlob);
                    } finally {
                        Arrays.fill(priv, (byte) 0);
                    }
                }
                try {
                    return Crypto.hkdfSha256(shared, maskInfo, 32);
                } finally {
                    Arrays.fill(shared, (byte) 0);
                }
            } catch (Exception exc) {
                boolean canFallback = userBlob != null && userBlob.length > 0
                        && password != null && password.length > 0;
                if (!canFallback) {
                    if (exc instanceof RuntimeException) {
                        throw (RuntimeException) exc;
                    }
                    throw new IllegalStateException("Master key recovery failed", exc);
                }
            }
        }
        if (userBlob == null || userBlob.length == 0) {
            throw new IllegalArgumentException("Ciphertext missing key transport data");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password required to decode this payload");
        }
        int kdfLen = userBlob[0] & 0xFF;
        int headerLen = 1 + kdfLen + Constants.USER_KDF_SALT_SIZE;
        if (userBlob.length < headerLen) {
            throw new IllegalArgumentException("Corrupted user key blob: truncated data");
        }
        String label = kdfLen > 0
                ? new String(userBlob, 1, kdfLen, StandardCharsets.US_ASCII)
                : resolveKdfLabel(kdf.label);
        byte[] salt = Arrays.copyOfRange(userBlob, 1 + kdfLen, headerLen);
        byte[] wrapped = Arrays.copyOfRange(userBlob, headerLen, userBlob.length);
        KdfOptions hardened = hardenKdfOptions(password, kdf);
        byte[] userKey = deriveUserKeyWithLabel(password, salt, label, hardened);
        try {
            return Crypto.aesGcmDecrypt(userKey, wrapped, aad);
        } finally {
            Arrays.fill(userKey, (byte) 0);
        }
    }

    public static byte[] maskPayload(byte[] maskKey, byte[] payload, byte[] info) {
        if (payload.length == 0) {
            return new byte[0];
        }
        byte[] out = new byte[payload.length];
        int len = payload.length;
        if (len <= Constants.HKDF_MAX_LEN) {
            byte[] stream = Crypto.hkdfSha256(maskKey, info, len);
            for (int i = 0; i < len; i++) {
                out[i] = (byte) (payload[i] ^ stream[i]);
            }
            return out;
        }
        byte[] prk = Crypto.hmacSha256(HKDF_ZERO_SALT, maskKey);
        Crypto.xorHmacStream(prk, info, payload, 0, out, 0, len, 1);
        return out;
    }

    public static byte[] maskPayload(byte[] maskKey,
                                     byte[] payload,
                                     int offset,
                                     int length,
                                     byte[] info) {
        if (length <= 0) {
            return new byte[0];
        }
        if (offset < 0 || offset + length > payload.length) {
            throw new IllegalArgumentException("Invalid payload bounds");
        }
        byte[] out = new byte[length];
        if (length <= Constants.HKDF_MAX_LEN) {
            byte[] stream = Crypto.hkdfSha256(maskKey, info, length);
            for (int i = 0; i < length; i++) {
                out[i] = (byte) (payload[offset + i] ^ stream[i]);
            }
            return out;
        }
        byte[] prk = Crypto.hmacSha256(HKDF_ZERO_SALT, maskKey);
        Crypto.xorHmacStream(prk, info, payload, offset, out, 0, length, 1);
        return out;
    }

    private static KdfOptions hardenKdfOptions(byte[] password, KdfOptions kdf) {
        if (password == null || password.length == 0) {
            return kdf;
        }
        if (Constants.TEST_KDF_OVERRIDE) {
            return kdf;
        }
        if (password.length >= Constants.SHORT_PASSWORD_MIN) {
            return kdf;
        }
        KdfOptions hardened = new KdfOptions(kdf.label, kdf.pbkdf2Iterations);
        hardened.argon2TimeCost = kdf.argon2TimeCost;
        hardened.argon2MemoryKib = kdf.argon2MemoryKib;
        hardened.argon2Parallelism = kdf.argon2Parallelism;
        if (hardened.pbkdf2Iterations < Constants.SHORT_PBKDF2_ITERS) {
            hardened.pbkdf2Iterations = Constants.SHORT_PBKDF2_ITERS;
        }
        // Match the C++ side's short-password Argon2 step-up.
        if (hardened.argon2TimeCost < Constants.SHORT_ARGON2_TIME_COST) {
            hardened.argon2TimeCost = Constants.SHORT_ARGON2_TIME_COST;
        }
        if (hardened.argon2MemoryKib < Constants.SHORT_ARGON2_MEMORY_KIB) {
            hardened.argon2MemoryKib = Constants.SHORT_ARGON2_MEMORY_KIB;
        }
        return hardened;
    }

    private static String resolveKdfLabel(String label) {
        if (label == null || label.isEmpty() || "auto".equalsIgnoreCase(label)) {
            return "pbkdf2";
        }
        String normalized = label.toLowerCase();
        // 3.7.0: Argon2id now supported on the Java side too (uses
        // BouncyCastle's Argon2BytesGenerator, which has been a
        // declared dep since the BC-PQ migration). Normalize both
        // "argon2" and "argon2id" to "argon2id" to match the C++ side.
        if (normalized.startsWith("argon2")) {
            return "argon2id";
        }
        if (!"pbkdf2".equals(normalized)) {
            // True unknown label — typed exception so callers can route
            // to a native helper or surface a specific error.
            throw new UnsupportedKdfException(normalized,
                    "Unsupported KDF label: " + normalized);
        }
        return normalized;
    }

    private static byte[] deriveUserKeyWithLabel(byte[] password, byte[] salt, String label, KdfOptions kdf) {
        if (salt.length < Constants.USER_KDF_SALT_SIZE) {
            throw new IllegalArgumentException("User key salt must be at least 16 bytes");
        }
        if ("argon2id".equals(label) || "argon2".equals(label)) {
            return Crypto.argon2idHashRaw(password, salt,
                    kdf.argon2TimeCost, kdf.argon2MemoryKib, kdf.argon2Parallelism, 32);
        }
        if (!"pbkdf2".equals(label)) {
            throw new UnsupportedKdfException(label,
                    "Unsupported KDF label: " + label);
        }
        return Crypto.pbkdf2HmacSha256(password, salt, kdf.pbkdf2Iterations, 32);
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    public static final class KdfOptions {
        public String label = "pbkdf2";
        public int pbkdf2Iterations = Constants.USER_KDF_ITERATIONS;
        // 3.7.0: Argon2id support — these defaults mirror the C++ side and
        // are only consulted when {@link #label} resolves to "argon2id" /
        // "argon2". Wire-format compatibility relies on encoder and
        // decoder agreeing on these values (they are not stored in the
        // wrap header), so callers should leave them at the defaults
        // unless they also control the C++ side.
        public int argon2TimeCost = Constants.ARGON2_TIME_COST;
        public int argon2MemoryKib = Constants.ARGON2_MEMORY_KIB;
        public int argon2Parallelism = Constants.ARGON2_PARALLELISM;

        public KdfOptions() {}

        public KdfOptions(String label, int iterations) {
            this.label = label;
            this.pbkdf2Iterations = iterations;
        }
    }

    public static final class MaskKeyResult {
        public byte[] maskKey;
        public byte[] userBlob;
        public byte[] masterBlob;
        public boolean usedMaster;
    }
}
