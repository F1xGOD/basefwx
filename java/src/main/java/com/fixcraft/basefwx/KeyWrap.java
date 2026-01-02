package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.IntStream;

public final class KeyWrap {
    private KeyWrap() {}

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
        EcKeys.EcKemResult kem = null;
        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(true);
                if (pub != null) {
                    kem = EcKeys.kemEncrypt(pub);
                    useMasterEffective = true;
                }
            } catch (Exception exc) {
                useMasterEffective = false;
            }
        }
        if (!hasPassword && !useMasterEffective) {
            throw new IllegalArgumentException("Password required when master key is unavailable");
        }

        MaskKeyResult result = new MaskKeyResult();
        result.usedMaster = useMasterEffective;
        if (useMasterEffective && kem != null) {
            result.masterBlob = kem.masterBlob;
            result.maskKey = Crypto.hkdfSha256(kem.shared, maskInfo, 32);
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
            byte[] wrapped = Crypto.aesGcmEncrypt(userKey, result.maskKey, aad);
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            if (labelBytes.length > 255) {
                throw new IllegalArgumentException("KDF label too long");
            }
            int total = 1 + labelBytes.length + salt.length + wrapped.length;
            byte[] userBlob = new byte[total];
            userBlob[0] = (byte) labelBytes.length;
            System.arraycopy(labelBytes, 0, userBlob, 1, labelBytes.length);
            System.arraycopy(salt, 0, userBlob, 1 + labelBytes.length, salt.length);
            System.arraycopy(wrapped, 0, userBlob, 1 + labelBytes.length + salt.length, wrapped.length);
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
            if (!startsWith(masterBlob, Constants.MASTER_EC_MAGIC)) {
                throw new IllegalArgumentException("PQ master key not supported in Java");
            }
            java.security.PrivateKey priv = EcKeys.loadMasterPrivate();
            byte[] shared = EcKeys.kemDecrypt(masterBlob, priv);
            return Crypto.hkdfSha256(shared, maskInfo, 32);
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
        return Crypto.aesGcmDecrypt(userKey, wrapped, aad);
    }

    public static byte[] maskPayload(byte[] maskKey, byte[] payload, byte[] info) {
        if (payload.length == 0) {
            return new byte[0];
        }
        byte[] stream = Crypto.hkdfSha256(maskKey, info, payload.length);
        byte[] out = new byte[payload.length];
        int len = payload.length;
        int cores = Runtime.getRuntime().availableProcessors();
        int threshold = 1 << 20;
        if (len < threshold || cores < 2) {
            for (int i = 0; i < len; i++) {
                out[i] = (byte) (payload[i] ^ stream[i]);
            }
            return out;
        }
        int chunk = 1 << 20;
        int segments = (len + chunk - 1) / chunk;
        IntStream.range(0, segments).parallel().forEach(seg -> {
            int start = seg * chunk;
            int end = Math.min(len, start + chunk);
            for (int i = start; i < end; i++) {
                out[i] = (byte) (payload[i] ^ stream[i]);
            }
        });
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
        if (hardened.pbkdf2Iterations < Constants.SHORT_PBKDF2_ITERS) {
            hardened.pbkdf2Iterations = Constants.SHORT_PBKDF2_ITERS;
        }
        return hardened;
    }

    private static String resolveKdfLabel(String label) {
        if (label == null || label.isEmpty() || "auto".equalsIgnoreCase(label)) {
            return "pbkdf2";
        }
        String normalized = label.toLowerCase();
        if (normalized.startsWith("argon2")) {
            throw new IllegalArgumentException("Argon2 KDF not supported in Java module");
        }
        if (!"pbkdf2".equals(normalized)) {
            throw new IllegalArgumentException("Unsupported KDF label: " + normalized);
        }
        return normalized;
    }

    private static byte[] deriveUserKeyWithLabel(byte[] password, byte[] salt, String label, KdfOptions kdf) {
        if (salt.length < Constants.USER_KDF_SALT_SIZE) {
            throw new IllegalArgumentException("User key salt must be at least 16 bytes");
        }
        if (!"pbkdf2".equals(label)) {
            throw new IllegalArgumentException("Unsupported KDF label: " + label);
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
