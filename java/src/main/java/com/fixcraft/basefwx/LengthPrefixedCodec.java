/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

final class LengthPrefixedCodec {
    private LengthPrefixedCodec() {}

    static byte[] encryptAesPayload(String plaintext,
                                            String password,
                                            boolean useMaster,
                                            String metadataBlob,
                                            String kdfLabel,
                                            int kdfIterations,
                                            boolean obfuscate,
                                            boolean fastObf) {
        byte[] payloadBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return encryptAesPayloadBytes(payloadBytes, password, useMaster, metadataBlob,
            kdfLabel, kdfIterations, obfuscate, fastObf);
    }

    static byte[] encryptAesPayloadBytes(byte[] payloadBytes,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataBlob,
                                                 String kdfLabel,
                                                 int kdfIterations,
                                                 boolean obfuscate,
                                                 boolean fastObf) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        if (pw.length == 0 && !useMaster) {
            throw new IllegalArgumentException("Cannot encrypt without password or master key");
        }
        byte[] metadataBytes = metadataBlob == null ? new byte[0] : metadataBlob.getBytes(StandardCharsets.UTF_8);
        byte[] aad = metadataBytes;

        byte[] masterBlob = new byte[0];
        byte[] ephemeralKey = null;
        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(EcKeys.masterEcAutoCreateEnabled());
                if (pub != null) {
                    EcKeys.EcKemResult kem = EcKeys.kemEncrypt(pub);
                    masterBlob = kem.masterBlob;
                    ephemeralKey = Crypto.hkdfSha256(kem.shared, Constants.KEM_INFO, 32);
                }
            } catch (RuntimeException exc) {
                ephemeralKey = null;
            }
        }
        if (ephemeralKey == null) {
            ephemeralKey = Crypto.randomBytes(32);
        }

        byte[] userBlob = new byte[0];
        if (pw.length > 0) {
            int iters = FileCodecs.hardenPbkdf2Iterations(pw, kdfIterations);
            byte[] salt = Crypto.randomBytes(Constants.USER_KDF_SALT_SIZE);
            String label = FileCodecs.resolveKdfLabel(kdfLabel);
            if (!"pbkdf2".equals(label)) {
                throw new UnsupportedKdfException(label, "Unsupported KDF label: " + label);
            }
            byte[] userKey = Crypto.pbkdf2HmacSha256(pw, salt, iters, 32);
            byte[] wrapped = Crypto.aesGcmEncrypt(userKey, ephemeralKey, aad);
            userBlob = new byte[salt.length + wrapped.length];
            System.arraycopy(salt, 0, userBlob, 0, salt.length);
            System.arraycopy(wrapped, 0, userBlob, salt.length, wrapped.length);
        }

        if (obfuscate && FileCodecs.payloadObfuscationEnabled()) {
            payloadBytes = FileCodecs.obfuscateBytes(payloadBytes, ephemeralKey, fastObf);
        }

        byte[] ciphertext = Crypto.aesGcmEncrypt(ephemeralKey, payloadBytes, aad);
        byte[] payload = new byte[4 + metadataBytes.length + ciphertext.length];
        BaseFwxUtil.writeU32(payload, 0, metadataBytes.length);
        System.arraycopy(metadataBytes, 0, payload, 4, metadataBytes.length);
        System.arraycopy(ciphertext, 0, payload, 4 + metadataBytes.length, ciphertext.length);
        return Format.packLengthPrefixed(Arrays.asList(userBlob, masterBlob, payload));
    }

    static String decryptAesPayload(byte[] blob, String password, boolean useMaster) {
        byte[] plain = decryptAesPayloadBytes(blob, password, useMaster);
        return new String(plain, StandardCharsets.UTF_8);
    }

    static byte[] decryptAesPayloadBytes(byte[] blob, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        byte[] userBlob = parts.get(0);
        byte[] masterBlob = parts.get(1);
        byte[] payloadBlob = parts.get(2);
        if (payloadBlob.length < 4) {
            throw new IllegalArgumentException("Ciphertext payload truncated");
        }
        int metadataLen = BaseFwxUtil.readU32(payloadBlob, 0);
        int metadataEnd = 4 + metadataLen;
        if (metadataEnd > payloadBlob.length) {
            throw new IllegalArgumentException("Malformed payload metadata header");
        }
        byte[] metadataBytes = Arrays.copyOfRange(payloadBlob, 4, metadataEnd);
        String metadataBlob = metadataBytes.length == 0
            ? ""
            : new String(metadataBytes, StandardCharsets.UTF_8);

        String obfHint = FileCodecs.metaValue(metadataBlob, "ENC-OBF");
        boolean shouldDeobfuscate = FileCodecs.payloadObfuscationEnabled() && !"no".equalsIgnoreCase(obfHint);
        boolean fastObf = "fast".equalsIgnoreCase(obfHint);
        String kdfHint = FileCodecs.metaValue(metadataBlob, "ENC-KDF");
        if (kdfHint.isEmpty()) {
            kdfHint = FileCodecs.resolveUserKdfLabel();
        }
        int kdfIterHint = FileCodecs.parseMetadataInt(FileCodecs.metaValue(metadataBlob, "ENC-KDF-ITER"), Constants.USER_KDF_ITERATIONS);

        byte[] ephemeralKey;
        if (masterBlob.length > 0) {
            if (!useMaster) {
                throw new IllegalArgumentException("Master key required to decrypt this payload");
            }
            if (!FileCodecs.startsWith(masterBlob, Constants.MASTER_EC_MAGIC)) {
                throw new IllegalArgumentException("Invalid master key blob magic");
            }
            java.security.PrivateKey priv = EcKeys.loadMasterPrivate();
            byte[] shared = EcKeys.kemDecrypt(masterBlob, priv);
            ephemeralKey = Crypto.hkdfSha256(shared, Constants.KEM_INFO, 32);
        } else if (userBlob.length > 0) {
            if (pw.length == 0) {
                throw new IllegalArgumentException("User password required to decrypt this payload");
            }
            if (userBlob.length < Constants.USER_KDF_SALT_SIZE + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Corrupted user key blob: missing salt or AEAD data");
            }
            byte[] salt = Arrays.copyOfRange(userBlob, 0, Constants.USER_KDF_SALT_SIZE);
            byte[] wrapped = Arrays.copyOfRange(userBlob, Constants.USER_KDF_SALT_SIZE, userBlob.length);
            String label = FileCodecs.resolveKdfLabel(kdfHint);
            if (!"pbkdf2".equals(label)) {
                throw new IllegalArgumentException("Unsupported KDF label: " + label);
            }
            int iters = FileCodecs.hardenPbkdf2Iterations(pw, kdfIterHint);
            byte[] userKey = Crypto.pbkdf2HmacSha256(pw, salt, iters, 32);
            ephemeralKey = Crypto.aesGcmDecrypt(userKey, wrapped, metadataBytes);
        } else {
            throw new IllegalArgumentException("Ciphertext missing key transport data");
        }

        byte[] ciphertext = Arrays.copyOfRange(payloadBlob, metadataEnd, payloadBlob.length);
        byte[] plain = Crypto.aesGcmDecrypt(ephemeralKey, ciphertext, metadataBytes);
        if (shouldDeobfuscate) {
            plain = FileCodecs.deobfuscateBytes(plain, ephemeralKey, fastObf);
        }
        return plain;
    }

}
