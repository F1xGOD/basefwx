/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
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
            kdfLabel, kdfIterations, obfuscate, fastObf,
            null, null, null, KeyWrap.selectMasterKey(useMaster));
    }

    static byte[] encryptAesPayloadBytes(byte[] payloadBytes,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataBlob,
                                                 String kdfLabel,
                                                 int kdfIterations,
                                                 boolean obfuscate,
                                                 boolean fastObf) {
        return encryptAesPayloadBytes(payloadBytes, password, useMaster, metadataBlob,
            kdfLabel, kdfIterations, obfuscate, fastObf, null, null, null,
            KeyWrap.selectMasterKey(useMaster));
    }

    static byte[] encryptAesPayloadBytes(byte[] payloadBytes,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataBlob,
                                                 String kdfLabel,
                                                 int kdfIterations,
                                                 boolean obfuscate,
                                                 boolean fastObf,
                                                 Integer argonTime,
                                                 Integer argonMem,
                                                 Integer argonPar) {
        return encryptAesPayloadBytes(
                payloadBytes, password, useMaster, metadataBlob, kdfLabel,
                kdfIterations, obfuscate, fastObf, argonTime, argonMem,
                argonPar, KeyWrap.selectMasterKey(useMaster));
    }

    static byte[] encryptAesPayloadBytes(byte[] payloadBytes,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataBlob,
                                                 String kdfLabel,
                                                 int kdfIterations,
                                                 boolean obfuscate,
                                                 boolean fastObf,
                                                 Integer argonTime,
                                                 Integer argonMem,
                                                 Integer argonPar,
                                                 KeyWrap.MasterKeySelection selectedMaster) {
        String resolvedKdfLabel = FileCodecKdf.resolveKdfLabel(kdfLabel);
        if ("pbkdf2".equals(resolvedKdfLabel)) {
            FileCodecKdf.requirePeerPbkdf2WithinLimits(kdfIterations);
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        try {
            return encryptAesPayloadBytesWithPassword(
                    payloadBytes,
                    pw,
                    useMaster,
                    metadataBlob,
                    resolvedKdfLabel,
                    kdfIterations,
                    obfuscate,
                    fastObf,
                    argonTime,
                    argonMem,
                    argonPar,
                    selectedMaster);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    private static byte[] encryptAesPayloadBytesWithPassword(
            byte[] payloadBytes,
            byte[] pw,
            boolean useMaster,
            String metadataBlob,
            String resolvedKdfLabel,
            int kdfIterations,
            boolean obfuscate,
            boolean fastObf,
            Integer argonTime,
            Integer argonMem,
            Integer argonPar,
            KeyWrap.MasterKeySelection selectedMaster) {
        PasswordPolicy.requireStrongPassword(pw, "Encryption");
        boolean useMasterEffective =
                useMaster && selectedMaster != null && selectedMaster.usedMaster();
        if (pw.length == 0 && !useMasterEffective) {
            throw new IllegalArgumentException("Cannot encrypt without password or master key");
        }
        if (useMaster && PQ.strictPqOnly()
                && (!useMasterEffective || selectedMaster.pqPublicKey == null)) {
            throw new IllegalStateException(
                    "PQ strict mode requires an ML-KEM master public key "
                    + "when master wrap is requested");
        }
        byte[] metadataBytes = metadataBlob == null ? new byte[0] : metadataBlob.getBytes(StandardCharsets.UTF_8);
        if (metadataBytes.length > Constants.METADATA_MAX) {
            throw new IllegalArgumentException(
                    "Payload metadata exceeds 1 MiB cap");
        }
        byte[] aad = metadataBytes;

        byte[] masterBlob = new byte[0];
        byte[] ephemeralKey = null;
        PayloadKeySeparation.PayloadKeys payloadKeys = null;
        try {
            if (useMasterEffective) {
                if (selectedMaster.pqPublicKey != null) {
                    try {
                        try (PQ.KemResult kem =
                                PQ.kemEncrypt(selectedMaster.pqPublicKey)) {
                            masterBlob = kem.ciphertext;
                            ephemeralKey = FileCodecKdf.deriveKemKeyAndWipe(
                                    kem.shared, Constants.KEM_INFO);
                        }
                    } catch (Exception exc) {
                        if (exc instanceof RuntimeException) {
                            throw (RuntimeException) exc;
                        }
                        throw new IllegalStateException("PQ master key wrap failed", exc);
                    }
                } else if (selectedMaster.ecPublicKey != null) {
                    try {
                        EcKeys.EcKemResult kem =
                                EcKeys.kemEncrypt(selectedMaster.ecPublicKey);
                        masterBlob = kem.masterBlob;
                        ephemeralKey =
                                FileCodecKdf.deriveKemKeyAndWipe(kem.shared, Constants.KEM_INFO);
                    } catch (Exception exc) {
                        throw new IllegalStateException(
                                "EC master key wrap failed", exc);
                    }
                }
            }
            if (ephemeralKey == null) {
                ephemeralKey = Crypto.randomBytes(32);
            }
            byte[] userBlob = new byte[0];
            if (pw.length > 0) {
                String label = resolvedKdfLabel;
                byte[] salt = Crypto.randomBytes(Constants.USER_KDF_SALT_SIZE);
                KeyWrap.KdfOptions opts = new KeyWrap.KdfOptions(label, kdfIterations);
                if (argonTime != null) {
                    opts.argon2TimeCost = argonTime;
                }
                if (argonMem != null) {
                    opts.argon2MemoryKib = argonMem;
                }
                if (argonPar != null) {
                    opts.argon2Parallelism = argonPar;
                }
                byte[] userKey = FileCodecKdf.deriveUserKey(pw, salt, label, opts);
                try {
                    byte[] wrapped = Crypto.aesGcmEncrypt(userKey, ephemeralKey, aad);
                    userBlob = new byte[salt.length + wrapped.length];
                    System.arraycopy(salt, 0, userBlob, 0, salt.length);
                    System.arraycopy(wrapped, 0, userBlob, salt.length, wrapped.length);
                } finally {
                    Arrays.fill(userKey, (byte) 0);
                }
            }

            boolean useDerivedKeys =
                    PayloadKeySeparation.usesDerivedKeys(metadataBlob);
            byte[] aeadKey = ephemeralKey;
            byte[] obfuscationKey = ephemeralKey;
            if (useDerivedKeys) {
                payloadKeys = PayloadKeySeparation.derive(ephemeralKey);
                aeadKey = payloadKeys.aead;
                obfuscationKey = payloadKeys.obfuscation;
            }
            if (obfuscate && FileCodecs.payloadObfuscationEnabled()) {
                payloadBytes = FileCodecs.obfuscateBytes(
                        payloadBytes, obfuscationKey, fastObf);
            }

            byte[] ciphertext = Crypto.aesGcmEncrypt(
                    aeadKey, payloadBytes, aad);
            byte[] payload = new byte[4 + metadataBytes.length + ciphertext.length];
            BaseFwxUtil.writeU32(payload, 0, metadataBytes.length);
            System.arraycopy(metadataBytes, 0, payload, 4, metadataBytes.length);
            System.arraycopy(ciphertext, 0, payload, 4 + metadataBytes.length, ciphertext.length);
            return Format.packLengthPrefixed(Arrays.asList(userBlob, masterBlob, payload));
        } finally {
            if (payloadKeys != null) {
                payloadKeys.close();
            }
            PayloadKeySeparation.wipe(ephemeralKey);
        }
    }

    static String decryptAesPayload(byte[] blob, String password, boolean useMaster) {
        byte[] plain = decryptAesPayloadBytes(blob, password, useMaster);
        try {
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    static byte[] decryptAesPayloadBytes(byte[] blob, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        try {
            return decryptAesPayloadBytesWithPassword(
                    blob, pw, useMaster);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    private static byte[] decryptAesPayloadBytesWithPassword(
            byte[] blob, byte[] pw, boolean useMaster) {
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        byte[] userBlob = parts.get(0);
        byte[] masterBlob = parts.get(1);
        byte[] payloadBlob = parts.get(2);
        if (payloadBlob.length < 4) {
            throw new IllegalArgumentException("Ciphertext payload truncated");
        }
        int metadataLen = BaseFwxUtil.readU32(payloadBlob, 0);
        if (metadataLen < 0) {
            throw new IllegalArgumentException(
                    "Malformed payload metadata header (negative length)");
        }
        if (metadataLen > Constants.METADATA_MAX) {
            throw new IllegalArgumentException(
                    "Payload metadata exceeds 1 MiB cap");
        }
        if (metadataLen > payloadBlob.length - 4) {
            throw new IllegalArgumentException("Malformed payload metadata header");
        }
        int metadataEnd = 4 + metadataLen;
        byte[] metadataBytes = Arrays.copyOfRange(payloadBlob, 4, metadataEnd);
        String metadataBlob = metadataBytes.length == 0
            ? ""
            : new String(metadataBytes, StandardCharsets.UTF_8);

        FileCodecs.requireSupportedPackMode(metadataBlob);
        String obfHint = FileCodecs.requirePayloadObfuscationMode(
                FileCodecs.metaValue(metadataBlob, "ENC-OBF"));
        boolean shouldDeobfuscate = !"no".equals(obfHint);
        boolean fastObf = "fast".equals(obfHint);
        String kdfHint = FileCodecs.metaValue(metadataBlob, "ENC-KDF");
        String label = kdfHint.isEmpty()
                ? FileCodecKdf.resolveUserKdfLabel()
                : FileCodecKdf.resolvePeerKdfLabel(kdfHint);
        int kdfIterHint = FileCodecs.parsePeerPbkdf2Iterations(
                FileCodecs.metaValue(metadataBlob, "ENC-KDF-ITER"),
                Constants.USER_KDF_ITERATIONS);
        Integer argonTime = FileCodecs.parseMetadataIntOrNull(FileCodecs.metaValue(metadataBlob, "ENC-ARGON2-TC"));
        Integer argonMem = FileCodecs.parseMetadataIntOrNull(FileCodecs.metaValue(metadataBlob, "ENC-ARGON2-MEM"));
        Integer argonPar = FileCodecs.parseMetadataIntOrNull(FileCodecs.metaValue(metadataBlob, "ENC-ARGON2-PAR"));
        FileCodecKdf.requirePeerArgon2WithinLimits(argonTime, argonMem, argonPar);

        KeyWrap.KdfOptions opts = new KeyWrap.KdfOptions(label, kdfIterHint);
        if (argonTime != null) {
            opts.argon2TimeCost = argonTime;
        }
        if (argonMem != null) {
            opts.argon2MemoryKib = argonMem;
        }
        if (argonPar != null) {
            opts.argon2Parallelism = argonPar;
        }
        boolean useDerivedKeys =
                PayloadKeySeparation.usesDerivedKeys(metadataBlob);
        byte[] ephemeralKey = null;
        PayloadKeySeparation.PayloadKeys payloadKeys = null;
        try {
            ephemeralKey = FileCodecKdf.recoverPayloadKey(
                    userBlob, masterBlob, pw, useMaster, Constants.KEM_INFO,
                    metadataBytes, label, opts);
        } catch (RuntimeException exc) {
            throw exc;
        } catch (Exception exc) {
            throw new IllegalStateException("Master key unwrap failed", exc);
        }

        try {
            byte[] aeadKey = ephemeralKey;
            byte[] obfuscationKey = ephemeralKey;
            if (useDerivedKeys) {
                payloadKeys = PayloadKeySeparation.derive(ephemeralKey);
                aeadKey = payloadKeys.aead;
                obfuscationKey = payloadKeys.obfuscation;
            }
            byte[] ciphertext = Arrays.copyOfRange(
                    payloadBlob, metadataEnd, payloadBlob.length);
            byte[] plain = Crypto.aesGcmDecrypt(
                    aeadKey, ciphertext, metadataBytes);
            if (shouldDeobfuscate) {
                plain = FileCodecs.deobfuscateBytes(
                        plain, obfuscationKey, fastObf);
            }
            return plain;
        } finally {
            if (payloadKeys != null) {
                payloadKeys.close();
            }
            PayloadKeySeparation.wipe(ephemeralKey);
        }
    }

}
