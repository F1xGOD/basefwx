/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.util.Arrays;

final class PayloadKeySeparation {
    private PayloadKeySeparation() {}

    static boolean usesDerivedKeys(String metadataBlob) {
        String version = FileCodecMetadata.metaValue(
                metadataBlob, "ENC-KSEP");
        if (version == null || version.isEmpty()) {
            return false;
        }
        if (!"v1".equals(version)) {
            throw new IllegalArgumentException(
                    "Unsupported payload key-separation version");
        }
        return true;
    }

    static PayloadKeys derive(byte[] rootKey) {
        if (rootKey == null || rootKey.length == 0) {
            throw new IllegalArgumentException(
                    "Payload root key must not be empty");
        }
        byte[] aead = null;
        byte[] obfuscation = null;
        try {
            aead = Crypto.hkdfSha256(
                    rootKey, Constants.FWXAES_PAYLOAD_AEAD_INFO, 32);
            obfuscation = Crypto.hkdfSha256(
                    rootKey, Constants.FWXAES_PAYLOAD_OBF_INFO, 32);
            return new PayloadKeys(aead, obfuscation);
        } catch (RuntimeException exc) {
            wipe(aead);
            wipe(obfuscation);
            throw exc;
        }
    }

    static void wipe(byte[] secret) {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
        }
    }

    static final class PayloadKeys implements AutoCloseable {
        final byte[] aead;
        final byte[] obfuscation;

        private PayloadKeys(byte[] aead, byte[] obfuscation) {
            this.aead = aead;
            this.obfuscation = obfuscation;
        }

        @Override
        public void close() {
            wipe(aead);
            wipe(obfuscation);
        }
    }
}
