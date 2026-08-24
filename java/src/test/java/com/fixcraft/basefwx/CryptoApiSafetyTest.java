/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CryptoApiSafetyTest {
    private static void expectIllegalArgument(Runnable action) {
        try {
            action.run();
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    @Test
    public void rejectsInvalidSlicesBeforeBackendDispatch() {
        if (Boolean.getBoolean("basefwx.test.requireJNI")) {
            assertTrue("JNI backend was required but not active",
                    NativeCryptoBackend.isAvailable() && CryptoBackends.usingNative());
        }
        byte[] key = new byte[32];
        byte[] iv = new byte[Constants.AEAD_NONCE_LEN];
        byte[] input = new byte[32];
        byte[] output = new byte[64];

        expectIllegalArgument(() -> Crypto.aesGcmEncryptWithIvInto(
                new byte[31], iv, input, 0, 1, output, 0, null));
        expectIllegalArgument(() -> Crypto.aesGcmEncryptWithIvInto(
                key, iv, input, -1, 1, output, 0, null));
        expectIllegalArgument(() -> Crypto.aesGcmEncryptWithIvInto(
                key, iv, input, Integer.MAX_VALUE, 1, output, 0, null));
        expectIllegalArgument(() -> Crypto.aesGcmEncryptWithIvInto(
                key, iv, input, 0, input.length, output, Integer.MAX_VALUE, null));
        expectIllegalArgument(() -> Crypto.aesGcmDecryptWithIvInto(
                key, iv, input, 0, Constants.AEAD_TAG_LEN - 1,
                output, 0, null));
        expectIllegalArgument(() -> Crypto.aesGcmDecryptWithIvInto(
                key, iv, input, Integer.MAX_VALUE, Constants.AEAD_TAG_LEN,
                output, 0, null));
    }

    @Test
    public void authenticationFailureDoesNotModifyCallerOutput() {
        byte[] key = new byte[32];
        byte[] iv = new byte[Constants.AEAD_NONCE_LEN];
        byte[] plaintext = new byte[] {1, 2, 3, 4, 5};
        byte[] ciphertext = Crypto.aesGcmEncryptWithIv(key, iv, plaintext, null);
        ciphertext[ciphertext.length - 1] ^= 1;

        byte[] output = new byte[plaintext.length + 4];
        Arrays.fill(output, (byte) 0x5a);
        byte[] before = output.clone();
        try {
            Crypto.aesGcmDecryptWithIvInto(
                    key, iv, ciphertext, 0, ciphertext.length, output, 2, null);
            fail("expected authentication failure");
        } catch (Crypto.AuthenticationException expected) {
            // Expected.
        }
        assertArrayEquals(before, output);
    }
}
