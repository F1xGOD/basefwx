/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CryptoApiSafetyTest {
    private static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex fixture");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

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
                new byte[16], iv, input, 0, 1, output, 0, null));
        expectIllegalArgument(() -> Crypto.aesGcmEncryptWithIvInto(
                new byte[24], iv, input, 0, 1, output, 0, null));
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

    @Test
    public void validatesHkdfBoundariesBeforeAllocation() {
        byte[] keyMaterial = new byte[] {1};
        byte[] info = new byte[] {2};
        assertTrue(Crypto.hkdfSha256(
                keyMaterial, info, Constants.HKDF_MAX_LEN).length
                == Constants.HKDF_MAX_LEN);
        expectIllegalArgument(() -> Crypto.hkdfSha256(
                keyMaterial, info, -1));
        expectIllegalArgument(() -> Crypto.hkdfSha256(
                keyMaterial, info, Constants.HKDF_MAX_LEN + 1));
        expectIllegalArgument(() -> Crypto.hkdfSha256(
                null, info, 32));
        expectIllegalArgument(() -> Crypto.compatPrfStreamSha256(
                keyMaterial, info, -1));
    }

    @Test
    public void pbkdf2UsesUtf8BytesAcrossRuntimeImplementations() {
        byte[] password = "pässwörd-密碼".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "basefwx-unicode-salt".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = fromHex(
                "f36111f8498228a4c642fb6fa1deef6a"
                + "2fa6d2441c727b68dac19d28f5455cb8");
        assertArrayEquals(
                expected,
                Crypto.pbkdf2HmacSha256(password, salt, 2, 32));
    }

    @Test
    public void pbkdf2RejectsInvalidInputsBeforeAllocation() {
        byte[] password = "password".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        expectIllegalArgument(() -> Crypto.pbkdf2HmacSha256(
                null, salt, 2, 32));
        expectIllegalArgument(() -> Crypto.pbkdf2HmacSha256(
                password, new byte[0], 2, 32));
        expectIllegalArgument(() -> Crypto.pbkdf2HmacSha256(
                password, salt, 2, Integer.MAX_VALUE / 8 + 1));
    }
}
