/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class JavaCryptoBackendStreamingTest {
    @Test
    public void decryptsPayloadLargerThanStreamingOutputBuffer() throws Exception {
        byte[] key = new byte[32];
        // SunJCE rejects reinitializing an encryption Cipher with a key/nonce
        // pair already used in the same worker. Other AES-GCM tests use the
        // all-zero pair, so generate a fresh nonce here just as production
        // callers must.
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        byte[] aad = "basefwx.test.streaming-aead.v1"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = new byte[3 * Constants.STREAM_CHUNK_SIZE + 37];
        for (int i = 0; i < plaintext.length; ++i) {
            plaintext[i] = (byte) (i * 31 + 17);
        }

        byte[] ciphertext = CryptoBackends.call(
                CryptoBackends.java(),
                () -> Crypto.aesGcmEncryptWithIv(key, nonce, plaintext, aad));
        int bodyLength = ciphertext.length - Constants.AEAD_TAG_LEN;
        byte[] outBuffer = new byte[Constants.STREAM_CHUNK_SIZE];
        ByteArrayOutputStream restored = new ByteArrayOutputStream(plaintext.length);

        try (CryptoBackend.AeadDecryptor decryptor =
                     CryptoBackends.java().newGcmDecryptor(key, nonce, aad)) {
            int offset = 0;
            while (offset < bodyLength) {
                int length = Math.min(Constants.STREAM_CHUNK_SIZE, bodyLength - offset);
                int written = decryptor.update(
                        ciphertext, offset, length, outBuffer, 0);
                restored.write(outBuffer, 0, written);
                offset += length;
            }
            int written = decryptor.doFinal(
                    ciphertext,
                    bodyLength,
                    Constants.AEAD_TAG_LEN,
                    outBuffer,
                    0);
            restored.write(outBuffer, 0, written);
        } finally {
            Arrays.fill(key, (byte) 0);
        }

        assertArrayEquals(plaintext, restored.toByteArray());
    }
}
