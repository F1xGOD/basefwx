/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public final class JavaCryptoBackend implements CryptoBackend {
    private static final byte[] RESET_KEY = new byte[Constants.FWXAES_KEY_LEN];

    @Override
    public boolean isNative() {
        return false;
    }

    @Override
    public AeadEncryptor newGcmEncryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
        return new JavaGcmEncryptor(key, iv, aad);
    }

    @Override
    public AeadDecryptor newGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
        return new JavaGcmDecryptor(key, iv, aad);
    }

    private static final class JavaGcmEncryptor implements AeadEncryptor {
        private Cipher cipher;

        private JavaGcmEncryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
        }

        @Override
        public int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException {
            // For streaming, use byte[] - AES-GCM buffers until doFinal anyway
            return requireOpen().update(in, inOff, len, out, outOff);
        }

        @Override
        public int doFinal(byte[] out, int outOff) throws GeneralSecurityException {
            return requireOpen().doFinal(out, outOff);
        }

        @Override
        public void close() {
            Cipher current = cipher;
            cipher = null;
            neutralize(current);
        }

        private Cipher requireOpen() throws GeneralSecurityException {
            if (cipher == null) {
                throw new GeneralSecurityException("AES-GCM encryptor is closed");
            }
            return cipher;
        }
    }

    private static final class JavaGcmDecryptor implements AeadDecryptor {
        private GCMModeCipher cipher;

        private JavaGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
            try {
                cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
                cipher.init(
                        false,
                        new AEADParameters(
                                new KeyParameter(key),
                                Constants.AEAD_TAG_LEN * 8,
                                iv,
                                aad == null ? new byte[0] : aad));
            } catch (RuntimeException exc) {
                throw new GeneralSecurityException("AES-GCM decrypt init failed", exc);
            }
        }

        @Override
        public int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException {
            try {
                return requireOpen().processBytes(in, inOff, len, out, outOff);
            } catch (RuntimeException exc) {
                throw new GeneralSecurityException("AES-GCM decrypt update failed", exc);
            }
        }

        @Override
        public int doFinal(byte[] tag, int tagOff, int tagLen, byte[] out, int outOff)
            throws GeneralSecurityException {
            if (tagLen != Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException(
                        "Invalid AES-GCM tag length: " + tagLen);
            }
            try {
                GCMModeCipher current = requireOpen();
                int processed = current.processBytes(
                        tag, tagOff, tagLen, out, outOff);
                return processed + current.doFinal(out, outOff + processed);
            } catch (InvalidCipherTextException exc) {
                AEADBadTagException badTag =
                        new AEADBadTagException("AES-GCM authentication failed");
                badTag.initCause(exc);
                throw badTag;
            } catch (RuntimeException exc) {
                throw new GeneralSecurityException(
                        "AES-GCM decrypt final failed", exc);
            }
        }

        @Override
        public void close() {
            GCMModeCipher current = cipher;
            cipher = null;
            neutralize(current);
        }

        private GCMModeCipher requireOpen() throws GeneralSecurityException {
            if (cipher == null) {
                throw new GeneralSecurityException("AES-GCM decryptor is closed");
            }
            return cipher;
        }
    }

    private static void neutralize(Cipher cipher) {
        if (cipher == null) {
            return;
        }
        byte[] resetIv = null;
        try {
            resetIv = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(RESET_KEY, "AES"),
                    new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, resetIv));
        } catch (GeneralSecurityException | RuntimeException ignored) {
            // Dropping the last reference still prevents reuse when a provider
            // cannot be explicitly reinitialized after finalization.
        } finally {
            if (resetIv != null) {
                Arrays.fill(resetIv, (byte) 0);
            }
        }
    }

    private static void neutralize(GCMModeCipher cipher) {
        if (cipher == null) {
            return;
        }
        byte[] resetIv = null;
        try {
            resetIv = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
            cipher.init(
                    false,
                    new AEADParameters(
                            new KeyParameter(RESET_KEY),
                            Constants.AEAD_TAG_LEN * 8,
                            resetIv,
                            new byte[0]));
        } catch (RuntimeException ignored) {
            // The context is unreachable after close even if neutralization
            // is unavailable in a particular provider implementation.
        } finally {
            if (resetIv != null) {
                Arrays.fill(resetIv, (byte) 0);
            }
        }
    }
}
