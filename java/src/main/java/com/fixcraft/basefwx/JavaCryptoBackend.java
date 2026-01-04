package com.fixcraft.basefwx;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class JavaCryptoBackend implements CryptoBackend {
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
        private final Cipher cipher;

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
            return cipher.update(in, inOff, len, out, outOff);
        }

        @Override
        public int doFinal(byte[] out, int outOff) throws GeneralSecurityException {
            return cipher.doFinal(out, outOff);
        }

        @Override
        public void close() {
        }
    }

    private static final class JavaGcmDecryptor implements AeadDecryptor {
        private final Cipher cipher;
        private final java.io.ByteArrayOutputStream buffer;

        private JavaGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            buffer = new java.io.ByteArrayOutputStream();
        }

        @Override
        public int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException {
            // Buffer the ciphertext instead of processing it immediately
            // This is because Java's GCM implementation doesn't support streaming
            buffer.write(in, inOff, len);
            return 0;  // No output until doFinal
        }

        @Override
        public int doFinal(byte[] tag, int tagOff, int tagLen, byte[] out, int outOff)
            throws GeneralSecurityException {
            // Append tag to buffered ciphertext
            buffer.write(tag, tagOff, tagLen);
            byte[] ciphertext = buffer.toByteArray();
            
            // Process all at once
            byte[] plaintext = cipher.doFinal(ciphertext);
            
            // Check if output buffer is large enough
            if (out.length - outOff < plaintext.length) {
                throw new javax.crypto.ShortBufferException(
                    "Output buffer too small: need " + plaintext.length + 
                    " bytes but only " + (out.length - outOff) + " available");
            }
            
            // Copy result to output buffer
            if (plaintext.length > 0) {
                System.arraycopy(plaintext, 0, out, outOff, plaintext.length);
            }
            return plaintext.length;
        }

        @Override
        public void close() {
        }
    }
}
