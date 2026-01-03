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

        private JavaGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
        }

        @Override
        public int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException {
            return cipher.update(in, inOff, len, out, outOff);
        }

        @Override
        public int doFinal(byte[] tag, int tagOff, int tagLen, byte[] out, int outOff)
            throws GeneralSecurityException {
            return cipher.doFinal(tag, tagOff, tagLen, out, outOff);
        }

        @Override
        public void close() {
        }
    }
}
