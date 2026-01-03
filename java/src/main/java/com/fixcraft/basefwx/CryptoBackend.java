package com.fixcraft.basefwx;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;

public interface CryptoBackend {
    boolean isNative();

    AeadEncryptor newGcmEncryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException;

    AeadDecryptor newGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException;

    interface AeadEncryptor extends AutoCloseable {
        int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException;

        int doFinal(byte[] out, int outOff) throws GeneralSecurityException;

        @Override
        void close();
    }

    interface AeadDecryptor extends AutoCloseable {
        int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException;

        int doFinal(byte[] tag, int tagOff, int tagLen, byte[] out, int outOff)
            throws AEADBadTagException, GeneralSecurityException;

        @Override
        void close();
    }
}
