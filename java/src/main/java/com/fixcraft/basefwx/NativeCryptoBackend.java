package com.fixcraft.basefwx;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;

public final class NativeCryptoBackend implements CryptoBackend {
    private static final boolean AVAILABLE = loadNative();

    public static NativeCryptoBackend tryCreate() {
        return AVAILABLE ? new NativeCryptoBackend() : null;
    }

    @Override
    public boolean isNative() {
        return true;
    }

    @Override
    public AeadEncryptor newGcmEncryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
        return new NativeGcmEncryptor(key, iv, aad);
    }

    @Override
    public AeadDecryptor newGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
        return new NativeGcmDecryptor(key, iv, aad);
    }

    private static boolean loadNative() {
        String raw = System.getenv("BASEFWX_NATIVE");
        if (raw != null && !raw.trim().isEmpty()) {
            String v = raw.trim().toLowerCase();
            if (v.equals("0") || v.equals("false") || v.equals("no") || v.equals("off")) {
                return false;
            }
        }
        String lib = System.getenv("BASEFWX_NATIVE_LIB");
        String name = (lib == null || lib.trim().isEmpty()) ? "basefwxcrypto" : lib.trim();
        try {
            System.loadLibrary(name);
            return true;
        } catch (UnsatisfiedLinkError exc) {
            return false;
        }
    }

    private static ByteBuffer toDirect(byte[] data) {
        if (data == null || data.length == 0) {
            return ByteBuffer.allocateDirect(0);
        }
        ByteBuffer buf = ByteBuffer.allocateDirect(data.length);
        buf.put(data);
        buf.flip();
        return buf;
    }

    private static final class NativeGcmEncryptor implements AeadEncryptor {
        private long ctx;

        private NativeGcmEncryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
            ByteBuffer keyBuf = toDirect(key);
            ByteBuffer ivBuf = toDirect(iv);
            ByteBuffer aadBuf = toDirect(aad == null ? new byte[0] : aad);
            ctx = nativeGcmInit(true, keyBuf, key.length, ivBuf, iv.length, aadBuf, aadBuf.remaining());
            if (ctx == 0) {
                throw new GeneralSecurityException("Native GCM init failed");
            }
        }

        @Override
        public int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException {
            if (len == 0) {
                return 0;
            }
            ByteBuffer inBuf = ByteBuffer.allocateDirect(len);
            inBuf.put(in, inOff, len);
            inBuf.flip();
            ByteBuffer outBuf = ByteBuffer.allocateDirect(len + Constants.AEAD_TAG_LEN);
            int written = nativeGcmUpdate(ctx, inBuf, len, outBuf, outBuf.capacity());
            if (written < 0) {
                throw new GeneralSecurityException("Native GCM update failed");
            }
            outBuf.get(out, outOff, written);
            return written;
        }

        @Override
        public int doFinal(byte[] out, int outOff) throws GeneralSecurityException {
            ByteBuffer outBuf = ByteBuffer.allocateDirect(Constants.AEAD_TAG_LEN * 2);
            int written = nativeGcmFinalEncrypt(ctx, outBuf, outBuf.capacity());
            if (written < 0) {
                throw new GeneralSecurityException("Native GCM final failed");
            }
            outBuf.get(out, outOff, written);
            return written;
        }

        @Override
        public void close() {
            if (ctx != 0) {
                nativeGcmFree(ctx);
                ctx = 0;
            }
        }
    }

    private static final class NativeGcmDecryptor implements AeadDecryptor {
        private long ctx;

        private NativeGcmDecryptor(byte[] key, byte[] iv, byte[] aad) throws GeneralSecurityException {
            ByteBuffer keyBuf = toDirect(key);
            ByteBuffer ivBuf = toDirect(iv);
            ByteBuffer aadBuf = toDirect(aad == null ? new byte[0] : aad);
            ctx = nativeGcmInit(false, keyBuf, key.length, ivBuf, iv.length, aadBuf, aadBuf.remaining());
            if (ctx == 0) {
                throw new GeneralSecurityException("Native GCM init failed");
            }
        }

        @Override
        public int update(byte[] in, int inOff, int len, byte[] out, int outOff) throws GeneralSecurityException {
            if (len == 0) {
                return 0;
            }
            ByteBuffer inBuf = ByteBuffer.allocateDirect(len);
            inBuf.put(in, inOff, len);
            inBuf.flip();
            ByteBuffer outBuf = ByteBuffer.allocateDirect(len);
            int written = nativeGcmUpdate(ctx, inBuf, len, outBuf, outBuf.capacity());
            if (written < 0) {
                throw new GeneralSecurityException("Native GCM update failed");
            }
            outBuf.get(out, outOff, written);
            return written;
        }

        @Override
        public int doFinal(byte[] tag, int tagOff, int tagLen, byte[] out, int outOff)
            throws AEADBadTagException, GeneralSecurityException {
            ByteBuffer tagBuf = ByteBuffer.allocateDirect(tagLen);
            tagBuf.put(tag, tagOff, tagLen);
            tagBuf.flip();
            int rc = nativeGcmFinalDecrypt(ctx, tagBuf, tagLen);
            if (rc < 0) {
                throw new AEADBadTagException("Native GCM auth failed");
            }
            return 0;
        }

        @Override
        public void close() {
            if (ctx != 0) {
                nativeGcmFree(ctx);
                ctx = 0;
            }
        }
    }

    private static native long nativeGcmInit(boolean encrypt,
                                             ByteBuffer key,
                                             int keyLen,
                                             ByteBuffer iv,
                                             int ivLen,
                                             ByteBuffer aad,
                                             int aadLen);

    private static native int nativeGcmUpdate(long ctx,
                                              ByteBuffer in,
                                              int inLen,
                                              ByteBuffer out,
                                              int outLen);

    private static native int nativeGcmFinalEncrypt(long ctx, ByteBuffer out, int outLen);

    private static native int nativeGcmFinalDecrypt(long ctx, ByteBuffer tag, int tagLen);

    private static native void nativeGcmFree(long ctx);
}
