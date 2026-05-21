/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

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
        String lib = System.getenv("BASEFWX_NATIVE_LIB");
        String name = (lib == null || lib.trim().isEmpty()) ? "basefwxcrypto" : lib.trim();
        return NativeLibraryLoader.load(name);
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

    /**
     * Zero-copy one-shot AES-GCM encrypt. Returns bytes written into {@code out}
     * (which equals {@code inLen + AEAD_TAG_LEN}) on success, or -1 on failure.
     * Implemented on the native side with {@code GetPrimitiveArrayCritical} so
     * heap byte[] arrays are accessed without a copy. Only available when
     * {@link #AVAILABLE} is true.
     */
    static int aesGcmEncryptOneShot(byte[] key, byte[] iv, byte[] aad,
                                    byte[] in, int inOff, int inLen,
                                    byte[] out, int outOff) {
        if (!AVAILABLE) return -1;
        int aadLen = aad == null ? 0 : aad.length;
        return nativeAesGcmEncryptOneShot(
            key, key.length,
            iv,  iv.length,
            aad, aadLen,
            in,  inOff, inLen,
            out, outOff, out.length - outOff);
    }

    /** Companion to {@link #aesGcmEncryptOneShot}: returns plaintext length on success. */
    static int aesGcmDecryptOneShot(byte[] key, byte[] iv, byte[] aad,
                                    byte[] in, int inOff, int inLen,
                                    byte[] out, int outOff) {
        if (!AVAILABLE) return -1;
        int aadLen = aad == null ? 0 : aad.length;
        return nativeAesGcmDecryptOneShot(
            key, key.length,
            iv,  iv.length,
            aad, aadLen,
            in,  inOff, inLen,
            out, outOff, out.length - outOff);
    }

    static boolean isAvailable() {
        return AVAILABLE;
    }

    // ----- Argon2id KDF native bridge (3.7.0) ------------------------
    //
    // BouncyCastle's pure-Java Argon2BytesGenerator is correct but ~5-10×
    // slower than libargon2 at the same params (4 lanes / 64 MiB / 4 iters).
    // When the JNI lib was built with libargon2 linked in, this path
    // returns Argon2id output in C-speed; otherwise the Java side falls
    // back to BouncyCastle.

    private static final boolean ARGON2_AVAILABLE = computeArgon2Available();

    private static boolean computeArgon2Available() {
        if (!AVAILABLE) return false;
        try {
            return nativeArgon2idAvailable();
        } catch (Throwable ignored) {
            return false;
        }
    }

    static boolean isArgon2idAvailable() {
        return ARGON2_AVAILABLE;
    }

    /**
     * Run Argon2id via libargon2 (when the JNI lib was built with it).
     * Returns the raw hash bytes, or {@code null} when the native lib
     * isn't loaded or the parameters are rejected — caller falls back
     * to BouncyCastle's pure-Java implementation.
     *
     * Param semantics match {@code basefwx::crypto::Argon2idHashRaw}:
     *   timeCost     — number of Argon2 passes (>=1)
     *   memoryKiB    — memory cost in KiB (>=8)
     *   parallelism  — lane count (>=1, typically 1-4)
     */
    static byte[] argon2idHashRaw(byte[] password, byte[] salt,
                                  int timeCost, int memoryKiB, int parallelism,
                                  int outLen) {
        if (!ARGON2_AVAILABLE) return null;
        if (password == null || salt == null || salt.length == 0
            || timeCost <= 0 || memoryKiB <= 0 || parallelism <= 0 || outLen <= 0) {
            return null;
        }
        byte[] out = new byte[outLen];
        int rc = nativeArgon2idHashRaw(password, salt, timeCost, memoryKiB, parallelism, out);
        return rc == 0 ? out : null;
    }

    private static native boolean nativeArgon2idAvailable();

    private static native int nativeArgon2idHashRaw(
        byte[] password,
        byte[] salt,
        int timeCost,
        int memoryKiB,
        int parallelism,
        byte[] out);

    private static native int nativeAesGcmEncryptOneShot(
        byte[] key, int keyLen,
        byte[] iv,  int ivLen,
        byte[] aad, int aadLen,
        byte[] in,  int inOff, int inLen,
        byte[] out, int outOff, int outCap);

    private static native int nativeAesGcmDecryptOneShot(
        byte[] key, int keyLen,
        byte[] iv,  int ivLen,
        byte[] aad, int aadLen,
        byte[] in,  int inOff, int inLen,
        byte[] out, int outOff, int outCap);
}
