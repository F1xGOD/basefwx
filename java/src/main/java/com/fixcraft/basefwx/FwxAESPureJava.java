package com.fixcraft.basefwx;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Pure-Java {@link FwxAES} implementation.
 *
 * <p>All AEAD work is routed through {@link JavaCryptoBackend}, which uses
 * {@code javax.crypto.Cipher}. No native dependencies. Safe on Android and
 * any JVM that exposes the standard JCA providers.
 *
 * <p>Wire format and behaviour are identical to {@link FwxAESJNI}; the two
 * differ only in which backend executes AES-GCM. A blob produced by either
 * implementation can be decrypted by either.
 */
public final class FwxAESPureJava implements FwxAES {

    private static final CryptoBackend BACKEND = CryptoBackends.java();

    private final boolean useMaster;

    public FwxAESPureJava() {
        this(true);
    }

    public FwxAESPureJava(boolean useMaster) {
        this.useMaster = useMaster;
    }

    @Override public boolean isNative() { return false; }
    @Override public boolean useMaster() { return useMaster; }

    @Override
    public byte[] encryptRaw(byte[] plaintext, String password) {
        return run(() -> BaseFwx.fwxAesEncryptRaw(plaintext, password, useMaster));
    }

    @Override
    public byte[] encryptRawBytes(byte[] plaintext, byte[] passwordBytes) {
        return run(() -> BaseFwx.fwxAesEncryptRawBytes(plaintext, passwordBytes, useMaster));
    }

    @Override
    public byte[] decryptRaw(byte[] blob, String password) {
        return run(() -> BaseFwx.fwxAesDecryptRaw(blob, password, useMaster));
    }

    @Override
    public byte[] decryptRawBytes(byte[] blob, byte[] passwordBytes) {
        return run(() -> BaseFwx.fwxAesDecryptRawBytes(blob, passwordBytes, useMaster));
    }

    @Override
    public long encryptStream(InputStream in, OutputStream out, String password) throws IOException {
        return runIo(() -> BaseFwx.fwxAesEncryptStream(in, out, password, useMaster));
    }

    @Override
    public long decryptStream(InputStream in, OutputStream out, String password) throws IOException {
        return runIo(() -> BaseFwx.fwxAesDecryptStream(in, out, password, useMaster));
    }

    @Override
    public void encryptFile(File src, File dst, String password) {
        run(() -> { BaseFwx.fwxAesEncryptFile(src, dst, password, useMaster); return null; });
    }

    @Override
    public void decryptFile(File src, File dst, String password) {
        run(() -> { BaseFwx.fwxAesDecryptFile(src, dst, password, useMaster); return null; });
    }

    @Override
    public long liveEncryptStream(InputStream in, OutputStream out, String password) throws IOException {
        return runIo(() -> BaseFwx.fwxAesLiveEncryptStream(in, out, password, useMaster));
    }

    @Override
    public long liveDecryptStream(InputStream in, OutputStream out, String password) throws IOException {
        return runIo(() -> BaseFwx.fwxAesLiveDecryptStream(in, out, password, useMaster));
    }

    private <T> T run(java.util.concurrent.Callable<T> body) {
        try {
            return CryptoBackends.call(BACKEND, body);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private long runIo(IoSupplier body) throws IOException {
        try {
            return CryptoBackends.call(BACKEND, body::get);
        } catch (IOException ioe) {
            throw ioe;
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @FunctionalInterface
    private interface IoSupplier {
        long get() throws IOException;
    }
}
