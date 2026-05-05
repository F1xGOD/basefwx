package com.fixcraft.basefwx;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * JNI {@link FwxAES} implementation. AEAD operations are routed through the
 * bundled {@code basefwxcrypto} shared library via {@link NativeCryptoBackend}.
 *
 * <p>Construct via {@link FwxAES#create(boolean)} or
 * {@link FwxAES#builder()}. Direct construction is supported for callers that
 * have already obtained a native backend reference; if {@link
 * CryptoBackends#nativeOrNull()} is {@code null}, the constructor throws.
 *
 * <p>Wire format and behaviour are identical to {@link FwxAESPureJava}; the
 * two differ only in which backend executes AES-GCM. A blob produced by either
 * implementation can be decrypted by either.
 */
public final class FwxAESJNI implements FwxAES {

    private final boolean useMaster;
    private final CryptoBackend backend;

    /**
     * Builds a JNI instance using the currently-loaded native backend.
     *
     * @throws IllegalStateException if the native backend is not available;
     *         use {@link FwxAES#create(boolean)} for the version that falls
     *         back to {@link FwxAESPureJava} silently.
     */
    public FwxAESJNI() {
        this(true, requireNative());
    }

    public FwxAESJNI(boolean useMaster) {
        this(useMaster, requireNative());
    }

    FwxAESJNI(boolean useMaster, CryptoBackend backend) {
        if (backend == null || !backend.isNative()) {
            throw new IllegalStateException("FwxAESJNI requires a native crypto backend");
        }
        this.useMaster = useMaster;
        this.backend = backend;
    }

    @Override public boolean isNative() { return true; }
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

    private static CryptoBackend requireNative() {
        CryptoBackend native_ = FwxAES.activateNative();
        if (native_ == null) {
            throw new IllegalStateException(
                "basefwxcrypto native library could not be loaded; "
                + "use FwxAES.create(true) for a version that falls back to pure Java");
        }
        return native_;
    }

    private <T> T run(java.util.concurrent.Callable<T> body) {
        try {
            return CryptoBackends.call(backend, body);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private long runIo(IoSupplier body) throws IOException {
        try {
            return CryptoBackends.call(backend, body::get);
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
