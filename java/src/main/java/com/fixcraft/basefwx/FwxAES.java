package com.fixcraft.basefwx;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * High-level entry point for fwxAES, fwxAES-light, and fwxAES-live.
 *
 * <p>Implementations: {@link FwxAESPureJava} (default, uses {@code javax.crypto.Cipher})
 * and {@link FwxAESJNI} (opt-in, calls the {@code basefwxcrypto} shared library
 * via JNI). Wire format and behaviour are identical; blobs from one are
 * decryptable by the other and by the Python and C++ implementations.
 *
 * <pre>{@code
 * FwxAES aes  = FwxAES.create();          // pure Java
 * FwxAES fast = FwxAES.create(true);      // try JNI, falls back to pure Java
 * FwxAES via  = FwxAES.builder().enableJNI(true).useMaster(false).build();
 * }</pre>
 */
public interface FwxAES {

    /** Pure-Java instance. */
    static FwxAES create() {
        return new FwxAESPureJava(true);
    }

    /**
     * Try the JNI backend, fall back to {@link FwxAESPureJava} (with a single
     * warning) if the shared library can't be loaded.
     */
    static FwxAES create(boolean preferNative) {
        if (preferNative) {
            CryptoBackend native_ = activateNative();
            if (native_ != null) return new FwxAESJNI(true, native_);
        }
        return new FwxAESPureJava(true);
    }

    static Builder builder() {
        return new Builder();
    }

    boolean isNative();
    boolean useMaster();

    byte[] encryptRaw(byte[] plaintext, String password);
    byte[] encryptRawBytes(byte[] plaintext, byte[] passwordBytes);
    byte[] decryptRaw(byte[] blob, String password);
    byte[] decryptRawBytes(byte[] blob, byte[] passwordBytes);

    long encryptStream(InputStream in, OutputStream out, String password) throws IOException;
    long decryptStream(InputStream in, OutputStream out, String password) throws IOException;

    void encryptFile(File src, File dst, String password);
    void decryptFile(File src, File dst, String password);

    long liveEncryptStream(InputStream in, OutputStream out, String password) throws IOException;
    long liveDecryptStream(InputStream in, OutputStream out, String password) throws IOException;

    /** Bring up the native backend on demand. Returns null if it can't be loaded. */
    static CryptoBackend activateNative() {
        CryptoBackend already = CryptoBackends.nativeOrNull();
        if (already != null) return already;
        if (System.getProperty("basefwx.useJNI") == null
            && System.getenv("BASEFWX_NATIVE") == null) {
            System.setProperty("basefwx.useJNI", "true");
        }
        return NativeCryptoBackend.tryCreate();
    }

    final class Builder {
        private boolean enableJni = false;
        private boolean useMaster = true;

        private Builder() {}

        public Builder enableJNI(boolean enable) {
            this.enableJni = enable;
            return this;
        }

        public Builder useMaster(boolean useMaster) {
            this.useMaster = useMaster;
            return this;
        }

        public FwxAES build() {
            if (enableJni) {
                CryptoBackend native_ = FwxAES.activateNative();
                if (native_ != null) return new FwxAESJNI(useMaster, native_);
            }
            return new FwxAESPureJava(useMaster);
        }
    }
}
