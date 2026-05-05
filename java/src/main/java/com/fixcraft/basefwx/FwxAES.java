package com.fixcraft.basefwx;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * High-level entry point for fwxAES, fwxAES-light, and fwxAES-live.
 *
 * <p>Two implementations of this interface are shipped:
 *
 * <ul>
 *   <li>{@link FwxAESPureJava} — uses {@code javax.crypto.Cipher} for AEAD.
 *       No native dependencies. Works on any JVM, including Android.
 *       This is the default.</li>
 *   <li>{@link FwxAESJNI} — calls into the bundled {@code basefwxcrypto}
 *       shared library for AEAD. Faster on desktop / server. Falls back to
 *       {@link FwxAESPureJava} (with a single warning line) if the native
 *       library cannot be loaded.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * // Default: pure Java
 * FwxAES aes = FwxAES.create();
 * byte[] blob = aes.encryptRaw(plaintext, "password");
 * byte[] back = aes.decryptRaw(blob, "password");
 *
 * // Opt into native, with automatic fallback to pure Java
 * FwxAES fast = FwxAES.create(true);
 *
 * // Builder
 * FwxAES configured = FwxAES.builder()
 *     .enableJNI(true)
 *     .useMaster(false)
 *     .build();
 * }</pre>
 *
 * <p>Format compatibility: bytes produced by either implementation are
 * byte-identical and interchangeable with the Python and C++ implementations.
 */
public interface FwxAES {

    /** Pure-Java instance. Equivalent to {@link FwxAESPureJava}. */
    static FwxAES create() {
        return new FwxAESPureJava(true);
    }

    /**
     * Returns an instance, opting into the JNI backend if requested.
     * If the native library cannot be loaded, a {@link FwxAESPureJava}
     * is returned and a single warning is logged.
     */
    static FwxAES create(boolean preferNative) {
        if (preferNative) {
            CryptoBackend nativeBackend = activateNative();
            if (nativeBackend != null) {
                return new FwxAESJNI(true, nativeBackend);
            }
        }
        return new FwxAESPureJava(true);
    }

    /** Fluent builder. */
    static Builder builder() {
        return new Builder();
    }

    /** {@code true} if AEAD operations are routed through the native backend. */
    boolean isNative();

    /**
     * Whether the embedded BaseFWX master keypair may participate in key
     * wrapping. The Python and C++ defaults are {@code true}.
     */
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

    /** Tries to bring up the native backend on demand. Returns null on failure. */
    static CryptoBackend activateNative() {
        CryptoBackend already = CryptoBackends.nativeOrNull();
        if (already != null) return already;
        // Force-attempt native load even if the JVM started without the opt-in flags.
        if (System.getProperty("basefwx.useJNI") == null
            && System.getenv("BASEFWX_NATIVE") == null) {
            System.setProperty("basefwx.useJNI", "true");
        }
        // The backend is decided at class-init time of CryptoBackends. If it
        // didn't pick up native then, NativeCryptoBackend.tryCreate is the only
        // way to bring it up retroactively.
        return NativeCryptoBackend.tryCreate();
    }

    /** Builder for {@link FwxAES} with non-default settings. */
    final class Builder {
        private boolean enableJni = false;
        private boolean useMaster = true;

        private Builder() {}

        /** Opt into the JNI backend. Default: false (pure Java). */
        public Builder enableJNI(boolean enable) {
            this.enableJni = enable;
            return this;
        }

        /** Master-key participation. Default: true. */
        public Builder useMaster(boolean useMaster) {
            this.useMaster = useMaster;
            return this;
        }

        public FwxAES build() {
            if (enableJni) {
                CryptoBackend nativeBackend = FwxAES.activateNative();
                if (nativeBackend != null) {
                    return new FwxAESJNI(useMaster, nativeBackend);
                }
            }
            return new FwxAESPureJava(useMaster);
        }
    }
}
