package com.fixcraft.basefwx;

import java.util.Locale;
import java.util.concurrent.Callable;

/**
 * Picks the active {@link CryptoBackend}. Default is pure Java; opt into
 * native with {@code -Dbasefwx.useJNI=true} or {@code BASEFWX_NATIVE=1}.
 * {@code BASEFWX_NATIVE=0} / {@code -Dbasefwx.useJNI=false} forces pure Java.
 *
 * <p>{@link #call(CryptoBackend, Callable)} pins a backend on the current
 * thread for the duration of the body so {@code FwxAESPureJava} and
 * {@code FwxAESJNI} can each route through their own backend regardless of
 * the JVM-wide default.
 */
public final class CryptoBackends {
    private static final CryptoBackend JAVA = new JavaCryptoBackend();
    private static final CryptoBackend NATIVE_BACKEND = createNativeIfRequested();
    private static final ThreadLocal<CryptoBackend> OVERRIDE = new ThreadLocal<>();

    private CryptoBackends() {}

    public static CryptoBackend get() {
        CryptoBackend override = OVERRIDE.get();
        if (override != null) return override;
        return NATIVE_BACKEND != null ? NATIVE_BACKEND : JAVA;
    }

    public static CryptoBackend java() {
        return JAVA;
    }

    public static CryptoBackend nativeOrNull() {
        return NATIVE_BACKEND;
    }

    public static boolean usingNative() {
        return get().isNative();
    }

    public static <T> T call(CryptoBackend backend, Callable<T> body) throws Exception {
        CryptoBackend prior = OVERRIDE.get();
        OVERRIDE.set(backend);
        try {
            return body.call();
        } finally {
            if (prior != null) OVERRIDE.set(prior);
            else OVERRIDE.remove();
        }
    }

    public static void run(CryptoBackend backend, Runnable body) {
        CryptoBackend prior = OVERRIDE.get();
        OVERRIDE.set(backend);
        try {
            body.run();
        } finally {
            if (prior != null) OVERRIDE.set(prior);
            else OVERRIDE.remove();
        }
    }

    private static CryptoBackend createNativeIfRequested() {
        if (isKillSwitchSet() || !isNativeRequested()) return null;
        CryptoBackend backend = NativeCryptoBackend.tryCreate();
        if (backend == null) {
            RuntimeLog.warn(
                "basefwx native backend requested but shared library could not be loaded; "
                + "falling back to pure-Java AEAD");
        }
        return backend;
    }

    private static boolean isNativeRequested() {
        return truthy(System.getProperty("basefwx.useJNI"))
            || truthy(System.getenv("BASEFWX_NATIVE"));
    }

    private static boolean isKillSwitchSet() {
        String env = System.getenv("BASEFWX_NATIVE");
        if (env != null && falsey(env)) return true;
        String prop = System.getProperty("basefwx.useJNI");
        return prop != null && falsey(prop);
    }

    private static boolean truthy(String raw) {
        if (raw == null) return false;
        String v = raw.trim().toLowerCase(Locale.ROOT);
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

    private static boolean falsey(String raw) {
        if (raw == null) return false;
        String v = raw.trim().toLowerCase(Locale.ROOT);
        return v.equals("0") || v.equals("false") || v.equals("no") || v.equals("off");
    }
}
