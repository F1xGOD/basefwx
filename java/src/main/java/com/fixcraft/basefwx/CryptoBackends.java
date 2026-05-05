package com.fixcraft.basefwx;

import java.util.Locale;
import java.util.concurrent.Callable;

/**
 * Selects the active {@link CryptoBackend}.
 *
 * <p>The default is the pure-Java implementation, which has no native
 * dependencies and runs unmodified on Android and any other JVM that exposes
 * {@code javax.crypto}. To opt into the native backend, set either the system
 * property {@code basefwx.useJNI=true} or the environment variable
 * {@code BASEFWX_NATIVE=1}. {@code BASEFWX_NATIVE=0} or {@code -Dbasefwx.useJNI=false}
 * is a kill switch that forces pure-Java even when the native library is
 * present.
 *
 * <p>If the native backend is requested but its shared library cannot be
 * loaded, the loader emits a single warning line and falls back to pure Java.
 * Callers never see an exception just because a native lib is missing.
 *
 * <p>Per-call overrides are available via {@link #call(CryptoBackend, Callable)}
 * and {@link #run(CryptoBackend, Runnable)}; these install a thread-local
 * backend for the duration of the body so that a {@code FwxAESPureJava}
 * instance can route its AEAD through the Java backend even on a JVM where
 * the global default is the native backend (and vice versa).
 */
public final class CryptoBackends {
    private static final CryptoBackend JAVA = new JavaCryptoBackend();
    private static final CryptoBackend NATIVE_BACKEND = createNativeIfRequested();
    private static final ThreadLocal<CryptoBackend> OVERRIDE = new ThreadLocal<>();

    private CryptoBackends() {}

    /**
     * Returns the active backend. If a thread-local override is set, returns
     * that; otherwise returns the native backend if loaded, otherwise the
     * pure-Java backend.
     */
    public static CryptoBackend get() {
        CryptoBackend override = OVERRIDE.get();
        if (override != null) return override;
        return NATIVE_BACKEND != null ? NATIVE_BACKEND : JAVA;
    }

    /** The pure-Java backend (always available). */
    public static CryptoBackend java() {
        return JAVA;
    }

    /**
     * The native backend if its shared library loaded, or {@code null}.
     */
    public static CryptoBackend nativeOrNull() {
        return NATIVE_BACKEND;
    }

    /** {@code true} if the active backend is the native one. */
    public static boolean usingNative() {
        return get().isNative();
    }

    /**
     * Runs {@code body} with {@code backend} pinned as the thread-local
     * override. The override is removed when the body returns or throws,
     * even if a nested call also installs an override.
     */
    public static <T> T call(CryptoBackend backend, Callable<T> body) throws Exception {
        CryptoBackend prior = OVERRIDE.get();
        OVERRIDE.set(backend);
        try {
            return body.call();
        } finally {
            if (prior != null) {
                OVERRIDE.set(prior);
            } else {
                OVERRIDE.remove();
            }
        }
    }

    /** Void variant of {@link #call(CryptoBackend, Callable)}. */
    public static void run(CryptoBackend backend, Runnable body) {
        CryptoBackend prior = OVERRIDE.get();
        OVERRIDE.set(backend);
        try {
            body.run();
        } finally {
            if (prior != null) {
                OVERRIDE.set(prior);
            } else {
                OVERRIDE.remove();
            }
        }
    }

    private static CryptoBackend createNativeIfRequested() {
        if (isKillSwitchSet()) {
            return null;
        }
        if (!isNativeRequested()) {
            return null;
        }
        CryptoBackend backend = NativeCryptoBackend.tryCreate();
        if (backend == null) {
            RuntimeLog.warn(
                "basefwx native backend requested but shared library could not be loaded; "
                + "falling back to pure-Java AEAD");
        }
        return backend;
    }

    private static boolean isNativeRequested() {
        if (truthy(System.getProperty("basefwx.useJNI"))) {
            return true;
        }
        return truthy(System.getenv("BASEFWX_NATIVE"));
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
