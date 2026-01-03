package com.fixcraft.basefwx;

public final class CryptoBackends {
    private static final CryptoBackend JAVA = new JavaCryptoBackend();
    private static final CryptoBackend NATIVE = NativeCryptoBackend.tryCreate();

    private CryptoBackends() {}

    public static CryptoBackend get() {
        return NATIVE != null ? NATIVE : JAVA;
    }

    public static boolean usingNative() {
        return NATIVE != null;
    }
}
