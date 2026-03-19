package com.fixcraft.basefwx;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public final class VersionInfo {
    private static final Properties PROPS = load();

    private VersionInfo() {}

    private static Properties load() {
        Properties props = new Properties();
        try (InputStream in = VersionInfo.class.getClassLoader().getResourceAsStream("basefwx-build.properties")) {
            if (in != null) {
                props.load(in);
            }
        } catch (IOException ignored) {
        }
        return props;
    }

    private static String get(String key, String fallback) {
        String value = PROPS.getProperty(key);
        if (value == null) {
            return fallback;
        }
        value = value.trim();
        return value.isEmpty() ? fallback : value;
    }

    public static String engineVersion() {
        return get("version", "0.0.0");
    }

    public static String buildUtc() {
        return get("build_utc", "unknown");
    }

    public static String buildOrigin() {
        return get("build_origin", "local");
    }

    public static String gpgFingerprint() {
        return get("gpg_fingerprint", "none");
    }
}
