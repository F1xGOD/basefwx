/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public final class VersionInfo {
    private static final String ENGINE_VERSION_FALLBACK = "3.8.0-dev1";
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
        return get("version", get("version_fallback", ENGINE_VERSION_FALLBACK));
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
