/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.media;

import com.fixcraft.basefwx.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class MediaCipherUtil {
    private MediaCipherUtil() {}

    static boolean looksLikeFwx(File input) {
        String name = input.getName().toLowerCase(Locale.US);
        if (name.endsWith(".fwx")) {
            return true;
        }
        try (FileInputStream in = new FileInputStream(input)) {
            byte[] header = new byte[Constants.FWXAES_MAGIC.length];
            int read = in.read(header);
            if (read != header.length) {
                return false;
            }
            return Arrays.equals(header, Constants.FWXAES_MAGIC);
        } catch (IOException exc) {
            return false;
        }
    }

    static File stripFwxSuffix(File input) {
        String name = input.getName();
        if (name.toLowerCase(Locale.US).endsWith(".fwx")) {
            name = name.substring(0, name.length() - 4);
        } else {
            name = name + ".out";
        }
        return new File(input.getParentFile(), name);
    }

    static File withMarker(File file, String marker) {
        String name = file.getName();
        int dot = name.lastIndexOf('.');
        String newName;
        if (dot >= 0) {
            newName = name.substring(0, dot) + marker + name.substring(dot);
        } else {
            newName = name + marker;
        }
        return new File(file.getParentFile(), newName);
    }

    static String extensionLower(File file) {
        String name = file.getName();
        int idx = name.lastIndexOf('.');
        if (idx < 0) {
            return "";
        }
        return name.substring(idx).toLowerCase(Locale.US);
    }

    static void ensureExists(File file) {
        if (file == null || !file.isFile()) {
            throw new IllegalArgumentException("Input file not found: " + (file == null ? "null" : file.getPath()));
        }
    }

    static void ensureParent(File file) {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
    }

    static File createTempDir() {
        try {
            return Files.createTempDirectory("basefwx-media-").toFile();
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to create temp dir", exc);
        }
    }

    static void deleteRecursive(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }

    static void moveReplace(File src, File dest) {
        try {
            Files.move(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to move output", exc);
        }
    }

    static byte[] readFileBytes(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read file bytes", exc);
        }
    }

    static void writeFileBytes(File file, byte[] data) {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to write file bytes", exc);
        }
    }

    static int lastIndexOf(byte[] data, byte[] needle) {
        if (needle.length == 0 || data.length < needle.length) {
            return -1;
        }
        for (int i = data.length - needle.length; i >= 0; i--) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    static boolean startsWith(byte[] data, int offset, byte[] prefix) {
        if (data.length < offset + prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    static byte[] writeU32(int value) {
        byte[] out = new byte[4];
        writeU32(out, 0, value);
        return out;
    }

    static void writeU32(byte[] out, int offset, int value) {
        out[offset] = (byte) ((value >>> 24) & 0xFF);
        out[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        out[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        out[offset + 3] = (byte) (value & 0xFF);
    }

    static long readU32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
            | ((long) (data[offset + 1] & 0xFF) << 16)
            | ((long) (data[offset + 2] & 0xFF) << 8)
            | ((long) (data[offset + 3] & 0xFF));
    }

    static void writeU64(byte[] out, int offset, long value) {
        out[offset] = (byte) ((value >>> 56) & 0xFF);
        out[offset + 1] = (byte) ((value >>> 48) & 0xFF);
        out[offset + 2] = (byte) ((value >>> 40) & 0xFF);
        out[offset + 3] = (byte) ((value >>> 32) & 0xFF);
        out[offset + 4] = (byte) ((value >>> 24) & 0xFF);
        out[offset + 5] = (byte) ((value >>> 16) & 0xFF);
        out[offset + 6] = (byte) ((value >>> 8) & 0xFF);
        out[offset + 7] = (byte) (value & 0xFF);
    }

    static long readU64(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 56)
            | ((long) (data[offset + 1] & 0xFF) << 48)
            | ((long) (data[offset + 2] & 0xFF) << 40)
            | ((long) (data[offset + 3] & 0xFF) << 32)
            | ((long) (data[offset + 4] & 0xFF) << 24)
            | ((long) (data[offset + 5] & 0xFF) << 16)
            | ((long) (data[offset + 6] & 0xFF) << 8)
            | ((long) (data[offset + 7] & 0xFF));
    }

    static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        return value.trim();
    }

    static int imageKdfIterations(byte[] password) {
        int iters = Math.max(200_000, Constants.USER_KDF_ITERATIONS);
        if (password != null && password.length > 0 && !Constants.TEST_KDF_OVERRIDE) {
            if (password.length < Constants.SHORT_PASSWORD_MIN && iters < Constants.SHORT_PBKDF2_ITERS) {
                iters = Constants.SHORT_PBKDF2_ITERS;
            }
        }
        return iters;
    }

    static double parseRate(String rate) {
        if (rate == null || rate.isEmpty() || "0/0".equals(rate)) {
            return 0.0;
        }
        if (rate.contains("/")) {
            String[] parts = rate.split("/", 2);
            try {
                double num = Double.parseDouble(parts[0]);
                double den = Double.parseDouble(parts[1]);
                if (den == 0.0) {
                    return 0.0;
                }
                return num / den;
            } catch (NumberFormatException exc) {
                return 0.0;
            }
        }
        try {
            return Double.parseDouble(rate);
        } catch (NumberFormatException exc) {
            return 0.0;
        }
    }

    static double parseDouble(String raw) {
        if (raw == null || raw.isEmpty()) {
            return 0.0;
        }
        try {
            return Double.parseDouble(raw);
        } catch (NumberFormatException exc) {
            return 0.0;
        }
    }

    static long parseLong(String raw) {
        if (raw == null || raw.isEmpty()) {
            return 0L;
        }
        try {
            return (long) Double.parseDouble(raw);
        } catch (NumberFormatException exc) {
            return 0L;
        }
    }

    static Map<String, String> parseKeyValues(String output) {
        Map<String, String> map = new HashMap<>();
        for (String line : output.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int idx = trimmed.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = trimmed.substring(0, idx).trim();
            String value = trimmed.substring(idx + 1).trim();
            map.put(key, value);
        }
        return map;
    }

    static byte[] concat(byte[] a, byte[] b) {
        if (a.length == 0) {
            return Arrays.copyOf(b, b.length);
        }
        if (b.length == 0) {
            return Arrays.copyOf(a, a.length);
        }
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static Set<String> buildSet(String... values) {
        Set<String> out = new HashSet<>();
        Collections.addAll(out, values);
        return Collections.unmodifiableSet(out);
    }

    static boolean samePath(File a, File b) {
        try {
            return a.getCanonicalFile().equals(b.getCanonicalFile());
        } catch (IOException exc) {
            return a.getAbsolutePath().equals(b.getAbsolutePath());
        }
    }

}