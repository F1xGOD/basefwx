/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;

final class BaseFwxUtil {
    private BaseFwxUtil() {}

    static File createPrivateTempFile(String prefix, String suffix) throws IOException {
        try {
            FileAttribute<?> attr = PosixFilePermissions.asFileAttribute(
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            Path tempPath = Files.createTempFile(prefix, suffix, attr);
            return tempPath.toFile();
        } catch (UnsupportedOperationException e) {
            return File.createTempFile(prefix, suffix);
        }
    }

    static void writeU32(byte[] target, int offset, int value) {
        target[offset] = (byte) ((value >> 24) & 0xFF);
        target[offset + 1] = (byte) ((value >> 16) & 0xFF);
        target[offset + 2] = (byte) ((value >> 8) & 0xFF);
        target[offset + 3] = (byte) (value & 0xFF);
    }

    static int readU32(byte[] source, int offset) {
        return ((source[offset] & 0xFF) << 24)
            | ((source[offset + 1] & 0xFF) << 16)
            | ((source[offset + 2] & 0xFF) << 8)
            | (source[offset + 3] & 0xFF);
    }

    static void writeU64(byte[] target, int offset, long value) {
        long v = value;
        for (int i = 7; i >= 0; i--) {
            target[offset + i] = (byte) (v & 0xFFL);
            v >>>= 8;
        }
    }

    static String getExtension(File file) {
        String name = file.getName();
        int idx = name.lastIndexOf('.');
        if (idx < 0) {
            return "";
        }
        return name.substring(idx);
    }

    static boolean samePath(File a, File b) {
        try {
            return a.getCanonicalFile().equals(b.getCanonicalFile());
        } catch (IOException ignored) {
            return a.getAbsoluteFile().equals(b.getAbsoluteFile());
        }
    }

    static byte[] readFileBytes(File file) {
        try (FileInputStream in = new FileInputStream(file);
             ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(file.length(), Integer.MAX_VALUE))) {
            byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
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
}
