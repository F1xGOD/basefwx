/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class FileCodecIo {
    private FileCodecIo() {}

static File resolveDecodedOutput(File input, File output, byte[] extBytes) {
        if (output != null) {
            return output;
        }
        String name = input.getName();
        if (name.endsWith(".fwx")) {
            name = name.substring(0, name.length() - 4);
        }
        String ext = "";
        if (extBytes.length > 0) {
            ext = new String(extBytes, StandardCharsets.UTF_8);
        }
        if (!ext.isEmpty()) {
            name += ext;
        }
        return new File(input.getParentFile(), name);
    }

static void readExact(InputStream input, byte[] buffer, int length, String error) throws IOException {
        int offset = 0;
        while (offset < length) {
            int read = input.read(buffer, offset, length - offset);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                int single = input.read();
                if (single < 0) {
                    break;
                }
                buffer[offset++] = (byte) single;
                continue;
            }
            offset += read;
        }
        if (offset != length) {
            throw new IllegalArgumentException(error);
        }
    }

static void readExactChannel(FileChannel channel, ByteBuffer buffer, int length, String error) throws IOException {
        buffer.clear();
        buffer.limit(length);
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer);
            if (read < 0) {
                throw new IllegalArgumentException(error);
            }
        }
        buffer.flip();
    }

static void writeFully(FileChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

static byte[] readExactBytes(InputStream input, int length, String error) throws IOException {
        if (length <= 0) {
            return new byte[0];
        }
        byte[] buf = new byte[length];
        readExact(input, buf, length, error);
        return buf;
    }

static void skipFully(InputStream input, int length, String error) throws IOException {
        if (length <= 0) {
            return;
        }
        byte[] buf = new byte[Math.min(8192, length)];
        int remaining = length;
        while (remaining > 0) {
            int take = Math.min(buf.length, remaining);
            int read = input.read(buf, 0, take);
            if (read < 0) {
                throw new IllegalArgumentException(error);
            }
            if (read == 0) {
                int single = input.read();
                if (single < 0) {
                    throw new IllegalArgumentException(error);
                }
                remaining -= 1;
                continue;
            }
            remaining -= read;
        }
    }

static long resolvePayloadLengthFromFileSize(File input,
                                                         int lenUser,
                                                         int lenMaster,
                                                         int encodedPayloadLen) {
        long payloadLen = encodedPayloadLen & 0xFFFFFFFFL;
        long prefixLen = 4L + (lenUser & 0xFFFFFFFFL)
            + 4L + (lenMaster & 0xFFFFFFFFL)
            + 4L;
        long fileSize = input.length();
        if (fileSize < prefixLen) {
            return payloadLen;
        }
        long actualPayloadLen = fileSize - prefixLen;
        if (actualPayloadLen == payloadLen) {
            return payloadLen;
        }
        long mod = 1L << 32;
        if (actualPayloadLen > payloadLen && ((actualPayloadLen - payloadLen) % mod) == 0L) {
            return actualPayloadLen;
        }
        return payloadLen;
    }

static int readU32(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 4, error);
        return BaseFwxUtil.readU32(buf, 0);
    }

static int readU16(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 2, error);
        return ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);
    }

static long readU64(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 8, error);
        long out = 0L;
        for (int i = 0; i < buf.length; i++) {
            out = (out << 8) | (buf[i] & 0xFFL);
        }
        return out;
    }

static void writeU32(OutputStream output, int value) throws IOException {
        output.write((value >> 24) & 0xFF);
        output.write((value >> 16) & 0xFF);
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }

static void writeU16(OutputStream output, int value) throws IOException {
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }

static void writeU64(OutputStream output, long value) throws IOException {
        long v = value;
        for (int i = 7; i >= 0; i--) {
            output.write((int) ((v >> (i * 8)) & 0xFF));
        }
    }

static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
