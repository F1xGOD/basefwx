package com.fixcraft.basefwx;

import java.util.ArrayList;
import java.util.List;

public final class Format {
    private Format() {}

    // Pick a sane cap for your app (or make it configurable).
    // For encryption formats, 64 MiB for metadata blobs is usually plenty.
    public static final int MAX_TOTAL = 64 * 1024 * 1024;

    public static byte[] packLengthPrefixed(List<byte[]> parts) {
        if (parts == null) throw new IllegalArgumentException("parts == null");

        long total = 4L * parts.size();
        for (byte[] part : parts) {
            if (part == null) throw new IllegalArgumentException("null part");
            total += part.length;
            if (total > MAX_TOTAL) {
                throw new IllegalArgumentException("length-prefixed blob too large");
            }
        }

        byte[] out = new byte[(int) total];
        int offset = 0;

        for (byte[] part : parts) {
            int len = part.length;
            out[offset]     = (byte) (len >>> 24);
            out[offset + 1] = (byte) (len >>> 16);
            out[offset + 2] = (byte) (len >>> 8);
            out[offset + 3] = (byte) (len);
            offset += 4;

            if (len != 0) {
                System.arraycopy(part, 0, out, offset, len);
                offset += len;
            }
        }
        return out;
    }

    public static List<byte[]> unpackLengthPrefixed(byte[] data, int count) {
        if (data == null) throw new IllegalArgumentException("data == null");
        if (count < 0) throw new IllegalArgumentException("count < 0");
        if (data.length > MAX_TOTAL) throw new IllegalArgumentException("blob too large");

        List<byte[]> parts = new ArrayList<>(count);
        int offset = 0;

        for (int i = 0; i < count; i++) {
            if (offset + 4 > data.length) {
                throw new IllegalArgumentException("Malformed length-prefixed blob (missing length)");
            }

            int len = ((data[offset] & 0xFF) << 24)
                    | ((data[offset + 1] & 0xFF) << 16)
                    | ((data[offset + 2] & 0xFF) << 8)
                    | (data[offset + 3] & 0xFF);
            offset += 4;

            // Critical: reject negative (and also crazy large).
            if (len < 0) {
                throw new IllegalArgumentException("Malformed length-prefixed blob (negative length)");
            }
            if (len > MAX_TOTAL) {
                throw new IllegalArgumentException("Malformed length-prefixed blob (part too large)");
            }
            if (offset > data.length - len) { // avoids offset+len overflow
                throw new IllegalArgumentException("Malformed length-prefixed blob (truncated part)");
            }

            byte[] part = new byte[len];
            if (len != 0) {
                System.arraycopy(data, offset, part, 0, len);
                offset += len;
            }
            parts.add(part);
        }

        if (offset != data.length) {
            throw new IllegalArgumentException("Malformed length-prefixed blob (extra bytes)");
        }
        return parts;
    }
}
