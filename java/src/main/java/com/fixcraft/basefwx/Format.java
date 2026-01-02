package com.fixcraft.basefwx;

import java.util.ArrayList;
import java.util.List;

public final class Format {
    private Format() {}

    public static byte[] packLengthPrefixed(List<byte[]> parts) {
        int total = 4 * parts.size();
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            int len = part.length;
            out[offset] = (byte) ((len >> 24) & 0xFF);
            out[offset + 1] = (byte) ((len >> 16) & 0xFF);
            out[offset + 2] = (byte) ((len >> 8) & 0xFF);
            out[offset + 3] = (byte) (len & 0xFF);
            offset += 4;
            if (len > 0) {
                System.arraycopy(part, 0, out, offset, len);
                offset += len;
            }
        }
        return out;
    }

    public static List<byte[]> unpackLengthPrefixed(byte[] data, int count) {
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
            if (offset + len > data.length) {
                throw new IllegalArgumentException("Malformed length-prefixed blob (truncated part)");
            }
            byte[] part = new byte[len];
            if (len > 0) {
                System.arraycopy(data, offset, part, 0, len);
            }
            parts.add(part);
            offset += len;
        }
        if (offset != data.length) {
            throw new IllegalArgumentException("Malformed length-prefixed blob (extra bytes)");
        }
        return parts;
    }
}
