package com.fixcraft.basefwx;

import java.io.ByteArrayOutputStream;

public final class Base64Codec {
    private Base64Codec() {}

    private static final char[] ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    private static final int[] DECODE = buildDecode();

    private static int[] buildDecode() {
        int[] table = new int[256];
        for (int i = 0; i < table.length; i++) {
            table[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length; i++) {
            table[ALPHABET[i]] = i;
        }
        return table;
    }

    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        int full = data.length / 3;
        int rem = data.length % 3;
        int outLen = (full + (rem > 0 ? 1 : 0)) * 4;
        StringBuilder out = new StringBuilder(outLen);
        int idx = 0;
        for (int i = 0; i < full; i++) {
            int b0 = data[idx++] & 0xFF;
            int b1 = data[idx++] & 0xFF;
            int b2 = data[idx++] & 0xFF;
            out.append(ALPHABET[(b0 >> 2) & 0x3F]);
            out.append(ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F]);
            out.append(ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F]);
            out.append(ALPHABET[b2 & 0x3F]);
        }
        if (rem == 1) {
            int b0 = data[idx] & 0xFF;
            out.append(ALPHABET[(b0 >> 2) & 0x3F]);
            out.append(ALPHABET[(b0 << 4) & 0x3F]);
            out.append('=');
            out.append('=');
        } else if (rem == 2) {
            int b0 = data[idx++] & 0xFF;
            int b1 = data[idx] & 0xFF;
            out.append(ALPHABET[(b0 >> 2) & 0x3F]);
            out.append(ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F]);
            out.append(ALPHABET[(b1 << 2) & 0x3F]);
            out.append('=');
        }
        return out.toString();
    }

    public static byte[] decode(String input) {
        if (input == null || input.isEmpty()) {
            return new byte[0];
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] quad = new int[4];
        int quadLen = 0;
        boolean sawPadding = false;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (Character.isWhitespace(ch)) {
                continue;
            }
            if (ch == '=') {
                quad[quadLen++] = -2;
            } else {
                int val = ch < 256 ? DECODE[ch] : -1;
                if (val < 0) {
                    throw new IllegalArgumentException("Invalid base64 payload");
                }
                quad[quadLen++] = val;
            }
            if (quadLen == 4) {
                decodeQuad(quad, out);
                if (quad[2] == -2 || quad[3] == -2) {
                    sawPadding = true;
                }
                quadLen = 0;
            } else if (sawPadding) {
                throw new IllegalArgumentException("Invalid base64 padding");
            }
        }
        if (quadLen != 0) {
            throw new IllegalArgumentException("Invalid base64 length");
        }
        return out.toByteArray();
    }

    private static void decodeQuad(int[] quad, ByteArrayOutputStream out) {
        int b0 = quad[0];
        int b1 = quad[1];
        int b2 = quad[2];
        int b3 = quad[3];
        if (b0 < 0 || b1 < 0) {
            throw new IllegalArgumentException("Invalid base64 payload");
        }
        if (b2 == -2 && b3 == -2) {
            int v = (b0 << 18) | (b1 << 12);
            out.write((v >> 16) & 0xFF);
            return;
        }
        if (b2 < 0) {
            throw new IllegalArgumentException("Invalid base64 payload");
        }
        if (b3 == -2) {
            int v = (b0 << 18) | (b1 << 12) | (b2 << 6);
            out.write((v >> 16) & 0xFF);
            out.write((v >> 8) & 0xFF);
            return;
        }
        if (b3 < 0) {
            throw new IllegalArgumentException("Invalid base64 payload");
        }
        int v = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
        out.write((v >> 16) & 0xFF);
        out.write((v >> 8) & 0xFF);
        out.write(v & 0xFF);
    }
}
