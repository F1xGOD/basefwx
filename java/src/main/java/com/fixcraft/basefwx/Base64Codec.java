package com.fixcraft.basefwx;

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
        
        // Fast path: count non-whitespace characters to pre-calculate output size
        int validChars = 0;
        int inputLen = input.length();
        for (int i = 0; i < inputLen; i++) {
            char ch = input.charAt(i);
            if (!Character.isWhitespace(ch)) {
                validChars++;
            }
        }
        
        if (validChars == 0) {
            return new byte[0];
        }
        
        // Base64 must have characters in groups of 4 (after removing whitespace)
        if ((validChars & 3) != 0) {
            throw new IllegalArgumentException("Invalid base64 length");
        }
        
        // Pre-allocate output buffer (max size, may be slightly less with padding)
        int maxOutLen = (validChars / 4) * 3;
        byte[] out = new byte[maxOutLen];
        int outPos = 0;
        
        int[] quad = new int[4];
        int quadLen = 0;
        boolean sawPadding = false;
        
        for (int i = 0; i < inputLen; i++) {
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
                outPos = decodeQuadFast(quad, out, outPos);
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
        
        // Return appropriately sized array if we wrote less due to padding
        if (outPos < maxOutLen) {
            byte[] result = new byte[outPos];
            System.arraycopy(out, 0, result, 0, outPos);
            return result;
        }
        return out;
    }

    private static int decodeQuadFast(int[] quad, byte[] out, int outPos) {
        int b0 = quad[0];
        int b1 = quad[1];
        int b2 = quad[2];
        int b3 = quad[3];
        
        if (b0 < 0 || b1 < 0) {
            throw new IllegalArgumentException("Invalid base64 payload");
        }
        
        // Decode the 24-bit value
        int v = (b0 << 18) | (b1 << 12);
        
        if (b2 == -2 && b3 == -2) {
            // Two padding chars: output 1 byte
            out[outPos++] = (byte) ((v >> 16) & 0xFF);
            return outPos;
        }
        
        if (b2 < 0) {
            throw new IllegalArgumentException("Invalid base64 payload");
        }
        
        v |= (b2 << 6);
        
        if (b3 == -2) {
            // One padding char: output 2 bytes
            out[outPos++] = (byte) ((v >> 16) & 0xFF);
            out[outPos++] = (byte) ((v >> 8) & 0xFF);
            return outPos;
        }
        
        if (b3 < 0) {
            throw new IllegalArgumentException("Invalid base64 payload");
        }
        
        v |= b3;
        
        // No padding: output 3 bytes
        out[outPos++] = (byte) ((v >> 16) & 0xFF);
        out[outPos++] = (byte) ((v >> 8) & 0xFF);
        out[outPos++] = (byte) (v & 0xFF);
        return outPos;
    }
}
