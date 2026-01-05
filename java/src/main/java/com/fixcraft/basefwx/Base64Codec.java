package com.fixcraft.basefwx;

import java.util.Base64;

/**
 * Base64 encoding/decoding using Java's standard library implementation.
 * This delegates to java.util.Base64 which uses optimized native code
 * similar to how Python's base64 module uses C implementations.
 */
public final class Base64Codec {
    private Base64Codec() {}

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();
    private static final Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();

    /**
     * Encode bytes to Base64 string.
     * Uses Java's standard library implementation which is optimized with native code.
     */
    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        return ENCODER.encodeToString(data);
    }

    /**
     * Decode Base64 string to bytes.
     * Uses Java's standard library implementation which is optimized with native code.
     * Handles whitespace in input gracefully.
     */
    public static byte[] decode(String input) {
        if (input == null || input.isEmpty()) {
            return new byte[0];
        }

        boolean hasWhitespace = false;
        boolean hasData = false;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (Character.isWhitespace(ch)) {
                hasWhitespace = true;
            } else {
                hasData = true;
            }
        }
        if (!hasData) {
            return new byte[0];
        }

        try {
            return (hasWhitespace ? MIME_DECODER : DECODER).decode(input);
        } catch (IllegalArgumentException e) {
            // Wrap with our own exception message for consistency
            throw new IllegalArgumentException("Invalid base64 payload", e);
        }
    }

    public static boolean looksLikeBase64(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        int len = 0;
        int padCount = 0;
        boolean seenPad = false;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (Character.isWhitespace(ch)) {
                continue;
            }
            len++;
            if (ch == '=') {
                seenPad = true;
                padCount++;
                continue;
            }
            if (seenPad) {
                return false;
            }
            if (!isBase64Char(ch)) {
                return false;
            }
        }
        if (len == 0 || (len % 4) != 0) {
            return false;
        }
        if (padCount > 2) {
            return false;
        }
        if (padCount > 0) {
            int remainingPads = padCount;
            for (int i = input.length() - 1; i >= 0; i--) {
                char ch = input.charAt(i);
                if (Character.isWhitespace(ch)) {
                    continue;
                }
                if (ch == '=') {
                    remainingPads--;
                    continue;
                }
                break;
            }
            if (remainingPads != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean isBase64Char(char ch) {
        return (ch >= 'A' && ch <= 'Z')
            || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '+'
            || ch == '/';
    }
}
