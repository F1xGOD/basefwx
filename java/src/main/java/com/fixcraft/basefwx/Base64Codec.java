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
        
        // Remove whitespace for compatibility with custom implementation
        String cleaned = input.replaceAll("\\s+", "");
        if (cleaned.isEmpty()) {
            return new byte[0];
        }
        
        try {
            return DECODER.decode(cleaned);
        } catch (IllegalArgumentException e) {
            // Wrap with our own exception message for consistency
            throw new IllegalArgumentException("Invalid base64 payload", e);
        }
    }
}
