package com.fixcraft.basefwx;

public class TestCodec {
    public static void main(String[] args) {
        String[] testCases = {
            "Hello World 123",
            "a",
            "The quick brown fox",
            "Special chars: !@#$%^&*()",
            "12345678901234567890"
        };

        System.out.println("Testing Java b256 codec:");
        for (String testStr : testCases) {
            String encoded = Codec.b256Encode(testStr);
            String decoded = Codec.b256Decode(encoded);
            boolean match = testStr.equals(decoded);
            String preview = encoded.length() > 20 ? encoded.substring(0, 20) + "..." : encoded;
            System.out.println("  '" + testStr + "' -> " + preview + " -> match=" + match);
            if (!match) {
                System.out.println("    ERROR: Got '" + decoded + "'");
            }
        }
    }
}
