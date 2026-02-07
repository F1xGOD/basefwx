package com.fixcraft.basefwx;

public class TestCrossLang {
    public static void main(String[] args) {
        // Encoded by Python
        String pythonEncoded = "59A4EG9J9SN2QK2R84KMIAHO85TJISRCFCSN6R3T8ONKII31CKL32AIB85F3EAH68T234JP6D50JCTB558OIK9I78GP4MDB1FD93EOBR58K4GGAIA95JAOBRFCSN6R1A51442KIIA8RM2UPA910MO99891842DPA910MO9A98SK423";
        String expected = "Cross-language test 2024";
        
        System.out.println("Java decoding Python-encoded string:");
        String decoded = Codec.b256Decode(pythonEncoded);
        System.out.println("  Encoded (from Python): " + pythonEncoded);
        System.out.println("  Decoded (in Java): " + decoded);
        System.out.println("  Expected: " + expected);
        System.out.println("  Match: " + expected.equals(decoded));
        
        // Now encode in Java and show it for Python to decode
        String javaTest = "Java to Python test";
        String javaEncoded = Codec.b256Encode(javaTest);
        System.out.println("\nJava encoding for Python:");
        System.out.println("  Original: " + javaTest);
        System.out.println("  Encoded: " + javaEncoded);
    }
}
