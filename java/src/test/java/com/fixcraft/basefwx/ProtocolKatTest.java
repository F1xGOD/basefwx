/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Byte-identity KATs vs C++/liboqs vectors in testdata/protocol_kats/.
 */
public class ProtocolKatTest {
    private static final Pattern OBJECT = Pattern.compile(
            "\"(hkdf_sha256_salted|hkdf_sha256_empty_salt|x25519|ml_kem_768|ml_kem_1024)\"\\s*:\\s*\\{");

    @Test
    public void hkdfSaltedMatchesCpp() throws Exception {
        Map<String, String> v = section("hkdf_sha256_salted");
        byte[] out = Crypto.hkdfSha256(
                unhex(v.get("ikm_hex")),
                unhex(v.get("salt_hex")),
                unhex(v.get("info_hex")),
                Integer.parseInt(v.get("length")));
        assertEquals(v.get("okm_hex"), hex(out));
    }

    @Test
    public void hkdfEmptySaltMatchesCpp() throws Exception {
        Map<String, String> v = section("hkdf_sha256_empty_salt");
        byte[] info = v.get("info_utf8").getBytes(StandardCharsets.US_ASCII);
        byte[] out = Crypto.hkdfSha256(unhex(v.get("ikm_hex")), new byte[0], info,
                Integer.parseInt(v.get("length")));
        assertEquals(v.get("okm_hex"), hex(out));
        assertArrayEquals(out, Crypto.hkdfSha256(unhex(v.get("ikm_hex")), info,
                Integer.parseInt(v.get("length"))));
    }

    @Test
    public void x25519MatchesCppAndRejectsAllZero() throws Exception {
        Map<String, String> v = section("x25519");
        byte[] shared = X25519.deriveSharedSecret(
                unhex(v.get("alice_private_hex")), unhex(v.get("bob_public_hex")));
        assertEquals(v.get("shared_hex"), hex(shared));
        byte[] shared2 = X25519.deriveSharedSecret(
                unhex(v.get("bob_private_hex")), unhex(v.get("alice_public_hex")));
        assertArrayEquals(shared, shared2);

        try {
            X25519.deriveSharedSecret(new byte[32], new byte[32]);
            fail("expected all-zero shared reject");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("all-zero"));
        }
    }

    @Test
    public void mlKem768DecapsMatchesCpp() throws Exception {
        Map<String, String> v = section("ml_kem_768");
        byte[] shared = PQ.kemDecrypt(
                unhex(v.get("private_key_hex")), unhex(v.get("ciphertext_hex")));
        assertEquals(v.get("shared_hex"), hex(shared));
    }

    @Test
    public void mlKem1024DecapsMatchesCpp() throws Exception {
        Map<String, String> v = section("ml_kem_1024");
        byte[] shared = PQ.kemDecrypt(
                unhex(v.get("private_key_hex")), unhex(v.get("ciphertext_hex")));
        assertEquals(v.get("shared_hex"), hex(shared));
    }

    @Test
    public void generateKeyPairRoundTrip() throws Exception {
        for (PQ.KemAlgorithm alg : PQ.KemAlgorithm.values()) {
            PQ.KemKeyPair kp = PQ.generateKeyPair(alg);
            PQ.KemResult enc = PQ.kemEncrypt(kp.publicKey);
            byte[] shared = PQ.kemDecrypt(kp.privateKey, enc.ciphertext);
            assertArrayEquals(enc.shared, shared);
            kp.wipePrivate();
            Arrays.fill(enc.shared, (byte) 0);
        }
    }

    @Test
    public void rejectsMismatchedKemSizesBeforeDecapsulation() throws Exception {
        PQ.KemKeyPair kp768 = PQ.generateKeyPair(PQ.KemAlgorithm.ML_KEM_768);
        PQ.KemKeyPair kp1024 = PQ.generateKeyPair(PQ.KemAlgorithm.ML_KEM_1024);
        PQ.KemResult enc1024 = PQ.kemEncrypt(kp1024.publicKey);
        try {
            PQ.kemDecrypt(kp768.privateKey, enc1024.ciphertext);
            fail("expected mismatched ML-KEM sizes to be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("mismatched"));
        } finally {
            kp768.wipePrivate();
            kp1024.wipePrivate();
            Arrays.fill(enc1024.shared, (byte) 0);
        }
    }

    private static Map<String, String> section(String name) throws Exception {
        String json = loadJson();
        Matcher m = OBJECT.matcher(json);
        while (m.find()) {
            if (!name.equals(m.group(1))) {
                continue;
            }
            int brace = m.end() - 1;
            int depth = 0;
            int end = -1;
            for (int i = brace; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        end = i;
                        break;
                    }
                }
            }
            String block = json.substring(brace, end + 1);
            Map<String, String> out = new HashMap<String, String>();
            Matcher fields = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(?:\"([^\"]*)\"|(\\d+)|true|false)")
                    .matcher(block);
            while (fields.find()) {
                if (fields.group(2) != null) {
                    out.put(fields.group(1), fields.group(2));
                } else if (fields.group(3) != null) {
                    out.put(fields.group(1), fields.group(3));
                }
            }
            return out;
        }
        throw new IllegalStateException("missing section " + name);
    }

    private static String loadJson() throws Exception {
        try (InputStream in = ProtocolKatTest.class.getResourceAsStream(
                "/protocol_kats/vectors.json")) {
            if (in == null) {
                throw new IllegalStateException("vectors.json not on classpath");
            }
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) >= 0) {
                buf.write(chunk, 0, n);
            }
            return new String(buf.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static byte[] unhex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
