/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PayloadKeySeparationTest {
    @Test
    public void v1UsesIndependentLabelsAndWipesDerivedKeys() {
        byte[] root = new byte[32];
        for (int i = 0; i < root.length; ++i) {
            root[i] = (byte) (i * 7 + 3);
        }
        PayloadKeySeparation.PayloadKeys keys =
                PayloadKeySeparation.derive(root);
        byte[] aeadReference = keys.aead;
        byte[] obfuscationReference = keys.obfuscation;
        assertArrayEquals(
                Crypto.hkdfSha256(
                        root, Constants.FWXAES_PAYLOAD_AEAD_INFO, 32),
                keys.aead);
        assertArrayEquals(
                Crypto.hkdfSha256(
                        root, Constants.FWXAES_PAYLOAD_OBF_INFO, 32),
                keys.obfuscation);
        assertFalse(java.util.Arrays.equals(
                keys.aead, keys.obfuscation));

        keys.close();

        assertAllZero(aeadReference);
        assertAllZero(obfuscationReference);
    }

    @Test
    public void markerIsStrictAndAbsentMetadataRemainsLegacy() {
        assertFalse(PayloadKeySeparation.usesDerivedKeys(""));
        String v1 = encodedMetadata("v1");
        assertTrue(PayloadKeySeparation.usesDerivedKeys(v1));

        try {
            PayloadKeySeparation.usesDerivedKeys(
                    encodedMetadata("v2"));
            fail("Unknown ENC-KSEP version was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains(
                    "key-separation"));
        }
    }

    @Test
    public void payloadObfuscationModeIsWireDrivenAndStrict() {
        assertTrue("yes".equals(
                FileCodecs.requirePayloadObfuscationMode(null)));
        assertTrue("no".equals(
                FileCodecs.requirePayloadObfuscationMode(" NO ")));
        assertTrue("fast".equals(
                FileCodecs.requirePayloadObfuscationMode("fast")));
        try {
            FileCodecs.requirePayloadObfuscationMode("future");
            fail("Unknown ENC-OBF mode was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains(
                    "obfuscation mode"));
        }
    }

    @Test
    public void metadataBuilderEmitsMarkerOnlyWhenNotStripped() {
        String metadata = FileCodecMetadata.buildMetadata(
                "AES-HEAVY", false, false, "none", "AESGCM",
                "pbkdf2", null, true, "yes", 600000,
                null, null, null, null, "v1");
        assertTrue(PayloadKeySeparation.usesDerivedKeys(metadata));

        String stripped = FileCodecMetadata.buildMetadata(
                "AES-HEAVY", true, false, "none", "AESGCM",
                "pbkdf2", null, true, "yes", 600000,
                null, null, null, null, "v1");
        assertTrue(stripped.isEmpty());
        assertFalse(PayloadKeySeparation.usesDerivedKeys(stripped));
    }

    @Test
    public void simplePayloadRoundTripsWithAndWithoutObfuscation() {
        byte[] payload =
                "payload-key-separation-roundtrip".getBytes(
                        StandardCharsets.UTF_8);
        String password = "correct-password";
        for (boolean obfuscate : new boolean[] {false, true}) {
            String metadata = FileCodecMetadata.buildMetadata(
                    "AES-HEAVY", false, false, "none", "AESGCM",
                    "pbkdf2", null, obfuscate,
                    obfuscate ? "yes" : "no", 1,
                    null, null, null, null, "v1");
            byte[] encrypted = LengthPrefixedCodec.encryptAesPayloadBytes(
                    payload,
                    password,
                    false,
                    metadata,
                    "pbkdf2",
                    1,
                    obfuscate,
                    false);
            assertArrayEquals(
                    payload,
                    LengthPrefixedCodec.decryptAesPayloadBytes(
                            encrypted, password, false));
        }
    }

    @Test
    public void streamObfuscatorMatchesCrossRuntimePcgVector()
            throws Exception {
        byte[] key = new byte[32];
        byte[] salt = new byte[16];
        byte[] payload = new byte[8193];
        for (int i = 0; i < key.length; ++i) {
            key[i] = (byte) i;
        }
        for (int i = 0; i < salt.length; ++i) {
            salt[i] = (byte) (i + 32);
        }
        for (int i = 0; i < payload.length; ++i) {
            payload[i] = (byte) (i * 17 + 3);
        }

        FileCodecObfuscation.StreamObfuscator fastEncoder =
                FileCodecObfuscation.StreamObfuscator.forKey(
                        key, salt, true);
        byte[] fastEncoded = payload.clone();
        fastEncoder.encodeChunkInPlace(fastEncoded);
        assertArrayEquals(
                hex("aa267e30454c667dfa132bafc2d068a7"
                        + "d185fc0c45b7187df9dd10d0c66d74a9"),
                MessageDigest.getInstance("SHA-256").digest(fastEncoded));

        FileCodecObfuscation.StreamObfuscator encoder =
                FileCodecObfuscation.StreamObfuscator.forKey(
                        key, salt, false);
        byte[] encoded = payload.clone();
        encoder.encodeChunkInPlace(encoded);
        assertArrayEquals(
                hex("92a1cf91bf2a09eaefd958f4c8d4cccd"
                        + "0453145a04683990f491881bf8061fc8"),
                MessageDigest.getInstance("SHA-256").digest(encoded));

        FileCodecObfuscation.StreamObfuscator decoder =
                FileCodecObfuscation.StreamObfuscator.forKey(
                        key, salt, false);
        decoder.decodeChunkInPlace(encoded);
        assertArrayEquals(payload, encoded);
    }

    private static String encodedMetadata(String version) {
        String json = "{\"ENC-KSEP\":\"" + version + "\"}";
        return Base64Codec.encode(
                json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertAllZero(byte[] bytes) {
        for (byte value : bytes) {
            if (value != 0) {
                fail("Derived key was not wiped");
            }
        }
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; ++i) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
