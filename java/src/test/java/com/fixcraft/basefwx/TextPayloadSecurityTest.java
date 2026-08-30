/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TextPayloadSecurityTest {
    private static final String PASSWORD =
            "basefwx-text-payload-test-password";
    private static final int PAYLOAD_VERSION_OFFSET = 0;
    private static final int PAYLOAD_LENGTH_OFFSET = 1;

    @Test
    public void b512AndPb512EmitAuthenticatedV3Payloads() {
        byte[] plaintext = "authenticated text payload"
                .getBytes(StandardCharsets.UTF_8);
        for (boolean heavy : new boolean[] {false, true}) {
            byte[] blob = encodeBytes(heavy, plaintext);
            List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
            byte[] payload = parts.get(2);
            assertEquals(3, payload[PAYLOAD_VERSION_OFFSET] & 0xff);
            assertEquals(
                    plaintext.length,
                    BaseFwxUtil.readU32(payload, PAYLOAD_LENGTH_OFFSET));
            assertArrayEquals(plaintext, decodeBytes(heavy, blob));
        }
    }

    @Test
    public void ciphertextTagAndHeaderTamperingAreRejected() {
        byte[] plaintext = "tamper resistance"
                .getBytes(StandardCharsets.UTF_8);
        for (boolean heavy : new boolean[] {false, true}) {
            List<byte[]> parts = Format.unpackLengthPrefixed(
                    encodeBytes(heavy, plaintext), 3);

            List<byte[]> tagTampered = cloneParts(parts);
            byte[] tagPayload = tagTampered.get(2);
            tagPayload[tagPayload.length - 1] ^= 1;
            expectIllegalArgument(
                    () -> decodeBytes(
                            heavy, Format.packLengthPrefixed(tagTampered)),
                    "corrupted");

            List<byte[]> headerTampered = cloneParts(parts);
            headerTampered.get(2)[4] ^= 1;
            expectIllegalArgument(
                    () -> decodeBytes(
                            heavy, Format.packLengthPrefixed(headerTampered)),
                    "length mismatch");
        }
    }

    @Test
    public void payloadDomainsAreCryptographicallySeparated() {
        byte[] plaintext = "domain separation"
                .getBytes(StandardCharsets.UTF_8);
        byte[] blob = TextCodecs.b512EncodeBytes(
                plaintext, PASSWORD, false);
        byte[] password = BaseFwx.resolvePasswordBytes(PASSWORD, false);
        try {
            expectIllegalArgument(
                    () -> TextCodecs.decodeMaskedPayloadBytes(
                            blob,
                            password,
                            false,
                            Constants.B512_MASK_INFO,
                            Constants.MASK_AAD_B512,
                            Constants.B512_STREAM_INFO,
                            Constants.PB512_PAYLOAD_AEAD_INFO,
                            Constants.PB512_PAYLOAD_AAD,
                            false),
                    "corrupted");
        } finally {
            Arrays.fill(password, (byte) 0);
        }
    }

    @Test
    public void legacyV2RequiresExplicitRecoveryPolicy() {
        byte[] plaintext = "trusted legacy recovery"
                .getBytes(StandardCharsets.UTF_8);
        for (boolean heavy : new boolean[] {false, true}) {
            byte[] legacy = makeLegacyV2(heavy, plaintext);
            byte[] password = BaseFwx.resolvePasswordBytes(PASSWORD, false);
            try {
                expectIllegalArgument(
                        () -> decodeBytesWithPolicy(
                                heavy, legacy, password, false),
                        "disabled");
                assertArrayEquals(
                        plaintext,
                        decodeBytesWithPolicy(
                                heavy, legacy, password, true));
            } finally {
                Arrays.fill(password, (byte) 0);
            }
        }
    }

    @Test
    public void canonicalOutputIsDefaultAndTokenMapInputStillDecodes() {
        assertFalse(TextCodecs.obfuscateCodecsEnabled());
        String plaintext = "canonical base64 text";
        for (boolean heavy : new boolean[] {false, true}) {
            String canonical = heavy
                    ? BaseFwx.pb512Encode(plaintext, PASSWORD, false)
                    : BaseFwx.b512Encode(plaintext, PASSWORD, false);
            assertTrue(Base64Codec.looksLikeBase64(canonical));
            assertEquals(
                    plaintext,
                    heavy
                            ? BaseFwx.pb512Decode(
                                    Codec.code(canonical), PASSWORD, false)
                            : BaseFwx.b512Decode(
                                    Codec.code(canonical), PASSWORD, false));
        }
    }

    private static byte[] encodeBytes(boolean heavy, byte[] plaintext) {
        return heavy
                ? TextCodecs.pb512EncodeBytes(
                        plaintext, PASSWORD, false)
                : TextCodecs.b512EncodeBytes(
                        plaintext, PASSWORD, false);
    }

    private static byte[] decodeBytes(boolean heavy, byte[] blob) {
        return heavy
                ? TextCodecs.pb512DecodeBytes(blob, PASSWORD, false)
                : TextCodecs.b512DecodeBytes(blob, PASSWORD, false);
    }

    private static byte[] decodeBytesWithPolicy(
            boolean heavy,
            byte[] blob,
            byte[] password,
            boolean allowLegacyTextV2) {
        return TextCodecs.decodeMaskedPayloadBytes(
                blob,
                password,
                false,
                heavy ? Constants.PB512_MASK_INFO : Constants.B512_MASK_INFO,
                heavy ? Constants.MASK_AAD_PB512 : Constants.MASK_AAD_B512,
                heavy ? Constants.PB512_STREAM_INFO : Constants.B512_STREAM_INFO,
                heavy
                        ? Constants.PB512_PAYLOAD_AEAD_INFO
                        : Constants.B512_PAYLOAD_AEAD_INFO,
                heavy
                        ? Constants.PB512_PAYLOAD_AAD
                        : Constants.B512_PAYLOAD_AAD,
                allowLegacyTextV2);
    }

    private static byte[] makeLegacyV2(boolean heavy, byte[] plaintext) {
        byte[] password = BaseFwx.resolvePasswordBytes(PASSWORD, false);
        KeyWrap.MaskKeyResult mask = null;
        try {
            mask = KeyWrap.prepareMaskKey(
                    password,
                    false,
                    heavy
                            ? Constants.PB512_MASK_INFO
                            : Constants.B512_MASK_INFO,
                    heavy,
                    heavy
                            ? Constants.MASK_AAD_PB512
                            : Constants.MASK_AAD_B512,
                    new KeyWrap.KdfOptions(
                            "pbkdf2", Constants.USER_KDF_ITERATIONS));
            byte[] masked = KeyWrap.maskPayload(
                    mask.maskKey,
                    plaintext,
                    heavy
                            ? Constants.PB512_STREAM_INFO
                            : Constants.B512_STREAM_INFO);
            byte[] payload = new byte[5 + masked.length];
            payload[0] = 2;
            BaseFwxUtil.writeU32(payload, 1, plaintext.length);
            System.arraycopy(masked, 0, payload, 5, masked.length);
            return Format.packLengthPrefixed(
                    Arrays.asList(mask.userBlob, mask.masterBlob, payload));
        } finally {
            Arrays.fill(password, (byte) 0);
            if (mask != null) {
                mask.close();
            }
        }
    }

    private static List<byte[]> cloneParts(List<byte[]> parts) {
        return Arrays.asList(
                parts.get(0).clone(),
                parts.get(1).clone(),
                parts.get(2).clone());
    }

    private static void expectIllegalArgument(
            Runnable action, String messagePart) {
        try {
            action.run();
            fail("expected payload rejection");
        } catch (IllegalArgumentException expected) {
            assertTrue(
                    "unexpected rejection: " + expected.getMessage(),
                    expected.getMessage().toLowerCase().contains(
                            messagePart.toLowerCase()));
        }
    }
}
