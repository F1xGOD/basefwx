/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

final class TextCodecs {
    private TextCodecs() {}

    private static final int AUTHENTICATED_PAYLOAD_VERSION = 3;
    private static final int LEGACY_MASKED_PAYLOAD_VERSION = 2;
    private static final int PAYLOAD_HEADER_LEN = 5;

    static byte[] encodeMaskedPayloadBytes(KeyWrap.MaskKeyResult mask,
                                            byte[] plain,
                                            byte[] payloadAeadInfo,
                                            byte[] payloadAadDomain) {
        byte[] payloadKey = null;
        try {
            payloadKey = Crypto.hkdfSha256(mask.maskKey, payloadAeadInfo, 32);
            byte[] header = new byte[PAYLOAD_HEADER_LEN];
            header[0] = (byte) AUTHENTICATED_PAYLOAD_VERSION;
            BaseFwxUtil.writeU32(header, 1, plain.length);
            byte[] encrypted = Crypto.aesGcmEncrypt(
                    payloadKey,
                    plain,
                    payloadAad(payloadAadDomain, header));
            byte[] payload = new byte[header.length + encrypted.length];
            System.arraycopy(header, 0, payload, 0, header.length);
            System.arraycopy(encrypted, 0, payload, header.length, encrypted.length);
            return Format.packLengthPrefixed(
                    Arrays.asList(mask.userBlob, mask.masterBlob, payload));
        } finally {
            if (payloadKey != null) {
                Arrays.fill(payloadKey, (byte) 0);
            }
            mask.close();
        }
    }

    private static byte[] payloadAad(byte[] domain, byte[] payload) {
        if (payload.length < PAYLOAD_HEADER_LEN) {
            throw new IllegalArgumentException("Malformed payload");
        }
        byte[] aad = new byte[domain.length + PAYLOAD_HEADER_LEN];
        System.arraycopy(domain, 0, aad, 0, domain.length);
        System.arraycopy(payload, 0, aad, domain.length, PAYLOAD_HEADER_LEN);
        return aad;
    }

    private static int validatePayloadStructure(
            byte[] payload, boolean allowLegacyTextV2) {
        if (payload.length < PAYLOAD_HEADER_LEN) {
            throw new IllegalArgumentException("Malformed payload");
        }
        int expectedLen = BaseFwxUtil.readU32(payload, 1);
        if (expectedLen < 0) {
            throw new IllegalArgumentException("Text payload is too large");
        }
        int version = payload[0] & 0xFF;
        if (version == AUTHENTICATED_PAYLOAD_VERSION) {
            long expectedTotal = (long) PAYLOAD_HEADER_LEN
                    + Constants.AEAD_NONCE_LEN
                    + Constants.AEAD_TAG_LEN
                    + expectedLen;
            if (expectedTotal != payload.length) {
                throw new IllegalArgumentException("Payload length mismatch");
            }
            return expectedLen;
        }
        if (version == LEGACY_MASKED_PAYLOAD_VERSION) {
            if (!allowLegacyTextV2) {
                throw new IllegalArgumentException(
                        "Unauthenticated text payload v2 is disabled; set "
                        + "BASEFWX_ALLOW_LEGACY_TEXT_V2=1 only to recover trusted legacy data");
            }
            if ((long) PAYLOAD_HEADER_LEN + expectedLen != payload.length) {
                throw new IllegalArgumentException("Payload length mismatch");
            }
            return expectedLen;
        }
        throw new IllegalArgumentException("Unsupported payload format");
    }

    private static List<byte[]> decodePayloadParts(String input) {
        byte[] raw = Base64Codec.decode(input);
        return Format.unpackLengthPrefixed(raw, 3);
    }

    static byte[] decodeMaskedPayloadBytesFromString(String input,
                                                      byte[] password,
                                                      boolean useMaster,
                                                      byte[] maskInfo,
                                                      byte[] aad,
                                                      byte[] streamInfo,
                                                      byte[] payloadAeadInfo,
                                                      byte[] payloadAadDomain) {
        List<byte[]> parts = null;
        IllegalArgumentException firstError = null;
        boolean looksBase64 = Base64Codec.looksLikeBase64(input);
        String primary = looksBase64 ? input : Codec.decode(input);
        try {
            parts = decodePayloadParts(primary);
        } catch (IllegalArgumentException exc) {
            firstError = exc;
            parts = null;
        }
        if (parts == null) {
            String secondary = looksBase64 ? Codec.decode(input) : input;
            if (!secondary.equals(primary)) {
                try {
                    parts = decodePayloadParts(secondary);
                } catch (IllegalArgumentException exc) {
                    if (firstError == null) {
                        firstError = exc;
                    }
                    parts = null;
                }
            }
        }
        if (parts == null) {
            throw new IllegalArgumentException("Invalid payload encoding", firstError);
        }
        return decodeMaskedPayloadBytesFromParts(
                parts,
                password,
                useMaster,
                maskInfo,
                aad,
                streamInfo,
                payloadAeadInfo,
                payloadAadDomain);
    }

    static byte[] decodeMaskedPayloadBytes(byte[] blob,
                                            byte[] password,
                                            boolean useMaster,
                                            byte[] maskInfo,
                                            byte[] aad,
                                            byte[] streamInfo,
                                            byte[] payloadAeadInfo,
                                            byte[] payloadAadDomain) {
        return decodeMaskedPayloadBytes(
                blob,
                password,
                useMaster,
                maskInfo,
                aad,
                streamInfo,
                payloadAeadInfo,
                payloadAadDomain,
                Constants.envEnabled("BASEFWX_ALLOW_LEGACY_TEXT_V2"));
    }

    static byte[] decodeMaskedPayloadBytes(byte[] blob,
                                            byte[] password,
                                            boolean useMaster,
                                            byte[] maskInfo,
                                            byte[] aad,
                                            byte[] streamInfo,
                                            byte[] payloadAeadInfo,
                                            byte[] payloadAadDomain,
                                            boolean allowLegacyTextV2) {
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        return decodeMaskedPayloadBytesFromParts(
                parts,
                password,
                useMaster,
                maskInfo,
                aad,
                streamInfo,
                payloadAeadInfo,
                payloadAadDomain,
                allowLegacyTextV2);
    }

    static byte[] decodeMaskedPayloadBytesFromParts(List<byte[]> parts,
                                                     byte[] password,
                                                     boolean useMaster,
                                                     byte[] maskInfo,
                                                     byte[] aad,
                                                     byte[] streamInfo,
                                                     byte[] payloadAeadInfo,
                                                     byte[] payloadAadDomain) {
        return decodeMaskedPayloadBytesFromParts(
                parts,
                password,
                useMaster,
                maskInfo,
                aad,
                streamInfo,
                payloadAeadInfo,
                payloadAadDomain,
                Constants.envEnabled("BASEFWX_ALLOW_LEGACY_TEXT_V2"));
    }

    static byte[] decodeMaskedPayloadBytesFromParts(List<byte[]> parts,
                                                     byte[] password,
                                                     boolean useMaster,
                                                     byte[] maskInfo,
                                                     byte[] aad,
                                                     byte[] streamInfo,
                                                     byte[] payloadAeadInfo,
                                                     byte[] payloadAadDomain,
                                                     boolean allowLegacyTextV2) {
        byte[] payload = parts.get(2);
        int expectedLen = validatePayloadStructure(
                payload, allowLegacyTextV2);
        byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                password,
                useMaster,
                maskInfo,
                aad,
                new KeyWrap.KdfOptions(
                        "pbkdf2", Constants.USER_KDF_ITERATIONS));
        try {
            if ((payload[0] & 0xFF) == AUTHENTICATED_PAYLOAD_VERSION) {
                byte[] payloadKey = Crypto.hkdfSha256(
                        maskKey, payloadAeadInfo, 32);
                try {
                    byte[] encrypted = Arrays.copyOfRange(
                            payload, PAYLOAD_HEADER_LEN, payload.length);
                    byte[] clear = Crypto.aesGcmDecrypt(
                            payloadKey,
                            encrypted,
                            payloadAad(payloadAadDomain, payload));
                    if (clear.length != expectedLen) {
                        Arrays.fill(clear, (byte) 0);
                        throw new IllegalArgumentException("Payload length mismatch");
                    }
                    return clear;
                } finally {
                    Arrays.fill(payloadKey, (byte) 0);
                }
            }
            return KeyWrap.maskPayload(
                    maskKey,
                    payload,
                    PAYLOAD_HEADER_LEN,
                    expectedLen,
                    streamInfo);
        } finally {
            Arrays.fill(maskKey, (byte) 0);
        }
    }

    static String encodePayloadString(byte[] blob) {
        String encoded = Base64Codec.encode(blob);
        return maybeObfuscateCodecs(encoded);
    }

    static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    static final ThreadLocal<MessageDigest> SHA512_DIGEST = threadLocalDigest("SHA-512");

    static ThreadLocal<MessageDigest> threadLocalDigest(String algorithm) {
        return ThreadLocal.withInitial(() -> newDigest(algorithm));
    }

    static MessageDigest newDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalStateException("Digest unavailable: " + algorithm, exc);
        }
    }

    static byte[] digestBytes(MessageDigest md, byte[] input) {
        md.reset();
        md.update(input);
        return md.digest();
    }

    static String hexToString(byte[] input) {
        char[] out = new char[input.length * 2];
        for (int i = 0; i < input.length; i++) {
            int v = input[i] & 0xFF;
            out[i * 2] = HEX_CHARS[v >>> 4];
            out[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(out);
    }

    static String digestHex(MessageDigest md, byte[] input) {
        return hexToString(digestBytes(md, input));
    }

    static boolean obfuscateCodecsEnabled() {
        return Constants.envEnabled("BASEFWX_OBFUSCATE_CODECS");
    }

    static String maybeObfuscateCodecs(String input) {
        if (!obfuscateCodecsEnabled()) {
            return input;
        }
        return Codec.code(input);
    }

    static String maybeDeobfuscateCodecs(String input) {
        try {
            Base64Codec.decode(input);
            return input;
        } catch (IllegalArgumentException exc) {
            return Codec.decode(input);
        }
    }

    static byte[] b512EncodeBytes(byte[] input, String password, boolean useMaster) {
        if (input == null) {
            throw new IllegalArgumentException("b512encode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        try {
            KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                    pw,
                    useMaster,
                    Constants.B512_MASK_INFO,
                    false,
                    Constants.MASK_AAD_B512,
                    new KeyWrap.KdfOptions(
                            "pbkdf2", Constants.USER_KDF_ITERATIONS));
            return encodeMaskedPayloadBytes(
                    mask,
                    input,
                    Constants.B512_PAYLOAD_AEAD_INFO,
                    Constants.B512_PAYLOAD_AAD);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    static String b512Decode(String input, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        byte[] plain = null;
        try {
            plain = decodeMaskedPayloadBytesFromString(
                    input,
                    pw,
                    useMaster,
                    Constants.B512_MASK_INFO,
                    Constants.MASK_AAD_B512,
                    Constants.B512_STREAM_INFO,
                    Constants.B512_PAYLOAD_AEAD_INFO,
                    Constants.B512_PAYLOAD_AAD);
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(pw, (byte) 0);
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
        }
    }

    static byte[] b512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("b512decode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        try {
            return decodeMaskedPayloadBytes(
                    blob,
                    pw,
                    useMaster,
                    Constants.B512_MASK_INFO,
                    Constants.MASK_AAD_B512,
                    Constants.B512_STREAM_INFO,
                    Constants.B512_PAYLOAD_AEAD_INFO,
                    Constants.B512_PAYLOAD_AAD);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    static String pb512Encode(String input, String password, boolean useMaster) {
        byte[] blob = pb512EncodeBytes(input.getBytes(StandardCharsets.UTF_8), password, useMaster);
        return encodePayloadString(blob);
    }

    static byte[] pb512EncodeBytes(byte[] input, String password, boolean useMaster) {
        if (input == null) {
            throw new IllegalArgumentException("pb512encode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        try {
            KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                    pw,
                    useMaster,
                    Constants.PB512_MASK_INFO,
                    true,
                    Constants.MASK_AAD_PB512,
                    new KeyWrap.KdfOptions(
                            "pbkdf2", Constants.USER_KDF_ITERATIONS));
            return encodeMaskedPayloadBytes(
                    mask,
                    input,
                    Constants.PB512_PAYLOAD_AEAD_INFO,
                    Constants.PB512_PAYLOAD_AAD);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    static String pb512Decode(String input, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        byte[] plain = null;
        try {
            plain = decodeMaskedPayloadBytesFromString(
                    input,
                    pw,
                    useMaster,
                    Constants.PB512_MASK_INFO,
                    Constants.MASK_AAD_PB512,
                    Constants.PB512_STREAM_INFO,
                    Constants.PB512_PAYLOAD_AEAD_INFO,
                    Constants.PB512_PAYLOAD_AAD);
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(pw, (byte) 0);
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
        }
    }

    static byte[] pb512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("pb512decode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        try {
            return decodeMaskedPayloadBytes(
                    blob,
                    pw,
                    useMaster,
                    Constants.PB512_MASK_INFO,
                    Constants.MASK_AAD_PB512,
                    Constants.PB512_STREAM_INFO,
                    Constants.PB512_PAYLOAD_AEAD_INFO,
                    Constants.PB512_PAYLOAD_AAD);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    static String b512EncodeString(String input, String password, boolean useMaster) {
        byte[] blob = b512EncodeBytes(input.getBytes(StandardCharsets.UTF_8), password, useMaster);
        return encodePayloadString(blob);
    }

    static String pb512EncodeString(String input, String password, boolean useMaster) {
        byte[] blob = pb512EncodeBytes(input.getBytes(StandardCharsets.UTF_8), password, useMaster);
        return encodePayloadString(blob);
    }

    static String b512DecodeString(String input, String password, boolean useMaster) {
        return b512Decode(input, password, useMaster);
    }

    static String pb512DecodeString(String input, String password, boolean useMaster) {
        return pb512Decode(input, password, useMaster);
    }

    static String hash512Bytes(byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("hash512 expects bytes");
        }
        return digestHex(SHA512_DIGEST.get(), input);
    }

}
