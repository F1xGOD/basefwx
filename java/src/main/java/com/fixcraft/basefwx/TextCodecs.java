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
import java.util.concurrent.atomic.AtomicBoolean;

final class TextCodecs {
    private TextCodecs() {}

    static final AtomicBoolean B256_RETIREMENT_WARNED = new AtomicBoolean(false);

    static void warnB256RetiredOnce() {
        if (B256_RETIREMENT_WARNED.compareAndSet(false, true)) {
            System.err.println(
                "🫡 b256 has been retired as of BaseFWX 3.7.0.\n" +
                "   b256 was the very first encoding method in BaseFWX —\n" +
                "   born in V1, back when this was a proof of concept and\n" +
                "   not a project. It served from day one. Existing\n" +
                "   b256-encoded blobs still decode; use base64 or\n" +
                "   hash512 / uhash513 for new code.\n" +
                "   ❤️  Thank you for the journey. It's time to go.");
        }
    }
    static byte[] encodeMaskedPayloadBytes(KeyWrap.MaskKeyResult mask,
                                                   byte[] plain,
                                                   byte[] streamInfo) {
        byte[] masked = KeyWrap.maskPayload(mask.maskKey, plain, streamInfo);
        byte[] payload = new byte[1 + 4 + masked.length];
        payload[0] = 0x02;
        BaseFwxUtil.writeU32(payload, 1, plain.length);
        System.arraycopy(masked, 0, payload, 5, masked.length);
        return Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob, payload));
    }

    static byte[] decodeMaskedPayloadBytesFromString(String input,
                                                             byte[] password,
                                                             boolean useMaster,
                                                             byte[] maskInfo,
                                                             byte[] aad,
                                                             byte[] streamInfo) {
        List<byte[]> parts = null;
        IllegalArgumentException firstError = null;
        boolean looksBase64 = Base64Codec.looksLikeBase64(input);
        String primary = looksBase64 ? input : Codec.decode(input);
        try {
            byte[] raw = Base64Codec.decode(primary);
            parts = Format.unpackLengthPrefixed(raw, 3);
            byte[] payload = parts.get(2);
            if (payload.length < 5 || payload[0] != 0x02) {
                throw new IllegalArgumentException("Unsupported payload format");
            }
            int expectedLen = BaseFwxUtil.readU32(payload, 1);
            if (expectedLen != payload.length - 5) {
                throw new IllegalArgumentException("Payload length mismatch");
            }
        } catch (IllegalArgumentException exc) {
            firstError = exc;
            parts = null;
        }
        if (parts == null) {
            String secondary = looksBase64 ? Codec.decode(input) : input;
            if (!secondary.equals(primary)) {
                try {
                    byte[] raw = Base64Codec.decode(secondary);
                    parts = Format.unpackLengthPrefixed(raw, 3);
                    byte[] payload = parts.get(2);
                    if (payload.length < 5 || payload[0] != 0x02) {
                        throw new IllegalArgumentException("Unsupported payload format");
                    }
                    int expectedLen = BaseFwxUtil.readU32(payload, 1);
                    if (expectedLen != payload.length - 5) {
                        throw new IllegalArgumentException("Payload length mismatch");
                    }
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
        return decodeMaskedPayloadBytesFromParts(parts, password, useMaster, maskInfo, aad, streamInfo);
    }

    static byte[] decodeMaskedPayloadBytes(byte[] blob,
                                                   byte[] password,
                                                   boolean useMaster,
                                                   byte[] maskInfo,
                                                   byte[] aad,
                                                   byte[] streamInfo) {
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        return decodeMaskedPayloadBytesFromParts(parts, password, useMaster, maskInfo, aad, streamInfo);
    }

    static byte[] decodeMaskedPayloadBytesFromParts(List<byte[]> parts,
                                                            byte[] password,
                                                            boolean useMaster,
                                                            byte[] maskInfo,
                                                            byte[] aad,
                                                            byte[] streamInfo) {
        byte[] maskKey = KeyWrap.recoverMaskKey(parts.get(0), parts.get(1), password, useMaster,
            maskInfo, aad, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        byte[] payload = parts.get(2);
        if (payload.length < 5 || payload[0] != 0x02) {
            throw new IllegalArgumentException("Unsupported payload format");
        }
        int expectedLen = BaseFwxUtil.readU32(payload, 1);
        if (expectedLen != payload.length - 5) {
            throw new IllegalArgumentException("Payload length mismatch");
        }
        return KeyWrap.maskPayload(maskKey, payload, 5, expectedLen, streamInfo);
    }

    static String encodePayloadString(byte[] blob) {
        String encoded = Base64Codec.encode(blob);
        return maybeObfuscateCodecs(encoded);
    }

    static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    static final byte[] HEX_BYTES = buildHexBytes();
    static final ThreadLocal<MessageDigest> SHA256_DIGEST = threadLocalDigest("SHA-256");
    static final ThreadLocal<MessageDigest> SHA1_DIGEST = threadLocalDigest("SHA-1");
    static final ThreadLocal<MessageDigest> SHA512_DIGEST = threadLocalDigest("SHA-512");

    static byte[] buildHexBytes() {
        byte[] out = new byte[512];
        for (int i = 0; i < 256; i++) {
            out[i * 2] = (byte) HEX_CHARS[i >>> 4];
            out[i * 2 + 1] = (byte) HEX_CHARS[i & 0x0F];
        }
        return out;
    }

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

    static MessageDigest digestFor(String algorithm) {
        if ("SHA-256".equalsIgnoreCase(algorithm)) {
            return SHA256_DIGEST.get();
        }
        if ("SHA-1".equalsIgnoreCase(algorithm)) {
            return SHA1_DIGEST.get();
        }
        if ("SHA-512".equalsIgnoreCase(algorithm)) {
            return SHA512_DIGEST.get();
        }
        return null;
    }

    static byte[] digestBytes(MessageDigest md, byte[] input) {
        md.reset();
        md.update(input);
        return md.digest();
    }

    static void hexToBytes(byte[] input, byte[] out) {
        if (out.length < input.length * 2) {
            throw new IllegalArgumentException("hex output buffer too small");
        }
        for (int i = 0; i < input.length; i++) {
            int v = input[i] & 0xFF;
            int idx = v << 1;
            out[i * 2] = HEX_BYTES[idx];
            out[i * 2 + 1] = HEX_BYTES[idx + 1];
        }
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

    static String digestHex(String algorithm, String input) {
        MessageDigest md = digestFor(algorithm);
        if (md == null) {
            md = newDigest(algorithm);
        }
        return digestHex(md, input.getBytes(StandardCharsets.UTF_8));
    }

    static String mdCode(String input) {
        ensureAscii(input);
        byte[] bytes = input.getBytes(StandardCharsets.US_ASCII);
        StringBuilder out = new StringBuilder(bytes.length * 3);
        for (byte b : bytes) {
            int val = b & 0xFF;
            if (val < 10) {
                out.append('1').append((char)('0' + val));
            } else if (val < 100) {
                out.append('2').append((char)('0' + val / 10)).append((char)('0' + val % 10));
            } else {
                out.append('3').append((char)('0' + val / 100)).append((char)('0' + (val / 10) % 10)).append((char)('0' + val % 10));
            }
        }
        return out.toString();
    }

    static String stripLeadingZeros(String input) {
        int idx = 0;
        while (idx < input.length() && input.charAt(idx) == '0') {
            idx++;
        }
        if (idx == input.length()) {
            return "0";
        }
        return input.substring(idx);
    }

    static int compareMagnitude(String a, String b) {
        String aa = stripLeadingZeros(a);
        String bb = stripLeadingZeros(b);
        if (aa.length() != bb.length()) {
            return aa.length() < bb.length() ? -1 : 1;
        }
        if (aa.equals(bb)) {
            return 0;
        }
        return aa.compareTo(bb) < 0 ? -1 : 1;
    }

    static String addMagnitude(String a, String b) {
        int i = a.length() - 1;
        int j = b.length() - 1;
        int carry = 0;
        StringBuilder out = new StringBuilder(Math.max(a.length(), b.length()) + 1);
        while (i >= 0 || j >= 0 || carry > 0) {
            int da = i >= 0 ? a.charAt(i) - '0' : 0;
            int db = j >= 0 ? b.charAt(j) - '0' : 0;
            int sum = da + db + carry;
            out.append((char) ('0' + (sum % 10)));
            carry = sum / 10;
            i--;
            j--;
        }
        out.reverse();
        return stripLeadingZeros(out.toString());
    }

    static String subtractMagnitude(String a, String b) {
        int i = a.length() - 1;
        int j = b.length() - 1;
        int borrow = 0;
        StringBuilder out = new StringBuilder(a.length());
        while (i >= 0) {
            int da = (a.charAt(i) - '0') - borrow;
            int db = j >= 0 ? b.charAt(j) - '0' : 0;
            if (da < db) {
                da += 10;
                borrow = 1;
            } else {
                borrow = 0;
            }
            int diff = da - db;
            out.append((char) ('0' + diff));
            i--;
            j--;
        }
        out.reverse();
        return stripLeadingZeros(out.toString());
    }

    static String addSigned(String a, String b) {
        boolean negA = false;
        boolean negB = false;
        String digitsA = a;
        String digitsB = b;
        if (!digitsA.isEmpty() && digitsA.charAt(0) == '-') {
            negA = true;
            digitsA = digitsA.substring(1);
        }
        if (!digitsB.isEmpty() && digitsB.charAt(0) == '-') {
            negB = true;
            digitsB = digitsB.substring(1);
        }
        digitsA = stripLeadingZeros(digitsA);
        digitsB = stripLeadingZeros(digitsB);
        if (digitsA.equals("0")) {
            negA = false;
        }
        if (digitsB.equals("0")) {
            negB = false;
        }
        if (negA == negB) {
            String sum = addMagnitude(digitsA, digitsB);
            if (sum.equals("0")) {
                return sum;
            }
            return (negA ? "-" : "") + sum;
        }
        int cmp = compareMagnitude(digitsA, digitsB);
        if (cmp == 0) {
            return "0";
        }
        if (cmp > 0) {
            String diff = subtractMagnitude(digitsA, digitsB);
            return (negA ? "-" : "") + diff;
        }
        String diff = subtractMagnitude(digitsB, digitsA);
        return (negB ? "-" : "") + diff;
    }

    static String mcode(String input) {
        StringBuilder out = new StringBuilder(input.length() / 2);
        int idx = 0;
        while (idx < input.length()) {
            char ch = input.charAt(idx);
            if (ch < '0' || ch > '9') {
                throw new IllegalArgumentException("Invalid mcode input");
            }
            int len = ch - '0';
            idx += 1;
            if (idx + len > input.length()) {
                throw new IllegalArgumentException("Invalid mcode length");
            }
            int val = 0;
            for (int i = 0; i < len; i++) {
                val = val * 10 + (input.charAt(idx + i) - '0');
            }
            out.append((char) val);
            idx += len;
        }
        return out.toString();
    }

    static void ensureAscii(String input) {
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) > 0x7F) {
                throw new IllegalArgumentException("Non-ASCII input");
            }
        }
    }
    static boolean obfuscateCodecsEnabled() {
        String raw = System.getenv("BASEFWX_OBFUSCATE_CODECS");
        if (raw == null || raw.trim().isEmpty()) {
            return true;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
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

    static String bi512EncodeImpl(String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("bi512encode expects non-empty input");
        }
        char[] code = new char[2];
        code[0] = input.charAt(0);
        code[1] = input.charAt(input.length() - 1);
        String md = mdCode(input);
        String mdCode = mdCode(new String(code));
        String diff;
        if (compareMagnitude(md, mdCode) >= 0) {
            diff = subtractMagnitude(md, mdCode);
        } else {
            diff = "0" + subtractMagnitude(mdCode, md);
        }
        String packed = Codec.b256Encode(diff).replace("=", "4G5tRA");
        return digestHex("SHA-256", packed);
    }

    static String a512EncodeImpl(String input) {
        String md = mdCode(input);
        int mdLen = md.length();
        String mdLenStr = Integer.toString(mdLen);
        String prefixLenStr = Integer.toString(mdLenStr.length());
        String prefix = prefixLenStr + mdLenStr;
        long lenVal = mdLen;
        String code = Long.toString(lenVal * lenVal);
        String mdCode = mdCode(code);
        String diff;
        if (compareMagnitude(md, mdCode) >= 0) {
            diff = subtractMagnitude(md, mdCode);
        } else {
            diff = "0" + subtractMagnitude(mdCode, md);
        }
        String packed = Codec.b256Encode(diff).replace("=", "4G5tRA");
        return prefix + packed;
    }

    static String a512DecodeImpl(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Empty a512 payload");
            }
            char lenCh = input.charAt(0);
            if (lenCh < '0' || lenCh > '9') {
                throw new IllegalArgumentException("Invalid a512 length marker");
            }
            int lenLen = lenCh - '0';
            if (lenLen <= 0 || input.length() < 1 + lenLen) {
                throw new IllegalArgumentException("Invalid a512 length encoding");
            }
            String lenStr = input.substring(1, 1 + lenLen);
            long mdLen = Long.parseLong(lenStr);
            String payload = input.substring(1 + lenLen);
            String code = Long.toString(mdLen * mdLen);
            String mdCode = mdCode(code);
            String restored = Codec.b256Decode(payload.replace("4G5tRA", "="));
            if (!restored.isEmpty() && restored.charAt(0) == '0') {
                restored = "-" + restored.substring(1);
            }
            String sum = addSigned(restored, mdCode);
            if (!sum.isEmpty() && sum.charAt(0) == '-') {
                throw new IllegalArgumentException("Negative a512 value");
            }
            return mcode(sum);
        } catch (RuntimeException exc) {
            return "AN ERROR OCCURED!";
        }
    }
    static byte[] b512EncodeBytes(byte[] input, String password, boolean useMaster) {
        if (input == null) {
            throw new IllegalArgumentException("b512encode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(pw, useMaster, Constants.B512_MASK_INFO,
            false, Constants.MASK_AAD_B512, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        return encodeMaskedPayloadBytes(mask, input, Constants.B512_STREAM_INFO);
    }

    static String b512Decode(String input, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        byte[] plain = decodeMaskedPayloadBytesFromString(input, pw, useMaster,
            Constants.B512_MASK_INFO, Constants.MASK_AAD_B512, Constants.B512_STREAM_INFO);
        return new String(plain, StandardCharsets.UTF_8);
    }

    static byte[] b512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("b512decode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        return decodeMaskedPayloadBytes(blob, pw, useMaster,
            Constants.B512_MASK_INFO, Constants.MASK_AAD_B512, Constants.B512_STREAM_INFO);
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
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(pw, useMaster, Constants.PB512_MASK_INFO,
            true, Constants.MASK_AAD_PB512, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        return encodeMaskedPayloadBytes(mask, input, Constants.PB512_STREAM_INFO);
    }

    static String pb512Decode(String input, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        byte[] plain = decodeMaskedPayloadBytesFromString(input, pw, useMaster,
            Constants.PB512_MASK_INFO, Constants.MASK_AAD_PB512, Constants.PB512_STREAM_INFO);
        return new String(plain, StandardCharsets.UTF_8);
    }

    static byte[] pb512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("pb512decode expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        return decodeMaskedPayloadBytes(blob, pw, useMaster,
            Constants.PB512_MASK_INFO, Constants.MASK_AAD_PB512, Constants.PB512_STREAM_INFO);
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
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        byte[] plain = decodeMaskedPayloadBytesFromString(input, pw, useMaster,
            Constants.B512_MASK_INFO, Constants.MASK_AAD_B512, Constants.B512_STREAM_INFO);
        return new String(plain, StandardCharsets.UTF_8);
    }

    static String pb512DecodeString(String input, String password, boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        byte[] plain = decodeMaskedPayloadBytesFromString(input, pw, useMaster,
            Constants.PB512_MASK_INFO, Constants.MASK_AAD_PB512, Constants.PB512_STREAM_INFO);
        return new String(plain, StandardCharsets.UTF_8);
    }

    static String hash512Bytes(byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("hash512 expects bytes");
        }
        return digestHex(SHA512_DIGEST.get(), input);
    }

    static String uhash513Bytes(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("uhash513 expects bytes");
        }
        MessageDigest md256 = SHA256_DIGEST.get();
        MessageDigest md1 = SHA1_DIGEST.get();
        MessageDigest md512 = SHA512_DIGEST.get();
        byte[] h1Bytes = digestBytes(md256, inputBytes);
        byte[] h1Hex = new byte[h1Bytes.length * 2];
        hexToBytes(h1Bytes, h1Hex);
        byte[] h2Bytes = digestBytes(md1, h1Hex);
        byte[] h2Hex = new byte[h2Bytes.length * 2];
        hexToBytes(h2Bytes, h2Hex);
        byte[] h3Bytes = digestBytes(md512, h2Hex);
        byte[] h4Bytes = digestBytes(md512, inputBytes);
        md256.reset();
        byte[] hexBuf = new byte[h3Bytes.length * 2];
        hexToBytes(h3Bytes, hexBuf);
        md256.update(hexBuf, 0, hexBuf.length);
        hexToBytes(h4Bytes, hexBuf);
        md256.update(hexBuf, 0, hexBuf.length);
        return hexToString(md256.digest());
    }

}
