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
import java.util.concurrent.atomic.AtomicBoolean;

/** Implementations available only in the retired-codec compatibility profile. */
final class RetiredCodecs {
    private RetiredCodecs() {}

    private static final char[] BASE32HEX_ALPHABET =
            "0123456789ABCDEFGHIJKLMNOPQRSTUV".toCharArray();
    private static final int[] BASE32HEX_DECODE = buildBase32Decode();
    private static final char[] HEX_CHARS =
            "0123456789abcdef".toCharArray();
    private static final byte[] HEX_BYTES = buildHexBytes();
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST =
            threadLocalDigest("SHA-256");
    private static final ThreadLocal<MessageDigest> SHA1_DIGEST =
            threadLocalDigest("SHA-1");
    private static final ThreadLocal<MessageDigest> SHA512_DIGEST =
            threadLocalDigest("SHA-512");
    private static final AtomicBoolean B256_RETIREMENT_WARNED =
            new AtomicBoolean(false);

    static void warnB256RetiredOnce() {
        if (B256_RETIREMENT_WARNED.compareAndSet(false, true)) {
            System.err.println(
                "b256 is available only for retired-data compatibility; "
                + "use base64 for new reversible encodings.");
        }
    }

    static String base32HexEncode(byte[] data) {
        if (data.length == 0) {
            return "";
        }
        int outLen = ((data.length + 4) / 5) * 8;
        char[] out = new char[outLen];
        int outPos = 0;
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                out[outPos++] = BASE32HEX_ALPHABET[index];
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            buffer <<= (5 - bitsLeft);
            int index = buffer & 0x1F;
            out[outPos++] = BASE32HEX_ALPHABET[index];
        }
        while (outPos % 8 != 0) {
            out[outPos++] = '=';
        }
        return new String(out, 0, outPos);
    }

    static byte[] base32HexDecode(String input) {
        boolean ok = true;
        int maxLen = (input.length() * 5) / 8 + 8;
        byte[] out = new byte[maxLen];
        int outPos = 0;
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (Character.isWhitespace(ch)) {
                continue;
            }
            if (ch == '=') {
                break;
            }
            int val = ch < 256 ? BASE32HEX_DECODE[ch] : -1;
            if (val < 0) {
                ok = false;
                break;
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                byte b = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
                out[outPos++] = b;
                bitsLeft -= 8;
            }
        }
        if (!ok) {
            throw new IllegalArgumentException("Invalid base32 payload");
        }
        return Arrays.copyOf(out, outPos);
    }

    static String b256Encode(String input) {
        String coded = Codec.code(input);
        byte[] raw = coded.getBytes(StandardCharsets.UTF_8);
        String encoded = base32HexEncode(raw);
        int end = encoded.length();
        int paddingCount = 0;
        while (end > 0 && encoded.charAt(end - 1) == '=') {
            paddingCount++;
            end--;
        }
        if (paddingCount > 9) {
            throw new IllegalArgumentException(
                    "Base32 padding count exceeded single digit");
        }
        return encoded.substring(0, end) + paddingCount;
    }

    static String b256Decode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        char padChar = input.charAt(input.length() - 1);
        if (padChar < '0' || padChar > '9') {
            throw new IllegalArgumentException(
                    "Invalid b256 padding marker");
        }
        int padding = padChar - '0';
        String base32 = input.substring(0, input.length() - 1)
                + repeat('=', padding);
        byte[] decoded = base32HexDecode(base32);
        String decodedText = new String(decoded, StandardCharsets.UTF_8);
        return Codec.decode(decodedText);
    }

    static String bi512Encode(String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException(
                    "bi512encode expects non-empty input");
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
        String packed = b256Encode(diff).replace("=", "4G5tRA");
        return digestHex("SHA-256", packed);
    }

    static String a512Encode(String input) {
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
        String packed = b256Encode(diff).replace("=", "4G5tRA");
        return prefix + packed;
    }

    static String a512Decode(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Empty a512 payload");
            }
            char lenCh = input.charAt(0);
            if (lenCh < '0' || lenCh > '9') {
                throw new IllegalArgumentException(
                        "Invalid a512 length marker");
            }
            int lenLen = lenCh - '0';
            if (lenLen <= 0 || input.length() < 1 + lenLen) {
                throw new IllegalArgumentException(
                        "Invalid a512 length encoding");
            }
            String lenStr = input.substring(1, 1 + lenLen);
            long mdLen = Long.parseLong(lenStr);
            String payload = input.substring(1 + lenLen);
            String code = Long.toString(mdLen * mdLen);
            String mdCode = mdCode(code);
            String restored = b256Decode(
                    payload.replace("4G5tRA", "="));
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

    private static int[] buildBase32Decode() {
        int[] table = new int[256];
        for (int i = 0; i < table.length; i++) {
            table[i] = -1;
        }
        for (int i = 0; i < BASE32HEX_ALPHABET.length; i++) {
            char ch = BASE32HEX_ALPHABET[i];
            table[ch] = i;
            table[Character.toLowerCase(ch)] = i;
        }
        return table;
    }

    private static byte[] buildHexBytes() {
        byte[] out = new byte[512];
        for (int i = 0; i < 256; i++) {
            out[i * 2] = (byte) HEX_CHARS[i >>> 4];
            out[i * 2 + 1] = (byte) HEX_CHARS[i & 0x0F];
        }
        return out;
    }

    private static ThreadLocal<MessageDigest> threadLocalDigest(
            String algorithm) {
        return ThreadLocal.withInitial(() -> newDigest(algorithm));
    }

    private static MessageDigest newDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalStateException(
                    "Digest unavailable: " + algorithm, exc);
        }
    }

    private static byte[] digestBytes(
            MessageDigest digest, byte[] input) {
        digest.reset();
        digest.update(input);
        return digest.digest();
    }

    private static void hexToBytes(byte[] input, byte[] out) {
        if (out.length < input.length * 2) {
            throw new IllegalArgumentException(
                    "hex output buffer too small");
        }
        for (int i = 0; i < input.length; i++) {
            int value = input[i] & 0xFF;
            int index = value << 1;
            out[i * 2] = HEX_BYTES[index];
            out[i * 2 + 1] = HEX_BYTES[index + 1];
        }
    }

    private static String hexToString(byte[] input) {
        char[] out = new char[input.length * 2];
        for (int i = 0; i < input.length; i++) {
            int value = input[i] & 0xFF;
            out[i * 2] = HEX_CHARS[value >>> 4];
            out[i * 2 + 1] = HEX_CHARS[value & 0x0F];
        }
        return new String(out);
    }

    private static String digestHex(
            String algorithm, String input) {
        return hexToString(digestBytes(
                newDigest(algorithm),
                input.getBytes(StandardCharsets.UTF_8)));
    }

    private static String mdCode(String input) {
        ensureAscii(input);
        byte[] bytes = input.getBytes(StandardCharsets.US_ASCII);
        StringBuilder out = new StringBuilder(bytes.length * 3);
        for (byte b : bytes) {
            int value = b & 0xFF;
            if (value < 10) {
                out.append('1').append((char) ('0' + value));
            } else if (value < 100) {
                out.append('2')
                        .append((char) ('0' + value / 10))
                        .append((char) ('0' + value % 10));
            } else {
                out.append('3')
                        .append((char) ('0' + value / 100))
                        .append((char) ('0' + (value / 10) % 10))
                        .append((char) ('0' + value % 10));
            }
        }
        return out.toString();
    }

    private static String stripLeadingZeros(String input) {
        int index = 0;
        while (index < input.length() && input.charAt(index) == '0') {
            index++;
        }
        if (index == input.length()) {
            return "0";
        }
        return input.substring(index);
    }

    private static int compareMagnitude(String left, String right) {
        String normalizedLeft = stripLeadingZeros(left);
        String normalizedRight = stripLeadingZeros(right);
        if (normalizedLeft.length() != normalizedRight.length()) {
            return normalizedLeft.length() < normalizedRight.length()
                    ? -1 : 1;
        }
        if (normalizedLeft.equals(normalizedRight)) {
            return 0;
        }
        return normalizedLeft.compareTo(normalizedRight) < 0 ? -1 : 1;
    }

    private static String addMagnitude(String left, String right) {
        int leftIndex = left.length() - 1;
        int rightIndex = right.length() - 1;
        int carry = 0;
        StringBuilder out = new StringBuilder(
                Math.max(left.length(), right.length()) + 1);
        while (leftIndex >= 0 || rightIndex >= 0 || carry > 0) {
            int leftDigit = leftIndex >= 0
                    ? left.charAt(leftIndex) - '0' : 0;
            int rightDigit = rightIndex >= 0
                    ? right.charAt(rightIndex) - '0' : 0;
            int sum = leftDigit + rightDigit + carry;
            out.append((char) ('0' + (sum % 10)));
            carry = sum / 10;
            leftIndex--;
            rightIndex--;
        }
        out.reverse();
        return stripLeadingZeros(out.toString());
    }

    private static String subtractMagnitude(String left, String right) {
        int leftIndex = left.length() - 1;
        int rightIndex = right.length() - 1;
        int borrow = 0;
        StringBuilder out = new StringBuilder(left.length());
        while (leftIndex >= 0) {
            int leftDigit = (left.charAt(leftIndex) - '0') - borrow;
            int rightDigit = rightIndex >= 0
                    ? right.charAt(rightIndex) - '0' : 0;
            if (leftDigit < rightDigit) {
                leftDigit += 10;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.append((char) ('0' + leftDigit - rightDigit));
            leftIndex--;
            rightIndex--;
        }
        out.reverse();
        return stripLeadingZeros(out.toString());
    }

    private static String addSigned(String left, String right) {
        boolean leftNegative = false;
        boolean rightNegative = false;
        String leftDigits = left;
        String rightDigits = right;
        if (!leftDigits.isEmpty() && leftDigits.charAt(0) == '-') {
            leftNegative = true;
            leftDigits = leftDigits.substring(1);
        }
        if (!rightDigits.isEmpty() && rightDigits.charAt(0) == '-') {
            rightNegative = true;
            rightDigits = rightDigits.substring(1);
        }
        leftDigits = stripLeadingZeros(leftDigits);
        rightDigits = stripLeadingZeros(rightDigits);
        if (leftDigits.equals("0")) {
            leftNegative = false;
        }
        if (rightDigits.equals("0")) {
            rightNegative = false;
        }
        if (leftNegative == rightNegative) {
            String sum = addMagnitude(leftDigits, rightDigits);
            if (sum.equals("0")) {
                return sum;
            }
            return (leftNegative ? "-" : "") + sum;
        }
        int comparison = compareMagnitude(leftDigits, rightDigits);
        if (comparison == 0) {
            return "0";
        }
        if (comparison > 0) {
            String difference = subtractMagnitude(
                    leftDigits, rightDigits);
            return (leftNegative ? "-" : "") + difference;
        }
        String difference = subtractMagnitude(rightDigits, leftDigits);
        return (rightNegative ? "-" : "") + difference;
    }

    private static String mcode(String input) {
        StringBuilder out = new StringBuilder(input.length() / 2);
        int index = 0;
        while (index < input.length()) {
            char ch = input.charAt(index);
            if (ch < '0' || ch > '9') {
                throw new IllegalArgumentException("Invalid mcode input");
            }
            int length = ch - '0';
            index += 1;
            if (index + length > input.length()) {
                throw new IllegalArgumentException("Invalid mcode length");
            }
            int value = 0;
            for (int offset = 0; offset < length; offset++) {
                value = value * 10 + (input.charAt(index + offset) - '0');
            }
            out.append((char) value);
            index += length;
        }
        return out.toString();
    }

    private static void ensureAscii(String input) {
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) > 0x7F) {
                throw new IllegalArgumentException("Non-ASCII input");
            }
        }
    }

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, ch);
        return new String(chars);
    }
}
