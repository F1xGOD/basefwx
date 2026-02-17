package com.fixcraft.basefwx;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;

public final class Codec {
    private Codec() {}

    private static final char[] CODE_CHARS = new char[] {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        ' ','-','=','+','&','%','#','@','!','^','*','(',')','{','}','[',']','|','/','~',';',':','?','.',
        '>','<',',','0','1','2','3','4','5','6','7','8','9','"'
    };

    private static final String[] CODE_TOKENS = new String[] {
        "e*1","&hl","*&Gs","*YHA","K5a{","(*HGA(","*&GD2","+*jsGA","(aj*a","g%","&G{A","/IHa",
        "*(oa","*KA^7",")i*8A","*H)PA-G","*YFSA","O.-P[A","{9sl","*(HARR","O&iA6u","n):u",
        "&^F*GV","(*HskW","{JM","J.!dA","(&Tav","t5","*TGA3","*GABD","{A","pW","*UAK(","&GH+",
        "&AN)","L&VA","(HAF5","&F*Va","^&FVB","(*HSA$i","*IHda&gT","&*FAl",")P{A]","*Ha$g","G)OA&",
        "|QG6","Qd&^","hA","8h^va","_9xlA","*J","*;pY&","R7a{","}F","OJ)_A","}J","%A","y{A3s",
        ".aGa!","l@","/A","OIp*a","(U","I*Ua]","{0aD","Av[","9j","[a)","*&GBA","]Vc!A",
        ")*HND_","(&*GHA","K}N=O","YGOI&Ah","Oa","8y)a","0{a9","v6Yha","I8ys#","(HPA7","}v",
        "*HAl%","_)JHS","IG(A","(*GFD","IU(&V","(JH*G","*GHBA","U&G*C","I(a-s"
    };

    private static final char[] BASE32HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV".toCharArray();
    private static final int[] BASE32HEX_DECODE = buildBase32Decode();
    private static final String[] CHAR_TO_TOKEN = buildCharToToken();
    private static final TrieNode TOKEN_TRIE = buildTokenTrie();
    private static final long N10_MOD = 10_000_000_000L;
    private static final long N10_MUL = 3_816_547_291L;
    private static final long N10_ADD = 7_261_940_353L;
    private static final String N10_MAGIC = "927451";
    private static final String N10_VERSION = "01";
    private static final int N10_HEADER_DIGITS = 28;
    private static final long N10_MUL_INVERSE = modInverse(N10_MUL, N10_MOD);

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

    public static String code(String input) {
        if (input == null || input.isEmpty()) {
            return input == null ? "" : input;
        }
        int len = input.length();
        StringBuilder out = new StringBuilder(len * 4);
        for (int i = 0; i < len; i++) {
            char ch = input.charAt(i);
            String token = ch < CHAR_TO_TOKEN.length ? CHAR_TO_TOKEN[ch] : null;
            if (token != null) {
                out.append(token);
            } else {
                out.append(ch);
            }
        }
        return out.toString();
    }

    public static String decode(String input) {
        if (input == null || input.isEmpty()) {
            return input == null ? "" : input;
        }
        int len = input.length();
        StringBuilder out = new StringBuilder(len);
        int idx = 0;
        TrieNode root = TOKEN_TRIE;
        while (idx < len) {
            char ch = input.charAt(idx);
            if (ch >= root.next.length) {
                out.append(ch);
                idx++;
                continue;
            }
            TrieNode node = root.next[ch];
            if (node == null) {
                out.append(ch);
                idx++;
                continue;
            }
            int scan = idx + 1;
            TrieNode current = node;
            char matchChar = 0;
            int matchLen = 0;
            if (current.terminal) {
                matchChar = current.value;
                matchLen = 1;
            }
            while (scan < len) {
                char next = input.charAt(scan);
                if (next >= current.next.length) {
                    break;
                }
                TrieNode nextNode = current.next[next];
                if (nextNode == null) {
                    break;
                }
                current = nextNode;
                scan++;
                if (current.terminal) {
                    matchChar = current.value;
                    matchLen = scan - idx;
                }
            }
            if (matchLen > 0) {
                out.append(matchChar);
                idx += matchLen;
            } else {
                out.append(ch);
                idx++;
            }
        }
        return out.toString();
    }

    public static String base32HexEncode(byte[] data) {
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

    public static byte[] base32HexDecode(String input) {
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

    public static String b256Encode(String input) {
        String coded = code(input);
        byte[] raw = coded.getBytes(StandardCharsets.UTF_8);
        String encoded = base32HexEncode(raw);
        int end = encoded.length();
        int paddingCount = 0;
        while (end > 0 && encoded.charAt(end - 1) == '=') {
            paddingCount++;
            end--;
        }
        if (paddingCount > 9) {
            throw new IllegalArgumentException("Base32 padding count exceeded single digit");
        }
        return encoded.substring(0, end) + paddingCount;
    }

    public static String b256Decode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        char padChar = input.charAt(input.length() - 1);
        if (padChar < '0' || padChar > '9') {
            throw new IllegalArgumentException("Invalid b256 padding marker");
        }
        int padding = padChar - '0';
        String base32 = input.substring(0, input.length() - 1) + repeat('=', padding);
        byte[] decoded = base32HexDecode(base32);
        String decodedText = new String(decoded, StandardCharsets.UTF_8);
        return decode(decodedText);
    }

    public static String n10Encode(String input) {
        if (input == null) {
            throw new IllegalArgumentException("n10encode expects text");
        }
        return n10EncodeBytes(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String n10EncodeBytes(byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("n10encode expects bytes");
        }
        if (input.length >= N10_MOD) {
            throw new IllegalArgumentException("n10 input is too large");
        }
        int blockCount = (input.length + 3) / 4;
        StringBuilder out = new StringBuilder(N10_HEADER_DIGITS + (blockCount * 10));
        out.append(N10_MAGIC);
        out.append(N10_VERSION);
        appendFixed10(out, n10Transform(input.length, 0));
        appendFixed10(out, n10Transform(Integer.toUnsignedLong(fnv1a32(input)), 1));

        int offset = 0;
        for (int block = 0; block < blockCount; block++) {
            int word = 0;
            int remaining = input.length - offset;
            int chunk = Math.min(remaining, 4);
            for (int i = 0; i < chunk; i++) {
                word |= (input[offset + i] & 0xFF) << (24 - (i * 8));
            }
            offset += chunk;
            appendFixed10(out, n10Transform(Integer.toUnsignedLong(word), block + 2L));
        }
        return out.toString();
    }

    public static String n10Decode(String input) {
        byte[] decoded = n10DecodeBytes(input);
        CharsetDecoder utf8 = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer chars = utf8.decode(ByteBuffer.wrap(decoded));
            return chars.toString();
        } catch (CharacterCodingException exc) {
            throw new IllegalArgumentException("n10 payload is not valid UTF-8", exc);
        }
    }

    public static byte[] n10DecodeBytes(String input) {
        if (input == null) {
            throw new IllegalArgumentException("n10decode expects digits");
        }
        String digits = input.trim();
        if (digits.length() < N10_HEADER_DIGITS) {
            throw new IllegalArgumentException("n10 payload is too short");
        }
        if (!digits.startsWith(N10_MAGIC) || !digits.regionMatches(6, N10_VERSION, 0, N10_VERSION.length())) {
            throw new IllegalArgumentException("n10 header mismatch");
        }

        long payloadLen = n10InverseTransform(parseFixed10(digits, 8), 0);
        if (payloadLen >= N10_MOD) {
            throw new IllegalArgumentException("n10 decoded length is invalid");
        }
        if (payloadLen > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("n10 decoded length is unsupported on this platform");
        }

        long checksumExpected = n10InverseTransform(parseFixed10(digits, 18), 1);
        if (checksumExpected > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("n10 checksum is invalid");
        }

        long blockCountLong = (payloadLen + 3L) / 4L;
        long expectedDigits = N10_HEADER_DIGITS + (blockCountLong * 10L);
        if (expectedDigits != digits.length()) {
            throw new IllegalArgumentException("n10 payload length mismatch");
        }
        if (blockCountLong > (Integer.MAX_VALUE / 4)) {
            throw new IllegalArgumentException("n10 payload length overflow");
        }

        int blockCount = (int) blockCountLong;
        byte[] out = new byte[blockCount * 4];
        int inOffset = N10_HEADER_DIGITS;
        for (int block = 0; block < blockCount; block++) {
            long decoded = n10InverseTransform(parseFixed10(digits, inOffset), block + 2L);
            inOffset += 10;
            if (decoded > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("n10 block out of range");
            }
            int word = (int) decoded;
            int outOffset = block * 4;
            out[outOffset] = (byte) ((word >>> 24) & 0xFF);
            out[outOffset + 1] = (byte) ((word >>> 16) & 0xFF);
            out[outOffset + 2] = (byte) ((word >>> 8) & 0xFF);
            out[outOffset + 3] = (byte) (word & 0xFF);
        }

        int outLen = (int) payloadLen;
        if (outLen != out.length) {
            out = Arrays.copyOf(out, outLen);
        }
        long checksumActual = Integer.toUnsignedLong(fnv1a32(out));
        if (checksumActual != checksumExpected) {
            throw new IllegalArgumentException("n10 checksum mismatch");
        }
        return out;
    }

    private static int fnv1a32(byte[] data) {
        int hash = 0x811C9DC5;
        for (byte b : data) {
            hash ^= (b & 0xFF);
            hash *= 0x01000193;
        }
        return hash;
    }

    private static long modSub(long value, long sub, long mod) {
        if (value >= sub) {
            return value - sub;
        }
        return mod - (sub - value);
    }

    private static long modInverse(long value, long mod) {
        long t = 0;
        long newT = 1;
        long r = mod;
        long newR = value;
        while (newR != 0) {
            long q = r / newR;
            long tempT = t - q * newT;
            t = newT;
            newT = tempT;
            long tempR = r - q * newR;
            r = newR;
            newR = tempR;
        }
        if (r != 1) {
            throw new IllegalArgumentException("n10 internal inverse failure");
        }
        if (t < 0) {
            t += mod;
        }
        return t;
    }

    private static long mix64(long value) {
        value += 0x9E3779B97F4A7C15L;
        value = (value ^ (value >>> 30)) * 0xBF58476D1CE4E5B9L;
        value = (value ^ (value >>> 27)) * 0x94D049BB133111EBL;
        return value ^ (value >>> 31);
    }

    private static long n10Offset(long index) {
        return Long.remainderUnsigned(mix64(index ^ 0xA5A5F0F01234ABCDL), N10_MOD);
    }

    private static long mulMod10(long lhs, long rhs) {
        long lhsHi = lhs / 100_000L;
        long lhsLo = lhs % 100_000L;
        long rhsHi = rhs / 100_000L;
        long rhsLo = rhs % 100_000L;
        long mid = lhsHi * rhsLo + lhsLo * rhsHi;
        long low = lhsLo * rhsLo;
        return ((mid % N10_MOD) * 100_000L + low) % N10_MOD;
    }

    private static long n10Transform(long value, long index) {
        if (value < 0 || value >= N10_MOD) {
            throw new IllegalArgumentException("n10 value too large");
        }
        long mixed = (value + n10Offset(index)) % N10_MOD;
        return (mulMod10(N10_MUL, mixed) + N10_ADD) % N10_MOD;
    }

    private static long n10InverseTransform(long encoded, long index) {
        if (encoded < 0 || encoded >= N10_MOD) {
            throw new IllegalArgumentException("n10 encoded value too large");
        }
        long step = modSub(encoded, N10_ADD, N10_MOD);
        long mixed = mulMod10(step, N10_MUL_INVERSE);
        return modSub(mixed, n10Offset(index), N10_MOD);
    }

    private static void appendFixed10(StringBuilder out, long value) {
        if (value < 0 || value >= N10_MOD) {
            throw new IllegalArgumentException("n10 fixed width overflow");
        }
        char[] digits = new char[10];
        long current = value;
        for (int idx = 9; idx >= 0; idx--) {
            digits[idx] = (char) ('0' + (int) (current % 10));
            current /= 10;
        }
        out.append(digits);
    }

    private static long parseFixed10(CharSequence input, int offset) {
        if (offset + 10 > input.length()) {
            throw new IllegalArgumentException("n10 payload truncated");
        }
        long value = 0;
        for (int i = 0; i < 10; i++) {
            char ch = input.charAt(offset + i);
            if (ch < '0' || ch > '9') {
                throw new IllegalArgumentException("n10 payload must contain only digits");
            }
            value = value * 10 + (ch - '0');
        }
        return value;
    }

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, ch);
        return new String(chars);
    }

    private static String[] buildCharToToken() {
        String[] map = new String[128];
        for (int i = 0; i < CODE_CHARS.length; i++) {
            char ch = CODE_CHARS[i];
            if (ch < map.length) {
                map[ch] = CODE_TOKENS[i];
            }
        }
        return map;
    }

    private static TrieNode buildTokenTrie() {
        TrieNode root = new TrieNode();
        for (int i = 0; i < CODE_TOKENS.length; i++) {
            String token = CODE_TOKENS[i];
            TrieNode node = root;
            for (int j = 0; j < token.length(); j++) {
                char ch = token.charAt(j);
                if (ch >= node.next.length) {
                    node = null;
                    break;
                }
                if (node.next[ch] == null) {
                    node.next[ch] = new TrieNode();
                }
                node = node.next[ch];
            }
            if (node != null) {
                node.terminal = true;
                node.value = CODE_CHARS[i];
            }
        }
        return root;
    }

    private static final class TrieNode {
        private final TrieNode[] next = new TrieNode[128];
        private boolean terminal = false;
        private char value;
    }
}
