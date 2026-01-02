package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

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
        StringBuilder out = new StringBuilder(input.length() * 4);
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            boolean mapped = false;
            for (int j = 0; j < CODE_CHARS.length; j++) {
                if (CODE_CHARS[j] == ch) {
                    out.append(CODE_TOKENS[j]);
                    mapped = true;
                    break;
                }
            }
            if (!mapped) {
                out.append(ch);
            }
        }
        return out.toString();
    }

    public static String decode(String input) {
        if (input == null || input.isEmpty()) {
            return input == null ? "" : input;
        }
        List<TokenEntry> tokens = new ArrayList<>();
        for (int i = 0; i < CODE_CHARS.length; i++) {
            tokens.add(new TokenEntry(CODE_TOKENS[i], CODE_CHARS[i]));
        }
        tokens.sort(Comparator.comparingInt((TokenEntry t) -> t.token.length()).reversed());

        StringBuilder out = new StringBuilder(input.length());
        int idx = 0;
        while (idx < input.length()) {
            boolean matched = false;
            for (TokenEntry entry : tokens) {
                if (entry.token.isEmpty()) {
                    continue;
                }
                if (idx + entry.token.length() <= input.length()
                    && input.startsWith(entry.token, idx)) {
                    out.append(entry.ch);
                    idx += entry.token.length();
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                out.append(input.charAt(idx));
                idx++;
            }
        }
        return out.toString();
    }

    public static String base32HexEncode(byte[] data) {
        if (data.length == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder(((data.length + 4) / 5) * 8);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                out.append(BASE32HEX_ALPHABET[index]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            buffer <<= (5 - bitsLeft);
            int index = buffer & 0x1F;
            out.append(BASE32HEX_ALPHABET[index]);
        }
        while (out.length() % 8 != 0) {
            out.append('=');
        }
        return out.toString();
    }

    public static byte[] base32HexDecode(String input) {
        boolean ok = true;
        List<Byte> out = new ArrayList<>();
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
                out.add(b);
                bitsLeft -= 8;
            }
        }
        if (!ok) {
            throw new IllegalArgumentException("Invalid base32 payload");
        }
        byte[] result = new byte[out.size()];
        for (int i = 0; i < out.size(); i++) {
            result[i] = out.get(i);
        }
        return result;
    }

    public static String b256Encode(String input) {
        String coded = code(input);
        byte[] raw = coded.getBytes(StandardCharsets.UTF_8);
        String encoded = base32HexEncode(raw);
        long paddingCount = encoded.chars().filter(ch -> ch == '=').count();
        encoded = encoded.replace("=", "");
        if (paddingCount > 9) {
            throw new IllegalArgumentException("Base32 padding count exceeded single digit");
        }
        return encoded + paddingCount;
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

    private static String repeat(char ch, int count) {
        StringBuilder out = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            out.append(ch);
        }
        return out.toString();
    }

    private static final class TokenEntry {
        private final String token;
        private final char ch;

        private TokenEntry(String token, char ch) {
            this.token = token;
            this.ch = ch;
        }
    }
}
