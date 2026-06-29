/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static com.fixcraft.basefwx.FileCodecIo.*;
import static com.fixcraft.basefwx.FileCodecKdf.*;
import static com.fixcraft.basefwx.FileCodecMetadata.*;
import static com.fixcraft.basefwx.FileCodecObfuscation.*;

final class FileCodecMetadata {
    private FileCodecMetadata() {}

static int parseMetadataInt(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

static boolean isStreamMode(String metadataBlob) {
        if (metadataBlob == null || metadataBlob.isEmpty()) {
            return false;
        }
        String mode = metaValue(metadataBlob, "ENC-MODE");
        return "stream".equalsIgnoreCase(mode);
    }

static String peekMetadataBlob(File input) {
        try (FileInputStream in = new FileInputStream(input)) {
            int lenUser = readU32(in, "Ciphertext payload truncated");
            skipFully(in, lenUser, "Ciphertext payload truncated");
            int lenMaster = readU32(in, "Ciphertext payload truncated");
            skipFully(in, lenMaster, "Ciphertext payload truncated");
            int lenPayload = readU32(in, "Ciphertext payload truncated");
            if (lenPayload < 4) {
                return "";
            }
            int metaLen = readU32(in, "Ciphertext payload truncated");
            if (metaLen <= 0) {
                return "";
            }
            byte[] meta = readExactBytes(in, metaLen, "Ciphertext payload truncated");
            return new String(meta, StandardCharsets.UTF_8);
        } catch (IOException | IllegalArgumentException exc) {
            return "";
        }
    }

static byte[] buildStreamHeader(long inputSize,
                                            byte[] streamSalt,
                                            byte[] extBytes,
                                            int chunkSize) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(Constants.STREAM_MAGIC);
            writeU32(out, chunkSize);
            writeU64(out, inputSize);
            out.write(streamSalt);
            writeU16(out, extBytes.length);
            if (extBytes.length > 0) {
                out.write(extBytes);
            }
        } catch (IOException exc) {
            throw new IllegalStateException("Stream header build failed", exc);
        }
        return out.toByteArray();
    }

static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String aead,
                                        String kdfLabel) {
        return buildMetadata(method, strip, useMaster, aead, kdfLabel,
            null, null, null, null, null, null, null, null);
    }

static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String aead,
                                        String kdfLabel,
                                        String mode,
                                        Boolean obfuscation,
                                        String obfMode,
                                        Integer kdfIters,
                                        Integer argonTime,
                                        Integer argonMem,
                                        Integer argonPar,
                                        String pack) {
        if (strip) {
            return "";
        }
        Map<String, String> info = new LinkedHashMap<>();
        info.put("ENC-TIME", Instant.now().toString());
        info.put("ENC-VERSION", Constants.ENGINE_VERSION);
        info.put("ENC-METHOD", method);
        info.put("ENC-MASTER", useMaster ? "yes" : "no");
        info.put("ENC-KEM", useMaster ? "EC" : "none");
        info.put("ENC-AEAD", aead);
        info.put("ENC-KDF", kdfLabel);
        if (mode != null && !mode.isEmpty()) {
            info.put("ENC-MODE", mode);
        }
        if (obfMode != null && !obfMode.isEmpty()) {
            info.put("ENC-OBF", obfMode);
        } else if (obfuscation != null) {
            info.put("ENC-OBF", obfuscation ? "yes" : "no");
        }
        if (kdfIters != null) {
            info.put("ENC-KDF-ITER", Integer.toString(kdfIters));
        }
        if (argonTime != null) {
            info.put("ENC-ARGON2-TC", Integer.toString(argonTime));
        }
        if (argonMem != null) {
            info.put("ENC-ARGON2-MEM", Integer.toString(argonMem));
        }
        if (argonPar != null) {
            info.put("ENC-ARGON2-PAR", Integer.toString(argonPar));
        }
        if (pack != null && !pack.isEmpty()) {
            info.put("ENC-P", pack);
        }
        String json = encodeJson(info);
        return Base64Codec.encode(json.getBytes(StandardCharsets.UTF_8));
    }

static String encodeJson(Map<String, String> map) {
        StringBuilder out = new StringBuilder();
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append('\"').append(escapeJson(entry.getKey())).append("\":\"")
                .append(escapeJson(entry.getValue())).append('\"');
        }
        out.append('}');
        return out.toString();
    }

static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

static String[] splitMetadata(String payload) {
        int idx = payload.indexOf(Constants.META_DELIM);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx),
                payload.substring(idx + Constants.META_DELIM.length())};
        }
        return new String[]{"", payload};
    }

static String metaValue(String metadataBlob, String key) {
        if (metadataBlob == null || metadataBlob.isEmpty()) {
            return "";
        }
        try {
            String json = new String(Base64Codec.decode(metadataBlob), StandardCharsets.UTF_8);
            return jsonValue(json, key);
        } catch (IllegalArgumentException exc) {
            return "";
        }
    }

static String jsonValue(String json, String key) {
        int idx = skipJsonWhitespace(json, 0);
        if (idx >= json.length() || json.charAt(idx) != '{') {
            return "";
        }
        idx++;
        while (idx < json.length()) {
            idx = skipJsonWhitespace(json, idx);
            if (idx >= json.length()) {
                return "";
            }
            if (json.charAt(idx) == '}') {
                return "";
            }
            StringBuilder name = new StringBuilder();
            int next = parseJsonString(json, idx, name);
            if (next < 0) {
                return "";
            }
            idx = skipJsonWhitespace(json, next);
            if (idx >= json.length() || json.charAt(idx) != ':') {
                return "";
            }
            idx = skipJsonWhitespace(json, idx + 1);
            if (idx >= json.length()) {
                return "";
            }
            StringBuilder value = new StringBuilder();
            next = parseJsonString(json, idx, value);
            if (next < 0) {
                return "";
            }
            if (name.toString().equals(key)) {
                return value.toString();
            }
            idx = skipJsonWhitespace(json, next);
            if (idx >= json.length()) {
                return "";
            }
            char ch = json.charAt(idx);
            if (ch == ',') {
                idx++;
                continue;
            }
            if (ch == '}') {
                return "";
            }
            return "";
        }
        return "";
    }

static int skipJsonWhitespace(String json, int idx) {
        int len = json.length();
        int pos = idx;
        while (pos < len) {
            char ch = json.charAt(pos);
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                pos++;
            } else {
                break;
            }
        }
        return pos;
    }

static int parseJsonString(String json, int start, StringBuilder out) {
        int len = json.length();
        if (start >= len || json.charAt(start) != '"') {
            return -1;
        }
        int i = start + 1;
        while (i < len) {
            char ch = json.charAt(i);
            if (ch == '"') {
                return i + 1;
            }
            if (ch == '\\') {
                if (i + 1 >= len) {
                    return -1;
                }
                char esc = json.charAt(i + 1);
                if (esc == 'u') {
                    if (i + 5 >= len) {
                        return -1;
                    }
                    int code = 0;
                    for (int j = 0; j < 4; j++) {
                        int val = Character.digit(json.charAt(i + 2 + j), 16);
                        if (val < 0) {
                            return -1;
                        }
                        code = (code << 4) | val;
                    }
                    out.append((char) code);
                    i += 6;
                    continue;
                }
                switch (esc) {
                    case '"':
                        out.append('"');
                        break;
                    case '\\':
                        out.append('\\');
                        break;
                    case '/':
                        out.append('/');
                        break;
                    case 'b':
                        out.append('\b');
                        break;
                    case 'f':
                        out.append('\f');
                        break;
                    case 'n':
                        out.append('\n');
                        break;
                    case 'r':
                        out.append('\r');
                        break;
                    case 't':
                        out.append('\t');
                        break;
                    default:
                        out.append(esc);
                        break;
                }
                i += 2;
                continue;
            }
            out.append(ch);
            i++;
        }
        return -1;
    }

static String[] splitWithDelims(String payload, String delim, String legacy, String label) {
        int idx = payload.indexOf(delim);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx), payload.substring(idx + delim.length())};
        }
        idx = payload.indexOf(legacy);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx), payload.substring(idx + legacy.length())};
        }
        throw new IllegalArgumentException("Malformed " + label + " payload");
    }
}
