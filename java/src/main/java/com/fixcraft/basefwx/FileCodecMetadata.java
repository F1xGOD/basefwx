/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.fixcraft.basefwx.FileCodecIo.*;
import static com.fixcraft.basefwx.FileCodecKdf.*;
import static com.fixcraft.basefwx.FileCodecObfuscation.*;

final class FileCodecMetadata {
    private FileCodecMetadata() {}

    static int parsePeerPbkdf2Iterations(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            FileCodecKdf.requirePeerPbkdf2WithinLimits(fallback);
            return fallback;
        }
        if (raw.length() > 10) {
            throw new IllegalArgumentException(
                    "Peer ENC-KDF-ITER exceeds int range");
        }
        if (raw.length() > 1 && raw.charAt(0) == '0') {
            throw new IllegalArgumentException(
                    "Peer ENC-KDF-ITER must not contain leading zeros");
        }
        int parsed = 0;
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch < '0' || ch > '9') {
                throw new IllegalArgumentException(
                        "Peer ENC-KDF-ITER must be an unsigned decimal integer");
            }
            int digit = ch - '0';
            if (parsed > (Integer.MAX_VALUE - digit) / 10) {
                throw new IllegalArgumentException(
                        "Peer ENC-KDF-ITER exceeds int range");
            }
            parsed = parsed * 10 + digit;
        }
        FileCodecKdf.requirePeerPbkdf2WithinLimits(parsed);
        return parsed;
    }

    /**
     * Java implements no tar/gzip/xz unpacking, so a container written with
     * --compress carries an ENC-P pack flag this runtime cannot honour. Reading
     * it silently would hand the caller the packed archive in place of their
     * file, so refuse instead. "g" is tgz and "x" is txz. An absent key means
     * the payload is not marked as packed; any non-empty value must fail closed
     * because this runtime implements no pack mode it could safely honor.
     */
    static void requireSupportedPackMode(String metadataBlob) {
        String pack = metaValue(metadataBlob, "ENC-P");
        if (pack == null || pack.isEmpty()) {
            return;
        }
        String detail = "Container is packed or uses an unsupported pack mode "
                + "(ENC-P=" + pack + "); this runtime cannot unpack it";
        if ("g".equals(pack) || "x".equals(pack)) {
            detail += "; decode it with the C++ or Python runtime";
        }
        throw new IllegalArgumentException(detail);
    }

    static Integer parseMetadataIntOrNull(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        if (raw.length() > 10) {
            throw new IllegalArgumentException(
                    "Peer Argon2 parameter exceeds int range");
        }
        if (raw.length() > 1 && raw.charAt(0) == '0') {
            throw new IllegalArgumentException(
                    "Peer Argon2 parameter must not contain leading zeros");
        }
        int parsed = 0;
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch < '0' || ch > '9') {
                throw new IllegalArgumentException(
                        "Peer Argon2 parameter must be an unsigned decimal integer");
            }
            int digit = ch - '0';
            if (parsed > (Integer.MAX_VALUE - digit) / 10) {
                throw new IllegalArgumentException(
                        "Peer Argon2 parameter exceeds int range");
            }
            parsed = parsed * 10 + digit;
        }
        if (parsed == 0) {
            throw new IllegalArgumentException(
                    "Peer Argon2 parameter must be positive");
        }
        return parsed;
    }

    static boolean isStreamMode(String metadataBlob) {
        if (metadataBlob == null || metadataBlob.isEmpty()) {
            return false;
        }
        String mode = metaValue(metadataBlob, "ENC-MODE");
        return "stream".equalsIgnoreCase(mode);
    }

    static String peekMetadataBlob(File input) {
        if (input.length() < 12L) {
            return "";
        }
        try (FileInputStream in = new FileInputStream(input)) {
            int lenUser = readU32(in, "Ciphertext payload truncated");
            requireBoundedFileLength(
                    input, 4L, lenUser, Constants.LENGTH_PREFIXED_MAX,
                    "user key transport");
            skipFully(in, lenUser, "Ciphertext payload truncated");
            int lenMaster = readU32(in, "Ciphertext payload truncated");
            requireHeaderLengthTotal((long) lenUser + lenMaster);
            requireBoundedFileLength(
                    input, 8L + lenUser, lenMaster,
                    Constants.LENGTH_PREFIXED_MAX, "master key transport");
            skipFully(in, lenMaster, "Ciphertext payload truncated");
            int lenPayload = readU32(in, "Ciphertext payload truncated");
            long payloadLength = resolvePayloadLengthFromFileSize(
                    input, lenUser, lenMaster, lenPayload);
            long payloadOffset = 12L + lenUser + lenMaster;
            if (payloadLength != input.length() - payloadOffset) {
                throw new IllegalArgumentException(
                        "Ciphertext payload length does not match remaining file");
            }
            if (payloadLength < 4) {
                return "";
            }
            int metaLen = readU32(in, "Ciphertext payload truncated");
            final long threeLengthPrefixes = 3L * 4L;
            long headerLength = (long) lenUser + lenMaster + metaLen;
            // Simple AEAD payloads begin with a random nonce. Treat its first
            // four bytes only as a possible stream-metadata length, and let
            // the authenticated simple decoder validate non-stream files.
            if (metaLen <= 0
                    || (long) metaLen > payloadLength - 4L
                    || metaLen > Constants.METADATA_MAX
                    || headerLength > Constants.LENGTH_PREFIXED_MAX
                            - threeLengthPrefixes) {
                return "";
            }
            requireBoundedFileLength(
                    input, payloadOffset + 4L, metaLen,
                    Constants.METADATA_MAX, "metadata");
            byte[] meta = readExactBytes(in, metaLen, "Ciphertext payload truncated");
            String metadataBlob = new String(meta, StandardCharsets.UTF_8);
            return isStreamMode(metadataBlob) ? metadataBlob : "";
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to preview ciphertext metadata", exc);
        }
    }

    static byte[] buildStreamHeader(long inputSize,
                                            byte[] streamSalt,
                                            byte[] extBytes,
                                            int chunkSize) {
        if (inputSize < 0L) {
            throw new IllegalArgumentException(
                    "Streaming input length must not be negative");
        }
        if (chunkSize <= 0
                || chunkSize > Constants.STREAM_CHUNK_SIZE_MAX) {
            throw new IllegalArgumentException(
                    "Streaming chunk size must be between 1 byte and 16 MiB");
        }
        if (streamSalt == null
                || streamSalt.length != Constants.STREAM_SALT_LEN) {
            throw new IllegalArgumentException(
                    "Streaming salt length mismatch");
        }
        if (extBytes == null || extBytes.length > 0xFFFF) {
            throw new IllegalArgumentException(
                    "Streaming file extension is too long");
        }
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
                                        String masterKem,
                                        String aead,
                                        String kdfLabel) {
        return buildMetadata(method, strip, useMaster, masterKem, aead, kdfLabel,
            null, null, null, null, null, null, null, null);
    }

    static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String masterKem,
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
        return buildMetadata(
                method, strip, useMaster, masterKem, aead, kdfLabel,
                mode, obfuscation, obfMode, kdfIters, argonTime,
                argonMem, argonPar, pack, null);
    }

    static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String masterKem,
                                        String aead,
                                        String kdfLabel,
                                        String mode,
                                        Boolean obfuscation,
                                        String obfMode,
                                        Integer kdfIters,
                                        Integer argonTime,
                                        Integer argonMem,
                                        Integer argonPar,
                                        String pack,
                                        String keySeparation) {
        kdfLabel = FileCodecKdf.resolveKdfLabel(kdfLabel);
        if (strip) {
            return "";
        }
        if (useMaster) {
            if (!Constants.MASTER_PQ_ALG_DEFAULT.equals(masterKem)
                    && !Constants.MASTER_PQ_ALG_HIGH.equals(masterKem)
                    && !"EC".equals(masterKem)) {
                throw new IllegalArgumentException(
                        "Master-enabled metadata requires an explicit selected KEM");
            }
        } else if (!"none".equals(masterKem)) {
            throw new IllegalArgumentException(
                    "Master-disabled metadata must use ENC-KEM=none");
        }
        Map<String, String> info = new LinkedHashMap<>();
        info.put("ENC-TIME", Instant.now().toString());
        info.put("ENC-VERSION", Constants.ENGINE_VERSION);
        info.put("ENC-METHOD", method);
        info.put("ENC-MASTER", useMaster ? "yes" : "no");
        info.put("ENC-KEM", masterKem);
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
        if (keySeparation != null && !keySeparation.isEmpty()) {
            info.put("ENC-KSEP", keySeparation);
        }
        String json = encodeJson(info);
        String encoded = Base64Codec.encode(
                json.getBytes(StandardCharsets.UTF_8));
        if (encoded.length() > Constants.METADATA_MAX) {
            throw new IllegalArgumentException(
                    "Payload metadata exceeds 1 MiB cap");
        }
        return encoded;
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
