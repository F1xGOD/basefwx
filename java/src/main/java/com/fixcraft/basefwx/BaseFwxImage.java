/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * ----------------------------------------------------------------
 * BaseFwxImage — desktop-only carrier / image-cipher API surface.
 *
 * This class carries the kFMe / kFMd / kFAe / kFAd container-encode
 * methods and the jmgEncryptFile / jmgDecryptFile media cipher entry
 * points. They pull in `java.awt.image.*` and `javax.imageio.ImageIO`
 * for PNG encode/decode, which Android does not ship — so these methods
 * are deliberately split out of BaseFwx.java to keep the core
 * cross-language-syncable to Android. See examples/plugins/README.md
 * for the broader split rationale.
 *
 * Wire format and byte-for-byte output are unchanged from the prior
 * BaseFwx.java versions (cross-runtime tests in scripts/test_all.sh —
 * kfme_py_enc_cpp_dec / kfme_cpp_enc_java_dec / etc. — still pass).
 *
 * NOT included in the Android Gradle sync list (build.gradle.kts) —
 * Android callers that need image carrier behavior must implement an
 * Android-native carrier using `android.graphics.Bitmap` separately.
 * ---------------------------------------------------------------- */

package com.fixcraft.basefwx;

import java.awt.image.BufferedImage;
import java.awt.image.DataBuffer;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import javax.imageio.ImageIO;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;

public final class BaseFwxImage {
    private BaseFwxImage() {}

    // ---- KFM constants ------------------------------------------------
    private static final byte[] KFM_MAGIC = "KFM!".getBytes(StandardCharsets.US_ASCII);
    private static final int KFM_VERSION = 1;
    private static final int KFM_MODE_IMAGE_AUDIO = 1;
    private static final int KFM_MODE_AUDIO_IMAGE = 2;
    private static final int KFM_FLAG_BW = 1;
    private static final int KFM_HEADER_LEN = 32;
    private static final long KFM_MAX_PAYLOAD = 1L << 30;
    private static final int KFM_AUDIO_RATE = 24000;
    private static final List<String> KFM_AUDIO_EXTENSIONS = Arrays.asList(
        ".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus",
        ".wma", ".amr", ".aiff", ".aif", ".alac", ".m4b", ".caf", ".mka"
    );
    private static final List<String> KFM_IMAGE_EXTENSIONS = Arrays.asList(
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif",
        ".tiff", ".ico", ".heic", ".heif", ".ppm", ".pgm"
    );

    private static final ThreadLocal<MessageDigest> SHA256_DIGEST = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException exc) {
            throw new IllegalStateException("SHA-256 unavailable", exc);
        }
    });

    // =====================================================================
    // Public API — moved verbatim from BaseFwx.java.
    // =====================================================================

    public static File kFMe(File input, File output) {
        return kFMe(input, output, false);
    }

    public static File kFMe(File input, File output, boolean bwMode) {
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("kFMe input file not found");
        }
        String inputExt = kfmCleanExt(BaseFwx.getExtension(input));
        byte[] payload = BaseFwx.readFileBytes(input);
        if (kfmIsAudioExtension(inputExt)) {
            int flags = bwMode ? KFM_FLAG_BW : 0;
            byte[] container = kfmPackContainer(KFM_MODE_AUDIO_IMAGE, payload, inputExt, flags);
            File out = kfmResolveOutput(input, output, ".png", "kfme");
            BaseFwx.writeFileBytes(out, kfmCarrierToPng(container, bwMode));
            return out;
        }
        byte[] container = kfmPackContainer(KFM_MODE_IMAGE_AUDIO, payload, inputExt, 0);
        File out = kfmResolveOutput(input, output, ".wav", "kfme");
        BaseFwx.writeFileBytes(out, kfmCarrierToWav(container));
        return out;
    }

    public static File kFMd(File input, File output, boolean bwMode) {
        if (bwMode) {
            kfmWarn("kFMd --bw is deprecated and ignored in strict decode mode.");
        }
        return kFMd(input, output);
    }

    public static File kFMd(File input, File output) {
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("kFMd input file not found");
        }
        String inputExt = kfmCleanExt(BaseFwx.getExtension(input));
        KfmDecoded decoded = kfmDecodeContainer(input, inputExt);
        if (decoded == null) {
            throw new IllegalArgumentException(
                "kFMd refused input: file is not a BaseFWX kFM carrier. Use kFMe to encode first."
            );
        }
        File out = kfmResolveOutput(input, output, decoded.extension, "kfmd");
        BaseFwx.writeFileBytes(out, decoded.payload);
        return out;
    }

    public static File kFAe(File input, File output, boolean bwMode) {
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("kFAe input file not found");
        }
        kfmWarn("kFAe is deprecated; using legacy PNG carrier mode. Prefer kFMe for auto mode.");
        String inputExt = kfmCleanExt(BaseFwx.getExtension(input));
        byte[] payload = BaseFwx.readFileBytes(input);
        int flags = bwMode ? KFM_FLAG_BW : 0;
        byte[] container = kfmPackContainer(KFM_MODE_AUDIO_IMAGE, payload, inputExt, flags);
        File out = kfmResolveOutput(input, output, ".png", "kfae");
        BaseFwx.writeFileBytes(out, kfmCarrierToPng(container, bwMode));
        return out;
    }

    public static File kFAd(File input, File output) {
        kfmWarn("kFAd is deprecated; use kFMd (auto-detect) instead.");
        return kFMd(input, output);
    }

    public static File jmgEncryptFile(File input,
                                      File output,
                                      String password,
                                      boolean useMaster,
                                      boolean keepMeta,
                                      boolean keepInput) {
        return jmgEncryptFile(input, output, password, useMaster, keepMeta, keepInput, true);
    }

    public static File jmgEncryptFile(File input,
                                      File output,
                                      String password,
                                      boolean useMaster,
                                      boolean keepMeta,
                                      boolean keepInput,
                                      boolean archiveOriginal) {
        return MediaCipher.encryptMedia(input, output, password, keepMeta, keepInput, useMaster, archiveOriginal);
    }

    public static File jmgDecryptFile(File input,
                                      File output,
                                      String password,
                                      boolean useMaster) {
        return MediaCipher.decryptMedia(input, output, password, useMaster);
    }

    // =====================================================================
    // Image-only helpers — package-private so future image-related classes
    // in the same package can reuse them. (Internal to the carrier
    // implementation; not part of the public ABI.)
    // =====================================================================

    private static File kfmResolveOutput(File input, File output, String extension, String tag) {
        if (output != null) {
            if (BaseFwx.samePath(input, output)) {
                throw new IllegalArgumentException("Refusing to overwrite input file; choose a different output path");
            }
            return output;
        }
        File candidate = replaceExtension(input, extension);
        if (BaseFwx.samePath(input, candidate)) {
            candidate = replaceExtensionWithTag(input, extension, tag);
        }
        return candidate;
    }

    private static File replaceExtension(File input, String extension) {
        String name = input.getName();
        int idx = name.lastIndexOf('.');
        if (idx >= 0) {
            name = name.substring(0, idx);
        }
        name += kfmCleanExt(extension);
        File parent = input.getParentFile();
        return parent == null ? new File(name) : new File(parent, name);
    }

    private static File replaceExtensionWithTag(File input, String extension, String tag) {
        String ext = kfmCleanExt(extension);
        String name = input.getName();
        int idx = name.lastIndexOf('.');
        String stem = idx >= 0 ? name.substring(0, idx) : name;
        String tagged = stem + "." + tag + ext;
        File parent = input.getParentFile();
        return parent == null ? new File(tagged) : new File(parent, tagged);
    }

    private static String kfmCleanExt(String ext) {
        if (ext == null || ext.trim().isEmpty()) {
            return ".bin";
        }
        String normalized = ext.trim().toLowerCase();
        if (!normalized.startsWith(".")) {
            normalized = "." + normalized;
        }
        if (normalized.length() > 24) {
            return ".bin";
        }
        for (int i = 0; i < normalized.length(); i++) {
            char ch = normalized.charAt(i);
            boolean ok = ch == '.' || ch == '_' || ch == '-'
                || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9');
            if (!ok) {
                return ".bin";
            }
        }
        return normalized;
    }

    private static boolean kfmIsAudioExtension(String ext) {
        return KFM_AUDIO_EXTENSIONS.contains(kfmCleanExt(ext));
    }

    private static boolean kfmIsImageExtension(String ext) {
        return KFM_IMAGE_EXTENSIONS.contains(kfmCleanExt(ext));
    }

    private static void kfmWarn(String message) {
        RuntimeLog.warn(message);
    }

    private static byte[] kfmReadHead(File input, int maxBytes) {
        try (InputStream in = Files.newInputStream(input.toPath())) {
            byte[] head = new byte[Math.max(0, maxBytes)];
            int read = in.read(head);
            if (read <= 0) {
                return new byte[0];
            }
            if (read == head.length) {
                return head;
            }
            return Arrays.copyOf(head, read);
        } catch (IOException exc) {
            return new byte[0];
        }
    }

    private static java.util.List<String> kfmDetectCarrierKinds(File input, String inputExt) {
        if (kfmIsAudioExtension(inputExt)) {
            return java.util.Collections.singletonList("audio");
        }
        if (kfmIsImageExtension(inputExt)) {
            return java.util.Collections.singletonList("image");
        }
        byte[] head = kfmReadHead(input, 16);
        java.util.ArrayList<String> kinds = new java.util.ArrayList<>();
        if (head.length >= 8
            && (head[0] & 0xFF) == 0x89
            && head[1] == 'P'
            && head[2] == 'N'
            && head[3] == 'G'
            && head[4] == '\r'
            && head[5] == '\n'
            && (head[6] & 0xFF) == 0x1A
            && head[7] == '\n') {
            kinds.add("image");
        }
        if (head.length >= 12
            && head[0] == 'R'
            && head[1] == 'I'
            && head[2] == 'F'
            && head[3] == 'F'
            && head[8] == 'W'
            && head[9] == 'A'
            && head[10] == 'V'
            && head[11] == 'E') {
            kinds.add("audio");
        }
        if (kinds.isEmpty()) {
            kinds.add("audio");
            kinds.add("image");
        } else {
            if (!kinds.contains("audio")) {
                kinds.add("audio");
            }
            if (!kinds.contains("image")) {
                kinds.add("image");
            }
        }
        return kinds;
    }

    private static KfmDecoded kfmDecodeContainer(File input, String inputExt) {
        java.util.List<String> kinds = kfmDetectCarrierKinds(input, inputExt);
        java.util.ArrayList<String> errors = new java.util.ArrayList<>();
        for (String kind : kinds) {
            byte[] carrier;
            try {
                if ("audio".equals(kind)) {
                    carrier = kfmAudioToCarrier(input);
                } else {
                    carrier = kfmPngToCarrier(BaseFwx.readFileBytes(input));
                }
            } catch (RuntimeException exc) {
                if (kinds.size() == 1) {
                    throw exc;
                }
                errors.add(kind + ": " + exc.getMessage());
                continue;
            }
            KfmDecoded decoded = kfmUnpackContainer(carrier);
            if (decoded != null) {
                return decoded;
            }
            errors.add(kind + ": no BaseFWX header");
        }
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(
                "kFMd refused input: file is not a BaseFWX kFM carrier. "
                    + "Use kFMe to encode first (" + errors.get(0) + ")."
            );
        }
        return null;
    }

    // ---- Byte-order helpers (image-only after grep audit) -------------

    private static long bytesToLong(byte[] input, int offset) {
        long out = 0L;
        for (int i = 0; i < 8; i++) {
            out = (out << 8) | (input[offset + i] & 0xFFL);
        }
        return out;
    }

    // Byte-order helpers — writeU64 / writeU32 / readU32 byte[] overloads
    // live in BaseFwx (package-private) for shared access. BaseFwxImage
    // calls them via BaseFwx.writeU64 / BaseFwx.writeU32 / BaseFwx.readU32.

    private static int readU16LE(byte[] source, int offset) {
        return (source[offset] & 0xFF) | ((source[offset + 1] & 0xFF) << 8);
    }

    private static int readU32LE(byte[] source, int offset) {
        return (source[offset] & 0xFF)
            | ((source[offset + 1] & 0xFF) << 8)
            | ((source[offset + 2] & 0xFF) << 16)
            | ((source[offset + 3] & 0xFF) << 24);
    }

    private static void writeU16LE(OutputStream out, int value) throws IOException {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
    }

    private static void writeU32LE(OutputStream out, long value) throws IOException {
        out.write((int) (value & 0xFFL));
        out.write((int) ((value >> 8) & 0xFFL));
        out.write((int) ((value >> 16) & 0xFFL));
        out.write((int) ((value >> 24) & 0xFFL));
    }

    // ---- KFM container packing ----------------------------------------

    private static byte[] kfmKeystream(long seed, int length) {
        byte[] out = new byte[length];
        if (length <= 0) {
            return out;
        }
        byte[] state = new byte[16];
        BaseFwx.writeU64(state, 0, seed);
        int offset = 0;
        long counter = 0L;
        while (offset < length) {
            BaseFwx.writeU64(state, 8, counter);
            MessageDigest sha = SHA256_DIGEST.get();
            sha.reset();
            byte[] block = sha.digest(state);
            int take = Math.min(block.length, length - offset);
            System.arraycopy(block, 0, out, offset, take);
            offset += take;
            counter++;
        }
        return out;
    }

    private static byte[] kfmXor(byte[] input, byte[] mask) {
        if (input.length != mask.length) {
            throw new IllegalArgumentException("kFM mask length mismatch");
        }
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            out[i] = (byte) (input[i] ^ mask[i]);
        }
        return out;
    }

    private static byte[] kfmPackContainer(int mode, byte[] payload, String ext, int flags) {
        if (payload == null) {
            throw new IllegalArgumentException("kFM payload is null");
        }
        if (payload.length > KFM_MAX_PAYLOAD) {
            throw new IllegalArgumentException("kFM payload is too large");
        }
        if (mode != KFM_MODE_IMAGE_AUDIO && mode != KFM_MODE_AUDIO_IMAGE) {
            throw new IllegalArgumentException("kFM mode is invalid");
        }
        String cleanedExt = kfmCleanExt(ext);
        byte[] extBytes = cleanedExt.getBytes(StandardCharsets.UTF_8);
        if (extBytes.length > 255) {
            extBytes = ".bin".getBytes(StandardCharsets.UTF_8);
        }
        byte[] body = new byte[extBytes.length + payload.length];
        System.arraycopy(extBytes, 0, body, 0, extBytes.length);
        System.arraycopy(payload, 0, body, extBytes.length, payload.length);

        long seed = bytesToLong(Crypto.randomBytes(8), 0);
        byte[] masked = kfmXor(body, kfmKeystream(seed, body.length));
        CRC32 crc32 = new CRC32();
        crc32.update(payload, 0, payload.length);

        byte[] out = new byte[KFM_HEADER_LEN + masked.length];
        System.arraycopy(KFM_MAGIC, 0, out, 0, KFM_MAGIC.length);
        out[4] = (byte) KFM_VERSION;
        out[5] = (byte) mode;
        out[6] = (byte) (flags & 0xFF);
        out[7] = (byte) extBytes.length;
        BaseFwx.writeU64(out, 8, payload.length);
        BaseFwx.writeU32(out, 16, (int) (crc32.getValue() & 0xFFFFFFFFL));
        BaseFwx.writeU64(out, 20, seed);
        BaseFwx.writeU32(out, 28, 0);
        System.arraycopy(masked, 0, out, KFM_HEADER_LEN, masked.length);
        return out;
    }

    private static KfmDecoded kfmUnpackContainer(byte[] blob) {
        if (blob == null || blob.length < KFM_HEADER_LEN) {
            return null;
        }
        for (int i = 0; i < KFM_MAGIC.length; i++) {
            if (blob[i] != KFM_MAGIC[i]) {
                return null;
            }
        }
        int version = blob[4] & 0xFF;
        int mode = blob[5] & 0xFF;
        int flags = blob[6] & 0xFF;
        int extLen = blob[7] & 0xFF;
        if (version != KFM_VERSION || (mode != KFM_MODE_IMAGE_AUDIO && mode != KFM_MODE_AUDIO_IMAGE)) {
            return null;
        }
        long payloadLen = bytesToLong(blob, 8);
        long bodyLenLong = payloadLen + extLen;
        if (payloadLen < 0 || bodyLenLong < extLen || bodyLenLong > (blob.length - KFM_HEADER_LEN)) {
            return null;
        }
        int bodyLen = (int) bodyLenLong;
        int crcExpected = BaseFwx.readU32(blob, 16);
        long seed = bytesToLong(blob, 20);
        byte[] body = Arrays.copyOfRange(blob, KFM_HEADER_LEN, KFM_HEADER_LEN + bodyLen);
        byte[] clear = kfmXor(body, kfmKeystream(seed, body.length));
        byte[] extBytes = Arrays.copyOfRange(clear, 0, extLen);
        byte[] payload = Arrays.copyOfRange(clear, extLen, clear.length);
        CRC32 crc32 = new CRC32();
        crc32.update(payload, 0, payload.length);
        if (((int) (crc32.getValue() & 0xFFFFFFFFL)) != crcExpected) {
            return null;
        }
        String ext = kfmCleanExt(new String(extBytes, StandardCharsets.UTF_8));
        return new KfmDecoded(mode, flags, ext, payload);
    }

    // ---- WAV codec (no java.awt) --------------------------------------

    private static byte[] kfmCarrierToWav(byte[] carrier) {
        byte[] raw = carrier;
        if ((raw.length & 1) != 0) {
            raw = Arrays.copyOf(raw, raw.length + 1);
        }
        byte[] pcm = new byte[raw.length];
        for (int i = 0; i + 2 <= raw.length; i += 2) {
            int value = (raw[i] & 0xFF) | ((raw[i + 1] & 0xFF) << 8);
            short sample = (short) (value - 32768);
            pcm[i] = (byte) (sample & 0xFF);
            pcm[i + 1] = (byte) ((sample >> 8) & 0xFF);
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream(44 + pcm.length)) {
            out.write('R'); out.write('I'); out.write('F'); out.write('F');
            writeU32LE(out, 36L + pcm.length);
            out.write('W'); out.write('A'); out.write('V'); out.write('E');
            out.write('f'); out.write('m'); out.write('t'); out.write(' ');
            writeU32LE(out, 16);
            writeU16LE(out, 1);
            writeU16LE(out, 1);
            writeU32LE(out, KFM_AUDIO_RATE);
            writeU32LE(out, KFM_AUDIO_RATE * 2L);
            writeU16LE(out, 2);
            writeU16LE(out, 16);
            out.write('d'); out.write('a'); out.write('t'); out.write('a');
            writeU32LE(out, pcm.length);
            out.write(pcm);
            return out.toByteArray();
        } catch (IOException exc) {
            throw new IllegalStateException("kFM WAV encode failed", exc);
        }
    }

    private static byte[] kfmWavToCarrier(byte[] wav) {
        if (wav.length < 44) {
            throw new IllegalArgumentException("kFM WAV input too short");
        }
        if (!(wav[0] == 'R' && wav[1] == 'I' && wav[2] == 'F' && wav[3] == 'F'
            && wav[8] == 'W' && wav[9] == 'A' && wav[10] == 'V' && wav[11] == 'E')) {
            throw new IllegalArgumentException("kFM WAV header mismatch");
        }
        boolean fmtPcm = false;
        int channels = 0;
        int bitsPerSample = 0;
        byte[] dataChunk = null;
        int offset = 12;
        while (offset + 8 <= wav.length) {
            int chunkLen = readU32LE(wav, offset + 4);
            long chunkLenU = chunkLen & 0xFFFFFFFFL;
            long dataOffset = offset + 8L;
            long next = dataOffset + chunkLenU;
            if (next > wav.length) {
                break;
            }
            if (wav[offset] == 'f' && wav[offset + 1] == 'm' && wav[offset + 2] == 't' && wav[offset + 3] == ' ') {
                if (chunkLenU >= 16) {
                    int format = readU16LE(wav, (int) dataOffset);
                    channels = readU16LE(wav, (int) dataOffset + 2);
                    bitsPerSample = readU16LE(wav, (int) dataOffset + 14);
                    fmtPcm = (format == 1);
                }
            } else if (wav[offset] == 'd' && wav[offset + 1] == 'a' && wav[offset + 2] == 't' && wav[offset + 3] == 'a') {
                dataChunk = Arrays.copyOfRange(wav, (int) dataOffset, (int) next);
            }
            offset = (int) (next + (chunkLenU & 1L));
        }
        if (dataChunk == null) {
            throw new IllegalArgumentException("kFM WAV data chunk missing");
        }
        if (!(fmtPcm && channels == 1 && bitsPerSample == 16)) {
            return dataChunk;
        }
        return kfmPcm16MonoToCarrier(dataChunk);
    }

    private static byte[] kfmPcm16MonoToCarrier(byte[] pcm) {
        byte[] normalized = pcm;
        if ((normalized.length & 1) != 0) {
            normalized = Arrays.copyOf(normalized, normalized.length + 1);
        }
        byte[] out = new byte[normalized.length];
        for (int i = 0; i + 2 <= normalized.length; i += 2) {
            short sample = (short) ((normalized[i] & 0xFF) | ((normalized[i + 1] & 0xFF) << 8));
            int value = (sample + 32768) & 0xFFFF;
            out[i] = (byte) (value & 0xFF);
            out[i + 1] = (byte) ((value >> 8) & 0xFF);
        }
        return out;
    }

    private static byte[] kfmDecodeAudioViaFfmpeg(File input) {
        String ffmpegBin = System.getenv("BASEFWX_FFMPEG_BIN");
        if (ffmpegBin == null || ffmpegBin.trim().isEmpty()) {
            ffmpegBin = "ffmpeg";
        }
        File tempRaw;
        try {
            tempRaw = BaseFwx.createPrivateTempFile("basefwx_kfm_", ".raw");
        } catch (IOException exc) {
            throw new IllegalStateException("Unable to create temporary ffmpeg output file", exc);
        }
        String output;
        int exitCode;
        try {
            List<String> cmd = Arrays.asList(
                ffmpegBin,
                "-v", "error",
                "-y",
                "-i", input.getAbsolutePath(),
                "-f", "s16le",
                "-ac", "1",
                "-ar", Integer.toString(KFM_AUDIO_RATE),
                tempRaw.getAbsolutePath()
            );
            Process process = new ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start();
            try (InputStream stream = process.getInputStream()) {
                ByteArrayOutputStream capture = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int read;
                while ((read = stream.read(chunk)) != -1) {
                    capture.write(chunk, 0, read);
                }
                output = new String(capture.toByteArray(), StandardCharsets.UTF_8);
            }
            exitCode = process.waitFor();
        } catch (IOException exc) {
            throw new IllegalStateException("Unable to start ffmpeg for audio decoding", exc);
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for ffmpeg", exc);
        }
        try {
            if (exitCode != 0) {
                String trimmed = output == null ? "" : output.trim();
                throw new IllegalArgumentException(
                    trimmed.isEmpty()
                        ? "ffmpeg failed to decode non-WAV audio input"
                        : "ffmpeg failed to decode non-WAV audio input: " + trimmed
                );
            }
            byte[] pcm = BaseFwx.readFileBytes(tempRaw);
            if (pcm.length == 0) {
                throw new IllegalArgumentException("ffmpeg decode produced empty PCM output");
            }
            return kfmPcm16MonoToCarrier(pcm);
        } finally {
            if (!tempRaw.delete()) {
                tempRaw.deleteOnExit();
            }
        }
    }

    private static byte[] kfmAudioToCarrier(File input) {
        byte[] raw = BaseFwx.readFileBytes(input);
        String wavError;
        try {
            return kfmWavToCarrier(raw);
        } catch (IllegalArgumentException exc) {
            wavError = exc.getMessage();
        }
        try {
            return kfmDecodeAudioViaFfmpeg(input);
        } catch (RuntimeException ffmpegExc) {
            throw new IllegalArgumentException(
                "Failed to decode audio carrier '" + input.getName()
                    + "' (WAV parse: " + wavError + "; ffmpeg: " + ffmpegExc.getMessage() + ")",
                ffmpegExc
            );
        }
    }

    // ---- PNG codec (uses java.awt — the reason this whole file is split) ----

    private static byte[] kfmCarrierToPng(byte[] carrier, boolean bwMode) {
        int channels = bwMode ? 1 : 3;
        int pixels = Math.max(1, (carrier.length + channels - 1) / channels);
        int width = Math.max(1, (int) Math.ceil(Math.sqrt(pixels)));
        int height = (int) Math.ceil(pixels / (double) width);
        int capacity = width * height * channels;
        byte[] raster = Crypto.randomBytes(capacity);
        System.arraycopy(carrier, 0, raster, 0, Math.min(carrier.length, raster.length));

        BufferedImage image;
        if (bwMode) {
            image = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
            DataBuffer db = image.getRaster().getDataBuffer();
            if (db instanceof DataBufferByte) {
                byte[] out = ((DataBufferByte) db).getData();
                System.arraycopy(raster, 0, out, 0, Math.min(out.length, raster.length));
            } else {
                WritableRaster imageRaster = image.getRaster();
                int idx = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        int v = raster[idx++] & 0xFF;
                        imageRaster.setSample(x, y, 0, v);
                    }
                }
            }
        } else {
            image = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
            DataBuffer db = image.getRaster().getDataBuffer();
            if (db instanceof DataBufferByte) {
                byte[] out = ((DataBufferByte) db).getData();
                int pxCount = Math.min(out.length / 3, raster.length / 3);
                for (int i = 0; i < pxCount; i++) {
                    int src = i * 3;
                    int dst = i * 3;
                    out[dst] = raster[src + 2];
                    out[dst + 1] = raster[src + 1];
                    out[dst + 2] = raster[src];
                }
            } else {
                int idx = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        int r = raster[idx++] & 0xFF;
                        int g = raster[idx++] & 0xFF;
                        int b = raster[idx++] & 0xFF;
                        image.setRGB(x, y, (r << 16) | (g << 8) | b);
                    }
                }
            }
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            if (!ImageIO.write(image, "png", out)) {
                throw new IllegalStateException("kFM PNG encode failed");
            }
            return out.toByteArray();
        } catch (IOException exc) {
            throw new IllegalStateException("kFM PNG encode failed", exc);
        }
    }

    private static byte[] kfmPngToCarrier(byte[] png) {
        try (ByteArrayInputStream in = new ByteArrayInputStream(png)) {
            BufferedImage image = ImageIO.read(in);
            if (image == null) {
                throw new IllegalArgumentException("kFM PNG decode failed");
            }
            int width = image.getWidth();
            int height = image.getHeight();
            int bands = image.getRaster().getNumBands();
            if (bands == 1) {
                DataBuffer db = image.getRaster().getDataBuffer();
                if (db instanceof DataBufferByte) {
                    byte[] src = ((DataBufferByte) db).getData();
                    int need = width * height;
                    if (src.length >= need) {
                        return Arrays.copyOf(src, need);
                    }
                }
                byte[] out = new byte[width * height];
                int idx = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        out[idx++] = (byte) image.getRaster().getSample(x, y, 0);
                    }
                }
                return out;
            }
            DataBuffer db = image.getRaster().getDataBuffer();
            if (image.getType() == BufferedImage.TYPE_3BYTE_BGR && db instanceof DataBufferByte) {
                byte[] src = ((DataBufferByte) db).getData();
                int pxCount = Math.min(src.length / 3, width * height);
                byte[] out = new byte[pxCount * 3];
                for (int i = 0; i < pxCount; i++) {
                    int s = i * 3;
                    int d = i * 3;
                    out[d] = src[s + 2];
                    out[d + 1] = src[s + 1];
                    out[d + 2] = src[s];
                }
                return out;
            }
            byte[] out = new byte[width * height * 3];
            int idx = 0;
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    int rgb = image.getRGB(x, y);
                    out[idx++] = (byte) ((rgb >> 16) & 0xFF);
                    out[idx++] = (byte) ((rgb >> 8) & 0xFF);
                    out[idx++] = (byte) (rgb & 0xFF);
                }
            }
            return out;
        } catch (IOException exc) {
            throw new IllegalStateException("kFM PNG decode failed", exc);
        }
    }

    // ---- Inner classes ------------------------------------------------

    private static final class KfmDecoded {
        final int mode;
        final int flags;
        final String extension;
        final byte[] payload;

        KfmDecoded(int mode, int flags, String extension, byte[] payload) {
            this.mode = mode;
            this.flags = flags;
            this.extension = extension;
            this.payload = payload;
        }
    }
}
