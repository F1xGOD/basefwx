package com.fixcraft.basefwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
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
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.awt.image.BufferedImage;
import java.awt.image.WritableRaster;
import javax.imageio.ImageIO;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BaseFWX Java implementation using native-backed standard library components.
 * 
 * Performance Strategy:
 * - Base64: Uses java.util.Base64 (native implementation, similar to Python's C-backed base64 module)
 * - Hashing: Uses java.security.MessageDigest (JVM native implementations for SHA-256, SHA-512, SHA-1)
 * - Crypto: Uses javax.crypto.Cipher (JVM native implementations for AES-GCM)
 * - PBKDF2: Uses javax.crypto.SecretKeyFactory (optimized native implementation)
 * 
 * Memory Management:
 * - Pre-sized arrays and buffers to minimize allocations
 * - Direct char[] construction for string building instead of StringBuilder where beneficial
 * - Reuse of byte arrays in hot paths
 * - Java's garbage collector handles automatic memory cleanup
 */
@SuppressWarnings("unused")
public final class BaseFwx {
    private BaseFwx() {}

    private static final boolean SINGLE_THREAD_OVERRIDE;

    static {
        // Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
        String forceSingle = System.getenv("BASEFWX_FORCE_SINGLE_THREAD");
        int available = Runtime.getRuntime().availableProcessors();
        boolean override = "1".equals(forceSingle) && available > 1;
        SINGLE_THREAD_OVERRIDE = override;
        if (override) {
            String orange = "\u001b[38;5;208m";
            String reset = "\u001b[0m";
            System.err.println(orange + "WARN: MULTI-THREAD DISABLED; PERFORMANCE MAY DETERIORATE. "
                + "Using BASEFWX_FORCE_SINGLE_THREAD=1 with " + available + " cores available." + reset);
        }
    }

    public static final class DecodedFile {
        public final byte[] data;
        public final String extension;

        public DecodedFile(byte[] data, String extension) {
            this.data = data;
            this.extension = extension == null ? "" : extension;
        }
    }

    private static final int STREAM_CHUNK = 1 << 20;
    private static final int PERF_OBFUSCATION_THRESHOLD = 1 << 20;
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

    public static byte[] fwxAesEncryptRaw(byte[] plaintext, String password, boolean useMaster) {
        if (plaintext == null) {
            throw new IllegalArgumentException("fwxAES_encrypt_raw expects bytes");
        }
        byte[] pw = resolvePasswordBytes(password, useMaster);
        return fwxAesEncryptRawBytes(plaintext, pw, useMaster);
    }

    public static byte[] fwxAesEncryptRawBytes(byte[] plaintext, byte[] passwordBytes, boolean useMaster) {
        if (plaintext == null) {
            throw new IllegalArgumentException("fwxAES_encrypt_raw expects bytes");
        }
        byte[] pw = passwordBytes == null ? new byte[0] : passwordBytes;
        if (!useMaster && pw.length == 0) {
            throw new IllegalArgumentException("Password required when master key usage is disabled");
        }
        boolean hasPassword = pw.length > 0;
        boolean useWrap = false;
        byte[] keyHeader = new byte[0];
        byte[] maskKey = new byte[0];

        if (useMaster) {
            try {
                KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                    pw,
                    true,
                    Constants.FWXAES_MASK_INFO,
                    false,
                    Constants.FWXAES_AAD,
                    new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
                );
                useWrap = mask.usedMaster || !hasPassword;
                if (useWrap) {
                    keyHeader = Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob));
                    maskKey = mask.maskKey;
                }
            } catch (RuntimeException exc) {
                if (!hasPassword) {
                    throw exc;
                }
                useWrap = false;
            }
        }

        byte[] iv = Crypto.randomBytes(Constants.FWXAES_IV_LEN);
        if (useWrap) {
            byte[] key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
            int ctLen = plaintext.length + Constants.AEAD_TAG_LEN;
            byte[] out = new byte[16 + keyHeader.length + iv.length + ctLen];
            System.arraycopy(Constants.FWXAES_MAGIC, 0, out, 0, Constants.FWXAES_MAGIC.length);
            out[4] = (byte) Constants.FWXAES_ALGO;
            out[5] = (byte) Constants.FWXAES_KDF_WRAP;
            out[6] = 0;
            out[7] = (byte) Constants.FWXAES_IV_LEN;
            writeU32(out, 8, keyHeader.length);
            writeU32(out, 12, ctLen);
            int offset = 16;
            if (keyHeader.length > 0) {
                System.arraycopy(keyHeader, 0, out, offset, keyHeader.length);
                offset += keyHeader.length;
            }
            System.arraycopy(iv, 0, out, offset, iv.length);
            offset += iv.length;
            int written = Crypto.aesGcmEncryptWithIvInto(
                key,
                iv,
                plaintext,
                0,
                plaintext.length,
                out,
                offset,
                Constants.FWXAES_AAD
            );
            if (written != ctLen) {
                throw new IllegalStateException("fwxAES encrypt length mismatch");
            }
            return out;
        }

        byte[] salt = Crypto.randomBytes(Constants.FWXAES_SALT_LEN);
        int iters = fwxaesIterations(pw);
        byte[] key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
        int ctLen = plaintext.length + Constants.AEAD_TAG_LEN;
        byte[] out = new byte[16 + salt.length + iv.length + ctLen];
        System.arraycopy(Constants.FWXAES_MAGIC, 0, out, 0, Constants.FWXAES_MAGIC.length);
        out[4] = (byte) Constants.FWXAES_ALGO;
        out[5] = (byte) Constants.FWXAES_KDF_PBKDF2;
        out[6] = (byte) Constants.FWXAES_SALT_LEN;
        out[7] = (byte) Constants.FWXAES_IV_LEN;
        writeU32(out, 8, iters);
        writeU32(out, 12, ctLen);
        int offset = 16;
        System.arraycopy(salt, 0, out, offset, salt.length);
        offset += salt.length;
        System.arraycopy(iv, 0, out, offset, iv.length);
        offset += iv.length;
        int written = Crypto.aesGcmEncryptWithIvInto(
            key,
            iv,
            plaintext,
            0,
            plaintext.length,
            out,
            offset,
            Constants.FWXAES_AAD
        );
        if (written != ctLen) {
            throw new IllegalStateException("fwxAES encrypt length mismatch");
        }
        return out;
    }

    public static byte[] fwxAesDecryptRaw(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("fwxAES_decrypt_raw expects bytes");
        }
        byte[] pw = resolvePasswordBytes(password, useMaster);
        return fwxAesDecryptRawBytes(blob, pw, useMaster);
    }

    public static byte[] fwxAesDecryptRawBytes(byte[] blob, byte[] passwordBytes, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("fwxAES_decrypt_raw expects bytes");
        }
        byte[] pw = passwordBytes == null ? new byte[0] : passwordBytes;
        if (!useMaster && pw.length == 0) {
            throw new IllegalArgumentException("Password required when master key usage is disabled");
        }
        if (blob.length < 16) {
            throw new IllegalArgumentException("fwxAES blob too short");
        }
        for (int i = 0; i < Constants.FWXAES_MAGIC.length; i++) {
            if (blob[i] != Constants.FWXAES_MAGIC[i]) {
                throw new IllegalArgumentException("fwxAES bad magic");
            }
        }
        int algo = blob[4] & 0xFF;
        int kdf = blob[5] & 0xFF;
        int saltLen = blob[6] & 0xFF;
        int ivLen = blob[7] & 0xFF;
        if (algo != Constants.FWXAES_ALGO
            || (kdf != Constants.FWXAES_KDF_PBKDF2 && kdf != Constants.FWXAES_KDF_WRAP)) {
            throw new IllegalArgumentException("fwxAES unsupported algo/kdf");
        }
        int iters = readU32(blob, 8);
        int ctLen = readU32(blob, 12);
        int offset = 16;
        if (kdf == Constants.FWXAES_KDF_WRAP) {
            int headerLen = iters;
            if (blob.length < offset + headerLen + ivLen + ctLen) {
                throw new IllegalArgumentException("fwxAES blob truncated");
            }
            byte[] header = Arrays.copyOfRange(blob, offset, offset + headerLen);
            offset += headerLen;
            byte[] iv = Arrays.copyOfRange(blob, offset, offset + ivLen);
            offset += ivLen;
            List<byte[]> parts = Format.unpackLengthPrefixed(header, 2);
            byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                pw,
                useMaster,
                Constants.FWXAES_MASK_INFO,
                Constants.FWXAES_AAD,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            byte[] key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
            if (ctLen < Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("fwxAES ciphertext too short");
            }
            byte[] plain = new byte[ctLen - Constants.AEAD_TAG_LEN];
            int written = Crypto.aesGcmDecryptWithIvInto(
                key,
                iv,
                blob,
                offset,
                ctLen,
                plain,
                0,
                Constants.FWXAES_AAD
            );
            if (written != plain.length) {
                return Arrays.copyOf(plain, Math.max(0, written));
            }
            return plain;
        }
        if (blob.length < offset + saltLen + ivLen + ctLen) {
            throw new IllegalArgumentException("fwxAES blob truncated");
        }
        byte[] salt = Arrays.copyOfRange(blob, offset, offset + saltLen);
        offset += saltLen;
        byte[] iv = Arrays.copyOfRange(blob, offset, offset + ivLen);
        offset += ivLen;
        if (pw.length == 0) {
            throw new IllegalArgumentException("fwxAES password required for PBKDF2 payload");
        }
        byte[] key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
        if (ctLen < Constants.AEAD_TAG_LEN) {
            throw new IllegalArgumentException("fwxAES ciphertext too short");
        }
        byte[] plain = new byte[ctLen - Constants.AEAD_TAG_LEN];
        int written = Crypto.aesGcmDecryptWithIvInto(
            key,
            iv,
            blob,
            offset,
            ctLen,
            plain,
            0,
            Constants.FWXAES_AAD
        );
        if (written != plain.length) {
            return Arrays.copyOf(plain, Math.max(0, written));
        }
        return plain;
    }

    public static long fwxAesEncryptStream(InputStream input,
                                           OutputStream output,
                                           String password,
                                           boolean useMaster) throws IOException {
        if (output instanceof FileOutputStream) {
            long ctLen = fwxAesEncryptStreamInternal(input, output, password, useMaster);
            patchCtLen((FileOutputStream) output, ctLen);
            return ctLen;
        }
        File temp = File.createTempFile("basefwx-fwxaes-", ".tmp");
        long ctLen;
        try (FileOutputStream tempOut = new FileOutputStream(temp)) {
            ctLen = fwxAesEncryptStreamInternal(input, tempOut, password, useMaster);
            patchCtLen(tempOut, ctLen);
        }
        try (InputStream tempIn = new FileInputStream(temp)) {
            copyStream(tempIn, output);
        } finally {
            temp.delete();
        }
        return ctLen;
    }

    public static long fwxAesDecryptStream(InputStream input,
                                           OutputStream output,
                                           String password,
                                           boolean useMaster) throws IOException {
        byte[] header = new byte[16];
        readExact(input, header, header.length, "fwxAES blob too short");
        for (int i = 0; i < Constants.FWXAES_MAGIC.length; i++) {
            if (header[i] != Constants.FWXAES_MAGIC[i]) {
                throw new IllegalArgumentException("fwxAES bad magic");
            }
        }
        int algo = header[4] & 0xFF;
        int kdf = header[5] & 0xFF;
        int saltLen = header[6] & 0xFF;
        int ivLen = header[7] & 0xFF;
        if (algo != Constants.FWXAES_ALGO
            || (kdf != Constants.FWXAES_KDF_PBKDF2 && kdf != Constants.FWXAES_KDF_WRAP)) {
            throw new IllegalArgumentException("fwxAES unsupported algo/kdf");
        }
        int iters = readU32(header, 8);
        int ctLen = readU32(header, 12);
        if (ctLen < Constants.AEAD_TAG_LEN) {
            throw new IllegalArgumentException("fwxAES ciphertext too short");
        }
        byte[] key;
        byte[] iv;
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (kdf == Constants.FWXAES_KDF_WRAP) {
            int headerLen = iters;
            byte[] keyHeader = new byte[headerLen];
            if (headerLen > 0) {
                readExact(input, keyHeader, headerLen, "fwxAES blob truncated");
            }
            iv = new byte[ivLen];
            readExact(input, iv, ivLen, "fwxAES blob truncated");
            List<byte[]> parts = Format.unpackLengthPrefixed(keyHeader, 2);
            byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                pw,
                useMaster,
                Constants.FWXAES_MASK_INFO,
                Constants.FWXAES_AAD,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
        } else {
            byte[] salt = new byte[saltLen];
            readExact(input, salt, saltLen, "fwxAES blob truncated");
            iv = new byte[ivLen];
            readExact(input, iv, ivLen, "fwxAES blob truncated");
            if (pw.length == 0) {
                throw new IllegalArgumentException("fwxAES password required for PBKDF2 payload");
            }
            key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
        }

        try {
            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec = backend.newGcmDecryptor(key, iv, Constants.FWXAES_AAD)) {
                long remaining = (long) ctLen - Constants.AEAD_TAG_LEN;
                byte[] buf = new byte[STREAM_CHUNK];
                // GCM decryption buffers all data until doFinal for tag verification
                // So we need a buffer large enough for all plaintext
                int plaintextLen = ctLen - Constants.AEAD_TAG_LEN;
                byte[] outBuf = new byte[Math.max(STREAM_CHUNK, plaintextLen)];
                long written = 0;
                int outBufOffset = 0;
                while (remaining > 0) {
                    int toRead = (int) Math.min(buf.length, remaining);
                    readExact(input, buf, toRead, "fwxAES blob truncated");
                    int outLen = dec.update(buf, 0, toRead, outBuf, outBufOffset);
                    outBufOffset += outLen;
                    remaining -= toRead;
                }
                byte[] tag = new byte[Constants.AEAD_TAG_LEN];
                readExact(input, tag, tag.length, "fwxAES blob truncated");
                try {
                    int finalLen = dec.doFinal(tag, 0, tag.length, outBuf, outBufOffset);
                    int totalOut = outBufOffset + finalLen;
                    if (totalOut > 0) {
                        output.write(outBuf, 0, totalOut);
                        written = totalOut;
                    }
                } catch (AEADBadTagException exc) {
                    throw new IllegalArgumentException("AES-GCM auth failed");
                }
                output.flush();
                return written;
            }
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("fwxAES decrypt failed", exc);
        }
    }

    public static String b512Encode(String input, String password, boolean useMaster) {
        byte[] blob = b512EncodeBytes(input.getBytes(StandardCharsets.UTF_8), password, useMaster);
        return encodePayloadString(blob);
    }

    public static byte[] b512EncodeBytes(byte[] input, String password, boolean useMaster) {
        if (input == null) {
            throw new IllegalArgumentException("b512encode expects bytes");
        }
        byte[] pw = resolvePasswordBytes(password, useMaster);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(pw, useMaster, Constants.B512_MASK_INFO,
            false, Constants.MASK_AAD_B512, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        return encodeMaskedPayloadBytes(mask, input, Constants.B512_STREAM_INFO);
    }

    public static String b512Decode(String input, String password, boolean useMaster) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        byte[] plain = decodeMaskedPayloadBytesFromString(input, pw, useMaster,
            Constants.B512_MASK_INFO, Constants.MASK_AAD_B512, Constants.B512_STREAM_INFO);
        return new String(plain, StandardCharsets.UTF_8);
    }

    public static byte[] b512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("b512decode expects bytes");
        }
        byte[] pw = resolvePasswordBytes(password, useMaster);
        return decodeMaskedPayloadBytes(blob, pw, useMaster,
            Constants.B512_MASK_INFO, Constants.MASK_AAD_B512, Constants.B512_STREAM_INFO);
    }

    public static String pb512Encode(String input, String password, boolean useMaster) {
        byte[] blob = pb512EncodeBytes(input.getBytes(StandardCharsets.UTF_8), password, useMaster);
        return encodePayloadString(blob);
    }

    public static byte[] pb512EncodeBytes(byte[] input, String password, boolean useMaster) {
        if (input == null) {
            throw new IllegalArgumentException("pb512encode expects bytes");
        }
        byte[] pw = resolvePasswordBytes(password, useMaster);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(pw, useMaster, Constants.PB512_MASK_INFO,
            true, Constants.MASK_AAD_PB512, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        return encodeMaskedPayloadBytes(mask, input, Constants.PB512_STREAM_INFO);
    }

    public static String pb512Decode(String input, String password, boolean useMaster) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        byte[] plain = decodeMaskedPayloadBytesFromString(input, pw, useMaster,
            Constants.PB512_MASK_INFO, Constants.MASK_AAD_PB512, Constants.PB512_STREAM_INFO);
        return new String(plain, StandardCharsets.UTF_8);
    }

    public static byte[] pb512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("pb512decode expects bytes");
        }
        byte[] pw = resolvePasswordBytes(password, useMaster);
        return decodeMaskedPayloadBytes(blob, pw, useMaster,
            Constants.PB512_MASK_INFO, Constants.MASK_AAD_PB512, Constants.PB512_STREAM_INFO);
    }

    public static String b256Encode(String input) {
        return Codec.b256Encode(input);
    }

    public static String b256Decode(String input) {
        return Codec.b256Decode(input);
    }

    public static String n10Encode(String input) {
        return Codec.n10Encode(input);
    }

    public static String n10EncodeBytes(byte[] input) {
        return Codec.n10EncodeBytes(input);
    }

    public static String n10Decode(String input) {
        return Codec.n10Decode(input);
    }

    public static byte[] n10DecodeBytes(String input) {
        return Codec.n10DecodeBytes(input);
    }

    public static File kFMe(File input, File output) {
        return kFMe(input, output, false);
    }

    public static File kFMe(File input, File output, boolean bwMode) {
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("kFMe input file not found");
        }
        String inputExt = kfmCleanExt(getExtension(input));
        byte[] payload = readFileBytes(input);
        if (kfmIsAudioExtension(inputExt)) {
            int flags = bwMode ? KFM_FLAG_BW : 0;
            byte[] container = kfmPackContainer(KFM_MODE_AUDIO_IMAGE, payload, inputExt, flags);
            File out = kfmResolveOutput(input, output, ".png", "kfme");
            writeFileBytes(out, kfmCarrierToPng(container, bwMode));
            return out;
        }
        byte[] container = kfmPackContainer(KFM_MODE_IMAGE_AUDIO, payload, inputExt, 0);
        File out = kfmResolveOutput(input, output, ".wav", "kfme");
        writeFileBytes(out, kfmCarrierToWav(container));
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
        String inputExt = kfmCleanExt(getExtension(input));
        KfmDecoded decoded = kfmDecodeContainer(input, inputExt);
        if (decoded == null) {
            throw new IllegalArgumentException(
                "kFMd refused input: file is not a BaseFWX kFM carrier. Use kFMe to encode first."
            );
        }
        File out = kfmResolveOutput(input, output, decoded.extension, "kfmd");
        writeFileBytes(out, decoded.payload);
        return out;
    }

    public static File kFAe(File input, File output, boolean bwMode) {
        kfmWarn("kFAe is deprecated; use kFMe (auto-detect) instead.");
        return kFMe(input, output, bwMode);
    }

    public static File kFAd(File input, File output) {
        kfmWarn("kFAd is deprecated; use kFMd (auto-detect) instead.");
        return kFMd(input, output);
    }

    public static String b64Encode(String input) {
        return Base64Codec.encode(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String b64Decode(String input) {
        return new String(Base64Codec.decode(input), StandardCharsets.UTF_8);
    }

    public static String hash512(String input) {
        return hash512Bytes(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String uhash513(String input) {
        return uhash513Bytes(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String hash512Bytes(byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("hash512 expects bytes");
        }
        return digestHex(SHA512_DIGEST.get(), input);
    }

    public static String uhash513Bytes(byte[] inputBytes) {
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
        byte[] finalDigest = md256.digest();
        return hexToString(finalDigest);
    }

    public static String bi512Encode(String input) {
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

    public static String a512Encode(String input) {
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

    public static String a512Decode(String input) {
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

    public static String b1024Encode(String input) {
        return bi512Encode(a512Encode(input));
    }

    public static byte[] b512FileEncodeBytes(byte[] data,
                                             String extension,
                                             String password,
                                             boolean useMaster) {
        return b512FileEncodeBytes(data, extension, password, useMaster, false, true);
    }

    public static byte[] b512FileEncodeBytes(byte[] data,
                                             String extension,
                                             String password,
                                             boolean useMaster,
                                             boolean stripMetadata,
                                             boolean enableAead) {
        if (data == null) {
            throw new IllegalArgumentException("b512file_encode_bytes expects bytes");
        }
        long approxB64Len = ((data.length + 2L) / 3L) * 4L;
        if (approxB64Len > Constants.HKDF_MAX_LEN) {
            throw new IllegalArgumentException("b512file_encode_bytes payload too large; use file-based streaming APIs");
        }
        boolean useMasterEffective = useMaster && !stripMetadata;
        byte[] pw = resolvePasswordBytes(password, useMasterEffective);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
            pw,
            useMasterEffective,
            Constants.B512_FILE_MASK_INFO,
            !useMasterEffective,
            Constants.B512_AEAD_INFO,
            new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
        );
        useMasterEffective = useMasterEffective && mask.usedMaster;
        String ext = extension == null ? "" : extension;
        String b64Payload = Base64Codec.encode(data);
        String extToken = b512Encode(ext, password, useMasterEffective);
        String dataToken = b512Encode(b64Payload, password, useMasterEffective);
        String metadata = buildMetadata("FWX512R", stripMetadata, useMasterEffective,
            enableAead ? "AESGCM" : "NONE", "pbkdf2");
        String body = extToken + Constants.FWX_DELIM + dataToken;
        String payload = metadata.isEmpty() ? body : metadata + Constants.META_DELIM + body;
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        if (!enableAead) {
            return payloadBytes;
        }
        byte[] aeadKey = Crypto.hkdfSha256(mask.maskKey, Constants.B512_AEAD_INFO, 32);
        byte[] ctBlob = Crypto.aesGcmEncrypt(aeadKey, payloadBytes, Constants.B512_AEAD_INFO);
        return Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob, ctBlob));
    }

    public static DecodedFile b512FileDecodeBytes(byte[] blob,
                                                  String password,
                                                  boolean useMaster) {
        return b512FileDecodeBytes(blob, password, useMaster, false);
    }

    public static DecodedFile b512FileDecodeBytes(byte[] blob,
                                                  String password,
                                                  boolean useMaster,
                                                  boolean stripMetadata) {
        if (blob == null) {
            throw new IllegalArgumentException("b512file_decode_bytes expects bytes");
        }
        boolean useMasterEffective = useMaster && !stripMetadata;
        byte[] pw = resolvePasswordBytes(password, useMasterEffective);
        String content;
        try {
            List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
            byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                pw,
                useMasterEffective,
                Constants.B512_FILE_MASK_INFO,
                Constants.B512_AEAD_INFO,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            byte[] aeadKey = Crypto.hkdfSha256(maskKey, Constants.B512_AEAD_INFO, 32);
            byte[] payloadBytes = Crypto.aesGcmDecrypt(aeadKey, parts.get(2), Constants.B512_AEAD_INFO);
            content = new String(payloadBytes, StandardCharsets.UTF_8);
        } catch (RuntimeException exc) {
            content = new String(blob, StandardCharsets.UTF_8);
        }
        String[] metaSplit = splitMetadata(content);
        String metadataBlob = metaSplit[0];
        String body = metaSplit[1];
        String masterHint = metaValue(metadataBlob, "ENC-MASTER");
        if ("no".equalsIgnoreCase(masterHint)) {
            useMasterEffective = false;
        }
        String[] parts = splitWithDelims(body, Constants.FWX_DELIM, Constants.LEGACY_FWX_DELIM, "FWX container");
        String ext = b512Decode(parts[0], password, useMasterEffective);
        String dataB64 = b512Decode(parts[1], password, useMasterEffective);
        byte[] decoded = Base64Codec.decode(dataB64);
        return new DecodedFile(decoded, ext);
    }

    public static File b512FileEncodeFile(File input,
                                          File output,
                                          String password,
                                          boolean useMaster) {
        long size = input.length();
        long approxB64Len = ((size + 2L) / 3L) * 4L;
        if (size >= Constants.STREAM_THRESHOLD || approxB64Len > Constants.HKDF_MAX_LEN) {
            return b512FileEncodeFileStream(input, output, password, useMaster);
        }
        byte[] data = readFileBytes(input);
        String ext = getExtension(input);
        byte[] encoded = b512FileEncodeBytes(data, ext, password, useMaster);
        File outFile = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");
        writeFileBytes(outFile, encoded);
        return outFile;
    }

    public static File b512FileDecodeFile(File input,
                                          File output,
                                          String password,
                                          boolean useMaster) {
        String metaPreview = peekMetadataBlob(input);
        if (isStreamMode(metaPreview)) {
            return b512FileDecodeFileStream(input, output, password, useMaster, metaPreview);
        }
        byte[] blob = readFileBytes(input);
        DecodedFile decoded = b512FileDecodeBytes(blob, password, useMaster);
        File outFile = output;
        if (outFile == null) {
            String name = input.getName();
            if (name.endsWith(".fwx")) {
                name = name.substring(0, name.length() - 4);
            }
            if (decoded.extension != null && !decoded.extension.isEmpty()) {
                name += decoded.extension;
            }
            outFile = new File(input.getParentFile(), name);
        }
        writeFileBytes(outFile, decoded.data);
        return outFile;
    }

    public static byte[] pb512FileEncodeBytes(byte[] data,
                                              String extension,
                                              String password,
                                              boolean useMaster) {
        return pb512FileEncodeBytes(data, extension, password, useMaster, false);
    }

    public static byte[] pb512FileEncodeBytes(byte[] data,
                                              String extension,
                                              String password,
                                              boolean useMaster,
                                              boolean stripMetadata) {
        if (data == null) {
            throw new IllegalArgumentException("pb512file_encode_bytes expects bytes");
        }
        long approxB64Len = ((data.length + 2L) / 3L) * 4L;
        if (approxB64Len > Constants.HKDF_MAX_LEN) {
            throw new IllegalArgumentException("pb512file_encode_bytes payload too large; use file-based streaming APIs");
        }
        boolean useMasterEffective = useMaster && !stripMetadata;
        String resolvedPassword = password == null ? "" : password;
        String ext = extension == null ? "" : extension;
        String b64Payload = Base64Codec.encode(data);
        String kdfLabel = resolveUserKdfLabel();
        boolean obfuscate = payloadObfuscationEnabled();
        int heavyIters = Constants.HEAVY_PBKDF2_ITERATIONS;

        String extToken = pb512Encode(ext, resolvedPassword, useMasterEffective);
        String dataToken = pb512Encode(b64Payload, resolvedPassword, useMasterEffective);

        String body = extToken + Constants.FWX_HEAVY_DELIM + dataToken;
        boolean fastObf = obfuscate && !stripMetadata && useFastObfuscation(body.length());
        String obfMode = obfuscate ? (fastObf ? "fast" : "yes") : "no";
        String metadata = buildMetadata(
            "AES-HEAVY",
            stripMetadata,
            useMasterEffective,
            "AESGCM",
            kdfLabel,
            null,
            obfuscate,
            obfMode,
            heavyIters,
            null,
            null,
            null,
            null
        );
        String plaintext = metadata.isEmpty()
            ? body
            : metadata + Constants.META_DELIM + body;
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return encryptAesPayloadBytes(plaintextBytes, resolvedPassword, useMasterEffective, metadata,
            kdfLabel, heavyIters, obfuscate, fastObf);
    }

    public static DecodedFile pb512FileDecodeBytes(byte[] blob,
                                                   String password,
                                                   boolean useMaster) {
        return pb512FileDecodeBytes(blob, password, useMaster, false);
    }

    public static DecodedFile pb512FileDecodeBytes(byte[] blob,
                                                   String password,
                                                   boolean useMaster,
                                                   boolean stripMetadata) {
        if (blob == null) {
            throw new IllegalArgumentException("pb512file_decode_bytes expects bytes");
        }
        boolean useMasterEffective = useMaster && !stripMetadata;
        String resolvedPassword = password == null ? "" : password;
        String plaintext = decryptAesPayload(blob, resolvedPassword, useMasterEffective);
        String[] metaSplit = splitMetadata(plaintext);
        String metadataBlob = metaSplit[0];
        String body = metaSplit[1];
        String masterHint = metaValue(metadataBlob, "ENC-MASTER");
        if ("no".equalsIgnoreCase(masterHint)) {
            useMasterEffective = false;
        }
        String[] parts = splitWithDelims(body, Constants.FWX_HEAVY_DELIM, Constants.LEGACY_FWX_HEAVY_DELIM, "FWX heavy");
        String ext = pb512Decode(parts[0], resolvedPassword, useMasterEffective);
        String dataB64 = pb512Decode(parts[1], resolvedPassword, useMasterEffective);
        byte[] decoded = Base64Codec.decode(dataB64);
        return new DecodedFile(decoded, ext);
    }

    public static File pb512FileEncodeFile(File input,
                                          File output,
                                          String password,
                                          boolean useMaster) {
        long size = input.length();
        long approxB64Len = ((size + 2L) / 3L) * 4L;
        if (size >= Constants.STREAM_THRESHOLD || approxB64Len > Constants.HKDF_MAX_LEN) {
            return pb512FileEncodeFileStream(input, output, password, useMaster);
        }
        byte[] data = readFileBytes(input);
        String ext = getExtension(input);
        byte[] encoded = pb512FileEncodeBytes(data, ext, password, useMaster);
        File outFile = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");
        writeFileBytes(outFile, encoded);
        return outFile;
    }

    public static File pb512FileDecodeFile(File input,
                                           File output,
                                           String password,
                                           boolean useMaster) {
        String metaPreview = peekMetadataBlob(input);
        if (isStreamMode(metaPreview)) {
            return pb512FileDecodeFileStream(input, output, password, useMaster, metaPreview);
        }
        byte[] blob = readFileBytes(input);
        DecodedFile decoded = pb512FileDecodeBytes(blob, password, useMaster);
        File outFile = output;
        if (outFile == null) {
            String name = input.getName();
            if (name.endsWith(".fwx")) {
                name = name.substring(0, name.length() - 4);
            }
            if (decoded.extension != null && !decoded.extension.isEmpty()) {
                name += decoded.extension;
            }
            outFile = new File(input.getParentFile(), name);
        }
        writeFileBytes(outFile, decoded.data);
        return outFile;
    }

    private static File b512FileEncodeFileStream(File input,
                                                 File output,
                                                 String password,
                                                 boolean useMaster) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for streaming b512 encode");
        }
        boolean useMasterEffective = false;
        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(true);
                useMasterEffective = pub != null;
            } catch (RuntimeException exc) {
                useMasterEffective = false;
            }
        }
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
            pw,
            useMasterEffective,
            Constants.B512_FILE_MASK_INFO,
            !useMasterEffective,
            Constants.B512_AEAD_INFO,
            new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
        );
        useMasterEffective = useMasterEffective && mask.usedMaster;
        String ext = getExtension(input);
        byte[] extBytes = ext.isEmpty() ? new byte[0] : ext.getBytes(StandardCharsets.UTF_8);
        byte[] streamSalt = StreamObfuscator.generateSalt();
        boolean fastObf = useFastObfuscation(input.length());
        String metadata = buildMetadata("FWX512R", false, useMasterEffective, "AESGCM", "pbkdf2",
            "STREAM", null, fastObf ? "fast" : "yes", null, null, null, null, null);
        byte[] metadataBytes = metadata.isEmpty()
            ? new byte[0]
            : metadata.getBytes(StandardCharsets.UTF_8);
        byte[] prefixBytes = metadataBytes.length == 0
            ? new byte[0]
            : concat(metadataBytes, Constants.META_DELIM.getBytes(StandardCharsets.UTF_8));
        byte[] streamHeader = buildStreamHeader(input.length(), streamSalt, extBytes, Constants.STREAM_CHUNK_SIZE);
        long plaintextLen = (long) prefixBytes.length + streamHeader.length + input.length();
        long payloadLen = 4L + metadataBytes.length + Constants.AEAD_NONCE_LEN + plaintextLen + Constants.AEAD_TAG_LEN;
        if (payloadLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Streaming payload too large");
        }
        File outFile = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");
        byte[] aeadKey = Crypto.hkdfSha256(mask.maskKey, Constants.B512_AEAD_INFO, 32);
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        StreamObfuscator obfuscator = StreamObfuscator.forPassword(pw, streamSalt, fastObf);

        try (FileInputStream fin = new FileInputStream(input);
             BufferedInputStream in = new BufferedInputStream(fin, Constants.STREAM_CHUNK_SIZE);
             FileOutputStream fout = new FileOutputStream(outFile);
             BufferedOutputStream out = new BufferedOutputStream(fout, Constants.STREAM_CHUNK_SIZE)) {
            writeU32(out, mask.userBlob.length);
            out.write(mask.userBlob);
            writeU32(out, mask.masterBlob.length);
            out.write(mask.masterBlob);
            writeU32(out, (int) payloadLen);
            writeU32(out, metadataBytes.length);
            if (metadataBytes.length > 0) {
                out.write(metadataBytes);
            }
            out.write(nonce);

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadEncryptor enc = backend.newGcmEncryptor(aeadKey, nonce, metadataBytes)) {
                byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE + Constants.AEAD_TAG_LEN];
                if (prefixBytes.length > 0) {
                    int outLen = enc.update(prefixBytes, 0, prefixBytes.length, outBuf, 0);
                    if (outLen > 0) {
                        out.write(outBuf, 0, outLen);
                    }
                }
                int headerLen = enc.update(streamHeader, 0, streamHeader.length, outBuf, 0);
                if (headerLen > 0) {
                    out.write(outBuf, 0, headerLen);
                }

                byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
                long remaining = input.length();
                while (remaining > 0) {
                    int take = (int) Math.min(buffer.length, remaining);
                    readExact(in, buffer, take, "Streaming payload truncated");
                    obfuscator.encodeChunkInPlace(buffer, take);
                    int outLen = enc.update(buffer, 0, take, outBuf, 0);
                    if (outLen > 0) {
                        out.write(outBuf, 0, outLen);
                    }
                    remaining -= take;
                }
                int finalLen = enc.doFinal(outBuf, 0);
                if (finalLen < Constants.AEAD_TAG_LEN) {
                    throw new IllegalStateException("AES-GCM final block too short");
                }
                int ctLen = finalLen - Constants.AEAD_TAG_LEN;
                if (ctLen > 0) {
                    out.write(outBuf, 0, ctLen);
                }
                out.write(outBuf, ctLen, Constants.AEAD_TAG_LEN);
            }
            out.flush();
        } catch (IOException | GeneralSecurityException exc) {
            throw new IllegalStateException("Streaming b512 encode failed", exc);
        }
        return outFile;
    }

    private static File b512FileDecodeFileStream(File input,
                                                 File output,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataPreview) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for streaming b512 decode");
        }
        File tempPlain = null;
        byte[] metadataBytes;
        String metadataBlob = "";
        boolean useMasterEffective = useMaster;
        boolean obfuscateStream = true;
        boolean fastObfStream = false;
        try (FileInputStream fin = new FileInputStream(input);
             BufferedInputStream in = new BufferedInputStream(fin, Constants.STREAM_CHUNK_SIZE)) {
            int lenUser = readU32(in, "Ciphertext payload truncated");
            byte[] userBlob = readExactBytes(in, lenUser, "Ciphertext payload truncated");
            int lenMaster = readU32(in, "Ciphertext payload truncated");
            byte[] masterBlob = readExactBytes(in, lenMaster, "Ciphertext payload truncated");
            int lenPayload = readU32(in, "Ciphertext payload truncated");
            if (lenPayload < 4 + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Ciphertext payload truncated");
            }
            int metaLen = readU32(in, "Ciphertext payload truncated");
            metadataBytes = readExactBytes(in, metaLen, "Ciphertext payload truncated");
            if (metadataBytes.length > 0) {
                metadataBlob = new String(metadataBytes, StandardCharsets.UTF_8);
            }
            if (metadataPreview != null && !metadataPreview.isEmpty() && !metadataPreview.equals(metadataBlob)) {
                throw new IllegalArgumentException("Metadata integrity mismatch detected");
            }
            String masterHint = metaValue(metadataBlob, "ENC-MASTER");
            if ("no".equalsIgnoreCase(masterHint)) {
                useMasterEffective = false;
            }
            String obfHint = metaValue(metadataBlob, "ENC-OBF");
            obfuscateStream = !"no".equalsIgnoreCase(obfHint);
            fastObfStream = "fast".equalsIgnoreCase(obfHint);
            byte[] nonce = readExactBytes(in, Constants.AEAD_NONCE_LEN, "Ciphertext payload truncated");
            long cipherBodyLen = (lenPayload & 0xFFFFFFFFL) - 4L - metaLen
                - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            if (cipherBodyLen < 0) {
                throw new IllegalArgumentException("Ciphertext payload truncated");
            }
            byte[] maskKey = KeyWrap.recoverMaskKey(
                userBlob,
                masterBlob,
                pw,
                useMasterEffective,
                Constants.B512_FILE_MASK_INFO,
                Constants.B512_AEAD_INFO,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            byte[] aeadKey = Crypto.hkdfSha256(maskKey, Constants.B512_AEAD_INFO, 32);

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec = backend.newGcmDecryptor(aeadKey, nonce, metadataBytes)) {
                tempPlain = File.createTempFile("basefwx-stream", ".plain");
                try (FileOutputStream fout = new FileOutputStream(tempPlain);
                     BufferedOutputStream plainOut = new BufferedOutputStream(fout, Constants.STREAM_CHUNK_SIZE)) {
                    byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
                    byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                    long remaining = cipherBodyLen;
                    while (remaining > 0) {
                        int take = (int) Math.min(buffer.length, remaining);
                        readExact(in, buffer, take, "Ciphertext truncated");
                        int outLen = dec.update(buffer, 0, take, outBuf, 0);
                        if (outLen > 0) {
                            plainOut.write(outBuf, 0, outLen);
                        }
                        remaining -= take;
                    }
                    byte[] tag = readExactBytes(in, Constants.AEAD_TAG_LEN, "Ciphertext payload truncated");
                    int finalLen = dec.doFinal(tag, 0, tag.length, outBuf, 0);
                    if (finalLen > 0) {
                        plainOut.write(outBuf, 0, finalLen);
                    }
                }
            }
        } catch (IOException | GeneralSecurityException exc) {
            if (tempPlain != null) {
                tempPlain.delete();
            }
            System.err.println("ERROR: Streaming b512 decode failed");
            exc.printStackTrace(System.err);
            throw new IllegalStateException("Streaming b512 decode failed", exc);
        }

        try (FileInputStream fin = new FileInputStream(tempPlain);
             BufferedInputStream plainIn = new BufferedInputStream(fin, Constants.STREAM_CHUNK_SIZE)) {
            if (metadataBytes.length > 0) {
                byte[] metaBuf = readExactBytes(plainIn, metadataBytes.length, "Metadata integrity mismatch detected");
                if (!Arrays.equals(metaBuf, metadataBytes)) {
                    throw new IllegalArgumentException("Metadata integrity mismatch detected");
                }
                byte[] delim = Constants.META_DELIM.getBytes(StandardCharsets.UTF_8);
                byte[] delimBuf = readExactBytes(plainIn, delim.length, "Malformed streaming payload: missing metadata delimiter");
                if (!Arrays.equals(delimBuf, delim)) {
                    throw new IllegalArgumentException("Malformed streaming payload: missing metadata delimiter");
                }
            }
            byte[] magic = readExactBytes(plainIn, Constants.STREAM_MAGIC.length, "Malformed streaming payload: magic mismatch");
            if (!Arrays.equals(magic, Constants.STREAM_MAGIC)) {
                throw new IllegalArgumentException("Malformed streaming payload: magic mismatch");
            }
            int chunkSize = readU32(plainIn, "Malformed streaming payload: missing chunk size");
            final int MAX_CHUNK = (16 << 20);  // 16 MiB
            final int MIN_FALLBACK = 4 * 1024 * 1024;  // 4 MiB
            if (chunkSize <= 0 || chunkSize > MAX_CHUNK) {
                chunkSize = Math.max(Constants.STREAM_CHUNK_SIZE, MIN_FALLBACK);
            }
            long originalSize = readU64(plainIn, "Malformed streaming payload: missing original size");
            byte[] salt = readExactBytes(plainIn, Constants.STREAM_SALT_LEN, "Malformed streaming payload: missing salt");
            int extLen = readU16(plainIn, "Malformed streaming payload: missing extension length");
            byte[] extBytes = extLen > 0
                ? readExactBytes(plainIn, extLen, "Malformed streaming payload: truncated extension")
                : new byte[0];

            StreamObfuscator decoder = obfuscateStream
                ? StreamObfuscator.forPassword(pw, salt, fastObfStream)
                : null;
            File outFile = resolveDecodedOutput(input, output, extBytes);
            try (FileOutputStream fout = new FileOutputStream(outFile);
                 BufferedOutputStream out = new BufferedOutputStream(fout, Constants.STREAM_CHUNK_SIZE)) {
                byte[] buffer = new byte[chunkSize];
                long remaining = originalSize;
                while (remaining > 0) {
                    int take = (int) Math.min(buffer.length, remaining);
                    readExact(plainIn, buffer, take, "Streaming payload truncated");
                    if (decoder != null) {
                        decoder.decodeChunkInPlace(buffer, take);
                    }
                    out.write(buffer, 0, take);
                    remaining -= take;
                }
                if (plainIn.read() != -1) {
                    throw new IllegalArgumentException("Streaming payload contained unexpected trailing data");
                }
            }
            return outFile;
        } catch (IOException exc) {
            System.err.println("ERROR: Streaming b512 decode failed");
            exc.printStackTrace(System.err);
            throw new IllegalStateException("Streaming b512 decode failed", exc);
        } finally {
            if (tempPlain != null) {
                tempPlain.delete();
            }
        }
    }

    private static File pb512FileEncodeFileStream(File input,
                                                  File output,
                                                  String password,
                                                  boolean useMaster) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for AES-heavy streaming mode");
        }
        String kdfLabel = resolveUserKdfLabel();
        int heavyIters = Constants.HEAVY_PBKDF2_ITERATIONS;
        boolean obfuscate = payloadObfuscationEnabled();
        boolean useMasterEffective = false;
        byte[] masterBlob = new byte[0];
        byte[] ephemeralKey = null;

        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(true);
                if (pub != null) {
                    EcKeys.EcKemResult kem = EcKeys.kemEncrypt(pub);
                    masterBlob = kem.masterBlob;
                    ephemeralKey = Crypto.hkdfSha256(kem.shared, Constants.KEM_INFO, 32);
                    useMasterEffective = true;
                }
            } catch (RuntimeException exc) {
                useMasterEffective = false;
            }
        }
        if (ephemeralKey == null) {
            ephemeralKey = Crypto.randomBytes(32);
        }
        byte[] streamSalt = StreamObfuscator.generateSalt();
        String ext = getExtension(input);
        byte[] extBytes = ext.isEmpty() ? new byte[0] : ext.getBytes(StandardCharsets.UTF_8);
        boolean fastObf = obfuscate && useFastObfuscation(input.length());
        String obfMode = obfuscate ? (fastObf ? "fast" : "yes") : "no";
        String metadata = buildMetadata(
            "AES-HEAVY",
            false,
            useMasterEffective,
            "AESGCM",
            kdfLabel,
            "STREAM",
            obfuscate,
            obfMode,
            heavyIters,
            null,
            null,
            null,
            null
        );
        byte[] metadataBytes = metadata.isEmpty()
            ? new byte[0]
            : metadata.getBytes(StandardCharsets.UTF_8);
        byte[] prefixBytes = metadataBytes.length == 0
            ? new byte[0]
            : concat(metadataBytes, Constants.META_DELIM.getBytes(StandardCharsets.UTF_8));
        byte[] streamHeader = buildStreamHeader(input.length(), streamSalt, extBytes, Constants.STREAM_CHUNK_SIZE);
        long plaintextLen = (long) prefixBytes.length + streamHeader.length + input.length();
        long payloadLen = 4L + metadataBytes.length + Constants.AEAD_NONCE_LEN + plaintextLen + Constants.AEAD_TAG_LEN;
        if (payloadLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Streaming payload too large");
        }
        byte[] userBlob = new byte[0];
        if (pw.length > 0) {
            int iters = hardenPbkdf2Iterations(pw, heavyIters);
            byte[] salt = Crypto.randomBytes(Constants.USER_KDF_SALT_SIZE);
            byte[] userKey = Crypto.pbkdf2HmacSha256(pw, salt, iters, 32);
            byte[] wrapped = Crypto.aesGcmEncrypt(userKey, ephemeralKey, metadataBytes);
            userBlob = new byte[salt.length + wrapped.length];
            System.arraycopy(salt, 0, userBlob, 0, salt.length);
            System.arraycopy(wrapped, 0, userBlob, salt.length, wrapped.length);
        }
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        StreamObfuscator obfuscator = StreamObfuscator.forPassword(pw, streamSalt, fastObf);
        File outFile = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");

        try (FileInputStream fin = new FileInputStream(input);
             BufferedInputStream in = new BufferedInputStream(fin, Constants.STREAM_CHUNK_SIZE);
             FileOutputStream fout = new FileOutputStream(outFile);
             BufferedOutputStream out = new BufferedOutputStream(fout, Constants.STREAM_CHUNK_SIZE)) {
            writeU32(out, userBlob.length);
            out.write(userBlob);
            writeU32(out, masterBlob.length);
            out.write(masterBlob);
            writeU32(out, (int) payloadLen);
            writeU32(out, metadataBytes.length);
            if (metadataBytes.length > 0) {
                out.write(metadataBytes);
            }
            out.write(nonce);

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadEncryptor enc = backend.newGcmEncryptor(ephemeralKey, nonce, metadataBytes)) {
                byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE + Constants.AEAD_TAG_LEN];
                if (prefixBytes.length > 0) {
                    int outLen = enc.update(prefixBytes, 0, prefixBytes.length, outBuf, 0);
                    if (outLen > 0) {
                        out.write(outBuf, 0, outLen);
                    }
                }
                int headerLen = enc.update(streamHeader, 0, streamHeader.length, outBuf, 0);
                if (headerLen > 0) {
                    out.write(outBuf, 0, headerLen);
                }

                byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
                long remaining = input.length();
                while (remaining > 0) {
                    int take = (int) Math.min(buffer.length, remaining);
                    readExact(in, buffer, take, "Streaming payload truncated");
                    obfuscator.encodeChunkInPlace(buffer, take);
                    int outLen = enc.update(buffer, 0, take, outBuf, 0);
                    if (outLen > 0) {
                        out.write(outBuf, 0, outLen);
                    }
                    remaining -= take;
                }
                int finalLen = enc.doFinal(outBuf, 0);
                if (finalLen < Constants.AEAD_TAG_LEN) {
                    throw new IllegalStateException("AES-GCM final block too short");
                }
                int ctLen = finalLen - Constants.AEAD_TAG_LEN;
                if (ctLen > 0) {
                    out.write(outBuf, 0, ctLen);
                }
                out.write(outBuf, ctLen, Constants.AEAD_TAG_LEN);
            }
            out.flush();
        } catch (IOException | GeneralSecurityException exc) {
            throw new IllegalStateException("AES-heavy streaming encode failed", exc);
        }
        return outFile;
    }

    private static File pb512FileDecodeFileStream(File input,
                                                  File output,
                                                  String password,
                                                  boolean useMaster,
                                                  String metadataPreview) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for AES-heavy streaming mode");
        }
        File tempPlain = null;
        byte[] metadataBytes;
        String metadataBlob = "";
        boolean useMasterEffective = useMaster;
        boolean obfuscateStream = true;
        boolean fastObfStream = false;
        try (FileInputStream fin = new FileInputStream(input);
             BufferedInputStream in = new BufferedInputStream(fin, Constants.STREAM_CHUNK_SIZE)) {
            int lenUser = readU32(in, "Ciphertext payload truncated");
            byte[] userBlob = readExactBytes(in, lenUser, "Ciphertext payload truncated");
            int lenMaster = readU32(in, "Ciphertext payload truncated");
            byte[] masterBlob = readExactBytes(in, lenMaster, "Ciphertext payload truncated");
            int lenPayload = readU32(in, "Ciphertext payload truncated");
            if (lenPayload < 4 + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Ciphertext payload truncated");
            }
            int metaLen = readU32(in, "Ciphertext payload truncated");
            metadataBytes = readExactBytes(in, metaLen, "Ciphertext payload truncated");
            if (metadataBytes.length > 0) {
                metadataBlob = new String(metadataBytes, StandardCharsets.UTF_8);
            }
            if (metadataPreview != null && !metadataPreview.isEmpty() && !metadataPreview.equals(metadataBlob)) {
                throw new IllegalArgumentException("Metadata integrity mismatch detected");
            }
            String masterHint = metaValue(metadataBlob, "ENC-MASTER");
            if ("no".equalsIgnoreCase(masterHint)) {
                useMasterEffective = false;
            }
            String obfHint = metaValue(metadataBlob, "ENC-OBF");
            obfuscateStream = !"no".equalsIgnoreCase(obfHint);
            fastObfStream = "fast".equalsIgnoreCase(obfHint);
            String kdfHint = metaValue(metadataBlob, "ENC-KDF");
            if (kdfHint == null || kdfHint.isEmpty()) {
                kdfHint = resolveUserKdfLabel();
            }
            int kdfIterHint = parseMetadataInt(metaValue(metadataBlob, "ENC-KDF-ITER"), Constants.HEAVY_PBKDF2_ITERATIONS);

            byte[] nonce = readExactBytes(in, Constants.AEAD_NONCE_LEN, "Ciphertext payload truncated");
            long cipherBodyLen = (lenPayload & 0xFFFFFFFFL) - 4L - metaLen
                - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            if (cipherBodyLen < 0) {
                throw new IllegalArgumentException("Ciphertext payload truncated");
            }

            byte[] ephemeralKey = null;
            if (masterBlob.length > 0) {
                if (!useMasterEffective) {
                    throw new IllegalArgumentException("Master key required to decode this payload");
                }
                java.security.PrivateKey priv = EcKeys.loadMasterPrivate();
                byte[] shared = EcKeys.kemDecrypt(masterBlob, priv);
                ephemeralKey = Crypto.hkdfSha256(shared, Constants.KEM_INFO, 32);
            }
            if (userBlob.length > 0) {
                if (pw.length == 0) {
                    throw new IllegalArgumentException("Password required to decode this payload");
                }
                if (userBlob.length < Constants.USER_KDF_SALT_SIZE) {
                    throw new IllegalArgumentException("Corrupted user key blob: truncated data");
                }
                int iters = hardenPbkdf2Iterations(pw, kdfIterHint);
                byte[] salt = Arrays.copyOfRange(userBlob, 0, Constants.USER_KDF_SALT_SIZE);
                byte[] wrapped = Arrays.copyOfRange(userBlob, Constants.USER_KDF_SALT_SIZE, userBlob.length);
                String label = resolveKdfLabel(kdfHint);
                if (!"pbkdf2".equals(label)) {
                    throw new IllegalArgumentException("Unsupported KDF label: " + label);
                }
                byte[] userKey = Crypto.pbkdf2HmacSha256(pw, salt, iters, 32);
                ephemeralKey = Crypto.aesGcmDecrypt(userKey, wrapped, metadataBytes);
            }
            if (ephemeralKey == null) {
                throw new IllegalArgumentException("Unable to derive payload key");
            }

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec = backend.newGcmDecryptor(ephemeralKey, nonce, metadataBytes)) {
                tempPlain = File.createTempFile("basefwx-stream", ".plain");
                try (FileOutputStream fout = new FileOutputStream(tempPlain);
                     BufferedOutputStream plainOut = new BufferedOutputStream(fout, Constants.STREAM_CHUNK_SIZE)) {
                    byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
                    byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                    long remaining = cipherBodyLen;
                    while (remaining > 0) {
                        int take = (int) Math.min(buffer.length, remaining);
                        readExact(in, buffer, take, "Ciphertext truncated");
                        int outLen = dec.update(buffer, 0, take, outBuf, 0);
                        if (outLen > 0) {
                            plainOut.write(outBuf, 0, outLen);
                        }
                        remaining -= take;
                    }
                    byte[] tag = readExactBytes(in, Constants.AEAD_TAG_LEN, "Ciphertext payload truncated");
                    int finalLen = dec.doFinal(tag, 0, tag.length, outBuf, 0);
                    if (finalLen > 0) {
                        plainOut.write(outBuf, 0, finalLen);
                    }
                }
            }
        } catch (IOException | GeneralSecurityException exc) {
            if (tempPlain != null) {
                tempPlain.delete();
            }
            System.err.println("ERROR: AES-heavy streaming decode failed");
            exc.printStackTrace(System.err);
            throw new IllegalStateException("AES-heavy streaming decode failed", exc);
        }

        try (FileInputStream fin = new FileInputStream(tempPlain);
             BufferedInputStream plainIn = new BufferedInputStream(fin, Constants.STREAM_CHUNK_SIZE)) {
            if (metadataBytes.length > 0) {
                byte[] metaBuf = readExactBytes(plainIn, metadataBytes.length, "Metadata integrity mismatch detected");
                if (!Arrays.equals(metaBuf, metadataBytes)) {
                    throw new IllegalArgumentException("Metadata integrity mismatch detected");
                }
                byte[] delim = Constants.META_DELIM.getBytes(StandardCharsets.UTF_8);
                byte[] delimBuf = readExactBytes(plainIn, delim.length, "Malformed streaming payload: missing metadata delimiter");
                if (!Arrays.equals(delimBuf, delim)) {
                    throw new IllegalArgumentException("Malformed streaming payload: missing metadata delimiter");
                }
            }
            byte[] magic = readExactBytes(plainIn, Constants.STREAM_MAGIC.length, "Malformed streaming payload: magic mismatch");
            if (!Arrays.equals(magic, Constants.STREAM_MAGIC)) {
                throw new IllegalArgumentException("Malformed streaming payload: magic mismatch");
            }
            int chunkSize = readU32(plainIn, "Malformed streaming payload: missing chunk size");
            final int MAX_CHUNK = (16 << 20);  // 16 MiB
            final int MIN_FALLBACK = 4 * 1024 * 1024;  // 4 MiB
            if (chunkSize <= 0 || chunkSize > MAX_CHUNK) {
                chunkSize = Math.max(Constants.STREAM_CHUNK_SIZE, MIN_FALLBACK);
            }
            long originalSize = readU64(plainIn, "Malformed streaming payload: missing original size");
            byte[] salt = readExactBytes(plainIn, Constants.STREAM_SALT_LEN, "Malformed streaming payload: missing salt");
            int extLen = readU16(plainIn, "Malformed streaming payload: missing extension length");
            byte[] extBytes = extLen > 0
                ? readExactBytes(plainIn, extLen, "Malformed streaming payload: truncated extension")
                : new byte[0];

            StreamObfuscator decoder = obfuscateStream
                ? StreamObfuscator.forPassword(pw, salt, fastObfStream)
                : null;
            File outFile = resolveDecodedOutput(input, output, extBytes);
            try (FileOutputStream fout = new FileOutputStream(outFile);
                 BufferedOutputStream out = new BufferedOutputStream(fout, Constants.STREAM_CHUNK_SIZE)) {
                byte[] buffer = new byte[chunkSize];
                long remaining = originalSize;
                while (remaining > 0) {
                    int take = (int) Math.min(buffer.length, remaining);
                    readExact(plainIn, buffer, take, "Streaming payload truncated");
                    if (decoder != null) {
                        decoder.decodeChunkInPlace(buffer, take);
                    }
                    out.write(buffer, 0, take);
                    remaining -= take;
                }
                if (plainIn.read() != -1) {
                    throw new IllegalArgumentException("Streaming payload contained unexpected trailing data");
                }
            }
            return outFile;
        } catch (IOException exc) {
            System.err.println("ERROR: AES-heavy streaming decode failed");
            exc.printStackTrace(System.err);
            throw new IllegalStateException("AES-heavy streaming decode failed", exc);
        } finally {
            if (tempPlain != null) {
                tempPlain.delete();
            }
        }
    }

    private static boolean isStreamMode(String metadataBlob) {
        if (metadataBlob == null || metadataBlob.isEmpty()) {
            return false;
        }
        String mode = metaValue(metadataBlob, "ENC-MODE");
        return "stream".equalsIgnoreCase(mode);
    }

    private static String peekMetadataBlob(File input) {
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

    private static byte[] buildStreamHeader(long inputSize,
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

    private static File resolveDecodedOutput(File input, File output, byte[] extBytes) {
        if (output != null) {
            return output;
        }
        String name = input.getName();
        if (name.endsWith(".fwx")) {
            name = name.substring(0, name.length() - 4);
        }
        String ext = "";
        if (extBytes.length > 0) {
            ext = new String(extBytes, StandardCharsets.UTF_8);
        }
        if (!ext.isEmpty()) {
            name += ext;
        }
        return new File(input.getParentFile(), name);
    }

    public static File jmgEncryptFile(File input,
                                      File output,
                                      String password,
                                      boolean useMaster,
                                      boolean keepMeta,
                                      boolean keepInput) {
        return MediaCipher.encryptMedia(input, output, password, keepMeta, keepInput, useMaster);
    }

    public static File jmgDecryptFile(File input,
                                      File output,
                                      String password,
                                      boolean useMaster) {
        return MediaCipher.decryptMedia(input, output, password, useMaster);
    }

    public static void fwxAesEncryptFile(File input, File output, String password, boolean useMaster) {
        try (FileInputStream in = new FileInputStream(input);
             FileOutputStream out = new FileOutputStream(output)) {
            fwxAesEncryptStream(in, out, password, useMaster);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file encrypt failed", exc);
        }
    }

    public static void fwxAesDecryptFile(File input, File output, String password, boolean useMaster) {
        try (FileInputStream in = new FileInputStream(input);
             FileOutputStream out = new FileOutputStream(output)) {
            fwxAesDecryptStream(in, out, password, useMaster);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file decrypt failed", exc);
        }
    }

    public static void fwxAesEncryptFileNio(File input, File output, String password, boolean useMaster) {
        try (FileInputStream fis = new FileInputStream(input);
             FileOutputStream fos = new FileOutputStream(output);
             FileChannel in = fis.getChannel();
             FileChannel out = fos.getChannel()) {
            long ctLen = fwxAesEncryptChannel(in, out, password, useMaster);
            patchCtLen(out, ctLen);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file encrypt failed", exc);
        }
    }

    public static void fwxAesDecryptFileNio(File input, File output, String password, boolean useMaster) {
        try (FileInputStream fis = new FileInputStream(input);
             FileOutputStream fos = new FileOutputStream(output);
             FileChannel in = fis.getChannel();
             FileChannel out = fos.getChannel()) {
            fwxAesDecryptChannel(in, out, password, useMaster);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file decrypt failed", exc);
        }
    }

    private static byte[] encryptAesPayload(String plaintext,
                                            String password,
                                            boolean useMaster,
                                            String metadataBlob,
                                            String kdfLabel,
                                            int kdfIterations,
                                            boolean obfuscate,
                                            boolean fastObf) {
        byte[] payloadBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return encryptAesPayloadBytes(payloadBytes, password, useMaster, metadataBlob,
            kdfLabel, kdfIterations, obfuscate, fastObf);
    }

    private static byte[] encryptAesPayloadBytes(byte[] payloadBytes,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataBlob,
                                                 String kdfLabel,
                                                 int kdfIterations,
                                                 boolean obfuscate,
                                                 boolean fastObf) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (pw.length == 0 && !useMaster) {
            throw new IllegalArgumentException("Cannot encrypt without password or master key");
        }
        byte[] metadataBytes = metadataBlob == null ? new byte[0] : metadataBlob.getBytes(StandardCharsets.UTF_8);
        byte[] aad = metadataBytes;

        byte[] masterBlob = new byte[0];
        byte[] ephemeralKey = null;
        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(true);
                if (pub != null) {
                    EcKeys.EcKemResult kem = EcKeys.kemEncrypt(pub);
                    masterBlob = kem.masterBlob;
                    ephemeralKey = Crypto.hkdfSha256(kem.shared, Constants.KEM_INFO, 32);
                }
            } catch (RuntimeException exc) {
                ephemeralKey = null;
            }
        }
        if (ephemeralKey == null) {
            ephemeralKey = Crypto.randomBytes(32);
        }

        byte[] userBlob = new byte[0];
        if (pw.length > 0) {
            int iters = hardenPbkdf2Iterations(pw, kdfIterations);
            byte[] salt = Crypto.randomBytes(Constants.USER_KDF_SALT_SIZE);
            String label = resolveKdfLabel(kdfLabel);
            if (!"pbkdf2".equals(label)) {
                throw new IllegalArgumentException("Unsupported KDF label: " + label);
            }
            byte[] userKey = Crypto.pbkdf2HmacSha256(pw, salt, iters, 32);
            byte[] wrapped = Crypto.aesGcmEncrypt(userKey, ephemeralKey, aad);
            userBlob = new byte[salt.length + wrapped.length];
            System.arraycopy(salt, 0, userBlob, 0, salt.length);
            System.arraycopy(wrapped, 0, userBlob, salt.length, wrapped.length);
        }

        if (obfuscate && payloadObfuscationEnabled()) {
            payloadBytes = obfuscateBytes(payloadBytes, ephemeralKey, fastObf);
        }

        byte[] ciphertext = Crypto.aesGcmEncrypt(ephemeralKey, payloadBytes, aad);
        byte[] payload = new byte[4 + metadataBytes.length + ciphertext.length];
        writeU32(payload, 0, metadataBytes.length);
        System.arraycopy(metadataBytes, 0, payload, 4, metadataBytes.length);
        System.arraycopy(ciphertext, 0, payload, 4 + metadataBytes.length, ciphertext.length);
        return Format.packLengthPrefixed(Arrays.asList(userBlob, masterBlob, payload));
    }

    private static String decryptAesPayload(byte[] blob, String password, boolean useMaster) {
        byte[] plain = decryptAesPayloadBytes(blob, password, useMaster);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static byte[] decryptAesPayloadBytes(byte[] blob, String password, boolean useMaster) {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        byte[] userBlob = parts.get(0);
        byte[] masterBlob = parts.get(1);
        byte[] payloadBlob = parts.get(2);
        if (payloadBlob.length < 4) {
            throw new IllegalArgumentException("Ciphertext payload truncated");
        }
        int metadataLen = readU32(payloadBlob, 0);
        int metadataEnd = 4 + metadataLen;
        if (metadataEnd > payloadBlob.length) {
            throw new IllegalArgumentException("Malformed payload metadata header");
        }
        byte[] metadataBytes = Arrays.copyOfRange(payloadBlob, 4, metadataEnd);
        String metadataBlob = metadataBytes.length == 0
            ? ""
            : new String(metadataBytes, StandardCharsets.UTF_8);

        String obfHint = metaValue(metadataBlob, "ENC-OBF");
        boolean shouldDeobfuscate = payloadObfuscationEnabled() && !"no".equalsIgnoreCase(obfHint);
        boolean fastObf = "fast".equalsIgnoreCase(obfHint);
        String kdfHint = metaValue(metadataBlob, "ENC-KDF");
        if (kdfHint.isEmpty()) {
            kdfHint = resolveUserKdfLabel();
        }
        int kdfIterHint = parseMetadataInt(metaValue(metadataBlob, "ENC-KDF-ITER"), Constants.USER_KDF_ITERATIONS);

        byte[] ephemeralKey;
        if (masterBlob.length > 0) {
            if (!useMaster) {
                throw new IllegalArgumentException("Master key required to decrypt this payload");
            }
            if (!startsWith(masterBlob, Constants.MASTER_EC_MAGIC)) {
                throw new IllegalArgumentException("Invalid master key blob magic");
            }
            java.security.PrivateKey priv = EcKeys.loadMasterPrivate();
            byte[] shared = EcKeys.kemDecrypt(masterBlob, priv);
            ephemeralKey = Crypto.hkdfSha256(shared, Constants.KEM_INFO, 32);
        } else if (userBlob.length > 0) {
            if (pw.length == 0) {
                throw new IllegalArgumentException("User password required to decrypt this payload");
            }
            if (userBlob.length < Constants.USER_KDF_SALT_SIZE + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Corrupted user key blob: missing salt or AEAD data");
            }
            byte[] salt = Arrays.copyOfRange(userBlob, 0, Constants.USER_KDF_SALT_SIZE);
            byte[] wrapped = Arrays.copyOfRange(userBlob, Constants.USER_KDF_SALT_SIZE, userBlob.length);
            String label = resolveKdfLabel(kdfHint);
            if (!"pbkdf2".equals(label)) {
                throw new IllegalArgumentException("Unsupported KDF label: " + label);
            }
            int iters = hardenPbkdf2Iterations(pw, kdfIterHint);
            byte[] userKey = Crypto.pbkdf2HmacSha256(pw, salt, iters, 32);
            ephemeralKey = Crypto.aesGcmDecrypt(userKey, wrapped, metadataBytes);
        } else {
            throw new IllegalArgumentException("Ciphertext missing key transport data");
        }

        byte[] ciphertext = Arrays.copyOfRange(payloadBlob, metadataEnd, payloadBlob.length);
        byte[] plain = Crypto.aesGcmDecrypt(ephemeralKey, ciphertext, metadataBytes);
        if (shouldDeobfuscate) {
            plain = deobfuscateBytes(plain, ephemeralKey, fastObf);
        }
        return plain;
    }

    private static boolean payloadObfuscationEnabled() {
        String raw = System.getenv("BASEFWX_OBFUSCATE");
        if (raw == null || raw.trim().isEmpty()) {
            return true;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

    private static boolean perfModeEnabled() {
        String raw = System.getenv("BASEFWX_PERF");
        if (raw == null || raw.trim().isEmpty()) {
            return false;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

    private static boolean useFastObfuscation(long length) {
        return perfModeEnabled() && length >= PERF_OBFUSCATION_THRESHOLD;
    }

    private static String resolveUserKdfLabel() {
        String raw = System.getenv("BASEFWX_USER_KDF");
        if (raw == null || raw.trim().isEmpty()) {
            return "pbkdf2";
        }
        return resolveKdfLabel(raw.trim().toLowerCase());
    }

    private static String resolveKdfLabel(String label) {
        if (label == null || label.isEmpty() || "auto".equalsIgnoreCase(label)) {
            return "pbkdf2";
        }
        String normalized = label.toLowerCase();
        if (normalized.startsWith("argon2")) {
            throw new IllegalArgumentException("Argon2 KDF not supported in Java module");
        }
        if (!"pbkdf2".equals(normalized)) {
            throw new IllegalArgumentException("Unsupported KDF label: " + normalized);
        }
        return normalized;
    }

    private static int parseMetadataInt(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

    private static int hardenPbkdf2Iterations(byte[] password, int iterations) {
        if (password == null || password.length == 0) {
            return iterations;
        }
        if (Constants.TEST_KDF_OVERRIDE) {
            return iterations;
        }
        if (password.length < Constants.SHORT_PASSWORD_MIN) {
            return Math.max(iterations, Constants.SHORT_PBKDF2_ITERS);
        }
        return iterations;
    }

    private static byte[] obfuscateBytes(byte[] data, byte[] key) {
        return obfuscateBytes(data, key, useFastObfuscation(data.length));
    }

    private static byte[] obfuscateBytes(byte[] data, byte[] key, boolean fast) {
        if (data.length == 0) {
            return data;
        }
        byte[] out = data.clone();
        xorKeystreamInPlace(out, key, Constants.OBF_INFO_MASK);
        if (!fast) {
            byte[] info = buildInfoWithLength(Constants.OBF_INFO_PERM, data.length);
            byte[] seedBytes = Crypto.hkdfSha256(key, info, 16);
            long seed = seed64FromBytes(seedBytes);
            reverseInPlace(out);
            permuteInPlace(out, seed);
        }
        return out;
    }

    private static byte[] deobfuscateBytes(byte[] data, byte[] key) {
        return deobfuscateBytes(data, key, useFastObfuscation(data.length));
    }

    private static byte[] deobfuscateBytes(byte[] data, byte[] key, boolean fast) {
        if (data.length == 0) {
            return data;
        }
        byte[] out = data.clone();
        if (!fast) {
            byte[] info = buildInfoWithLength(Constants.OBF_INFO_PERM, data.length);
            byte[] seedBytes = Crypto.hkdfSha256(key, info, 16);
            long seed = seed64FromBytes(seedBytes);
            unpermuteInPlace(out, seed);
            reverseInPlace(out);
        }
        xorKeystreamInPlace(out, key, Constants.OBF_INFO_MASK);
        return out;
    }

    private static byte[] buildInfoWithLength(byte[] prefix, int length) {
        byte[] out = new byte[prefix.length + 8];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        long len = length & 0xFFFFFFFFFFFFFFFFL;
        for (int i = 7; i >= 0; i--) {
            out[prefix.length + i] = (byte) (len & 0xFF);
            len >>>= 8;
        }
        return out;
    }

    private static void xorKeystreamInPlace(byte[] buf, byte[] key, byte[] info) {
        if (buf.length == 0) {
            return;
        }
        byte[] blockKey = Crypto.hkdfSha256(key, info, 32);
        byte[] lenBytes = new byte[8];
        long len = buf.length & 0xFFFFFFFFFFFFFFFFL;
        for (int i = 7; i >= 0; i--) {
            lenBytes[i] = (byte) (len & 0xFF);
            len >>>= 8;
        }
        long ctr = 0;
        int offset = 0;
        while (offset < buf.length) {
            byte[] ctrBytes = new byte[8];
            long val = ctr;
            for (int i = 7; i >= 0; i--) {
                ctrBytes[i] = (byte) (val & 0xFF);
                val >>>= 8;
            }
            byte[] data = new byte[info.length + lenBytes.length + ctrBytes.length];
            System.arraycopy(info, 0, data, 0, info.length);
            System.arraycopy(lenBytes, 0, data, info.length, lenBytes.length);
            System.arraycopy(ctrBytes, 0, data, info.length + lenBytes.length, ctrBytes.length);
            byte[] block = Crypto.hmacSha256(blockKey, data);
            int take = Math.min(block.length, buf.length - offset);
            for (int i = 0; i < take; i++) {
                buf[offset + i] = (byte) (buf[offset + i] ^ block[i]);
            }
            offset += take;
            ctr += 1;
        }
    }

    private static long seed64FromBytes(byte[] seedBytes) {
        if (seedBytes.length < 8) {
            return 0L;
        }
        long out = 0L;
        int start = seedBytes.length - 8;
        for (int i = 0; i < 8; i++) {
            out = (out << 8) | (seedBytes[start + i] & 0xFFL);
        }
        return out;
    }

    private static void reverseInPlace(byte[] data) {
        for (int i = 0, j = data.length - 1; i < j; i++, j--) {
            byte tmp = data[i];
            data[i] = data[j];
            data[j] = tmp;
        }
    }

    private static final ThreadLocal<int[]> PERM_SWAP_CACHE = ThreadLocal.withInitial(() -> new int[0]);

    private static void permuteInPlace(byte[] data, long seed) {
        permuteInPlace(data, data.length, seed);
    }

    private static void permuteInPlace(byte[] data, int length, long seed) {
        int n = length;
        if (n < 2) {
            return;
        }
        if (n >= 4096) {
            Pcg64Rng rng = new Pcg64Rng(seed);
            for (int i = n - 1; i > 0; i--) {
                int j = (int) rng.randomInterval(i);
                if (j != i) {
                    byte tmp = data[i];
                    data[i] = data[j];
                    data[j] = tmp;
                }
            }
            return;
        }
        long[] state = new long[]{seed};
        for (int i = n - 1; i > 0; i--) {
            long rnd = splitMix64Next(state);
            int j = (int) Long.remainderUnsigned(rnd, i + 1L);
            if (j != i) {
                byte tmp = data[i];
                data[i] = data[j];
                data[j] = tmp;
            }
        }
    }

    private static void unpermuteInPlace(byte[] data, long seed) {
        unpermuteInPlace(data, data.length, seed);
    }

    private static void unpermuteInPlace(byte[] data, int length, long seed) {
        int n = length;
        if (n < 2) {
            return;
        }
        if (n >= 4096) {
            Pcg64Rng rng = new Pcg64Rng(seed);
            int[] swaps = PERM_SWAP_CACHE.get();
            if (swaps.length < n) {
                swaps = new int[n];
                PERM_SWAP_CACHE.set(swaps);
            }
            for (int i = n - 1; i > 0; i--) {
                swaps[i] = (int) rng.randomInterval(i);
            }
            for (int i = 1; i < n; i++) {
                int j = swaps[i];
                if (j != i) {
                    byte tmp = data[i];
                    data[i] = data[j];
                    data[j] = tmp;
                }
            }
            return;
        }
        int total = n - 1;
        int[] swapI = new int[total];
        int[] swapJ = new int[total];
        long[] state = new long[]{seed};
        int idx = 0;
        for (int i = n - 1; i > 0; i--) {
            long rnd = splitMix64Next(state);
            int j = (int) Long.remainderUnsigned(rnd, i + 1L);
            swapI[idx] = i;
            swapJ[idx] = j;
            idx++;
        }
        for (int k = idx - 1; k >= 0; k--) {
            int i = swapI[k];
            int j = swapJ[k];
            if (j != i) {
                byte tmp = data[i];
                data[i] = data[j];
                data[j] = tmp;
            }
        }
    }

    private static long splitMix64Next(long[] state) {
        long z = state[0] + 0x9E3779B97F4A7C15L;
        state[0] = z;
        long x = z;
        x = (x ^ (x >>> 30)) * 0xBF58476D1CE4E5B9L;
        x = (x ^ (x >>> 27)) * 0x94D049BB133111EBL;
        x ^= (x >>> 31);
        return x;
    }

    private static final class Pcg64Rng {
        private static final long MULT_HI = 2549297995355413924L;
        private static final long MULT_LO = 4865540595714422341L;
        private long stateHi = 0L;
        private long stateLo = 0L;
        private long incHi = 0L;
        private long incLo = 0L;
        private boolean hasUint32 = false;
        private int cachedUint32 = 0;

        Pcg64Rng(long seed) {
            long[] stateVals = seedSequenceState(seed);
            seed(stateVals[0], stateVals[1], stateVals[2], stateVals[3]);
            hasUint32 = false;
            cachedUint32 = 0;
            next64();
        }

        long next64() {
            long oldHi = stateHi;
            long oldLo = stateLo;
            step();
            long xorshifted = oldHi ^ oldLo;
            long rot = oldHi >>> 58;
            return Long.rotateRight(xorshifted, (int) rot);
        }

        int next32() {
            if (hasUint32) {
                hasUint32 = false;
                return cachedUint32;
            }
            long next = next64();
            hasUint32 = true;
            cachedUint32 = (int) (next >>> 32);
            return (int) next;
        }

        long randomInterval(long max) {
            if (max == 0) {
                return 0;
            }
            long mask = max;
            mask |= mask >>> 1;
            mask |= mask >>> 2;
            mask |= mask >>> 4;
            mask |= mask >>> 8;
            mask |= mask >>> 16;
            mask |= mask >>> 32;
            if (Long.compareUnsigned(max, 0xFFFFFFFFL) <= 0) {
                long value;
                do {
                    value = (next32() & 0xFFFFFFFFL) & mask;
                } while (Long.compareUnsigned(value, max) > 0);
                return value;
            }
            long value;
            do {
                value = next64() & mask;
            } while (Long.compareUnsigned(value, max) > 0);
            return value;
        }

        private void seed(long seedHigh, long seedLow, long incHigh, long incLow) {
            stateHi = 0L;
            stateLo = 0L;
            long initSeqHi = incHigh;
            long initSeqLo = incLow;
            incHi = (initSeqHi << 1) | (initSeqLo >>> 63);
            incLo = (initSeqLo << 1) | 1L;
            step();
            addState(seedHigh, seedLow);
            step();
        }

        private void step() {
            long prodLo = stateLo * MULT_LO;
            long prodHi = mulHighUnsigned(stateLo, MULT_LO);
            prodHi += stateLo * MULT_HI;
            prodHi += stateHi * MULT_LO;
            long lo = prodLo + incLo;
            long carry = Long.compareUnsigned(lo, prodLo) < 0 ? 1L : 0L;
            long hi = prodHi + incHi + carry;
            stateHi = hi;
            stateLo = lo;
        }

        private void addState(long addHi, long addLo) {
            long lo = stateLo + addLo;
            long carry = Long.compareUnsigned(lo, stateLo) < 0 ? 1L : 0L;
            stateLo = lo;
            stateHi = stateHi + addHi + carry;
        }

        private long mulHighUnsigned(long x, long y) {
            long x0 = x & 0xFFFFFFFFL;
            long x1 = x >>> 32;
            long y0 = y & 0xFFFFFFFFL;
            long y1 = y >>> 32;

            long z0 = x0 * y0;
            long t = x1 * y0 + (z0 >>> 32);
            long z1 = t & 0xFFFFFFFFL;
            long z2 = t >>> 32;
            t = x0 * y1 + z1;
            long high = x1 * y1 + z2 + (t >>> 32);
            return high;
        }

        private long[] seedSequenceState(long entropy) {
            int[] pool = seedPool(entropy);
            int[] state32 = new int[8];
            int hashConst = 0x8b51f9dd;
            for (int i = 0; i < state32.length; i++) {
                int dataVal = pool[i % pool.length];
                dataVal ^= hashConst;
                hashConst = (int) ((hashConst * 0x58f38dedL) & 0xFFFFFFFFL);
                dataVal = (int) ((dataVal * (long) hashConst) & 0xFFFFFFFFL);
                dataVal ^= (dataVal >>> 16);
                state32[i] = dataVal;
            }
            long[] state64 = new long[4];
            for (int i = 0; i < state64.length; i++) {
                long lo = state32[i * 2] & 0xFFFFFFFFL;
                long hi = state32[i * 2 + 1] & 0xFFFFFFFFL;
                state64[i] = lo | (hi << 32);
            }
            return state64;
        }

        private int[] seedPool(long entropy) {
            int[] pool = new int[4];
            int[] entropyArray = intToUint32Array(entropy);
            int[] hashConst = new int[]{0x43b0d7e5};
            for (int i = 0; i < pool.length; i++) {
                int value = i < entropyArray.length ? entropyArray[i] : 0;
                pool[i] = hashMix(value, hashConst);
            }
            for (int iSrc = 0; iSrc < pool.length; iSrc++) {
                for (int iDst = 0; iDst < pool.length; iDst++) {
                    if (iSrc == iDst) {
                        continue;
                    }
                    pool[iDst] = mix32(pool[iDst], hashMix(pool[iSrc], hashConst));
                }
            }
            for (int iSrc = pool.length; iSrc < entropyArray.length; iSrc++) {
                for (int iDst = 0; iDst < pool.length; iDst++) {
                    pool[iDst] = mix32(pool[iDst], hashMix(entropyArray[iSrc], hashConst));
                }
            }
            return pool;
        }

        private int[] intToUint32Array(long n) {
            if (n == 0) {
                return new int[]{0};
            }
            int[] tmp = new int[2];
            int count = 0;
            long value = n;
            while (value != 0) {
                tmp[count++] = (int) (value & 0xFFFFFFFFL);
                value >>>= 32;
            }
            int[] out = new int[count];
            System.arraycopy(tmp, 0, out, 0, count);
            return out;
        }

        private int hashMix(int value, int[] hashConst) {
            int v = value ^ hashConst[0];
            hashConst[0] = (int) ((hashConst[0] * 0x931e8875L) & 0xFFFFFFFFL);
            v = (int) ((v * (long) hashConst[0]) & 0xFFFFFFFFL);
            v ^= (v >>> 16);
            return v;
        }

        private int mix32(int x, int y) {
            long result = (0xca01f9ddL * (x & 0xFFFFFFFFL)) - (0x4973f715L * (y & 0xFFFFFFFFL));
            result &= 0xFFFFFFFFL;
            result ^= (result >>> 16);
            return (int) result;
        }
    }

    private static final class StreamObfuscator {
        private final Cipher ctrCipher;
        private final Mac permMac;
        private final byte[] permInfo;
        private final boolean fast;
        private long chunkIndex = 0L;

        private StreamObfuscator(Mac permMac, Cipher ctrCipher, boolean fast) {
            this.permMac = permMac;
            this.permInfo = new byte[Constants.STREAM_INFO_PERM.length + 8];
            System.arraycopy(Constants.STREAM_INFO_PERM, 0, permInfo, 0, Constants.STREAM_INFO_PERM.length);
            this.ctrCipher = ctrCipher;
            this.fast = fast;
        }

        static byte[] generateSalt() {
            return Crypto.randomBytes(Constants.STREAM_SALT_LEN);
        }

        static StreamObfuscator forPassword(byte[] password, byte[] salt, boolean fast) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password required for streaming obfuscation");
            }
            if (salt == null || salt.length < Constants.STREAM_SALT_LEN) {
                throw new IllegalArgumentException("Streaming obfuscation salt must be at least 16 bytes");
            }
            byte[] base = new byte[password.length + salt.length];
            System.arraycopy(password, 0, base, 0, password.length);
            System.arraycopy(salt, 0, base, password.length, salt.length);
            byte[] maskKey = Crypto.hkdfSha256(base, Constants.STREAM_INFO_KEY, 32);
            // lgtm[java/static-initialization-vector] - IV derived from HKDF with password+random salt, unique per stream
            byte[] iv = Crypto.hkdfSha256(base, Constants.STREAM_INFO_IV, 16);
            byte[] permMaterial = Crypto.hkdfSha256(base, Constants.STREAM_INFO_PERM, 32);
            byte[] permPrk = Crypto.hkdfPrkSha256(permMaterial);
            Mac permMac = Crypto.initHmac(permPrk);
            try {
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                // IV is derived from HKDF at line 2181 using password+salt, unique per stream
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(maskKey, "AES"), new IvParameterSpec(iv));
                return new StreamObfuscator(permMac, cipher, fast);
            } catch (GeneralSecurityException exc) {
                throw new IllegalStateException("AES-CTR init failed", exc);
            }
        }

        void encodeChunkInPlace(byte[] buffer) {
            encodeChunkInPlace(buffer, buffer.length);
        }

        void encodeChunkInPlace(byte[] buffer, int length) {
            if (length <= 0) {
                return;
            }
            if (fast) {
                applyCtrInPlace(buffer, length);
                chunkIndex += 1;
                return;
            }
            ChunkParams params = nextParams();
            applyCtrInPlace(buffer, length);
            if (params.swap) {
                swapNibbles(buffer, length);
            }
            if (params.rotation != 0) {
                rotateLeft(buffer, length, params.rotation);
            }
            permuteInPlace(buffer, length, params.seed);
        }

        void decodeChunkInPlace(byte[] buffer) {
            decodeChunkInPlace(buffer, buffer.length);
        }

        void decodeChunkInPlace(byte[] buffer, int length) {
            if (length <= 0) {
                return;
            }
            if (fast) {
                applyCtrInPlace(buffer, length);
                chunkIndex += 1;
                return;
            }
            ChunkParams params = nextParams();
            unpermuteInPlace(buffer, length, params.seed);
            if (params.rotation != 0) {
                rotateRight(buffer, length, params.rotation);
            }
            if (params.swap) {
                swapNibbles(buffer, length);
            }
            applyCtrInPlace(buffer, length);
        }

        private void applyCtrInPlace(byte[] buffer, int length) {
            if (length <= 0) {
                return;
            }
            try {
                int outLen = ctrCipher.update(buffer, 0, length, buffer, 0);
                if (outLen != length) {
                    throw new IllegalStateException("AES-CTR output length mismatch");
                }
            } catch (GeneralSecurityException exc) {
                throw new IllegalStateException("AES-CTR update failed", exc);
            }
        }

        private ChunkParams nextParams() {
            byte[] info = permInfo;
            long idx = chunkIndex;
            for (int i = 7; i >= 0; i--) {
                info[Constants.STREAM_INFO_PERM.length + i] = (byte) (idx & 0xFF);
                idx >>>= 8;
            }
            permMac.update(info);
            permMac.update((byte) 1);
            byte[] seedBytes = permMac.doFinal();
            ChunkParams params = new ChunkParams();
            params.seed = seed64FromBytes(seedBytes);
            params.rotation = seedBytes[0] & 0x07;
            params.swap = (seedBytes[1] & 0x01) != 0;
            chunkIndex += 1;
            return params;
        }

        private static void swapNibbles(byte[] buffer) {
            swapNibbles(buffer, buffer.length);
        }

        private static void swapNibbles(byte[] buffer, int length) {
            for (int i = 0; i < length; i++) {
                int b = buffer[i] & 0xFF;
                buffer[i] = (byte) ((b >>> 4) | ((b & 0x0F) << 4));
            }
        }

        private static void rotateLeft(byte[] buffer, int rotation) {
            rotateLeft(buffer, buffer.length, rotation);
        }

        private static void rotateLeft(byte[] buffer, int length, int rotation) {
            if (rotation == 0 || length == 0) {
                return;
            }
            for (int i = 0; i < length; i++) {
                int b = buffer[i] & 0xFF;
                buffer[i] = (byte) ((b << rotation) | (b >>> (8 - rotation)));
            }
        }

        private static void rotateRight(byte[] buffer, int rotation) {
            rotateRight(buffer, buffer.length, rotation);
        }

        private static void rotateRight(byte[] buffer, int length, int rotation) {
            if (rotation == 0 || length == 0) {
                return;
            }
            for (int i = 0; i < length; i++) {
                int b = buffer[i] & 0xFF;
                buffer[i] = (byte) ((b >>> rotation) | (b << (8 - rotation)));
            }
        }

        private static final class ChunkParams {
            long seed;
            int rotation;
            boolean swap;
        }
    }

    private static byte[] encodeMaskedPayloadBytes(KeyWrap.MaskKeyResult mask,
                                                   byte[] plain,
                                                   byte[] streamInfo) {
        byte[] masked = KeyWrap.maskPayload(mask.maskKey, plain, streamInfo);
        byte[] payload = new byte[1 + 4 + masked.length];
        payload[0] = 0x02;
        writeU32(payload, 1, plain.length);
        System.arraycopy(masked, 0, payload, 5, masked.length);
        return Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob, payload));
    }

    private static byte[] decodeMaskedPayloadBytesFromString(String input,
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
            int expectedLen = readU32(payload, 1);
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
                    int expectedLen = readU32(payload, 1);
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

    private static byte[] decodeMaskedPayloadBytes(byte[] blob,
                                                   byte[] password,
                                                   boolean useMaster,
                                                   byte[] maskInfo,
                                                   byte[] aad,
                                                   byte[] streamInfo) {
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        return decodeMaskedPayloadBytesFromParts(parts, password, useMaster, maskInfo, aad, streamInfo);
    }

    private static byte[] decodeMaskedPayloadBytesFromParts(List<byte[]> parts,
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
        int expectedLen = readU32(payload, 1);
        if (expectedLen != payload.length - 5) {
            throw new IllegalArgumentException("Payload length mismatch");
        }
        return KeyWrap.maskPayload(maskKey, payload, 5, expectedLen, streamInfo);
    }

    private static String encodePayloadString(byte[] blob) {
        String encoded = Base64Codec.encode(blob);
        return maybeObfuscateCodecs(encoded);
    }

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    private static final byte[] HEX_BYTES = buildHexBytes();
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST = threadLocalDigest("SHA-256");
    private static final ThreadLocal<MessageDigest> SHA1_DIGEST = threadLocalDigest("SHA-1");
    private static final ThreadLocal<MessageDigest> SHA512_DIGEST = threadLocalDigest("SHA-512");

    private static byte[] buildHexBytes() {
        byte[] out = new byte[512];
        for (int i = 0; i < 256; i++) {
            out[i * 2] = (byte) HEX_CHARS[i >>> 4];
            out[i * 2 + 1] = (byte) HEX_CHARS[i & 0x0F];
        }
        return out;
    }

    private static ThreadLocal<MessageDigest> threadLocalDigest(String algorithm) {
        return ThreadLocal.withInitial(() -> newDigest(algorithm));
    }

    private static MessageDigest newDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalStateException("Digest unavailable: " + algorithm, exc);
        }
    }

    private static MessageDigest digestFor(String algorithm) {
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

    private static byte[] digestBytes(MessageDigest md, byte[] input) {
        md.reset();
        md.update(input);
        return md.digest();
    }

    private static void hexToBytes(byte[] input, byte[] out) {
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

    private static String hexToString(byte[] input) {
        char[] out = new char[input.length * 2];
        for (int i = 0; i < input.length; i++) {
            int v = input[i] & 0xFF;
            out[i * 2] = HEX_CHARS[v >>> 4];
            out[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(out);
    }

    private static String digestHex(MessageDigest md, byte[] input) {
        return hexToString(digestBytes(md, input));
    }

    private static String digestHex(String algorithm, String input) {
        MessageDigest md = digestFor(algorithm);
        if (md == null) {
            md = newDigest(algorithm);
        }
        return digestHex(md, input.getBytes(StandardCharsets.UTF_8));
    }

    private static String mdCode(String input) {
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

    private static String stripLeadingZeros(String input) {
        int idx = 0;
        while (idx < input.length() && input.charAt(idx) == '0') {
            idx++;
        }
        if (idx == input.length()) {
            return "0";
        }
        return input.substring(idx);
    }

    private static int compareMagnitude(String a, String b) {
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

    private static String addMagnitude(String a, String b) {
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

    private static String subtractMagnitude(String a, String b) {
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

    private static String addSigned(String a, String b) {
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

    private static String mcode(String input) {
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

    private static void ensureAscii(String input) {
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) > 0x7F) {
                throw new IllegalArgumentException("Non-ASCII input");
            }
        }
    }

    private static int fwxaesIterations(byte[] pw) {
        int iters = Constants.FWXAES_PBKDF2_ITERS;
        if (Constants.TEST_KDF_OVERRIDE) {
            return iters;
        }
        if (pw.length > 0 && pw.length < Constants.SHORT_PASSWORD_MIN) {
            iters = Math.max(iters, Constants.SHORT_PBKDF2_ITERS);
        }
        return iters;
    }

    private static long fwxAesEncryptStreamInternal(InputStream input,
                                                    OutputStream output,
                                                    String password,
                                                    boolean useMaster) throws IOException {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        boolean hasPassword = pw.length > 0;
        boolean useWrap = false;
        byte[] keyHeader = new byte[0];
        byte[] maskKey = new byte[0];

        if (useMaster) {
            KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                pw,
                true,
                Constants.FWXAES_MASK_INFO,
                false,
                Constants.FWXAES_AAD,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            useWrap = mask.usedMaster || !hasPassword;
            if (useWrap) {
                keyHeader = Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob));
                maskKey = mask.maskKey;
            }
        }

        byte[] iv = Crypto.randomBytes(Constants.FWXAES_IV_LEN);
        byte[] header = new byte[16];
        System.arraycopy(Constants.FWXAES_MAGIC, 0, header, 0, Constants.FWXAES_MAGIC.length);
        header[4] = (byte) Constants.FWXAES_ALGO;
        byte[] key;
        if (useWrap) {
            key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
            header[5] = (byte) Constants.FWXAES_KDF_WRAP;
            header[6] = 0;
            header[7] = (byte) Constants.FWXAES_IV_LEN;
            writeU32(header, 8, keyHeader.length);
            writeU32(header, 12, 0);
            output.write(header);
            output.write(keyHeader);
            output.write(iv);
        } else {
            byte[] salt = Crypto.randomBytes(Constants.FWXAES_SALT_LEN);
            int iters = fwxaesIterations(pw);
            key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
            header[5] = (byte) Constants.FWXAES_KDF_PBKDF2;
            header[6] = (byte) Constants.FWXAES_SALT_LEN;
            header[7] = (byte) Constants.FWXAES_IV_LEN;
            writeU32(header, 8, iters);
            writeU32(header, 12, 0);
            output.write(header);
            output.write(salt);
            output.write(iv);
        }

        try {
            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadEncryptor enc = backend.newGcmEncryptor(key, iv, Constants.FWXAES_AAD)) {
                byte[] buf = new byte[STREAM_CHUNK];
                byte[] outBuf = new byte[STREAM_CHUNK + Constants.AEAD_TAG_LEN];
                long ctLen = 0;
                int read;
                while ((read = input.read(buf)) != -1) {
                    int outLen = enc.update(buf, 0, read, outBuf, 0);
                    if (outLen > 0) {
                        output.write(outBuf, 0, outLen);
                        ctLen += outLen;
                    }
                }
                int finalLen = enc.doFinal(outBuf, 0);
                if (finalLen > 0) {
                    output.write(outBuf, 0, finalLen);
                    ctLen += finalLen;
                }
                output.flush();
                return ctLen;
            }
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("fwxAES encrypt failed", exc);
        }
    }

    private static long fwxAesEncryptChannel(FileChannel input,
                                             FileChannel output,
                                             String password,
                                             boolean useMaster) throws IOException {
        byte[] pw = resolvePasswordBytes(password, useMaster);
        boolean hasPassword = pw.length > 0;
        boolean useWrap = false;
        byte[] keyHeader = new byte[0];
        byte[] maskKey = new byte[0];

        if (useMaster) {
            KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                pw,
                true,
                Constants.FWXAES_MASK_INFO,
                false,
                Constants.FWXAES_AAD,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            useWrap = mask.usedMaster || !hasPassword;
            if (useWrap) {
                keyHeader = Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob));
                maskKey = mask.maskKey;
            }
        }

        byte[] iv = Crypto.randomBytes(Constants.FWXAES_IV_LEN);
        byte[] header = new byte[16];
        System.arraycopy(Constants.FWXAES_MAGIC, 0, header, 0, Constants.FWXAES_MAGIC.length);
        header[4] = (byte) Constants.FWXAES_ALGO;
        byte[] key;
        if (useWrap) {
            key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
            header[5] = (byte) Constants.FWXAES_KDF_WRAP;
            header[6] = 0;
            header[7] = (byte) Constants.FWXAES_IV_LEN;
            writeU32(header, 8, keyHeader.length);
            writeU32(header, 12, 0);
            writeFully(output, ByteBuffer.wrap(header));
            if (keyHeader.length > 0) {
                writeFully(output, ByteBuffer.wrap(keyHeader));
            }
            writeFully(output, ByteBuffer.wrap(iv));
        } else {
            byte[] salt = Crypto.randomBytes(Constants.FWXAES_SALT_LEN);
            int iters = fwxaesIterations(pw);
            key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
            header[5] = (byte) Constants.FWXAES_KDF_PBKDF2;
            header[6] = (byte) Constants.FWXAES_SALT_LEN;
            header[7] = (byte) Constants.FWXAES_IV_LEN;
            writeU32(header, 8, iters);
            writeU32(header, 12, 0);
            writeFully(output, ByteBuffer.wrap(header));
            writeFully(output, ByteBuffer.wrap(salt));
            writeFully(output, ByteBuffer.wrap(iv));
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            // IV is randomly generated at line 2768 using Crypto.randomBytes()
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            cipher.updateAAD(Constants.FWXAES_AAD);

            ByteBuffer inBuf = ByteBuffer.allocateDirect(STREAM_CHUNK);
            ByteBuffer outBuf = ByteBuffer.allocateDirect(STREAM_CHUNK + Constants.AEAD_TAG_LEN);
            long ctLen = 0;
            while (true) {
                int read = input.read(inBuf);
                if (read < 0) {
                    break;
                }
                inBuf.flip();
                outBuf.clear();
                int outLen = cipher.update(inBuf, outBuf);
                if (outLen > 0) {
                    outBuf.flip();
                    writeFully(output, outBuf);
                    ctLen += outLen;
                }
                inBuf.clear();
            }
            outBuf.clear();
            int finalLen = cipher.doFinal(ByteBuffer.allocate(0), outBuf);
            if (finalLen > 0) {
                outBuf.flip();
                writeFully(output, outBuf);
                ctLen += finalLen;
            }
            return ctLen;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("fwxAES encrypt failed", exc);
        }
    }

    private static void fwxAesDecryptChannel(FileChannel input,
                                             FileChannel output,
                                             String password,
                                             boolean useMaster) throws IOException {
        byte[] header = new byte[16];
        readExactChannel(input, ByteBuffer.wrap(header), header.length, "fwxAES blob too short");
        for (int i = 0; i < Constants.FWXAES_MAGIC.length; i++) {
            if (header[i] != Constants.FWXAES_MAGIC[i]) {
                throw new IllegalArgumentException("fwxAES bad magic");
            }
        }
        int algo = header[4] & 0xFF;
        int kdf = header[5] & 0xFF;
        int saltLen = header[6] & 0xFF;
        int ivLen = header[7] & 0xFF;
        if (algo != Constants.FWXAES_ALGO
            || (kdf != Constants.FWXAES_KDF_PBKDF2 && kdf != Constants.FWXAES_KDF_WRAP)) {
            throw new IllegalArgumentException("fwxAES unsupported algo/kdf");
        }
        int iters = readU32(header, 8);
        int ctLen = readU32(header, 12);
        if (ctLen < Constants.AEAD_TAG_LEN) {
            throw new IllegalArgumentException("fwxAES ciphertext too short");
        }
        byte[] key;
        byte[] iv;
        byte[] pw = resolvePasswordBytes(password, useMaster);
        if (kdf == Constants.FWXAES_KDF_WRAP) {
            int headerLen = iters;
            byte[] keyHeader = new byte[headerLen];
            if (headerLen > 0) {
                readExactChannel(input, ByteBuffer.wrap(keyHeader), headerLen, "fwxAES blob truncated");
            }
            iv = new byte[ivLen];
            readExactChannel(input, ByteBuffer.wrap(iv), ivLen, "fwxAES blob truncated");
            List<byte[]> parts = Format.unpackLengthPrefixed(keyHeader, 2);
            byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                pw,
                useMaster,
                Constants.FWXAES_MASK_INFO,
                Constants.FWXAES_AAD,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
        } else {
            byte[] salt = new byte[saltLen];
            readExactChannel(input, ByteBuffer.wrap(salt), saltLen, "fwxAES blob truncated");
            iv = new byte[ivLen];
            readExactChannel(input, ByteBuffer.wrap(iv), ivLen, "fwxAES blob truncated");
            if (pw.length == 0) {
                throw new IllegalArgumentException("fwxAES password required for PBKDF2 payload");
            }
            key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            // lgtm[java/static-initialization-vector] - IV is read from ciphertext stream (lines 2870, 2887), not static
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            cipher.updateAAD(Constants.FWXAES_AAD);

            long remaining = (long) ctLen - Constants.AEAD_TAG_LEN;
            ByteBuffer inBuf = ByteBuffer.allocateDirect(STREAM_CHUNK);
            ByteBuffer outBuf = ByteBuffer.allocateDirect(STREAM_CHUNK);
            while (remaining > 0) {
                int toRead = (int) Math.min(inBuf.capacity(), remaining);
                readExactChannel(input, inBuf, toRead, "fwxAES blob truncated");
                outBuf.clear();
                int outLen = cipher.update(inBuf, outBuf);
                if (outLen > 0) {
                    outBuf.flip();
                    writeFully(output, outBuf);
                }
                remaining -= toRead;
            }
            ByteBuffer tagBuf = ByteBuffer.allocate(Constants.AEAD_TAG_LEN);
            readExactChannel(input, tagBuf, Constants.AEAD_TAG_LEN, "fwxAES blob truncated");
            outBuf.clear();
            try {
                int finalLen = cipher.doFinal(tagBuf, outBuf);
                if (finalLen > 0) {
                    outBuf.flip();
                    writeFully(output, outBuf);
                }
            } catch (AEADBadTagException exc) {
                throw new IllegalArgumentException("AES-GCM auth failed");
            }
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("fwxAES decrypt failed", exc);
        }
    }

    private static void patchCtLen(FileOutputStream output, long ctLen) throws IOException {
        if (ctLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("fwxAES ciphertext too large");
        }
        FileChannel channel = output.getChannel();
        long pos = channel.position();
        ByteBuffer buf = ByteBuffer.allocate(4);
        buf.putInt((int) ctLen);
        buf.flip();
        channel.position(12);
        channel.write(buf);
        channel.position(pos);
    }

    private static void patchCtLen(FileChannel channel, long ctLen) throws IOException {
        if (ctLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("fwxAES ciphertext too large");
        }
        long pos = channel.position();
        ByteBuffer buf = ByteBuffer.allocate(4);
        buf.putInt((int) ctLen);
        buf.flip();
        channel.position(12);
        writeFully(channel, buf);
        channel.position(pos);
    }

    private static void readExact(InputStream input, byte[] buffer, int length, String error) throws IOException {
        int offset = 0;
        while (offset < length) {
            int read = input.read(buffer, offset, length - offset);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                int single = input.read();
                if (single < 0) {
                    break;
                }
                buffer[offset++] = (byte) single;
                continue;
            }
            offset += read;
        }
        if (offset != length) {
            throw new IllegalArgumentException(error);
        }
    }

    private static void readExactChannel(FileChannel channel, ByteBuffer buffer, int length, String error) throws IOException {
        buffer.clear();
        buffer.limit(length);
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer);
            if (read < 0) {
                throw new IllegalArgumentException(error);
            }
        }
        buffer.flip();
    }

    private static void writeFully(FileChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

    private static byte[] readExactBytes(InputStream input, int length, String error) throws IOException {
        if (length <= 0) {
            return new byte[0];
        }
        byte[] buf = new byte[length];
        readExact(input, buf, length, error);
        return buf;
    }

    private static void skipFully(InputStream input, int length, String error) throws IOException {
        if (length <= 0) {
            return;
        }
        byte[] buf = new byte[Math.min(8192, length)];
        int remaining = length;
        while (remaining > 0) {
            int take = Math.min(buf.length, remaining);
            int read = input.read(buf, 0, take);
            if (read < 0) {
                throw new IllegalArgumentException(error);
            }
            if (read == 0) {
                int single = input.read();
                if (single < 0) {
                    throw new IllegalArgumentException(error);
                }
                remaining -= 1;
                continue;
            }
            remaining -= read;
        }
    }

    private static int readU32(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 4, error);
        return readU32(buf, 0);
    }

    private static int readU16(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 2, error);
        return ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);
    }

    private static long readU64(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 8, error);
        long out = 0L;
        for (int i = 0; i < buf.length; i++) {
            out = (out << 8) | (buf[i] & 0xFFL);
        }
        return out;
    }

    private static void copyStream(InputStream input, OutputStream output) throws IOException {
        byte[] buf = new byte[STREAM_CHUNK];
        int read;
        while ((read = input.read(buf)) != -1) {
            output.write(buf, 0, read);
        }
        output.flush();
    }

    private static void writeU32(byte[] target, int offset, int value) {
        target[offset] = (byte) ((value >> 24) & 0xFF);
        target[offset + 1] = (byte) ((value >> 16) & 0xFF);
        target[offset + 2] = (byte) ((value >> 8) & 0xFF);
        target[offset + 3] = (byte) (value & 0xFF);
    }

    private static void writeU32(OutputStream output, int value) throws IOException {
        output.write((value >> 24) & 0xFF);
        output.write((value >> 16) & 0xFF);
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static void writeU16(OutputStream output, int value) throws IOException {
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static void writeU64(OutputStream output, long value) throws IOException {
        long v = value;
        for (int i = 7; i >= 0; i--) {
            output.write((int) ((v >> (i * 8)) & 0xFF));
        }
    }

    private static int readU32(byte[] source, int offset) {
        return ((source[offset] & 0xFF) << 24)
            | ((source[offset + 1] & 0xFF) << 16)
            | ((source[offset + 2] & 0xFF) << 8)
            | (source[offset + 3] & 0xFF);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean obfuscateCodecsEnabled() {
        String raw = System.getenv("BASEFWX_OBFUSCATE_CODECS");
        if (raw == null || raw.trim().isEmpty()) {
            return true;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

    private static String maybeObfuscateCodecs(String input) {
        if (!obfuscateCodecsEnabled()) {
            return input;
        }
        return Codec.code(input);
    }

    private static String maybeDeobfuscateCodecs(String input) {
        try {
            Base64Codec.decode(input);
            return input;
        } catch (IllegalArgumentException exc) {
            return Codec.decode(input);
        }
    }

    private static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String aead,
                                        String kdfLabel) {
        return buildMetadata(method, strip, useMaster, aead, kdfLabel,
            null, null, null, null, null, null, null, null);
    }

    private static String buildMetadata(String method,
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

    private static String encodeJson(Map<String, String> map) {
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

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String[] splitMetadata(String payload) {
        int idx = payload.indexOf(Constants.META_DELIM);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx),
                payload.substring(idx + Constants.META_DELIM.length())};
        }
        return new String[]{"", payload};
    }

    private static String metaValue(String metadataBlob, String key) {
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

    private static String jsonValue(String json, String key) {
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

    private static int skipJsonWhitespace(String json, int idx) {
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

    private static int parseJsonString(String json, int start, StringBuilder out) {
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

    private static String[] splitWithDelims(String payload, String delim, String legacy, String label) {
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

    private static String getExtension(File file) {
        String name = file.getName();
        int idx = name.lastIndexOf('.');
        if (idx < 0) {
            return "";
        }
        return name.substring(idx);
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

    private static boolean samePath(File a, File b) {
        try {
            return a.getCanonicalFile().equals(b.getCanonicalFile());
        } catch (IOException ignored) {
            return a.getAbsoluteFile().equals(b.getAbsoluteFile());
        }
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

    private static File kfmResolveOutput(File input, File output, String extension, String tag) {
        if (output != null) {
            if (samePath(input, output)) {
                throw new IllegalArgumentException("Refusing to overwrite input file; choose a different output path");
            }
            return output;
        }
        File candidate = replaceExtension(input, extension);
        if (samePath(input, candidate)) {
            candidate = replaceExtensionWithTag(input, extension, tag);
        }
        return candidate;
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
        System.err.println("WARN: " + message);
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
                    carrier = kfmPngToCarrier(readFileBytes(input));
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

    private static long bytesToLong(byte[] input, int offset) {
        long out = 0L;
        for (int i = 0; i < 8; i++) {
            out = (out << 8) | (input[offset + i] & 0xFFL);
        }
        return out;
    }

    private static void writeU64(byte[] target, int offset, long value) {
        long v = value;
        for (int i = 7; i >= 0; i--) {
            target[offset + i] = (byte) (v & 0xFFL);
            v >>>= 8;
        }
    }

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

    private static byte[] kfmKeystream(long seed, int length) {
        byte[] out = new byte[length];
        if (length <= 0) {
            return out;
        }
        byte[] state = new byte[16];
        writeU64(state, 0, seed);
        int offset = 0;
        long counter = 0L;
        while (offset < length) {
            writeU64(state, 8, counter);
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
        writeU64(out, 8, payload.length);
        writeU32(out, 16, (int) (crc32.getValue() & 0xFFFFFFFFL));
        writeU64(out, 20, seed);
        writeU32(out, 28, 0);
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
        int crcExpected = readU32(blob, 16);
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

    private static byte[] kfmCarrierToWav(byte[] carrier) {
        byte[] raw = carrier;
        if ((raw.length & 1) != 0) {
            raw = Arrays.copyOf(raw, raw.length + 1);
        }
        byte[] pcm = new byte[raw.length];
        for (int i = 0; i < raw.length; i += 2) {
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
        for (int i = 0; i < normalized.length; i += 2) {
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
            tempRaw = File.createTempFile("basefwx_kfm_", ".raw");
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
            byte[] pcm = readFileBytes(tempRaw);
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
        byte[] raw = readFileBytes(input);
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
            WritableRaster imageRaster = image.getRaster();
            int idx = 0;
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    int v = raster[idx++] & 0xFF;
                    imageRaster.setSample(x, y, 0, v);
                }
            }
        } else {
            image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
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
                byte[] out = new byte[width * height];
                int idx = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        out[idx++] = (byte) image.getRaster().getSample(x, y, 0);
                    }
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

    public static byte[] resolvePasswordBytes(String password, boolean useMaster) {
        if (password == null) {
            if (!useMaster) {
                throw new IllegalArgumentException("Password required when master key usage is disabled");
            }
            return new byte[0];
        }
        if (password.isEmpty()) {
            if (!useMaster) {
                throw new IllegalArgumentException("Password required when master key usage is disabled");
            }
            return new byte[0];
        }
        File candidate = expandUser(password);
        if (candidate.isFile()) {
            return readFileBytes(candidate);
        }
        return password.getBytes(StandardCharsets.UTF_8);
    }

    private static File expandUser(String path) {
        if (path.startsWith("~/") || path.startsWith("~\\")) {
            String home = System.getProperty("user.home");
            if (home != null && !home.isEmpty()) {
                return new File(home, path.substring(2));
            }
        }
        return new File(path);
    }

    private static byte[] readFileBytes(File file) {
        try (FileInputStream in = new FileInputStream(file);
             ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(file.length(), Integer.MAX_VALUE))) {
            byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read file bytes", exc);
        }
    }

    private static void writeFileBytes(File file, byte[] data) {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to write file bytes", exc);
        }
    }
}
