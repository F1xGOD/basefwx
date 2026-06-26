/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

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
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
// 3.7.x: java.awt.image.* and javax.imageio.ImageIO imports were
// removed from this file when kFMe/kFMd/kFAe/kFAd and the jmg*
// entry points moved to BaseFwxImage.java. The carve-out was needed
// so this file (the cross-language-syncable core) can be pulled into
// the Android Gradle build without Android's missing-java.awt
// breaking the sync. See BaseFwxImage.java for the carrier API.
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

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
            if (RuntimeLog.shouldLog()) {
                System.err.println(orange + "WARN: MULTI-THREAD DISABLED; PERFORMANCE MAY DETERIORATE. "
                    + "Using BASEFWX_FORCE_SINGLE_THREAD=1 with " + available + " cores available." + reset);
            }
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

    public static final class An7Result {
        public final File outputPath;
        public final String restoredName;
        public final long bytesWritten;

        public An7Result(File outputPath, String restoredName, long bytesWritten) {
            this.outputPath = outputPath;
            this.restoredName = restoredName;
            this.bytesWritten = bytesWritten;
        }
    }

    static final int AN7_CHUNK_SIZE = 1 << 20;
    static final int AN7_SUPERBLOCK_CHUNKS = 10;
    static final int AN7_FLIP_STRIDE = 10;
    static final int AN7_FOOTER_SIZE = 64;
    static final int AN7_TAIL_PLAIN_LEN = 20;
    static final int AN7_TAIL_NONCE_LEN = 12;
    static final int AN7_TAIL_CIPHER_LEN = 20;
    static final int AN7_TAIL_TAG_LEN = 16;
    static final int AN7_SALT_LEN = 16;
    static final int AN7_TRAILER_NONCE_LEN = 12;
    static final int AN7_SHA256_LEN = 32;
    static final int AN7_ARGON2_TIME_COST = 5;
    static final int AN7_ARGON2_MEMORY_KIB = 131072;
    static final int AN7_ARGON2_PARALLELISM = 4;
    static final long AN7_TEN_DIGITS_MOD = 10_000_000_000L;
    static final byte[] AN7_TRAILER_VERSION = "AN7v1".getBytes(StandardCharsets.US_ASCII);
    // KFM_* constants moved to BaseFwxImage.java together with the
    // kFMe / kFMd / kFAe / kFAd / jmg* public API. See class header
    // in BaseFwxImage.java for the rationale (java.awt-free core).

    public static byte[] fwxAesEncryptRaw(byte[] plaintext, String password, boolean useMaster) {
        return FwxAesCodec.fwxAesEncryptRaw(plaintext, password, useMaster);
    }

    public static byte[] fwxAesEncryptRawBytes(byte[] plaintext, byte[] passwordBytes, boolean useMaster) {
        return FwxAesCodec.fwxAesEncryptRawBytes(plaintext, passwordBytes, useMaster);
    }

    public static byte[] fwxAesDecryptRaw(byte[] blob, String password, boolean useMaster) {
        return FwxAesCodec.fwxAesDecryptRaw(blob, password, useMaster);
    }

    public static byte[] fwxAesDecryptRawBytes(byte[] blob, byte[] passwordBytes, boolean useMaster) {
        return FwxAesCodec.fwxAesDecryptRawBytes(blob, passwordBytes, useMaster);
    }

    static File createPrivateTempFile(String prefix, String suffix) throws IOException {
        return BaseFwxUtil.createPrivateTempFile(prefix, suffix);
    }

    public static long fwxAesEncryptStream(InputStream input, OutputStream output,
                                           String password, boolean useMaster) throws IOException {
        return FwxAesCodec.fwxAesEncryptStreamPublic(input, output, password, useMaster);
    }

    public static long fwxAesDecryptStream(InputStream input, OutputStream output,
                                           String password, boolean useMaster) throws IOException {
        return FwxAesCodec.fwxAesDecryptStreamPublic(input, output, password, useMaster);
    }

    public static File an7File(File input, String password, File output, boolean keepInput, boolean forceAny) {
        return An7Codec.an7File(input, password, output, keepInput, forceAny);
    }

    public static An7Result dean7File(File input, String password, File output, boolean keepInput) {
        return An7Codec.dean7File(input, password, output, keepInput);
    }

    public static String b512Encode(String input, String password, boolean useMaster) {
        return TextCodecs.b512EncodeString(input, password, useMaster);
    }

    public static byte[] b512EncodeBytes(byte[] input, String password, boolean useMaster) {
        return TextCodecs.b512EncodeBytes(input, password, useMaster);
    }

    public static String b512Decode(String input, String password, boolean useMaster) {
        return TextCodecs.b512DecodeString(input, password, useMaster);
    }

    public static byte[] b512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        return TextCodecs.b512DecodeBytes(blob, password, useMaster);
    }

    public static String pb512Encode(String input, String password, boolean useMaster) {
        return TextCodecs.pb512EncodeString(input, password, useMaster);
    }

    public static byte[] pb512EncodeBytes(byte[] input, String password, boolean useMaster) {
        return TextCodecs.pb512EncodeBytes(input, password, useMaster);
    }

    public static String pb512Decode(String input, String password, boolean useMaster) {
        return TextCodecs.pb512DecodeString(input, password, useMaster);
    }

    public static byte[] pb512DecodeBytes(byte[] blob, String password, boolean useMaster) {
        return TextCodecs.pb512DecodeBytes(blob, password, useMaster);
    }

    @Deprecated
    public static String b256Encode(String input) {
        TextCodecs.warnB256RetiredOnce();
        return Codec.b256Encode(input);
    }

    @Deprecated
    public static String b256Decode(String input) {
        TextCodecs.warnB256RetiredOnce();
        return Codec.b256Decode(input);
    }

    public static String n10Encode(String input) { return Codec.n10Encode(input); }
    public static String n10EncodeBytes(byte[] input) { return Codec.n10EncodeBytes(input); }
    public static String n10Decode(String input) { return Codec.n10Decode(input); }
    public static byte[] n10DecodeBytes(String input) { return Codec.n10DecodeBytes(input); }

    public static String b64Encode(String input) {
        return Base64Codec.encode(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String b64Decode(String input) {
        return new String(Base64Codec.decode(input), StandardCharsets.UTF_8);
    }

    public static String hash512(String input) {
        return hash512Bytes(input.getBytes(StandardCharsets.UTF_8));
    }

    @Deprecated
    public static String uhash513(String input) {
        return uhash513Bytes(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String hash512Bytes(byte[] input) { return TextCodecs.hash512Bytes(input); }

    @Deprecated
    public static String uhash513Bytes(byte[] inputBytes) { return TextCodecs.uhash513Bytes(inputBytes); }

    @Deprecated
    public static String bi512Encode(String input) { return TextCodecs.bi512EncodeImpl(input); }

    @Deprecated
    public static String a512Encode(String input) { return TextCodecs.a512EncodeImpl(input); }

    @Deprecated
    public static String a512Decode(String input) { return TextCodecs.a512DecodeImpl(input); }

    public static byte[] b512FileEncodeBytes(byte[] data, String extension, String password, boolean useMaster) {
        return FileCodecs.b512FileEncodeBytes(data, extension, password, useMaster);
    }

    public static byte[] b512FileEncodeBytes(byte[] data, String extension, String password,
                                             boolean useMaster, boolean stripMetadata, boolean enableAead) {
        return FileCodecs.b512FileEncodeBytes(data, extension, password, useMaster, stripMetadata, enableAead);
    }

    public static DecodedFile b512FileDecodeBytes(byte[] blob, String password, boolean useMaster) {
        return FileCodecs.b512FileDecodeBytes(blob, password, useMaster);
    }

    public static DecodedFile b512FileDecodeBytes(byte[] blob, String password, boolean useMaster, boolean stripMetadata) {
        return FileCodecs.b512FileDecodeBytes(blob, password, useMaster, stripMetadata);
    }

    public static File b512FileEncodeFile(File input, File output, String password, boolean useMaster) {
        return FileCodecs.b512FileEncodeFile(input, output, password, useMaster);
    }

    public static File b512FileDecodeFile(File input, File output, String password, boolean useMaster) {
        return FileCodecs.b512FileDecodeFile(input, output, password, useMaster);
    }

    public static byte[] pb512FileEncodeBytes(byte[] data, String extension, String password, boolean useMaster) {
        return FileCodecs.pb512FileEncodeBytes(data, extension, password, useMaster);
    }

    public static byte[] pb512FileEncodeBytes(byte[] data, String extension, String password,
                                              boolean useMaster, boolean stripMetadata) {
        return FileCodecs.pb512FileEncodeBytes(data, extension, password, useMaster, stripMetadata);
    }

    public static DecodedFile pb512FileDecodeBytes(byte[] blob, String password, boolean useMaster) {
        return FileCodecs.pb512FileDecodeBytes(blob, password, useMaster);
    }

    public static DecodedFile pb512FileDecodeBytes(byte[] blob, String password, boolean useMaster, boolean stripMetadata) {
        return FileCodecs.pb512FileDecodeBytes(blob, password, useMaster, stripMetadata);
    }

    public static File pb512FileEncodeFile(File input, File output, String password, boolean useMaster) {
        return FileCodecs.pb512FileEncodeFile(input, output, password, useMaster);
    }

    public static File pb512FileDecodeFile(File input, File output, String password, boolean useMaster) {
        return FileCodecs.pb512FileDecodeFile(input, output, password, useMaster);
    }
    public static LiveCipher.LiveEncryptor newLiveEncryptor(String password, boolean useMaster) {
        return new LiveCipher.LiveEncryptor(password, useMaster);
    }

    public static LiveCipher.LiveDecryptor newLiveDecryptor(String password, boolean useMaster) {
        return new LiveCipher.LiveDecryptor(password, useMaster);
    }

    public static List<byte[]> fwxAesLiveEncryptChunks(Iterable<byte[]> chunks,
                                                       String password,
                                                       boolean useMaster) {
        return LiveCipher.fwxAesLiveEncryptChunks(chunks, password, useMaster);
    }

    public static List<byte[]> fwxAesLiveDecryptChunks(Iterable<byte[]> chunks,
                                                       String password,
                                                       boolean useMaster) {
        return LiveCipher.fwxAesLiveDecryptChunks(chunks, password, useMaster);
    }

    public static long fwxAesLiveEncryptStream(InputStream source,
                                               OutputStream dest,
                                               String password,
                                               boolean useMaster) {
        return LiveCipher.fwxAesLiveEncryptStream(source, dest, password, useMaster, Constants.STREAM_CHUNK_SIZE);
    }

    public static long fwxAesLiveEncryptStream(InputStream source,
                                               OutputStream dest,
                                               String password,
                                               boolean useMaster,
                                               int chunkSize) {
        return LiveCipher.fwxAesLiveEncryptStream(source, dest, password, useMaster, chunkSize);
    }

    public static long fwxAesLiveDecryptStream(InputStream source,
                                               OutputStream dest,
                                               String password,
                                               boolean useMaster) {
        return LiveCipher.fwxAesLiveDecryptStream(source, dest, password, useMaster, Constants.STREAM_CHUNK_SIZE);
    }

    public static long fwxAesLiveDecryptStream(InputStream source,
                                               OutputStream dest,
                                               String password,
                                               boolean useMaster,
                                               int chunkSize) {
        return LiveCipher.fwxAesLiveDecryptStream(source, dest, password, useMaster, chunkSize);
    }

    public static void fwxAesEncryptFile(File input, File output, String password, boolean useMaster) {
        try (FileInputStream in = new FileInputStream(input);
             FileOutputStream out = new FileOutputStream(output)) {
            FwxAesCodec.fwxAesEncryptStreamPublic(in, out, password, useMaster);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file encrypt failed", exc);
        }
    }

    public static void fwxAesDecryptFile(File input, File output, String password, boolean useMaster) {
        try (FileInputStream in = new FileInputStream(input);
             FileOutputStream out = new FileOutputStream(output)) {
            FwxAesCodec.fwxAesDecryptStreamPublic(in, out, password, useMaster);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file decrypt failed", exc);
        }
    }

    public static void fwxAesEncryptFileNio(File input, File output, String password, boolean useMaster) {
        try (FileInputStream fis = new FileInputStream(input);
             FileOutputStream fos = new FileOutputStream(output);
             FileChannel in = fis.getChannel();
             FileChannel out = fos.getChannel()) {
            long ctLen = FwxAesCodec.fwxAesEncryptChannel(in, out, password, useMaster);
            FwxAesCodec.patchCtLen(out, ctLen);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file encrypt failed", exc);
        }
    }

    public static void fwxAesDecryptFileNio(File input, File output, String password, boolean useMaster) {
        try (FileInputStream fis = new FileInputStream(input);
             FileOutputStream fos = new FileOutputStream(output);
             FileChannel in = fis.getChannel();
             FileChannel out = fos.getChannel()) {
            FwxAesCodec.fwxAesDecryptChannel(in, out, password, useMaster);
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file decrypt failed", exc);
        }
    }
    // Package-private (was private): BaseFwxImage calls this via
    // BaseFwx.getExtension(input) for its image-carrier public API.
    static String getExtension(File file) {
        return BaseFwxUtil.getExtension(file);
    }

    // Package-private (was private): used by BaseFwxImage for
    // kfmResolveOutput AND by non-image callers in this file (lines 534, 690).
    // Survived the kfm-cluster deletion by being re-declared here.
    static boolean samePath(File a, File b) {
        return BaseFwxUtil.samePath(a, b);
    }

    // replaceExtension / replaceExtensionWithTag / kfmResolveOutput / kfmCleanExt /
    // kfmIsAudioExtension / kfmIsImageExtension / kfmWarn / kfmReadHead /
    // kfmDetectCarrierKinds / kfmDecodeContainer / bytesToLong moved to BaseFwxImage.java in 3.7.x.

    // Package-private (was private): byte[] overload, used by BaseFwxImage
    // for kfmKeystream and kfmPackContainer.
    static void writeU64(byte[] target, int offset, long value) {
        BaseFwxUtil.writeU64(target, offset, value);
    }

    // Package-private (was private): byte[] overload, used by BaseFwxImage
    // for kfmPackContainer.
    static void writeU32(byte[] target, int offset, int value) {
        BaseFwxUtil.writeU32(target, offset, value);
    }

    // Package-private (was private): byte[] overload, used by BaseFwxImage
    // for kfmUnpackContainer.
    static int readU32(byte[] source, int offset) {
        return BaseFwxUtil.readU32(source, offset);
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

    // Package-private (was private): used by BaseFwxImage carrier path.
    static byte[] readFileBytes(File file) {
        return BaseFwxUtil.readFileBytes(file);
    }

    // Package-private (was private): used by BaseFwxImage carrier path.
    static void writeFileBytes(File file, byte[] data) {
        BaseFwxUtil.writeFileBytes(file, data);
    }
}
