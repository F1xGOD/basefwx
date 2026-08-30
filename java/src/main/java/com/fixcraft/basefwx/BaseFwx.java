/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
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
 * Performance strategy:
 * - Base64 uses the JDK implementation.
 * - Hashing, AES-GCM, and PBKDF2 use JCA providers selected by the runtime.
 * - The optional JNI backend accelerates supported AES-GCM entry points.
 * - Hot codec loops are ordinary Java so the JVM can JIT-compile them.
 * 
 * Memory Management:
 * - Pre-sized arrays and buffers to minimize allocations
 * - Direct char[] construction for string building instead of StringBuilder where beneficial
 * - Reuse of byte arrays in hot paths
 * - Mutable secret buffers are wiped explicitly where ownership permits;
 *   garbage collection is not treated as secret erasure.
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

    // BASEFWX_PROFILE_METHODS

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

    public static String hash512Bytes(byte[] input) { return TextCodecs.hash512Bytes(input); }

    public static byte[] b512FileEncodeBytes(byte[] data, String extension, String password, boolean useMaster) {
        return FileCodecs.b512FileEncodeBytes(data, extension, password, useMaster);
    }

    /**
     * @deprecated Use the overload without {@code enableAead}. Passing
     * {@code false} is rejected because unauthenticated b512file writing is
     * retired.
     */
    @Deprecated
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
        File temp = null;
        try {
            temp = BaseFwxUtil.createPrivateSiblingTempFile(
                    output, ".basefwx-fwxaes-auth-", ".tmp");
            try (FileInputStream in = new FileInputStream(input);
                 FileOutputStream out = new FileOutputStream(temp)) {
                FwxAesCodec.fwxAesDecryptStreamPublic(
                        in, out, password, useMaster);
                out.getFD().sync();
            }
            BaseFwxUtil.commitAuthenticatedFile(temp, output);
            temp = null;
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file decrypt failed", exc);
        } finally {
            if (temp != null) {
                temp.delete();
            }
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
        File temp = null;
        try {
            temp = BaseFwxUtil.createPrivateSiblingTempFile(
                    output, ".basefwx-fwxaes-auth-", ".tmp");
            try (FileInputStream fis = new FileInputStream(input);
                 FileOutputStream fos = new FileOutputStream(temp);
                 FileChannel in = fis.getChannel();
                 FileChannel out = fos.getChannel()) {
                FwxAesCodec.fwxAesDecryptChannel(
                        in, out, password, useMaster);
                out.force(true);
            }
            BaseFwxUtil.commitAuthenticatedFile(temp, output);
            temp = null;
        } catch (IOException exc) {
            throw new IllegalStateException("fwxAES file decrypt failed", exc);
        } finally {
            if (temp != null) {
                temp.delete();
            }
        }
    }
    static String getExtension(File file) {
        return BaseFwxUtil.getExtension(file);
    }

    static boolean samePath(File a, File b) {
        return BaseFwxUtil.samePath(a, b);
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
        // Match C++ ResolvePassword (3.7.0+): bare passwords are ALWAYS
        // literal. Filesystem read is opt-in via an explicit file:// URI.
        // password:// forces the literal-string interpretation even when
        // the string contains ://. Auto-detecting "string names an existing
        // path → read that file" is removed — it silently changed secrets
        // based on filesystem state.
        final String passwordScheme = "password://";
        final String fileScheme = "file://";
        if (password.startsWith(passwordScheme)) {
            return password.substring(passwordScheme.length())
                    .getBytes(StandardCharsets.UTF_8);
        }
        if (password.startsWith(fileScheme)) {
            String path = password.substring(fileScheme.length());
            File candidate = expandUser(path);
            if (!candidate.isFile()) {
                throw new IllegalArgumentException("Password file not found: " + path);
            }
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

    static byte[] readFileBytes(File file) {
        return BaseFwxUtil.readFileBytes(file);
    }

    static void writeFileBytes(File file, byte[] data) {
        BaseFwxUtil.writeFileBytes(file, data);
    }
}
