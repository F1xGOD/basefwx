/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.zip.CRC32;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

final class An7Codec {
    private An7Codec() {}

    static File an7File(File input,
                               String password,
                               File output,
                               boolean keepInput,
                               boolean forceAny) {
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("Input file not found: " + (input == null ? "null" : input.getPath()));
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, false);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password is required for an7");
        }
        String ext = BaseFwx.getExtension(input).toLowerCase();
        if (!forceAny && !".fwx".equals(ext)) {
            throw new IllegalArgumentException("an7 accepts only .fwx input by default (use --force-any to override)");
        }
        File out = an7ResolveOutputPath(input, output);
        if (BaseFwx.samePath(input, out)) {
            throw new IllegalArgumentException("Output path must differ from input path");
        }
        File temp = an7MakeTempPath(out);

        long payloadLen = input.length();
        long totalChunks = an7TotalChunks(payloadLen, BaseFwx.AN7_CHUNK_SIZE);
        byte[] salt = Crypto.randomBytes(BaseFwx.AN7_SALT_LEN);
        An7Keys keys = an7DeriveKeys(pw, salt);
        byte[] streamNonce = Crypto.randomBytes(BaseFwx.AN7_TRAILER_NONCE_LEN);
        MessageDigest sha = sha256Digest();

        try (InputStream src = new BufferedInputStream(new FileInputStream(input));
             OutputStream dst = new BufferedOutputStream(new FileOutputStream(temp))) {
            long superblocks = an7TotalChunks(totalChunks, BaseFwx.AN7_SUPERBLOCK_CHUNKS);
            for (long superIdx = 0; superIdx < superblocks; superIdx++) {
                long startChunk = superIdx * BaseFwx.AN7_SUPERBLOCK_CHUNKS;
                int blockChunks = (int) Math.min(BaseFwx.AN7_SUPERBLOCK_CHUNKS, totalChunks - startChunk);
                byte[][] chunks = new byte[blockChunks][];
                for (int local = 0; local < blockChunks; local++) {
                    long globalChunk = startChunk + local;
                    int chunkLen = an7ChunkBytesAt(payloadLen, BaseFwx.AN7_CHUNK_SIZE, globalChunk);
                    byte[] chunk = new byte[chunkLen];
                    FileCodecs.readExact(src, chunk, chunkLen, "AN7 failed to read source payload chunk");
                    sha.update(chunk);
                    byte[] transformed = an7ApplyXorTransform(chunk, keys.stream, streamNonce, globalChunk);
                    if ((local & 1) == 1) {
                        int flipStart = an7FlipStart(keys.perm, globalChunk, BaseFwx.AN7_FLIP_STRIDE);
                        an7ApplySparseFlip(transformed, flipStart, BaseFwx.AN7_FLIP_STRIDE);
                    }
                    chunks[local] = transformed;
                }
                int[] order = an7BuildPermutation(keys.perm, superIdx, blockChunks);
                for (int pos = 0; pos < blockChunks; pos++) {
                    dst.write(chunks[order[pos]]);
                }
            }

            An7Trailer trailer = new An7Trailer();
            trailer.originalBasename = an7Stem(input.getName());
            trailer.originalExtension = BaseFwx.getExtension(input);
            trailer.originalSize = payloadLen;
            trailer.chunkSize = BaseFwx.AN7_CHUNK_SIZE;
            trailer.superblockChunks = BaseFwx.AN7_SUPERBLOCK_CHUNKS;
            trailer.flipStride = BaseFwx.AN7_FLIP_STRIDE;
            trailer.streamNonce = streamNonce;
            trailer.sha256Original = sha.digest();
            trailer.createdUtc = Instant.now().toString();

            byte[] trailerPlain = an7SerializeTrailer(trailer);
            byte[] trailerNonce = Crypto.randomBytes(BaseFwx.AN7_TRAILER_NONCE_LEN);
            byte[] trailerCipherTag = Crypto.aesGcmEncryptWithIv(keys.meta, trailerNonce, trailerPlain, new byte[0]);
            byte[] encryptedTrailer = FileCodecs.concat(trailerNonce, trailerCipherTag);
            long trailerLen = encryptedTrailer.length;
            long trailerCrc = an7Crc32(encryptedTrailer);
            dst.write(encryptedTrailer);

            byte[] tailPlain = new byte[BaseFwx.AN7_TAIL_PLAIN_LEN];
            an7WriteU64Le(tailPlain, 0, trailerLen);
            an7WriteU64Le(tailPlain, 8, payloadLen);
            an7WriteU32Le(tailPlain, 16, trailerCrc);
            byte[] tailNonce = Crypto.randomBytes(BaseFwx.AN7_TAIL_NONCE_LEN);
            byte[] tailCipherTag = Crypto.aesGcmEncryptWithIv(keys.tail, tailNonce, tailPlain, new byte[0]);
            if (tailCipherTag.length != BaseFwx.AN7_TAIL_CIPHER_LEN + BaseFwx.AN7_TAIL_TAG_LEN) {
                throw new IllegalStateException("AN7 tail encrypt produced unexpected length");
            }
            byte[] footer = new byte[BaseFwx.AN7_FOOTER_SIZE];
            System.arraycopy(salt, 0, footer, 0, BaseFwx.AN7_SALT_LEN);
            System.arraycopy(tailNonce, 0, footer, BaseFwx.AN7_SALT_LEN, BaseFwx.AN7_TAIL_NONCE_LEN);
            System.arraycopy(tailCipherTag, 0, footer, BaseFwx.AN7_SALT_LEN + BaseFwx.AN7_TAIL_NONCE_LEN, BaseFwx.AN7_TAIL_CIPHER_LEN);
            System.arraycopy(
                tailCipherTag,
                BaseFwx.AN7_TAIL_CIPHER_LEN,
                footer,
                BaseFwx.AN7_SALT_LEN + BaseFwx.AN7_TAIL_NONCE_LEN + BaseFwx.AN7_TAIL_CIPHER_LEN,
                BaseFwx.AN7_TAIL_TAG_LEN
            );
            dst.write(footer);
            dst.flush();
        } catch (IOException exc) {
            temp.delete();
            throw new IllegalStateException("an7 failed", exc);
        } catch (RuntimeException exc) {
            temp.delete();
            throw exc;
        }

        try {
            an7CommitTempFile(temp, out);
            if (!keepInput) {
                Files.delete(input.toPath());
            }
        } catch (IOException exc) {
            temp.delete();
            throw new IllegalStateException("an7 output finalize failed", exc);
        }
        return out;
    }

    static BaseFwx.An7Result dean7File(File input,
                                      String password,
                                      File output,
                                      boolean keepInput) {
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("Input file not found: " + (input == null ? "null" : input.getPath()));
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, false);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password is required for dean7");
        }
        long fileSize = input.length();
        if (fileSize < BaseFwx.AN7_FOOTER_SIZE) {
            throw new IllegalArgumentException("Input is too small to be an AN7 file");
        }

        byte[] footerBuf = new byte[BaseFwx.AN7_FOOTER_SIZE];
        try (RandomAccessFile raf = new RandomAccessFile(input, "r")) {
            raf.seek(fileSize - BaseFwx.AN7_FOOTER_SIZE);
            raf.readFully(footerBuf);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read AN7 footer", exc);
        }

        An7FooterContext footer = an7ParseFooterAndDerive(footerBuf, pw);
        if (footer.trailerLen < (BaseFwx.AN7_TRAILER_NONCE_LEN + Constants.AEAD_TAG_LEN)
            || footer.payloadLen > fileSize
            || footer.payloadLen + footer.trailerLen + BaseFwx.AN7_FOOTER_SIZE != fileSize) {
            throw new IllegalArgumentException("AN7 footer length fields are invalid");
        }

        byte[] encryptedTrailer = new byte[(int) footer.trailerLen];
        try (RandomAccessFile raf = new RandomAccessFile(input, "r")) {
            raf.seek(footer.payloadLen);
            raf.readFully(encryptedTrailer);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read AN7 encrypted trailer", exc);
        }
        if (an7Crc32(encryptedTrailer) != footer.trailerCrc32) {
            throw new IllegalArgumentException("AN7 trailer CRC mismatch");
        }

        byte[] trailerNonce = Arrays.copyOfRange(encryptedTrailer, 0, BaseFwx.AN7_TRAILER_NONCE_LEN);
        byte[] trailerCipherTag = Arrays.copyOfRange(encryptedTrailer, BaseFwx.AN7_TRAILER_NONCE_LEN, encryptedTrailer.length);
        byte[] trailerPlain = Crypto.aesGcmDecryptWithIv(footer.keys.meta, trailerNonce, trailerCipherTag, new byte[0]);
        An7Trailer trailer = an7ParseTrailer(trailerPlain);
        if (trailer.chunkSize <= 0
            || trailer.superblockChunks <= 0
            || trailer.flipStride <= 0
            || trailer.streamNonce.length != BaseFwx.AN7_TRAILER_NONCE_LEN) {
            throw new IllegalArgumentException("AN7 trailer contains invalid transform parameters");
        }
        if (trailer.originalSize != footer.payloadLen) {
            throw new IllegalArgumentException("AN7 payload size mismatch");
        }

        File out = an7ResolveDeanOutputPath(input, trailer, output);
        if (BaseFwx.samePath(input, out)) {
            throw new IllegalArgumentException("Output path must differ from input path");
        }
        File temp = an7MakeTempPath(out);

        long bytesRead = 0L;
        long bytesWritten = 0L;
        MessageDigest sha = sha256Digest();

        try (InputStream src = new BufferedInputStream(new FileInputStream(input));
             OutputStream dst = new BufferedOutputStream(new FileOutputStream(temp))) {
            long totalChunks = an7TotalChunks(footer.payloadLen, trailer.chunkSize);
            long superblocks = an7TotalChunks(totalChunks, trailer.superblockChunks);
            for (long superIdx = 0; superIdx < superblocks; superIdx++) {
                long startChunk = superIdx * trailer.superblockChunks;
                int blockChunks = (int) Math.min(trailer.superblockChunks, totalChunks - startChunk);

                int[] chunkSizes = new int[blockChunks];
                for (int i = 0; i < blockChunks; i++) {
                    chunkSizes[i] = an7ChunkBytesAt(footer.payloadLen, trailer.chunkSize, startChunk + i);
                }

                byte[][] chunks = new byte[blockChunks][];
                int[] order = an7BuildPermutation(footer.keys.perm, superIdx, blockChunks);
                for (int pos = 0; pos < blockChunks; pos++) {
                    int originalSlot = order[pos];
                    int len = chunkSizes[originalSlot];
                    byte[] chunk = new byte[len];
                    FileCodecs.readExact(src, chunk, len, "AN7 payload is truncated");
                    bytesRead += chunk.length;
                    chunks[originalSlot] = chunk;
                }

                for (int local = 0; local < blockChunks; local++) {
                    long globalChunk = startChunk + local;
                    byte[] chunk = chunks[local];
                    if ((local & 1) == 1) {
                        int flipStart = an7FlipStart(footer.keys.perm, globalChunk, trailer.flipStride);
                        an7ApplySparseFlip(chunk, flipStart, trailer.flipStride);
                    }
                    byte[] plain = an7ApplyXorTransform(chunk, footer.keys.stream, trailer.streamNonce, globalChunk);
                    sha.update(plain);
                    dst.write(plain);
                    bytesWritten += plain.length;
                }
            }
            dst.flush();
        } catch (IOException exc) {
            temp.delete();
            throw new IllegalStateException("dean7 failed", exc);
        } catch (RuntimeException exc) {
            temp.delete();
            throw exc;
        }

        if (bytesRead != footer.payloadLen || bytesWritten != footer.payloadLen) {
            temp.delete();
            throw new IllegalArgumentException("AN7 payload length verification failed");
        }
        if (!Arrays.equals(sha.digest(), trailer.sha256Original)) {
            temp.delete();
            throw new IllegalArgumentException("AN7 payload hash mismatch");
        }

        try {
            an7CommitTempFile(temp, out);
            if (!keepInput) {
                Files.delete(input.toPath());
            }
        } catch (IOException exc) {
            temp.delete();
            throw new IllegalStateException("dean7 output finalize failed", exc);
        }
        return new BaseFwx.An7Result(out, out.getName(), bytesWritten);
    }
    static final class An7Keys {
        byte[] stream;
        byte[] perm;
        byte[] meta;
        byte[] tail;
    }

    static final class An7Trailer {
        String originalBasename = "";
        String originalExtension = "";
        long originalSize = 0L;
        int chunkSize = BaseFwx.AN7_CHUNK_SIZE;
        int superblockChunks = BaseFwx.AN7_SUPERBLOCK_CHUNKS;
        int flipStride = BaseFwx.AN7_FLIP_STRIDE;
        byte[] streamNonce = new byte[BaseFwx.AN7_TRAILER_NONCE_LEN];
        byte[] sha256Original = new byte[BaseFwx.AN7_SHA256_LEN];
        String createdUtc = "";
    }

    static final class An7FooterContext {
        An7Keys keys;
        long trailerLen;
        long payloadLen;
        long trailerCrc32;
    }

    static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalStateException("SHA-256 unavailable", exc);
        }
    }

    static long an7TotalChunks(long payloadLen, int chunkSize) {
        if (payloadLen <= 0) {
            return 0L;
        }
        return (payloadLen + chunkSize - 1L) / (long) chunkSize;
    }

    static int an7ChunkBytesAt(long payloadLen, int chunkSize, long chunkIndex) {
        if (payloadLen <= 0) {
            return 0;
        }
        long offset = chunkIndex * (long) chunkSize;
        if (offset >= payloadLen) {
            return 0;
        }
        long remain = payloadLen - offset;
        return (int) Math.min(remain, (long) chunkSize);
    }

    static long an7ReadU64Le(byte[] data, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value |= (long) (data[offset + i] & 0xFF) << (i * 8);
        }
        return value;
    }

    static int an7ReadU32Le(byte[] data, int offset) {
        return (data[offset] & 0xFF)
            | ((data[offset + 1] & 0xFF) << 8)
            | ((data[offset + 2] & 0xFF) << 16)
            | ((data[offset + 3] & 0xFF) << 24);
    }

    static int an7ReadU16Le(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    static void an7WriteU64Le(byte[] target, int offset, long value) {
        long v = value;
        for (int i = 0; i < 8; i++) {
            target[offset + i] = (byte) (v & 0xFFL);
            v >>>= 8;
        }
    }

    static void an7WriteU32Le(byte[] target, int offset, long value) {
        long v = value;
        for (int i = 0; i < 4; i++) {
            target[offset + i] = (byte) (v & 0xFFL);
            v >>>= 8;
        }
    }

    static void an7WriteU16Le(byte[] target, int offset, int value) {
        target[offset] = (byte) (value & 0xFF);
        target[offset + 1] = (byte) ((value >>> 8) & 0xFF);
    }

    static byte[] an7Argon2idRaw(byte[] password,
                                         byte[] salt,
                                         int outLen,
                                         int timeCost,
                                         int memoryKib,
                                         int parallelism) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withIterations(timeCost)
            .withMemoryAsKB(memoryKib)
            .withParallelism(parallelism);
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        byte[] out = new byte[outLen];
        generator.generateBytes(password, out);
        return out;
    }

    static An7Keys an7DeriveKeys(byte[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is required for AN7");
        }
        if (salt == null || salt.length != BaseFwx.AN7_SALT_LEN) {
            throw new IllegalArgumentException("Invalid AN7 salt length");
        }
        byte[] root = an7Argon2idRaw(
            password,
            salt,
            64,
            BaseFwx.AN7_ARGON2_TIME_COST,
            BaseFwx.AN7_ARGON2_MEMORY_KIB,
            BaseFwx.AN7_ARGON2_PARALLELISM
        );
        An7Keys keys = new An7Keys();
        keys.stream = Crypto.hkdfSha256(root, "an7-stream".getBytes(StandardCharsets.US_ASCII), 32);
        keys.perm = Crypto.hkdfSha256(root, "an7-perm".getBytes(StandardCharsets.US_ASCII), 32);
        keys.meta = Crypto.hkdfSha256(root, "an7-meta".getBytes(StandardCharsets.US_ASCII), 32);
        keys.tail = Crypto.hkdfSha256(root, "an7-tail".getBytes(StandardCharsets.US_ASCII), 32);
        return keys;
    }

    static byte[] an7BuildLabel(byte[] prefix, byte[] nonce, long index) {
        byte[] out = new byte[prefix.length + nonce.length + 8];
        int offset = 0;
        System.arraycopy(prefix, 0, out, offset, prefix.length);
        offset += prefix.length;
        System.arraycopy(nonce, 0, out, offset, nonce.length);
        offset += nonce.length;
        an7WriteU64Le(out, offset, index);
        return out;
    }

    static byte[] an7CtrIv(byte[] streamKey, byte[] streamNonce, long chunkIndex) {
        byte[] label = an7BuildLabel("ctr:".getBytes(StandardCharsets.US_ASCII), streamNonce, chunkIndex);
        byte[] digest = Crypto.hmacSha256(streamKey, label);
        return Arrays.copyOf(digest, 16);
    }

    static byte[] an7ApplyXorTransform(byte[] chunk, byte[] streamKey, byte[] streamNonce, long chunkIndex) {
        byte[] iv = an7CtrIv(streamKey, streamNonce, chunkIndex);
        // In-place CTR on the caller's chunk buffer: skips both the
        // per-call JCA provider lookup (now cached on a thread-local)
        // and the fresh byte[chunk.length] that doFinal(byte[]) used to
        // allocate per chunk. For a 220 MiB an7 run that's ~220 MiB of
        // pure heap allocations + zero-fills removed from the hot loop.
        Crypto.aesCtrTransformInPlace(streamKey, iv, chunk, 0, chunk.length);
        return chunk;
    }

    static int an7FlipStart(byte[] permKey, long chunkIndex, int stride) {
        if (stride <= 0) {
            return 0;
        }
        byte[] label = new byte[5 + 8];
        System.arraycopy("flip:".getBytes(StandardCharsets.US_ASCII), 0, label, 0, 5);
        an7WriteU64Le(label, 5, chunkIndex);
        byte[] digest = Crypto.hmacSha256(permKey, label);
        long value = an7ReadU64Le(digest, 0);
        return (int) Long.remainderUnsigned(value, stride);
    }

    static void an7ApplySparseFlip(byte[] chunk, int start, int stride) {
        if (chunk.length == 0 || stride <= 0) {
            return;
        }
        for (int i = start; i < chunk.length; i += stride) {
            chunk[i] = (byte) (chunk[i] ^ 0xFF);
        }
    }

    static int[] an7BuildPermutation(byte[] permKey, long superblockIndex, int count) {
        int[] order = new int[count];
        for (int i = 0; i < count; i++) {
            order[i] = i;
        }
        if (count <= 1) {
            return order;
        }
        byte[] label = new byte[5 + 8];
        System.arraycopy("perm:".getBytes(StandardCharsets.US_ASCII), 0, label, 0, 5);
        an7WriteU64Le(label, 5, superblockIndex);
        byte[] digest = Crypto.hmacSha256(permKey, label);
        long[] state = new long[]{an7ReadU64Le(digest, 0)};
        for (int i = count - 1; i > 0; i--) {
            long rnd = FileCodecs.splitMix64Next(state);
            int j = (int) Long.remainderUnsigned(rnd, i + 1L);
            int tmp = order[i];
            order[i] = order[j];
            order[j] = tmp;
        }
        return order;
    }

    static long an7Crc32(byte[] data) {
        CRC32 crc32 = new CRC32();
        crc32.update(data, 0, data.length);
        return crc32.getValue() & 0xFFFFFFFFL;
    }

    static byte[] an7SerializeTrailer(An7Trailer trailer) {
        if (trailer.streamNonce.length != BaseFwx.AN7_TRAILER_NONCE_LEN) {
            throw new IllegalArgumentException("AN7 trailer has invalid stream nonce length");
        }
        byte[] basename = trailer.originalBasename.getBytes(StandardCharsets.UTF_8);
        byte[] extension = trailer.originalExtension.getBytes(StandardCharsets.UTF_8);
        byte[] created = trailer.createdUtc.getBytes(StandardCharsets.UTF_8);
        if (basename.length > 0xFFFF || extension.length > 0xFFFF || created.length > 64) {
            throw new IllegalArgumentException("AN7 trailer metadata is too large");
        }
        int total = BaseFwx.AN7_TRAILER_VERSION.length
            + 4 + 2 + 2 + 8 + 2
            + created.length
            + BaseFwx.AN7_TRAILER_NONCE_LEN
            + BaseFwx.AN7_SHA256_LEN
            + 2 + basename.length
            + 2 + extension.length;
        byte[] out = new byte[total];
        int offset = 0;
        System.arraycopy(BaseFwx.AN7_TRAILER_VERSION, 0, out, offset, BaseFwx.AN7_TRAILER_VERSION.length);
        offset += BaseFwx.AN7_TRAILER_VERSION.length;
        an7WriteU32Le(out, offset, trailer.chunkSize);
        offset += 4;
        an7WriteU16Le(out, offset, trailer.superblockChunks);
        offset += 2;
        an7WriteU16Le(out, offset, trailer.flipStride);
        offset += 2;
        an7WriteU64Le(out, offset, trailer.originalSize);
        offset += 8;
        an7WriteU16Le(out, offset, created.length);
        offset += 2;
        System.arraycopy(created, 0, out, offset, created.length);
        offset += created.length;
        System.arraycopy(trailer.streamNonce, 0, out, offset, BaseFwx.AN7_TRAILER_NONCE_LEN);
        offset += BaseFwx.AN7_TRAILER_NONCE_LEN;
        System.arraycopy(trailer.sha256Original, 0, out, offset, BaseFwx.AN7_SHA256_LEN);
        offset += BaseFwx.AN7_SHA256_LEN;
        an7WriteU16Le(out, offset, basename.length);
        offset += 2;
        System.arraycopy(basename, 0, out, offset, basename.length);
        offset += basename.length;
        an7WriteU16Le(out, offset, extension.length);
        offset += 2;
        System.arraycopy(extension, 0, out, offset, extension.length);
        return out;
    }

    static An7Trailer an7ParseTrailer(byte[] data) {
        int minLen = BaseFwx.AN7_TRAILER_VERSION.length + 4 + 2 + 2 + 8 + 2 + BaseFwx.AN7_TRAILER_NONCE_LEN + BaseFwx.AN7_SHA256_LEN + 2 + 2;
        if (data.length < minLen) {
            throw new IllegalArgumentException("AN7 trailer is too short");
        }
        for (int i = 0; i < BaseFwx.AN7_TRAILER_VERSION.length; i++) {
            if (data[i] != BaseFwx.AN7_TRAILER_VERSION[i]) {
                throw new IllegalArgumentException("AN7 trailer version mismatch");
            }
        }
        int offset = BaseFwx.AN7_TRAILER_VERSION.length;
        An7Trailer trailer = new An7Trailer();
        trailer.chunkSize = an7ReadU32Le(data, offset);
        offset += 4;
        trailer.superblockChunks = an7ReadU16Le(data, offset);
        offset += 2;
        trailer.flipStride = an7ReadU16Le(data, offset);
        offset += 2;
        trailer.originalSize = an7ReadU64Le(data, offset);
        offset += 8;
        int createdLen = an7ReadU16Le(data, offset);
        offset += 2;
        if (createdLen > 64 || offset + createdLen > data.length) {
            throw new IllegalArgumentException("AN7 trailer created timestamp is invalid");
        }
        trailer.createdUtc = new String(data, offset, createdLen, StandardCharsets.UTF_8);
        offset += createdLen;
        if (offset + BaseFwx.AN7_TRAILER_NONCE_LEN + BaseFwx.AN7_SHA256_LEN > data.length) {
            throw new IllegalArgumentException("AN7 trailer payload is truncated");
        }
        trailer.streamNonce = Arrays.copyOfRange(data, offset, offset + BaseFwx.AN7_TRAILER_NONCE_LEN);
        offset += BaseFwx.AN7_TRAILER_NONCE_LEN;
        trailer.sha256Original = Arrays.copyOfRange(data, offset, offset + BaseFwx.AN7_SHA256_LEN);
        offset += BaseFwx.AN7_SHA256_LEN;
        int basenameLen = an7ReadU16Le(data, offset);
        offset += 2;
        if (offset + basenameLen > data.length) {
            throw new IllegalArgumentException("AN7 trailer basename is truncated");
        }
        trailer.originalBasename = new String(data, offset, basenameLen, StandardCharsets.UTF_8);
        offset += basenameLen;
        int extLen = an7ReadU16Le(data, offset);
        offset += 2;
        if (offset + extLen > data.length) {
            throw new IllegalArgumentException("AN7 trailer extension is truncated");
        }
        trailer.originalExtension = new String(data, offset, extLen, StandardCharsets.UTF_8);
        offset += extLen;
        if (offset != data.length) {
            throw new IllegalArgumentException("AN7 trailer has trailing bytes");
        }
        return trailer;
    }

    static An7FooterContext an7ParseFooterAndDerive(byte[] footer, byte[] password) {
        if (footer.length != BaseFwx.AN7_FOOTER_SIZE) {
            throw new IllegalArgumentException("AN7 footer length mismatch");
        }
        byte[] salt = Arrays.copyOfRange(footer, 0, BaseFwx.AN7_SALT_LEN);
        byte[] tailNonce = Arrays.copyOfRange(footer, BaseFwx.AN7_SALT_LEN, BaseFwx.AN7_SALT_LEN + BaseFwx.AN7_TAIL_NONCE_LEN);
        byte[] tailBlob = Arrays.copyOfRange(footer, BaseFwx.AN7_SALT_LEN + BaseFwx.AN7_TAIL_NONCE_LEN, footer.length);
        An7Keys keys = an7DeriveKeys(password, salt);
        byte[] tailPlain = Crypto.aesGcmDecryptWithIv(keys.tail, tailNonce, tailBlob, new byte[0]);
        if (tailPlain.length != BaseFwx.AN7_TAIL_PLAIN_LEN) {
            throw new IllegalArgumentException("AN7 footer tail length mismatch");
        }
        An7FooterContext out = new An7FooterContext();
        out.keys = keys;
        out.trailerLen = an7ReadU64Le(tailPlain, 0);
        out.payloadLen = an7ReadU64Le(tailPlain, 8);
        out.trailerCrc32 = an7ReadU32Le(tailPlain, 16) & 0xFFFFFFFFL;
        return out;
    }

    static String an7Stem(String name) {
        int idx = name.lastIndexOf('.');
        if (idx < 0) {
            return name;
        }
        return name.substring(0, idx);
    }

    static String an7RandomDigits10() {
        byte[] rnd = Crypto.randomBytes(8);
        long value = 0L;
        for (byte b : rnd) {
            value = (value << 8) | ((long) b & 0xFFL);
        }
        value = Long.remainderUnsigned(value, BaseFwx.AN7_TEN_DIGITS_MOD);
        return String.format(java.util.Locale.US, "%010d", value);
    }

    static File an7EnsureCollisionSuffix(File desired) {
        if (!desired.exists()) {
            return desired;
        }
        String base = desired.getPath();
        for (int i = 1; i < Integer.MAX_VALUE; i++) {
            File candidate = new File(base + "." + i);
            if (!candidate.exists()) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to resolve output path collision");
    }

    static File an7MakeTempPath(File finalPath) {
        File parent = finalPath.getParentFile();
        if (parent == null) {
            parent = new File(".");
        }
        for (int i = 0; i < 128; i++) {
            File candidate = new File(parent, finalPath.getName() + ".tmp." + an7RandomDigits10());
            if (!candidate.exists()) {
                return candidate;
            }
        }
        throw new IllegalStateException("Failed to allocate temp output file path");
    }

    static void an7CommitTempFile(File tempPath, File finalPath) throws IOException {
        try {
            Files.move(
                tempPath.toPath(),
                finalPath.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
            );
            return;
        } catch (IOException ignored) {
        }
        Files.copy(tempPath.toPath(), finalPath.toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.deleteIfExists(tempPath.toPath());
    }

    static File an7ResolveOutputPath(File input, File output) {
        File desired;
        if (output != null) {
            desired = output;
            if (desired.exists() && desired.isDirectory()) {
                desired = new File(desired, "data" + an7RandomDigits10());
            }
        } else {
            File parent = input.getParentFile();
            if (parent == null) {
                parent = new File(".");
            }
            desired = new File(parent, "data" + an7RandomDigits10());
        }
        desired = an7EnsureCollisionSuffix(desired);
        File parent = desired.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Failed to create output directory: " + parent.getPath());
        }
        return desired;
    }

    static boolean an7AsciiAlnum(char ch) {
        return (ch >= '0' && ch <= '9')
            || (ch >= 'a' && ch <= 'z')
            || (ch >= 'A' && ch <= 'Z');
    }

    static String an7SanitizeBasename(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '/' || ch == '\\' || ch < 32) {
                out.append('_');
            } else {
                out.append(ch);
            }
        }
        if (out.length() == 0) {
            return "data";
        }
        return out.toString();
    }

    static String an7SanitizeExtension(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        String ext = value.startsWith(".") ? value : ("." + value);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < ext.length(); i++) {
            char ch = ext.charAt(i);
            if (ch == '.') {
                out.append(ch);
            } else if (an7AsciiAlnum(ch) || ch == '_' || ch == '-') {
                out.append(ch);
            } else {
                out.append('_');
            }
        }
        return out.toString();
    }

    static File an7ResolveDeanOutputPath(File input, An7Trailer trailer, File output) {
        String restored = an7SanitizeBasename(trailer.originalBasename) + an7SanitizeExtension(trailer.originalExtension);
        if (restored.isEmpty()) {
            restored = "dean7.out";
        }
        File desired;
        if (output != null) {
            desired = output;
            if (desired.exists() && desired.isDirectory()) {
                desired = new File(desired, restored);
            }
        } else {
            File parent = input.getParentFile();
            if (parent == null) {
                parent = new File(".");
            }
            desired = new File(parent, restored);
        }
        desired = an7EnsureCollisionSuffix(desired);
        File parent = desired.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Failed to create output directory: " + parent.getPath());
        }
        return desired;
    }

}
