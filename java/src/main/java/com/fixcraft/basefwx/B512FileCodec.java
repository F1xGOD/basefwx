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

final class B512FileCodec {
    private B512FileCodec() {}

static File b512FileEncodeFileStream(File input,
                                                 File output,
                                                 String password,
                                                 boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        PasswordPolicy.requireStrongPassword(pw, "Encryption");
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for streaming b512 encode");
        }
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
            pw,
            useMaster,
            Constants.B512_FILE_MASK_INFO,
            true,
            Constants.MASK_AAD_B512FILE,
            new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
        );
        try {
            boolean useMasterEffective = mask.usedMaster;
            String ext = BaseFwx.getExtension(input);
            byte[] extBytes = ext.isEmpty() ? new byte[0] : ext.getBytes(StandardCharsets.UTF_8);
            byte[] streamSalt = StreamObfuscator.generateSalt();
            boolean fastObf = useFastObfuscation(input.length());
            String metadata = buildMetadata("FWX512R", false, useMasterEffective,
                mask.masterKem, "AESGCM", "pbkdf2",
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
            byte[] aeadKey = KeyWrap.deriveKeyAndWipe(
                    mask.maskKey, Constants.B512_AEAD_INFO, 32);
            try {
                byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
                StreamObfuscator obfuscator = StreamObfuscator.forPassword(
                        pw, streamSalt, fastObf);
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
                    try (CryptoBackend.AeadEncryptor enc =
                                 backend.newGcmEncryptor(aeadKey, nonce, metadataBytes)) {
                        byte[] outBuf = new byte[
                                Constants.STREAM_CHUNK_SIZE + Constants.AEAD_TAG_LEN];
                        if (prefixBytes.length > 0) {
                            int outLen = enc.update(
                                    prefixBytes, 0, prefixBytes.length, outBuf, 0);
                            if (outLen > 0) {
                                out.write(outBuf, 0, outLen);
                            }
                        }
                        int headerLen = enc.update(
                                streamHeader, 0, streamHeader.length, outBuf, 0);
                        if (headerLen > 0) {
                            out.write(outBuf, 0, headerLen);
                        }

                        byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
                        long remaining = input.length();
                        while (remaining > 0) {
                            int take = (int) Math.min(buffer.length, remaining);
                            readExact(
                                    in, buffer, take,
                                    "Streaming payload truncated");
                            obfuscator.encodeChunkInPlace(buffer, take);
                            int outLen = enc.update(buffer, 0, take, outBuf, 0);
                            if (outLen > 0) {
                                out.write(outBuf, 0, outLen);
                            }
                            remaining -= take;
                        }
                        int finalLen = enc.doFinal(outBuf, 0);
                        if (finalLen < Constants.AEAD_TAG_LEN) {
                            throw new IllegalStateException(
                                    "AES-GCM final block too short");
                        }
                        int ctLen = finalLen - Constants.AEAD_TAG_LEN;
                        if (ctLen > 0) {
                            out.write(outBuf, 0, ctLen);
                        }
                        out.write(outBuf, ctLen, Constants.AEAD_TAG_LEN);
                    }
                    out.flush();
                }
            } catch (IOException | GeneralSecurityException exc) {
                throw new IllegalStateException("Streaming b512 encode failed", exc);
            } finally {
                Arrays.fill(aeadKey, (byte) 0);
            }
            return outFile;
        } finally {
            mask.close();
        }
    }

static File b512FileDecodeFileStream(File input,
                                                 File output,
                                                 String password,
                                                 boolean useMaster,
                                                 String metadataPreview) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
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
            requireBoundedFileLength(
                    input, 4L, lenUser, Constants.LENGTH_PREFIXED_MAX,
                    "user key transport");
            byte[] userBlob = readExactBytes(in, lenUser, "Ciphertext payload truncated");
            int lenMaster = readU32(in, "Ciphertext payload truncated");
            requireHeaderLengthTotal((long) lenUser + lenMaster);
            requireBoundedFileLength(
                    input, 8L + lenUser, lenMaster,
                    Constants.LENGTH_PREFIXED_MAX, "master key transport");
            byte[] masterBlob = readExactBytes(in, lenMaster, "Ciphertext payload truncated");
            int lenPayloadHeader = readU32(in, "Ciphertext payload truncated");
            long lenPayload = resolvePayloadLengthFromFileSize(input, lenUser, lenMaster, lenPayloadHeader);
            long payloadOffset = 12L + lenUser + lenMaster;
            if (lenPayload != input.length() - payloadOffset) {
                throw new IllegalArgumentException(
                        "Ciphertext payload length does not match remaining file");
            }
            if (lenPayload < 4L + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Ciphertext payload truncated");
            }
            int metaLen = readU32(in, "Ciphertext payload truncated");
            if (metaLen < 0
                    || (long) metaLen > lenPayload - 4L
                            - Constants.AEAD_NONCE_LEN
                            - Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException(
                        "Ciphertext metadata length invalid");
            }
            requireHeaderLengthTotal(
                    (long) lenUser + lenMaster + metaLen);
            requireBoundedFileLength(
                    input, payloadOffset + 4L, metaLen,
                    Constants.METADATA_MAX, "metadata");
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
            long cipherBodyLen = lenPayload - 4L - metaLen
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
                Constants.MASK_AAD_B512FILE,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS),
                Constants.B512_AEAD_INFO
            );
            byte[] aeadKey = KeyWrap.deriveKeyAndWipe(
                    maskKey, Constants.B512_AEAD_INFO, 32);

            try {
                CryptoBackend backend = CryptoBackends.get();
                try (CryptoBackend.AeadDecryptor dec =
                             backend.newGcmDecryptor(
                                     aeadKey, nonce, metadataBytes)) {
                    tempPlain = BaseFwx.createPrivateTempFile(
                            "basefwx-stream", ".plain");
                    try (FileOutputStream fout = new FileOutputStream(tempPlain);
                         BufferedOutputStream plainOut =
                                 new BufferedOutputStream(
                                         fout,
                                         Constants.STREAM_CHUNK_SIZE)) {
                        byte[] buffer = new byte[Constants.STREAM_CHUNK_SIZE];
                        byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                        long remaining = cipherBodyLen;
                        while (remaining > 0) {
                            int take = (int) Math.min(
                                    buffer.length, remaining);
                            readExact(
                                    in, buffer, take,
                                    "Ciphertext truncated");
                            int outLen = dec.update(
                                    buffer, 0, take, outBuf, 0);
                            if (outLen > 0) {
                                plainOut.write(outBuf, 0, outLen);
                            }
                            remaining -= take;
                        }
                        byte[] tag = readExactBytes(
                                in,
                                Constants.AEAD_TAG_LEN,
                                "Ciphertext payload truncated");
                        int finalLen = dec.doFinal(
                                tag, 0, tag.length, outBuf, 0);
                        if (finalLen > 0) {
                            plainOut.write(outBuf, 0, finalLen);
                        }
                    }
                }
            } finally {
                Arrays.fill(aeadKey, (byte) 0);
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

static byte[] b512FileEncodeBytes(byte[] data,
                                             String extension,
                                             String password,
                                             boolean useMaster) {
        return b512FileEncodeBytes(data, extension, password, useMaster, false, true);
    }

static byte[] b512FileEncodeBytes(byte[] data,
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
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMasterEffective);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
            pw,
            useMasterEffective,
            Constants.B512_FILE_MASK_INFO,
            !useMasterEffective,
            Constants.MASK_AAD_B512FILE,
            new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
        );
        try {
            useMasterEffective = useMasterEffective && mask.usedMaster;
            String ext = extension == null ? "" : extension;
            String b64Payload = Base64Codec.encode(data);
            String extToken = TextCodecs.b512EncodeString(ext, password, useMasterEffective);
            String dataToken = TextCodecs.b512EncodeString(b64Payload, password, useMasterEffective);
            String metadata = buildMetadata("FWX512R", stripMetadata, useMasterEffective,
                mask.masterKem, enableAead ? "AESGCM" : "NONE", "pbkdf2");
            String body = extToken + Constants.FWX_DELIM + dataToken;
            String payload = metadata.isEmpty() ? body : metadata + Constants.META_DELIM + body;
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
            if (!enableAead) {
                return payloadBytes;
            }
            byte[] aeadKey = KeyWrap.deriveKeyAndWipe(
                    mask.maskKey, Constants.B512_AEAD_INFO, 32);
            try {
                byte[] ctBlob = Crypto.aesGcmEncrypt(
                        aeadKey, payloadBytes, Constants.B512_AEAD_INFO);
                return Format.packLengthPrefixed(
                        Arrays.asList(mask.userBlob, mask.masterBlob, ctBlob));
            } finally {
                Arrays.fill(aeadKey, (byte) 0);
            }
        } finally {
            mask.close();
        }
    }

static BaseFwx.DecodedFile b512FileDecodeBytes(byte[] blob,
                                                  String password,
                                                  boolean useMaster) {
        return b512FileDecodeBytes(blob, password, useMaster, false);
    }

static BaseFwx.DecodedFile b512FileDecodeBytes(byte[] blob,
                                                  String password,
                                                  boolean useMaster,
                                                  boolean stripMetadata) {
        if (blob == null) {
            throw new IllegalArgumentException("b512file_decode_bytes expects bytes");
        }
        boolean useMasterEffective = useMaster && !stripMetadata;
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMasterEffective);
        String content = null;
        List<byte[]> binaryParts = null;
        try {
            binaryParts = Format.unpackLengthPrefixed(blob, 3);
        } catch (IllegalArgumentException formatFailure) {
            // A blob that is not structurally length-prefixed may be the
            // historical raw-text format. Once structural recognition
            // succeeds, all keywrap and payload authentication failures are
            // terminal and must never downgrade to this path.
            content = new String(blob, StandardCharsets.UTF_8);
        }
        if (binaryParts != null) {
            byte[] maskKey = KeyWrap.recoverMaskKey(
                binaryParts.get(0),
                binaryParts.get(1),
                pw,
                useMasterEffective,
                Constants.B512_FILE_MASK_INFO,
                Constants.MASK_AAD_B512FILE,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS),
                Constants.B512_AEAD_INFO
            );
            byte[] aeadKey = KeyWrap.deriveKeyAndWipe(
                    maskKey, Constants.B512_AEAD_INFO, 32);
            try {
                byte[] payloadBytes = Crypto.aesGcmDecrypt(
                        aeadKey,
                        binaryParts.get(2),
                        Constants.B512_AEAD_INFO);
                content = new String(
                        payloadBytes, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(aeadKey, (byte) 0);
            }
        }
        String[] metaSplit = splitMetadata(content);
        String metadataBlob = metaSplit[0];
        String body = metaSplit[1];
        String masterHint = metaValue(metadataBlob, "ENC-MASTER");
        if ("no".equalsIgnoreCase(masterHint)) {
            useMasterEffective = false;
        }
        String[] parts = splitWithDelims(body, Constants.FWX_DELIM, Constants.LEGACY_FWX_DELIM, "FWX container");
        String ext = TextCodecs.b512DecodeString(parts[0], password, useMasterEffective);
        String dataB64 = TextCodecs.b512DecodeString(parts[1], password, useMasterEffective);
        byte[] decoded = Base64Codec.decode(dataB64);
        return new BaseFwx.DecodedFile(decoded, ext);
    }

static File b512FileEncodeFile(File input,
                                          File output,
                                          String password,
                                          boolean useMaster) {
        long size = input.length();
        long approxB64Len = ((size + 2L) / 3L) * 4L;
        if (size >= Constants.STREAM_THRESHOLD || approxB64Len > Constants.HKDF_MAX_LEN) {
            return b512FileEncodeFileStream(input, output, password, useMaster);
        }
        byte[] data = BaseFwx.readFileBytes(input);
        String ext = BaseFwx.getExtension(input);
        byte[] encoded = b512FileEncodeBytes(data, ext, password, useMaster);
        File outFile = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");
        BaseFwx.writeFileBytes(outFile, encoded);
        return outFile;
    }

static File b512FileDecodeFile(File input,
                                          File output,
                                          String password,
                                          boolean useMaster) {
        String metaPreview = peekMetadataBlob(input);
        if (isStreamMode(metaPreview)) {
            return b512FileDecodeFileStream(input, output, password, useMaster, metaPreview);
        }
        if (input.length() > Constants.LENGTH_PREFIXED_MAX) {
            throw new IllegalArgumentException(
                    "Non-stream b512file exceeds 64 MiB decode cap");
        }
        byte[] blob = BaseFwx.readFileBytes(input);
        BaseFwx.DecodedFile decoded = b512FileDecodeBytes(blob, password, useMaster);
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
        BaseFwx.writeFileBytes(outFile, decoded.data);
        return outFile;
    }
}
