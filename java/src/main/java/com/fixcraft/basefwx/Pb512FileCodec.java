/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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

final class Pb512FileCodec {
    private Pb512FileCodec() {}

static File pb512FileEncodeFileStream(File input,
                                                  File output,
                                                  String password,
                                                  boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for AES-heavy streaming mode");
        }
        String kdfLabel = resolveUserKdfLabel();
        if (!"pbkdf2".equals(kdfLabel)) {
            throw new UnsupportedKdfException(kdfLabel,
                "pb512file: Argon2 KDF is not yet implemented in Java; use pbkdf2");
        }
        int heavyIters = Constants.HEAVY_PBKDF2_ITERATIONS;
        boolean obfuscate = payloadObfuscationEnabled();
        boolean useMasterEffective = false;
        byte[] masterBlob = new byte[0];
        byte[] ephemeralKey = null;

        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(EcKeys.masterEcAutoCreateEnabled());
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
        String ext = BaseFwx.getExtension(input);
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

static File pb512FileDecodeFileStream(File input,
                                                  File output,
                                                  String password,
                                                  boolean useMaster,
                                                  String metadataPreview) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
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
            int lenPayloadHeader = readU32(in, "Ciphertext payload truncated");
            long lenPayload = resolvePayloadLengthFromFileSize(input, lenUser, lenMaster, lenPayloadHeader);
            if (lenPayload < 4L + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
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
            long cipherBodyLen = lenPayload - 4L - metaLen
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
                tempPlain = BaseFwx.createPrivateTempFile("basefwx-stream", ".plain");
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

static byte[] pb512FileEncodeBytes(byte[] data,
                                              String extension,
                                              String password,
                                              boolean useMaster) {
        return pb512FileEncodeBytes(data, extension, password, useMaster, false);
    }

static byte[] pb512FileEncodeBytes(byte[] data,
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
        if (!"pbkdf2".equals(kdfLabel)) {
            throw new UnsupportedKdfException(kdfLabel,
                "pb512file: Argon2 KDF is not yet implemented in Java; use pbkdf2");
        }
        boolean obfuscate = payloadObfuscationEnabled();
        int heavyIters = Constants.HEAVY_PBKDF2_ITERATIONS;

        String extToken = TextCodecs.pb512EncodeString(ext, resolvedPassword, useMasterEffective);
        String dataToken = TextCodecs.pb512EncodeString(b64Payload, resolvedPassword, useMasterEffective);

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
        return LengthPrefixedCodec.encryptAesPayloadBytes(plaintextBytes, resolvedPassword, useMasterEffective, metadata,
            kdfLabel, heavyIters, obfuscate, fastObf);
    }

static BaseFwx.DecodedFile pb512FileDecodeBytes(byte[] blob,
                                                   String password,
                                                   boolean useMaster) {
        return pb512FileDecodeBytes(blob, password, useMaster, false);
    }

static BaseFwx.DecodedFile pb512FileDecodeBytes(byte[] blob,
                                                   String password,
                                                   boolean useMaster,
                                                   boolean stripMetadata) {
        if (blob == null) {
            throw new IllegalArgumentException("pb512file_decode_bytes expects bytes");
        }
        boolean useMasterEffective = useMaster && !stripMetadata;
        String resolvedPassword = password == null ? "" : password;
        String plaintext = LengthPrefixedCodec.decryptAesPayload(blob, resolvedPassword, useMasterEffective);
        String[] metaSplit = splitMetadata(plaintext);
        String metadataBlob = metaSplit[0];
        String body = metaSplit[1];
        String masterHint = metaValue(metadataBlob, "ENC-MASTER");
        if ("no".equalsIgnoreCase(masterHint)) {
            useMasterEffective = false;
        }
        String[] parts = splitWithDelims(body, Constants.FWX_HEAVY_DELIM, Constants.LEGACY_FWX_HEAVY_DELIM, "FWX heavy");
        String ext = TextCodecs.pb512DecodeString(parts[0], resolvedPassword, useMasterEffective);
        String dataB64 = TextCodecs.pb512DecodeString(parts[1], resolvedPassword, useMasterEffective);
        byte[] decoded = Base64Codec.decode(dataB64);
        return new BaseFwx.DecodedFile(decoded, ext);
    }

static File pb512FileEncodeFile(File input,
                                          File output,
                                          String password,
                                          boolean useMaster) {
        long size = input.length();
        long approxB64Len = ((size + 2L) / 3L) * 4L;
        if (size >= Constants.STREAM_THRESHOLD || approxB64Len > Constants.HKDF_MAX_LEN) {
            return pb512FileEncodeFileStream(input, output, password, useMaster);
        }
        byte[] data = BaseFwx.readFileBytes(input);
        String ext = BaseFwx.getExtension(input);
        byte[] encoded = pb512FileEncodeBytes(data, ext, password, useMaster);
        File outFile = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");
        BaseFwx.writeFileBytes(outFile, encoded);
        return outFile;
    }

static File pb512FileDecodeFile(File input,
                                           File output,
                                           String password,
                                           boolean useMaster) {
        String metaPreview = peekMetadataBlob(input);
        if (isStreamMode(metaPreview)) {
            return pb512FileDecodeFileStream(input, output, password, useMaster, metaPreview);
        }
        byte[] blob = BaseFwx.readFileBytes(input);
        BaseFwx.DecodedFile decoded = pb512FileDecodeBytes(blob, password, useMaster);
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
