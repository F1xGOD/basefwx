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

final class Pb512FileCodec {
    private Pb512FileCodec() {}

static File pb512FileEncodeFileStream(File input,
                                                  File output,
                                                  String password,
                                                  boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        PasswordPolicy.requireStrongPassword(pw, "Encryption");
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for AES-heavy streaming mode");
        }
        String kdfLabel = resolveUserKdfLabel();
        int heavyIters = Constants.HEAVY_PBKDF2_ITERATIONS;
        requirePeerPbkdf2WithinLimits(heavyIters);
        Integer heavyArgonTime = null;
        Integer heavyArgonMem = null;
        Integer heavyArgonPar = null;
        if ("argon2id".equals(kdfLabel)) {
            heavyArgonTime = Constants.HEAVY_ARGON2_TIME_COST;
            heavyArgonMem = Constants.HEAVY_ARGON2_MEMORY_KIB;
            heavyArgonPar = Constants.HEAVY_ARGON2_PARALLELISM;
        }
        boolean obfuscate = payloadObfuscationEnabled();
        KeyWrap.MasterKeySelection selectedMaster =
                KeyWrap.selectMasterKey(useMaster);
        boolean useMasterEffective = selectedMaster.usedMaster();
        byte[] masterBlob = new byte[0];
        byte[] ephemeralKey = null;
        PayloadKeySeparation.PayloadKeys payloadKeys = null;

        try {
        if (useMasterEffective) {
            if (selectedMaster.pqPublicKey != null) {
                try {
                    PQ.KemResult kem =
                            PQ.kemEncrypt(selectedMaster.pqPublicKey);
                    masterBlob = kem.ciphertext;
                    ephemeralKey = deriveKemKeyAndWipe(kem.shared, Constants.KEM_INFO);
                } catch (Exception exc) {
                    if (exc instanceof RuntimeException) {
                        throw (RuntimeException) exc;
                    }
                    throw new IllegalStateException("PQ master key wrap failed", exc);
                }
            } else if (selectedMaster.ecPublicKey != null) {
                try {
                    EcKeys.EcKemResult kem =
                            EcKeys.kemEncrypt(selectedMaster.ecPublicKey);
                    masterBlob = kem.masterBlob;
                    ephemeralKey = deriveKemKeyAndWipe(kem.shared, Constants.KEM_INFO);
                } catch (Exception exc) {
                    throw new IllegalStateException(
                            "EC master key wrap failed", exc);
                }
            }
        }
        if (useMaster && PQ.strictPqOnly() && ephemeralKey == null) {
            throw new IllegalStateException(
                    "PQ strict mode requires an ML-KEM master public key "
                    + "when master wrap is requested");
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
            selectedMaster.kemLabel,
            "AESGCM",
            kdfLabel,
            "STREAM",
            obfuscate,
            obfMode,
            heavyIters,
            heavyArgonTime,
            heavyArgonMem,
            heavyArgonPar,
            null,
            "v1"
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
            byte[] salt = Crypto.randomBytes(Constants.USER_KDF_SALT_SIZE);
            KeyWrap.KdfOptions opts = new KeyWrap.KdfOptions(kdfLabel, heavyIters);
            if (heavyArgonTime != null) {
                opts.argon2TimeCost = heavyArgonTime;
            }
            if (heavyArgonMem != null) {
                opts.argon2MemoryKib = heavyArgonMem;
            }
            if (heavyArgonPar != null) {
                opts.argon2Parallelism = heavyArgonPar;
            }
            byte[] userKey = deriveUserKey(pw, salt, kdfLabel, opts);
            try {
                byte[] wrapped = Crypto.aesGcmEncrypt(userKey, ephemeralKey, metadataBytes);
                userBlob = new byte[salt.length + wrapped.length];
                System.arraycopy(salt, 0, userBlob, 0, salt.length);
                System.arraycopy(wrapped, 0, userBlob, salt.length, wrapped.length);
            } finally {
                Arrays.fill(userKey, (byte) 0);
            }
        }
        boolean useDerivedKeys =
                PayloadKeySeparation.usesDerivedKeys(metadata);
        byte[] aeadKey = ephemeralKey;
        byte[] obfuscationKey = ephemeralKey;
        if (useDerivedKeys) {
            payloadKeys = PayloadKeySeparation.derive(ephemeralKey);
            aeadKey = payloadKeys.aead;
            obfuscationKey = payloadKeys.obfuscation;
        }
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        StreamObfuscator obfuscator = obfuscate
                ? (useDerivedKeys
                    ? StreamObfuscator.forKey(
                            obfuscationKey, streamSalt, fastObf)
                    : StreamObfuscator.forPassword(
                            pw, streamSalt, fastObf))
                : null;
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
            try (CryptoBackend.AeadEncryptor enc =
                         backend.newGcmEncryptor(
                                 aeadKey, nonce, metadataBytes)) {
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
                    if (obfuscator != null) {
                        obfuscator.encodeChunkInPlace(buffer, take);
                    }
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
        } finally {
            if (payloadKeys != null) {
                payloadKeys.close();
            }
            PayloadKeySeparation.wipe(ephemeralKey);
        }
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
        boolean useDerivedKeys = false;
        byte[] ephemeralKey = null;
        PayloadKeySeparation.PayloadKeys payloadKeys = null;
        try {
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
            String obfHint = FileCodecs.requirePayloadObfuscationMode(
                    metaValue(metadataBlob, "ENC-OBF"));
            obfuscateStream = !"no".equals(obfHint);
            fastObfStream = "fast".equals(obfHint);
            String kdfHint = metaValue(metadataBlob, "ENC-KDF");
            String label = kdfHint == null || kdfHint.isEmpty()
                    ? resolveUserKdfLabel()
                    : resolvePeerKdfLabel(kdfHint);
            int kdfIterHint = parsePeerPbkdf2Iterations(
                    metaValue(metadataBlob, "ENC-KDF-ITER"),
                    Constants.HEAVY_PBKDF2_ITERATIONS);
            Integer argonTime = parseMetadataIntOrNull(metaValue(metadataBlob, "ENC-ARGON2-TC"));
            Integer argonMem = parseMetadataIntOrNull(metaValue(metadataBlob, "ENC-ARGON2-MEM"));
            Integer argonPar = parseMetadataIntOrNull(metaValue(metadataBlob, "ENC-ARGON2-PAR"));
            requirePeerArgon2WithinLimits(argonTime, argonMem, argonPar);
            useDerivedKeys =
                    PayloadKeySeparation.usesDerivedKeys(metadataBlob);

            byte[] nonce = readExactBytes(in, Constants.AEAD_NONCE_LEN, "Ciphertext payload truncated");
            long cipherBodyLen = lenPayload - 4L - metaLen
                - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            if (cipherBodyLen < 0) {
                throw new IllegalArgumentException("Ciphertext payload truncated");
            }

            KeyWrap.KdfOptions opts = new KeyWrap.KdfOptions(label, kdfIterHint);
            if (argonTime != null) {
                opts.argon2TimeCost = argonTime;
            }
            if (argonMem != null) {
                opts.argon2MemoryKib = argonMem;
            }
            if (argonPar != null) {
                opts.argon2Parallelism = argonPar;
            }
            try {
                ephemeralKey = recoverPayloadKey(
                        userBlob, masterBlob, pw, useMasterEffective,
                        Constants.KEM_INFO, metadataBytes, label, opts);
            } catch (RuntimeException exc) {
                throw exc;
            } catch (Exception exc) {
                throw new IllegalStateException("Master key unwrap failed", exc);
            }
            byte[] aeadKey = ephemeralKey;
            if (useDerivedKeys) {
                payloadKeys =
                        PayloadKeySeparation.derive(ephemeralKey);
                aeadKey = payloadKeys.aead;
            }

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec =
                         backend.newGcmDecryptor(
                                 aeadKey, nonce, metadataBytes)) {
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
                ? (useDerivedKeys
                    ? StreamObfuscator.forKey(
                            payloadKeys.obfuscation, salt,
                            fastObfStream)
                    : StreamObfuscator.forPassword(
                            pw, salt, fastObfStream))
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
        } finally {
            if (payloadKeys != null) {
                payloadKeys.close();
            }
            PayloadKeySeparation.wipe(ephemeralKey);
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
        boolean useMasterRequested = useMaster && !stripMetadata;
        KeyWrap.MasterKeySelection selectedMaster =
                KeyWrap.selectMasterKey(useMasterRequested);
        boolean useMasterEffective = selectedMaster.usedMaster();
        String resolvedPassword = password == null ? "" : password;
        PasswordPolicy.requireStrongPassword(
                BaseFwx.resolvePasswordBytes(resolvedPassword, useMasterEffective), "Encryption");
        String ext = extension == null ? "" : extension;
        String b64Payload = Base64Codec.encode(data);
        String kdfLabel = resolveUserKdfLabel();
        boolean obfuscate = payloadObfuscationEnabled();
        int heavyIters = Constants.HEAVY_PBKDF2_ITERATIONS;
        requirePeerPbkdf2WithinLimits(heavyIters);
        Integer heavyArgonTime = null;
        Integer heavyArgonMem = null;
        Integer heavyArgonPar = null;
        if ("argon2id".equals(kdfLabel)) {
            heavyArgonTime = Constants.HEAVY_ARGON2_TIME_COST;
            heavyArgonMem = Constants.HEAVY_ARGON2_MEMORY_KIB;
            heavyArgonPar = Constants.HEAVY_ARGON2_PARALLELISM;
        }

        String extToken = TextCodecs.pb512EncodeString(ext, resolvedPassword, useMasterEffective);
        String dataToken = TextCodecs.pb512EncodeString(b64Payload, resolvedPassword, useMasterEffective);

        String body = extToken + Constants.FWX_HEAVY_DELIM + dataToken;
        boolean fastObf = obfuscate && !stripMetadata && useFastObfuscation(body.length());
        String obfMode = obfuscate ? (fastObf ? "fast" : "yes") : "no";
        String metadata = buildMetadata(
            "AES-HEAVY",
            stripMetadata,
            useMasterEffective,
            selectedMaster.kemLabel,
            "AESGCM",
            kdfLabel,
            null,
            obfuscate,
            obfMode,
            heavyIters,
            heavyArgonTime,
            heavyArgonMem,
            heavyArgonPar,
            null,
            "v1"
        );
        String plaintext = metadata.isEmpty()
            ? body
            : metadata + Constants.META_DELIM + body;
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return LengthPrefixedCodec.encryptAesPayloadBytes(plaintextBytes, resolvedPassword, useMasterEffective, metadata,
            kdfLabel, heavyIters, obfuscate, fastObf, heavyArgonTime,
            heavyArgonMem, heavyArgonPar, selectedMaster);
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
        if (input.length() > Constants.LENGTH_PREFIXED_MAX) {
            throw new IllegalArgumentException(
                    "Non-stream pb512file exceeds 64 MiB decode cap");
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
