/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.media;

import com.fixcraft.basefwx.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class MediaTrailerCodec {
    private MediaTrailerCodec() {}

    static void appendTrailerStream(File output,
                                            byte[] password,
                                            boolean useMaster,
                                            File original,
                                            byte[] archiveKey,
                                            byte[] keyHeader,
                                            byte[] archiveInfo) {
        if (archiveInfo == null || archiveInfo.length == 0) {
            archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
        }
        if (archiveKey == null) {
            byte[] material = deriveMediaMaterial(password);
            archiveKey = Crypto.hkdfSha256(material, archiveInfo, 32);
        }
        long size = original.length();
        long blobLen = (long) keyHeader.length + Constants.AEAD_NONCE_LEN + size + Constants.AEAD_TAG_LEN;
        if (blobLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Trailer too large");
        }
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        byte[] lenBytes = MediaCipherUtil.writeU32((int) blobLen);
        try (FileInputStream in = new FileInputStream(original);
             BufferedInputStream bufIn = new BufferedInputStream(in, Constants.STREAM_CHUNK_SIZE);
             FileOutputStream out = new FileOutputStream(output, true);
             BufferedOutputStream bufOut = new BufferedOutputStream(out, Constants.STREAM_CHUNK_SIZE)) {
            bufOut.write(Constants.IMAGECIPHER_TRAILER_MAGIC);
            bufOut.write(lenBytes);
            if (keyHeader.length > 0) {
                bufOut.write(keyHeader);
            }
            bufOut.write(nonce);

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadEncryptor enc = backend.newGcmEncryptor(
                archiveKey, nonce, archiveInfo)) {
                byte[] inBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE + Constants.AEAD_TAG_LEN];
                int read;
                while ((read = bufIn.read(inBuf)) != -1) {
                    int outLen = enc.update(inBuf, 0, read, outBuf, 0);
                    if (outLen > 0) {
                        bufOut.write(outBuf, 0, outLen);
                    }
                }
                int finalLen = enc.doFinal(outBuf, 0);
                if (finalLen < Constants.AEAD_TAG_LEN) {
                    throw new IllegalStateException("AES-GCM final block too short");
                }
                int ctLen = finalLen - Constants.AEAD_TAG_LEN;
                if (ctLen > 0) {
                    bufOut.write(outBuf, 0, ctLen);
                }
                bufOut.write(outBuf, ctLen, Constants.AEAD_TAG_LEN);
            }
            bufOut.write(Constants.IMAGECIPHER_TRAILER_MAGIC);
            bufOut.write(lenBytes);
            bufOut.flush();
        } catch (IOException | RuntimeException | java.security.GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to append trailer", exc);
        }
    }

    static boolean decryptTrailerStream(File input,
                                                byte[] password,
                                                boolean useMaster,
                                                File output) {
        boolean headerSeen = false;
        try (RandomAccessFile raf = new RandomAccessFile(input, "r")) {
            byte[] magic = Constants.IMAGECIPHER_TRAILER_MAGIC;
            int footerLen = magic.length + 4;
            long size = raf.length();
            if (size < footerLen) {
                return false;
            }
            raf.seek(size - footerLen);
            byte[] footer = new byte[footerLen];
            raf.readFully(footer);
            if (!MediaCipherUtil.startsWith(footer, 0, magic)) {
                return false;
            }
            long blobLen = MediaCipherUtil.readU32(footer, magic.length);
            long trailerStart = size - footerLen - blobLen - footerLen;
            if (trailerStart < 0) {
                return false;
            }
            raf.seek(trailerStart);
            byte[] header = new byte[footerLen];
            raf.readFully(header);
            if (!MediaCipherUtil.startsWith(header, 0, magic)) {
                return false;
            }
            long headerLen = MediaCipherUtil.readU32(header, magic.length);
            if (headerLen != blobLen) {
                return false;
            }
            long blobStart = trailerStart + footerLen;
            raf.seek(blobStart);

            byte[] prefix = new byte[Constants.JMG_KEY_MAGIC.length];
            raf.readFully(prefix);

            byte[] archiveKey;
            byte[] archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
            long headerBytes = 0;
            byte[] nonce;
            long cipherBodyLen;
            if (Arrays.equals(prefix, Constants.JMG_KEY_MAGIC)) {
                headerSeen = true;
                int version = raf.read();
                if (version < 0) {
                    return false;
                }
                if (version != Constants.JMG_KEY_VERSION_LEGACY && version != Constants.JMG_KEY_VERSION) {
                    throw new IllegalArgumentException("Unsupported JMG key header version");
                }
                byte[] payloadLenBytes = new byte[4];
                raf.readFully(payloadLenBytes);
                long payloadLen = MediaCipherUtil.readU32(payloadLenBytes, 0);
                headerBytes = Constants.JMG_KEY_MAGIC.length + 1 + 4 + payloadLen;
                byte[] payload = new byte[(int) payloadLen];
                raf.readFully(payload);
                int profileId = Constants.JMG_SECURITY_PROFILE_LEGACY;
                byte[] keyPayload = payload;
                if (version == Constants.JMG_KEY_VERSION) {
                    if (payload.length < 1) {
                        throw new IllegalArgumentException("Truncated JMG key header profile");
                    }
                    profileId = normalizeJmgProfile(payload[0] & 0xFF);
                    keyPayload = Arrays.copyOfRange(payload, 1, payload.length);
                }
                List<byte[]> parts = Format.unpackLengthPrefixed(keyPayload, 2);
                byte[] maskKey = KeyWrap.recoverMaskKey(parts.get(0), parts.get(1), password, useMaster,
                    Constants.JMG_MASK_INFO, Constants.MASK_AAD_JMG, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
                archiveInfo = jmgArchiveInfoForProfile(profileId);
                archiveKey = Crypto.hkdfSha256(maskKey, archiveInfo, 32);
                nonce = new byte[Constants.AEAD_NONCE_LEN];
                raf.readFully(nonce);
                cipherBodyLen = blobLen - headerBytes - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            } else {
                archiveKey = Crypto.hkdfSha256(deriveMediaMaterial(password), Constants.IMAGECIPHER_ARCHIVE_INFO, 32);
                nonce = new byte[Constants.AEAD_NONCE_LEN];
                System.arraycopy(prefix, 0, nonce, 0, prefix.length);
                raf.readFully(nonce, prefix.length, Constants.AEAD_NONCE_LEN - prefix.length);
                cipherBodyLen = blobLen - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            }
            if (cipherBodyLen < 0) {
                return false;
            }

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec = backend.newGcmDecryptor(
                archiveKey, nonce, archiveInfo)) {
                try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output),
                    Constants.STREAM_CHUNK_SIZE)) {
                    byte[] inBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                    byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                    long remaining = cipherBodyLen;
                    while (remaining > 0) {
                        int toRead = (int) Math.min(inBuf.length, remaining);
                        int read = raf.read(inBuf, 0, toRead);
                        if (read <= 0) {
                            return false;
                        }
                        int outLen = dec.update(inBuf, 0, read, outBuf, 0);
                        if (outLen > 0) {
                            out.write(outBuf, 0, outLen);
                        }
                        remaining -= read;
                    }
                    byte[] tag = new byte[Constants.AEAD_TAG_LEN];
                    raf.readFully(tag);
                    int finalLen = dec.doFinal(tag, 0, tag.length, outBuf, 0);
                    if (finalLen > 0) {
                        out.write(outBuf, 0, finalLen);
                    }
                }
            }
            return true;
        } catch (Exception exc) {
            if (headerSeen) {
                throw new IllegalStateException("Failed to decrypt trailer", exc);
            }
            return false;
        }
    }

    static byte[] decryptTrailer(byte[] fileBytes,
                                         byte[] password,
                                         boolean useMaster) {
        TrailerSplit split = splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_TRAILER_MAGIC);
        if (split.trailer == null) {
            return null;
        }
        byte[] trailer = split.trailer;
        JmgHeader header = parseJmgHeader(trailer, password, useMaster);
        byte[] archiveKey;
        byte[] archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
        byte[] archiveBlob;
        if (header != null) {
            archiveKey = header.archiveKey;
            archiveInfo = jmgArchiveInfoForProfile(header.profileId);
            archiveBlob = Arrays.copyOfRange(trailer, header.headerLen, trailer.length);
        } else {
            archiveKey = Crypto.hkdfSha256(deriveMediaMaterial(password), Constants.IMAGECIPHER_ARCHIVE_INFO, 32);
            archiveBlob = trailer;
        }
        try {
            return Crypto.aesGcmDecrypt(archiveKey, archiveBlob, archiveInfo);
        } catch (RuntimeException exc) {
            return null;
        }
    }

    static TrailerSplit splitTrailer(byte[] data) {
        return splitTrailerForMagic(data, Constants.IMAGECIPHER_TRAILER_MAGIC);
    }

    static TrailerSplit splitTrailerForMagic(byte[] data, byte[] magic) {
        int footerLen = magic.length + 4;
        byte[] payload = data;
        byte[] trailer = null;
        if (data.length >= footerLen) {
            int footerIdx = data.length - footerLen;
            if (MediaCipherUtil.startsWith(data, footerIdx, magic)) {
                long len = MediaCipherUtil.readU32(data, footerIdx + magic.length);
                long trailerStart = data.length - footerLen - len - footerLen;
                if (trailerStart >= 0) {
                    int headerPos = (int) trailerStart;
                    if (MediaCipherUtil.startsWith(data, headerPos, magic)
                        && MediaCipherUtil.readU32(data, headerPos + magic.length) == len) {
                        int blobStart = headerPos + footerLen;
                        int blobEnd = (int) (blobStart + len);
                        payload = Arrays.copyOfRange(data, 0, headerPos);
                        trailer = Arrays.copyOfRange(data, blobStart, blobEnd);
                    }
                }
            }
        }
        if (trailer == null) {
            int markerIdx = MediaCipherUtil.lastIndexOf(data, magic);
            if (markerIdx >= 0 && markerIdx + footerLen <= data.length) {
                long len = MediaCipherUtil.readU32(data, markerIdx + magic.length);
                int blobStart = markerIdx + footerLen;
                int blobEnd = (int) (blobStart + len);
                if (blobEnd == data.length) {
                    payload = Arrays.copyOfRange(data, 0, markerIdx);
                    trailer = Arrays.copyOfRange(data, blobStart, blobEnd);
                }
            }
        }
        return new TrailerSplit(payload, trailer);
    }

    static void appendKeyTrailer(File output, byte[] keyHeader) {
        if (keyHeader == null || keyHeader.length == 0) {
            throw new IllegalArgumentException("Missing JMG key header for no-archive mode");
        }
        appendBalancedTrailer(output, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC, keyHeader);
    }

    static byte[] loadBaseKeyFromKeyTrailer(File path,
                                                    byte[] password,
                                                    boolean useMaster,
                                                    int[] profileOut) {
        TrailerInfo info = extractBalancedTrailerInfo(path, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
        if (info == null) {
            return null;
        }
        byte[] blob = new byte[(int) info.blobLen];
        try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
            raf.seek(info.blobStart);
            raf.readFully(blob);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read JMG key trailer", exc);
        }
        JmgHeader header = parseJmgHeader(blob, password, useMaster);
        if (header == null) {
            throw new IllegalArgumentException("Invalid JMG key trailer");
        }
        if (header.headerLen != blob.length) {
            throw new IllegalArgumentException("Invalid JMG key trailer payload");
        }
        if (profileOut != null && profileOut.length > 0) {
            profileOut[0] = header.profileId;
        }
        return header.baseKey;
    }

    static byte[] loadBaseKeyFromKeyTrailerBytes(byte[] fileBytes,
                                                         byte[] password,
                                                         boolean useMaster,
                                                         int[] profileOut) {
        TrailerSplit split = splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
        if (split.trailer == null) {
            return null;
        }
        JmgHeader header = parseJmgHeader(split.trailer, password, useMaster);
        if (header == null) {
            throw new IllegalArgumentException("Invalid JMG key trailer");
        }
        if (header.headerLen != split.trailer.length) {
            throw new IllegalArgumentException("Invalid JMG key trailer payload");
        }
        if (profileOut != null && profileOut.length > 0) {
            profileOut[0] = header.profileId;
        }
        return header.baseKey;
    }

    static TrailerInfo extractBalancedTrailerInfo(File path, byte[] magic) {
        int footerLen = magic.length + 4;
        long size;
        try {
            size = path.length();
        } catch (Exception exc) {
            return null;
        }
        if (size < footerLen) {
            return null;
        }
        try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
            raf.seek(size - footerLen);
            byte[] footer = new byte[footerLen];
            raf.readFully(footer);
            if (!MediaCipherUtil.startsWith(footer, 0, magic)) {
                return null;
            }
            long blobLen = MediaCipherUtil.readU32(footer, magic.length);
            long trailerStart = size - footerLen - blobLen - footerLen;
            if (trailerStart < 0) {
                return null;
            }
            raf.seek(trailerStart);
            byte[] header = new byte[footerLen];
            raf.readFully(header);
            if (!MediaCipherUtil.startsWith(header, 0, magic)) {
                return null;
            }
            if (MediaCipherUtil.readU32(header, magic.length) != blobLen) {
                return null;
            }
            return new TrailerInfo(trailerStart + footerLen, blobLen, trailerStart);
        } catch (IOException exc) {
            return null;
        }
    }

    static int normalizeJmgProfile(int profileId) {
        if (profileId == Constants.JMG_SECURITY_PROFILE_LEGACY
            || profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return profileId;
        }
        throw new IllegalArgumentException("Unsupported JMG security profile id");
    }

    static byte[] jmgStreamInfoForProfile(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return "basefwx.imagecipher.stream.v1.max".getBytes(StandardCharsets.US_ASCII);
        }
        return Constants.IMAGECIPHER_STREAM_INFO;
    }

    static byte[] jmgArchiveInfoForProfile(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return "basefwx.imagecipher.archive.v1.max".getBytes(StandardCharsets.US_ASCII);
        }
        return Constants.IMAGECIPHER_ARCHIVE_INFO;
    }

    static String jmgProfileLabel(String label, int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return label + ".max";
        }
        return label;
    }

    static int jmgVideoMaskBits(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return MediaRawTransforms.VIDEO_MASK_BITS_MAX;
        }
        return MediaRawTransforms.VIDEO_MASK_BITS;
    }

    static int jmgAudioMaskBits(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return MediaRawTransforms.AUDIO_MASK_BITS_MAX;
        }
        return MediaRawTransforms.AUDIO_MASK_BITS;
    }

    static JmgKeys prepareJmgKeys(byte[] password, boolean useMaster) {
        return prepareJmgKeys(password, useMaster, Constants.JMG_SECURITY_PROFILE_DEFAULT);
    }

    static JmgKeys prepareJmgKeys(byte[] password, boolean useMaster, int securityProfile) {
        securityProfile = normalizeJmgProfile(securityProfile);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(password, useMaster, Constants.JMG_MASK_INFO,
            false, Constants.MASK_AAD_JMG, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        byte[] material = Crypto.hkdfSha256(mask.maskKey, jmgStreamInfoForProfile(securityProfile), 64);
        byte[] baseKey = Arrays.copyOfRange(material, 0, 32);
        byte[] archiveKey = Crypto.hkdfSha256(mask.maskKey, jmgArchiveInfoForProfile(securityProfile), 32);
        byte[] header = buildJmgHeader(mask.userBlob, mask.masterBlob, securityProfile);
        return new JmgKeys(baseKey, archiveKey, material, header, securityProfile);
    }

    static JmgHeader parseJmgHeader(byte[] blob, byte[] password, boolean useMaster) {
        int headerMin = Constants.JMG_KEY_MAGIC.length + 1 + 4;
        if (blob.length < headerMin) {
            return null;
        }
        if (!MediaCipherUtil.startsWith(blob, 0, Constants.JMG_KEY_MAGIC)) {
            return null;
        }
        int version = blob[Constants.JMG_KEY_MAGIC.length] & 0xFF;
        if (version != Constants.JMG_KEY_VERSION_LEGACY && version != Constants.JMG_KEY_VERSION) {
            throw new IllegalArgumentException("Unsupported JMG key header version");
        }
        long payloadLen = MediaCipherUtil.readU32(blob, Constants.JMG_KEY_MAGIC.length + 1);
        int headerLen = (int) (headerMin + payloadLen);
        if (blob.length < headerLen) {
            throw new IllegalArgumentException("Truncated JMG key header");
        }
        byte[] payload = Arrays.copyOfRange(blob, headerMin, headerLen);
        int profileId = Constants.JMG_SECURITY_PROFILE_LEGACY;
        byte[] keyPayload = payload;
        if (version == Constants.JMG_KEY_VERSION) {
            if (payload.length < 1) {
                throw new IllegalArgumentException("Truncated JMG key header profile");
            }
            profileId = normalizeJmgProfile(payload[0] & 0xFF);
            keyPayload = Arrays.copyOfRange(payload, 1, payload.length);
        }
        List<byte[]> parts = Format.unpackLengthPrefixed(keyPayload, 2);
        byte[] maskKey = KeyWrap.recoverMaskKey(parts.get(0), parts.get(1), password, useMaster,
            Constants.JMG_MASK_INFO, Constants.MASK_AAD_JMG, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        byte[] material = Crypto.hkdfSha256(maskKey, jmgStreamInfoForProfile(profileId), 64);
        byte[] baseKey = Arrays.copyOfRange(material, 0, 32);
        byte[] archiveKey = Crypto.hkdfSha256(maskKey, jmgArchiveInfoForProfile(profileId), 32);
        return new JmgHeader(headerLen, baseKey, archiveKey, material, profileId);
    }

    static byte[] buildJmgHeader(byte[] userBlob, byte[] masterBlob, int securityProfile) {
        securityProfile = normalizeJmgProfile(securityProfile);
        byte[] packed = Format.packLengthPrefixed(Arrays.asList(userBlob, masterBlob));
        byte[] payload = new byte[packed.length + 1];
        payload[0] = (byte) securityProfile;
        System.arraycopy(packed, 0, payload, 1, packed.length);
        int total = Constants.JMG_KEY_MAGIC.length + 1 + 4 + payload.length;
        byte[] out = new byte[total];
        int offset = 0;
        System.arraycopy(Constants.JMG_KEY_MAGIC, 0, out, offset, Constants.JMG_KEY_MAGIC.length);
        offset += Constants.JMG_KEY_MAGIC.length;
        out[offset++] = (byte) Constants.JMG_KEY_VERSION;
        MediaCipherUtil.writeU32(out, offset, payload.length);
        offset += 4;
        System.arraycopy(payload, 0, out, offset, payload.length);
        return out;
    }

    static byte[] deriveMediaMaterial(byte[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password required for media key derivation");
        }
        int iters = MediaCipherUtil.imageKdfIterations(password);
        return Crypto.pbkdf2HmacSha256(password, Constants.IMAGECIPHER_STREAM_INFO, iters, 64);
    }

    static byte[] deriveBaseKey(String password) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, true);
        byte[] material = deriveMediaMaterial(pw);
        return Arrays.copyOfRange(material, 0, 32);
    }

    static void appendBalancedTrailer(File output, byte[] magic, byte[] blob) {
        if (blob == null || blob.length == 0) {
            return;
        }
        byte[] lenBytes = MediaCipherUtil.writeU32(blob.length);
        try (FileOutputStream out = new FileOutputStream(output, true)) {
            out.write(magic);
            out.write(lenBytes);
            out.write(blob);
            out.write(magic);
            out.write(lenBytes);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to append trailer", exc);
        }
    }

    static void warnNoArchivePayload() {
        RuntimeLog.warn(
            "jMG no-archive payload detected; restored media may not be byte-identical to the original input."
        );
    }

    static final class JmgKeys {
        final byte[] baseKey;
        final byte[] archiveKey;
        final byte[] material;
        final byte[] header;
        final int profileId;

        JmgKeys(byte[] baseKey, byte[] archiveKey, byte[] material, byte[] header, int profileId) {
            this.baseKey = baseKey;
            this.archiveKey = archiveKey;
            this.material = material;
            this.header = header;
            this.profileId = profileId;
        }
    }

    static final class JmgHeader {
        final int headerLen;
        final byte[] baseKey;
        final byte[] archiveKey;
        final byte[] material;
        final int profileId;

        JmgHeader(int headerLen, byte[] baseKey, byte[] archiveKey, byte[] material, int profileId) {
            this.headerLen = headerLen;
            this.archiveKey = archiveKey;
            this.baseKey = baseKey;
            this.material = material;
            this.profileId = profileId;
        }
    }

    static final class MaskState {
        final byte[] mask;
        final byte[] rotations;
        final int[] perm;

        MaskState(byte[] mask, byte[] rotations, int[] perm) {
            this.mask = mask;
            this.rotations = rotations;
            this.perm = perm;
        }
    }

    static final class ImageData {
        final int width;
        final int height;
        final int channels;
        final byte[] pixels;
        final String format;

        ImageData(int width, int height, int channels, byte[] pixels, String format) {
            this.width = width;
            this.height = height;
            this.channels = channels;
            this.pixels = pixels;
            this.format = format == null ? "" : format.toLowerCase(Locale.US);
        }
    }

    static final class TrailerSplit {
        final byte[] payload;
        final byte[] trailer;

        TrailerSplit(byte[] payload, byte[] trailer) {
            this.payload = payload;
            this.trailer = trailer;
        }
    }

    static final class TrailerInfo {
        final long blobStart;
        final long blobLen;
        final long trailerStart;

        TrailerInfo(long blobStart, long blobLen, long trailerStart) {
            this.blobStart = blobStart;
            this.blobLen = blobLen;
            this.trailerStart = trailerStart;
        }
    }

}