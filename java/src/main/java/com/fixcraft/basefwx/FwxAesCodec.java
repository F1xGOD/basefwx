/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class FwxAesCodec {
    private FwxAesCodec() {}

    static final int STREAM_CHUNK = 1 << 20;

    static byte[] fwxAesEncryptRaw(byte[] plaintext, String password, boolean useMaster) {
        if (plaintext == null) {
            throw new IllegalArgumentException("fwxAES_encrypt_raw expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        return fwxAesEncryptRawBytes(plaintext, pw, useMaster);
    }

    static byte[] fwxAesEncryptRawBytes(byte[] plaintext, byte[] passwordBytes, boolean useMaster) {
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
            try {
                int ctLen = plaintext.length + Constants.AEAD_TAG_LEN;
                byte[] out = new byte[16 + keyHeader.length + iv.length + ctLen];
                System.arraycopy(Constants.FWXAES_MAGIC, 0, out, 0, Constants.FWXAES_MAGIC.length);
                out[4] = (byte) Constants.FWXAES_ALGO;
                out[5] = (byte) Constants.FWXAES_KDF_WRAP;
                out[6] = 0;
                out[7] = (byte) Constants.FWXAES_IV_LEN;
                BaseFwxUtil.writeU32(out, 8, keyHeader.length);
                BaseFwxUtil.writeU32(out, 12, ctLen);
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
            } finally {
                // Mirror C++'s SecretGuard discipline: wipe the AES key
                // and the wrap mask before the buffers escape into GC.
                Arrays.fill(key, (byte) 0);
                if (maskKey.length > 0) {
                    Arrays.fill(maskKey, (byte) 0);
                }
            }
        }

        byte[] salt = Crypto.randomBytes(Constants.FWXAES_SALT_LEN);
        int iters = fwxaesIterations(pw);
        byte[] key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
        try {
            int ctLen = plaintext.length + Constants.AEAD_TAG_LEN;
            byte[] out = new byte[16 + salt.length + iv.length + ctLen];
            System.arraycopy(Constants.FWXAES_MAGIC, 0, out, 0, Constants.FWXAES_MAGIC.length);
            out[4] = (byte) Constants.FWXAES_ALGO;
            out[5] = (byte) Constants.FWXAES_KDF_PBKDF2;
            out[6] = (byte) Constants.FWXAES_SALT_LEN;
            out[7] = (byte) Constants.FWXAES_IV_LEN;
            BaseFwxUtil.writeU32(out, 8, iters);
            BaseFwxUtil.writeU32(out, 12, ctLen);
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
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static byte[] fwxAesDecryptRaw(byte[] blob, String password, boolean useMaster) {
        if (blob == null) {
            throw new IllegalArgumentException("fwxAES_decrypt_raw expects bytes");
        }
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        return fwxAesDecryptRawBytes(blob, pw, useMaster);
    }

    static byte[] fwxAesDecryptRawBytes(byte[] blob, byte[] passwordBytes, boolean useMaster) {
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
        int iters = BaseFwxUtil.readU32(blob, 8);
        int ctLen = BaseFwxUtil.readU32(blob, 12);
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
            try {
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
            } finally {
                // Mirror C++ SecretGuard: wipe AES key and wrap mask
                // before they escape into GC.
                Arrays.fill(key, (byte) 0);
                if (maskKey.length > 0) {
                    Arrays.fill(maskKey, (byte) 0);
                }
            }
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
        try {
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
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }
    static int fwxaesIterations(byte[] pw) {
        int iters = Constants.FWXAES_PBKDF2_ITERS;
        if (Constants.TEST_KDF_OVERRIDE) {
            return iters;
        }
        if (pw.length > 0 && pw.length < Constants.SHORT_PASSWORD_MIN) {
            iters = Math.max(iters, Constants.SHORT_PBKDF2_ITERS);
        }
        return iters;
    }

    static long fwxAesEncryptStreamInternal(InputStream input,
                                                    OutputStream output,
                                                    String password,
                                                    boolean useMaster) throws IOException {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
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
            BaseFwxUtil.writeU32(header, 8, keyHeader.length);
            BaseFwxUtil.writeU32(header, 12, 0);
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
            BaseFwxUtil.writeU32(header, 8, iters);
            BaseFwxUtil.writeU32(header, 12, 0);
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

    static long fwxAesEncryptChannel(FileChannel input,
                                             FileChannel output,
                                             String password,
                                             boolean useMaster) throws IOException {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
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
            BaseFwxUtil.writeU32(header, 8, keyHeader.length);
            BaseFwxUtil.writeU32(header, 12, 0);
            FileCodecs.writeFully(output, ByteBuffer.wrap(header));
            if (keyHeader.length > 0) {
                FileCodecs.writeFully(output, ByteBuffer.wrap(keyHeader));
            }
            FileCodecs.writeFully(output, ByteBuffer.wrap(iv));
        } else {
            byte[] salt = Crypto.randomBytes(Constants.FWXAES_SALT_LEN);
            int iters = fwxaesIterations(pw);
            key = Crypto.pbkdf2HmacSha256(pw, salt, iters, Constants.FWXAES_KEY_LEN);
            header[5] = (byte) Constants.FWXAES_KDF_PBKDF2;
            header[6] = (byte) Constants.FWXAES_SALT_LEN;
            header[7] = (byte) Constants.FWXAES_IV_LEN;
            BaseFwxUtil.writeU32(header, 8, iters);
            BaseFwxUtil.writeU32(header, 12, 0);
            FileCodecs.writeFully(output, ByteBuffer.wrap(header));
            FileCodecs.writeFully(output, ByteBuffer.wrap(salt));
            FileCodecs.writeFully(output, ByteBuffer.wrap(iv));
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
                    FileCodecs.writeFully(output, outBuf);
                    ctLen += outLen;
                }
                inBuf.clear();
            }
            outBuf.clear();
            int finalLen = cipher.doFinal(ByteBuffer.allocate(0), outBuf);
            if (finalLen > 0) {
                outBuf.flip();
                FileCodecs.writeFully(output, outBuf);
                ctLen += finalLen;
            }
            return ctLen;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("fwxAES encrypt failed", exc);
        }
    }

    static void fwxAesDecryptChannel(FileChannel input,
                                             FileChannel output,
                                             String password,
                                             boolean useMaster) throws IOException {
        byte[] header = new byte[16];
        FileCodecs.readExactChannel(input, ByteBuffer.wrap(header), header.length, "fwxAES blob too short");
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
        int iters = BaseFwxUtil.readU32(header, 8);
        int ctLen = BaseFwxUtil.readU32(header, 12);
        if (ctLen < Constants.AEAD_TAG_LEN) {
            throw new IllegalArgumentException("fwxAES ciphertext too short");
        }
        byte[] key;
        byte[] iv;
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        if (kdf == Constants.FWXAES_KDF_WRAP) {
            int headerLen = iters;
            byte[] keyHeader = new byte[headerLen];
            if (headerLen > 0) {
                FileCodecs.readExactChannel(input, ByteBuffer.wrap(keyHeader), headerLen, "fwxAES blob truncated");
            }
            iv = new byte[ivLen];
            FileCodecs.readExactChannel(input, ByteBuffer.wrap(iv), ivLen, "fwxAES blob truncated");
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
            FileCodecs.readExactChannel(input, ByteBuffer.wrap(salt), saltLen, "fwxAES blob truncated");
            iv = new byte[ivLen];
            FileCodecs.readExactChannel(input, ByteBuffer.wrap(iv), ivLen, "fwxAES blob truncated");
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
                FileCodecs.readExactChannel(input, inBuf, toRead, "fwxAES blob truncated");
                outBuf.clear();
                int outLen = cipher.update(inBuf, outBuf);
                if (outLen > 0) {
                    outBuf.flip();
                    FileCodecs.writeFully(output, outBuf);
                }
                remaining -= toRead;
            }
            ByteBuffer tagBuf = ByteBuffer.allocate(Constants.AEAD_TAG_LEN);
            FileCodecs.readExactChannel(input, tagBuf, Constants.AEAD_TAG_LEN, "fwxAES blob truncated");
            outBuf.clear();
            try {
                int finalLen = cipher.doFinal(tagBuf, outBuf);
                if (finalLen > 0) {
                    outBuf.flip();
                    FileCodecs.writeFully(output, outBuf);
                }
            } catch (AEADBadTagException exc) {
                throw new IllegalArgumentException("AES-GCM auth failed");
            }
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("fwxAES decrypt failed", exc);
        }
    }

    static void patchCtLen(FileOutputStream output, long ctLen) throws IOException {
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

    static void patchCtLen(FileChannel channel, long ctLen) throws IOException {
        if (ctLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("fwxAES ciphertext too large");
        }
        long pos = channel.position();
        ByteBuffer buf = ByteBuffer.allocate(4);
        buf.putInt((int) ctLen);
        buf.flip();
        channel.position(12);
        FileCodecs.writeFully(channel, buf);
        channel.position(pos);
    }
    static void copyStream(InputStream input, OutputStream output) throws IOException {
        byte[] buf = new byte[STREAM_CHUNK];
        int read;
        while ((read = input.read(buf)) != -1) {
            output.write(buf, 0, read);
        }
        output.flush();
    }

    static long fwxAesDecryptStreamPublic(InputStream input,
                                          OutputStream output,
                                          String password,
                                          boolean useMaster) throws IOException {
        byte[] header = new byte[16];
        FileCodecs.readExact(input, header, header.length, "fwxAES blob too short");
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
        int iters = BaseFwxUtil.readU32(header, 8);
        int ctLen = BaseFwxUtil.readU32(header, 12);
        if (ctLen < Constants.AEAD_TAG_LEN) {
            throw new IllegalArgumentException("fwxAES ciphertext too short");
        }
        byte[] key;
        byte[] iv;
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        if (kdf == Constants.FWXAES_KDF_WRAP) {
            int headerLen = iters;
            byte[] keyHeader = new byte[headerLen];
            if (headerLen > 0) {
                FileCodecs.readExact(input, keyHeader, headerLen, "fwxAES blob truncated");
            }
            iv = new byte[ivLen];
            FileCodecs.readExact(input, iv, ivLen, "fwxAES blob truncated");
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
            FileCodecs.readExact(input, salt, saltLen, "fwxAES blob truncated");
            iv = new byte[ivLen];
            FileCodecs.readExact(input, iv, ivLen, "fwxAES blob truncated");
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
                    FileCodecs.readExact(input, buf, toRead, "fwxAES blob truncated");
                    int outLen = dec.update(buf, 0, toRead, outBuf, outBufOffset);
                    outBufOffset += outLen;
                    remaining -= toRead;
                }
                byte[] tag = new byte[Constants.AEAD_TAG_LEN];
                FileCodecs.readExact(input, tag, tag.length, "fwxAES blob truncated");
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

    static long fwxAesEncryptStreamPublic(InputStream input,
                                          OutputStream output,
                                          String password,
                                          boolean useMaster) throws IOException {
        if (output instanceof FileOutputStream) {
            long ctLen = fwxAesEncryptStreamInternal(input, output, password, useMaster);
            patchCtLen((FileOutputStream) output, ctLen);
            return ctLen;
        }
        File temp = BaseFwx.createPrivateTempFile("basefwx-fwxaes-", ".tmp");
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

}
