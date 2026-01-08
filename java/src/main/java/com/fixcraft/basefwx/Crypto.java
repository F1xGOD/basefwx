package com.fixcraft.basefwx;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class Crypto {
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] HKDF_ZERO_SALT = new byte[32];
    // ThreadLocals must be initialized before detectPbkdf2Compat() to avoid init-order bug
    private static final ThreadLocal<Cipher> AES_GCM_ENC = ThreadLocal.withInitial(Crypto::initAesGcmCipher);
    private static final ThreadLocal<Cipher> AES_GCM_DEC = ThreadLocal.withInitial(Crypto::initAesGcmCipher);
    private static final ThreadLocal<Mac> HMAC_SHA256 = ThreadLocal.withInitial(Crypto::initHmacInstance);
    private static final ThreadLocal<SecretKeyFactory> PBKDF2_FACTORY = ThreadLocal.withInitial(Crypto::initPbkdf2Factory);
    // DirectByteBuffer pools for fast AES-GCM (16x faster than byte[] arrays)
    private static final int DIRECT_BUF_SIZE = 8 * 1024 * 1024; // 8 MiB chunks
    private static final ThreadLocal<ByteBuffer> DIRECT_IN = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(DIRECT_BUF_SIZE));
    private static final ThreadLocal<ByteBuffer> DIRECT_OUT = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(DIRECT_BUF_SIZE + Constants.AEAD_TAG_LEN));
    // PBKDF2 compat detection must come after HMAC_SHA256 is initialized
    private static final boolean PBKDF2_NATIVE_ENABLED = resolvePbkdf2Native();
    private static final boolean PBKDF2_JCE_COMPAT = PBKDF2_NATIVE_ENABLED && detectPbkdf2Compat();

    private Crypto() {}

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        if (length > 0) {
            RNG.nextBytes(out);
        }
        return out;
    }

    public static byte[] hkdfSha256(byte[] keyMaterial, byte[] info, int length) {
        byte[] prk = hmacSha256(HKDF_ZERO_SALT, keyMaterial);
        return hkdfExpandRfc(prk, info == null ? new byte[0] : info, length);
    }

    static byte[] hkdfPrkSha256(byte[] keyMaterial) {
        return hmacSha256(HKDF_ZERO_SALT, keyMaterial);
    }

    /**
     * Returns RFC HKDF output for lengths up to {@link Constants#HKDF_MAX_LEN}, and a PRF stream
     * (HMAC-SHA256 with 4-byte counter) for larger lengths.
     */
    @Deprecated
    public static byte[] hkdfSha256Stream(byte[] keyMaterial, byte[] info, int length) {
        if (length <= Constants.HKDF_MAX_LEN) {
            return hkdfSha256(keyMaterial, info, length);
        }
        byte[] prk = hmacSha256(HKDF_ZERO_SALT, keyMaterial);
        return prfStreamHmacSha256(prk, info == null ? new byte[0] : info, length);
    }

    private static byte[] hkdfExpandRfc(byte[] prk, byte[] info, int length) {
        int hashLen = 32;
        int n = (length + hashLen - 1) / hashLen;
        if (n > 255) {
            throw new IllegalArgumentException("HKDF length too large");
        }
        byte[] out = new byte[length];
        byte[] t = new byte[hashLen];
        int tLen = 0;
        int offset = 0;
        Mac mac = initHmac(prk);
        for (int i = 1; i <= n; i++) {
            if (tLen > 0) {
                mac.update(t, 0, tLen);
            }
            if (info.length > 0) {
                mac.update(info);
            }
            mac.update((byte) i);
            try {
                mac.doFinal(t, 0);
                tLen = t.length;
            } catch (GeneralSecurityException exc) {
                throw new IllegalStateException("HKDF expand failed", exc);
            }
            int toCopy = Math.min(tLen, length - offset);
            System.arraycopy(t, 0, out, offset, toCopy);
            offset += toCopy;
        }
        return out;
    }

    private static byte[] prfStreamHmacSha256(byte[] prk, byte[] info, int length) {
        if (length < 0) {
            throw new IllegalArgumentException("length < 0");
        }
        long blocks = (length + 31L) / 32L;
        if (blocks > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("stream too large");
        }
        int hashLen = 32;
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        int counter = 1;
        Mac mac = initHmac(prk);
        byte[] counterBytes = new byte[4];
        while (offset < length) {
            if (t.length > 0) {
                mac.update(t);
            }
            if (info.length > 0) {
                mac.update(info);
            }
            counterBytes[0] = (byte) (counter >>> 24);
            counterBytes[1] = (byte) (counter >>> 16);
            counterBytes[2] = (byte) (counter >>> 8);
            counterBytes[3] = (byte) counter;
            mac.update(counterBytes);
            t = mac.doFinal();
            int toCopy = Math.min(hashLen, length - offset);
            System.arraycopy(t, 0, out, offset, toCopy);
            offset += toCopy;
            counter++;
        }
        return out;
    }

    /**
     * XORs input with a HMAC-SHA256 PRF stream (4-byte counter, not RFC HKDF).
     */
    public static void xorHmacStream(byte[] prk,
                                     byte[] info,
                                     byte[] in,
                                     int inOff,
                                     byte[] out,
                                     int outOff,
                                     int len,
                                     int counterStart) {
        if (len < 0) {
            throw new IllegalArgumentException("length < 0");
        }
        if (len == 0) {
            return;
        }
        if (inOff < 0 || outOff < 0 || inOff + len > in.length || outOff + len > out.length) {
            throw new IllegalArgumentException("Invalid buffer bounds");
        }
        long blocks = (len + 31L) / 32L;
        if (blocks > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("stream too large");
        }
        if (counterStart <= 0) {
            throw new IllegalArgumentException("counterStart must be > 0");
        }
        long endCounter = (long) counterStart + blocks - 1L;
        if (endCounter > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("counter overflow");
        }
        byte[] infoBytes = info == null ? new byte[0] : info;
        try {
            Mac mac = initHmac(prk);
            byte[] t = new byte[32];
            int tLen = 0;
            int offset = 0;
            int counter = counterStart;
            byte[] counterBytes = new byte[4];
            while (offset < len) {
                if (tLen > 0) {
                    mac.update(t, 0, tLen);
                }
                if (infoBytes.length > 0) {
                    mac.update(infoBytes);
                }
                counterBytes[0] = (byte) (counter >>> 24);
                counterBytes[1] = (byte) (counter >>> 16);
                counterBytes[2] = (byte) (counter >>> 8);
                counterBytes[3] = (byte) counter;
                mac.update(counterBytes);
                mac.doFinal(t, 0);
                tLen = t.length;
                int take = Math.min(tLen, len - offset);
                for (int i = 0; i < take; i++) {
                    out[outOff + offset + i] = (byte) (in[inOff + offset + i] ^ t[i]);
                }
                offset += take;
                counter += 1;
            }
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("HKDF stream XOR failed", exc);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        Mac mac = initHmac(key);
        mac.update(data);
        return mac.doFinal();
    }

    static Mac initHmac(byte[] key) {
        try {
            Mac mac = HMAC_SHA256.get();
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("HMAC init failed", exc);
        }
    }

    public static byte[] pbkdf2HmacSha256(byte[] password, byte[] salt, int iterations, int length) {
        if (iterations <= 0) {
            throw new IllegalArgumentException("iterations must be > 0");
        }
        if (length <= 0) {
            throw new IllegalArgumentException("length must be > 0");
        }
        if (PBKDF2_JCE_COMPAT) {
            byte[] fast = pbkdf2HmacSha256Native(password, salt, iterations, length);
            if (fast != null) {
                return fast;
            }
        }
        return pbkdf2HmacSha256Slow(password, salt, iterations, length);
    }

    private static byte[] pbkdf2HmacSha256Native(byte[] password, byte[] salt, int iterations, int length) {
        if (password == null) {
            return null;
        }
        String pwStr = new String(password, StandardCharsets.UTF_8);
        byte[] roundTrip = pwStr.getBytes(StandardCharsets.UTF_8);
        if (!Arrays.equals(roundTrip, password)) {
            return null;
        }
        char[] chars = pwStr.toCharArray();
        try {
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, length * 8);
            SecretKeyFactory factory = PBKDF2_FACTORY.get();
            if (factory == null) {
                return null;
            }
            byte[] out = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return out;
        } catch (GeneralSecurityException exc) {
            return null;
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    private static boolean detectPbkdf2Compat() {
        byte[] pw = "password".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        int iterations = 2;
        int length = 32;
        try {
            byte[] slow = pbkdf2HmacSha256Slow(pw, salt, iterations, length);
            byte[] fast = pbkdf2HmacSha256Native(pw, salt, iterations, length);
            return fast != null && Arrays.equals(fast, slow);
        } catch (RuntimeException exc) {
            return false;
        }
    }

    private static byte[] pbkdf2HmacSha256Slow(byte[] password, byte[] salt, int iterations, int length) {
        int hashLen = 32;
        int blocks = (length + hashLen - 1) / hashLen;
        byte[] output = new byte[length];
        for (int block = 1; block <= blocks; block++) {
            byte[] t = pbkdf2Block(password, salt, iterations, block);
            int offset = (block - 1) * hashLen;
            int toCopy = Math.min(hashLen, length - offset);
            System.arraycopy(t, 0, output, offset, toCopy);
        }
        return output;
    }

    private static byte[] pbkdf2Block(byte[] password, byte[] salt, int iterations, int blockIndex) {
        byte[] blockSalt = new byte[salt.length + 4];
        System.arraycopy(salt, 0, blockSalt, 0, salt.length);
        blockSalt[blockSalt.length - 4] = (byte) ((blockIndex >> 24) & 0xFF);
        blockSalt[blockSalt.length - 3] = (byte) ((blockIndex >> 16) & 0xFF);
        blockSalt[blockSalt.length - 2] = (byte) ((blockIndex >> 8) & 0xFF);
        blockSalt[blockSalt.length - 1] = (byte) (blockIndex & 0xFF);

        Mac mac = initHmac(password);
        byte[] u = new byte[32];
        byte[] t = new byte[32];
        try {
            mac.update(blockSalt);
            mac.doFinal(u, 0);
            System.arraycopy(u, 0, t, 0, u.length);
            for (int i = 1; i < iterations; i++) {
                mac.update(u);
                mac.doFinal(u, 0);
                for (int j = 0; j < t.length; j++) {
                    t[j] ^= u[j];
                }
            }
            return t;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("PBKDF2 failed", exc);
        }
    }

    public static byte[] aesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad) {
        byte[] iv = randomBytes(Constants.AEAD_NONCE_LEN);
        byte[] cipher = aesGcmEncryptWithIv(key, iv, plaintext, aad);
        byte[] out = new byte[iv.length + cipher.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipher, 0, out, iv.length, cipher.length);
        return out;
    }

    public static byte[] aesGcmEncryptWithIv(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) {
        int outLen = plaintext.length + Constants.AEAD_TAG_LEN;
        byte[] out = new byte[outLen];
        int written = aesGcmEncryptWithIvInto(key, iv, plaintext, 0, plaintext.length, out, 0, aad);
        if (written == outLen) {
            return out;
        }
        return Arrays.copyOf(out, Math.max(0, written));
    }

    public static int aesGcmEncryptWithIvInto(byte[] key,
                                              byte[] iv,
                                              byte[] plaintext,
                                              int plainOff,
                                              int plainLen,
                                              byte[] out,
                                              int outOff,
                                              byte[] aad) {
        try {
            Cipher cipher = AES_GCM_ENC.get();
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            // Use DirectByteBuffer for ~16x faster AES-GCM on HotSpot
            // Process in chunks for large data
            ByteBuffer inBuf = DIRECT_IN.get();
            ByteBuffer outBuf = DIRECT_OUT.get();
            int totalWritten = 0;
            int remaining = plainLen;
            int srcOff = plainOff;
            int dstOff = outOff;
            
            while (remaining > DIRECT_BUF_SIZE) {
                // Process full chunks with update()
                inBuf.clear().limit(DIRECT_BUF_SIZE);
                inBuf.put(plaintext, srcOff, DIRECT_BUF_SIZE);
                inBuf.flip();
                outBuf.clear();
                int written = cipher.update(inBuf, outBuf);
                if (written > 0) {
                    outBuf.flip();
                    outBuf.get(out, dstOff, written);
                    totalWritten += written;
                    dstOff += written;
                }
                srcOff += DIRECT_BUF_SIZE;
                remaining -= DIRECT_BUF_SIZE;
            }
            
            // Process final chunk with doFinal()
            inBuf.clear().limit(remaining);
            inBuf.put(plaintext, srcOff, remaining);
            inBuf.flip();
            outBuf.clear();
            int written = cipher.doFinal(inBuf, outBuf);
            outBuf.flip();
            outBuf.get(out, dstOff, written);
            totalWritten += written;
            return totalWritten;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("AES-GCM encrypt failed", exc);
        }
    }

    public static byte[] aesGcmDecrypt(byte[] key, byte[] payload, byte[] aad) {
        if (payload.length < Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN) {
            throw new IllegalArgumentException("AEAD payload too short");
        }
        byte[] iv = new byte[Constants.AEAD_NONCE_LEN];
        byte[] ct = new byte[payload.length - Constants.AEAD_NONCE_LEN];
        System.arraycopy(payload, 0, iv, 0, iv.length);
        System.arraycopy(payload, iv.length, ct, 0, ct.length);
        return aesGcmDecryptWithIv(key, iv, ct, aad);
    }

    public static byte[] aesGcmDecryptWithIv(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) {
        int outLen = ciphertext.length - Constants.AEAD_TAG_LEN;
        if (outLen < 0) {
            throw new IllegalArgumentException("AEAD payload too short");
        }
        byte[] out = new byte[outLen];
        int written = aesGcmDecryptWithIvInto(key, iv, ciphertext, 0, ciphertext.length, out, 0, aad);
        if (written == outLen) {
            return out;
        }
        return Arrays.copyOf(out, Math.max(0, written));
    }

    public static int aesGcmDecryptWithIvInto(byte[] key,
                                              byte[] iv,
                                              byte[] ciphertext,
                                              int ctOff,
                                              int ctLen,
                                              byte[] out,
                                              int outOff,
                                              byte[] aad) {
        try {
            Cipher cipher = AES_GCM_DEC.get();
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            
            // GCM decryption: Must process ALL ciphertext before plaintext (authentication)
            // DirectByteBuffer optimization applies only when ciphertext fits in pooled buffer
            if (ctLen <= DIRECT_BUF_SIZE) {
                // Fits in pooled DirectByteBuffer - ~16x faster
                ByteBuffer inBuf = DIRECT_IN.get();
                ByteBuffer outBuf = DIRECT_OUT.get();
                inBuf.clear().limit(ctLen);
                inBuf.put(ciphertext, ctOff, ctLen);
                inBuf.flip();
                outBuf.clear();
                int written = cipher.doFinal(inBuf, outBuf);
                outBuf.flip();
                outBuf.get(out, outOff, written);
                return written;
            } else {
                // Large data: byte[] fallback (can't use chunked DirectByteBuffer for GCM decrypt output)
                return cipher.doFinal(ciphertext, ctOff, ctLen, out, outOff);
            }
        } catch (GeneralSecurityException exc) {
            throw new IllegalArgumentException("Bad password or corrupted payload", exc);
        }
    }

    private static Cipher initAesGcmCipher() {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("AES-GCM unavailable", exc);
        }
    }

    private static Mac initHmacInstance() {
        try {
            return Mac.getInstance("HmacSHA256");
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("HMAC unavailable", exc);
        }
    }

    private static SecretKeyFactory initPbkdf2Factory() {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (GeneralSecurityException exc) {
            return null;
        }
    }

    private static boolean resolvePbkdf2Native() {
        String raw = System.getenv("BASEFWX_PBKDF2_NATIVE");
        if (raw == null || raw.trim().isEmpty()) {
            return true;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }
}
