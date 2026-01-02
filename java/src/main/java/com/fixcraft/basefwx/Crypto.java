package com.fixcraft.basefwx;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Crypto {
    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {}

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        if (length > 0) {
            RNG.nextBytes(out);
        }
        return out;
    }

    public static byte[] hkdfSha256(byte[] keyMaterial, byte[] info, int length) {
        byte[] salt = new byte[32];
        byte[] prk = hmacSha256(salt, keyMaterial);
        return hkdfExpand(prk, info == null ? new byte[0] : info, length);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        int hashLen = 32;
        int n = (length + hashLen - 1) / hashLen;
        if (n > 255) {
            throw new IllegalArgumentException("HKDF length too large");
        }
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        for (int i = 1; i <= n; i++) {
            Mac mac = initHmac(prk);
            mac.update(t);
            if (info.length > 0) {
                mac.update(info);
            }
            mac.update((byte) i);
            t = mac.doFinal();
            int toCopy = Math.min(hashLen, length - offset);
            System.arraycopy(t, 0, out, offset, toCopy);
            offset += toCopy;
        }
        return out;
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        Mac mac = initHmac(key);
        mac.update(data);
        return mac.doFinal();
    }

    private static Mac initHmac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("HMAC init failed", exc);
        }
    }

    public static byte[] pbkdf2HmacSha256(byte[] password, byte[] salt, int iterations, int length) {
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
        byte[] u = mac.doFinal(blockSalt);
        byte[] t = u.clone();
        for (int i = 1; i < iterations; i++) {
            u = mac.doFinal(u);
            for (int j = 0; j < t.length; j++) {
                t[j] ^= u[j];
            }
        }
        return t;
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
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
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
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(Constants.AEAD_TAG_LEN * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("AES-GCM decrypt failed", exc);
        }
    }
}
