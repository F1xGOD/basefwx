/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * X25519 building block mirroring {@code basefwx::x25519} (raw 32-byte keys,
 * wipe private material, reject the all-zero shared secret). Not wired into
 * fwxAES / keywrap file formats.
 *
 * <p>Android sync-list note: when the Android Yume tree is next updated, add
 * {@code X25519.java} to {@code syncBasefwxJava} (Rule 12).
 */
public final class X25519 {
    public static final int KEY_LEN = 32;

    private X25519() {}

    public static final class KeyPairResult {
        public final byte[] publicKey;
        public final byte[] privateKey;

        public KeyPairResult(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /** Wipe the private scalar. Call when done with the keypair. */
        public void wipePrivate() {
            if (privateKey != null) {
                Arrays.fill(privateKey, (byte) 0);
            }
        }
    }

    public static KeyPairResult generateKeyPair() {
        X25519PrivateKeyParameters privateKey =
                new X25519PrivateKeyParameters(new SecureRandom());
        return new KeyPairResult(
                privateKey.generatePublicKey().getEncoded(),
                privateKey.getEncoded());
    }

    public static byte[] deriveSharedSecret(byte[] privateKey, byte[] peerPublicKey) {
        if (privateKey == null || privateKey.length != KEY_LEN) {
            throw new IllegalArgumentException("X25519 private key must be 32 bytes");
        }
        if (peerPublicKey == null || peerPublicKey.length != KEY_LEN) {
            throw new IllegalArgumentException("X25519 public key must be 32 bytes");
        }
        X25519PrivateKeyParameters local =
                new X25519PrivateKeyParameters(privateKey);
        X25519PublicKeyParameters peer =
                new X25519PublicKeyParameters(peerPublicKey);
        byte[] shared = new byte[KEY_LEN];
        try {
            local.generateSecret(peer, shared, 0);
        } catch (IllegalStateException exc) {
            Arrays.fill(shared, (byte) 0);
            throw new IllegalArgumentException(
                    "X25519 peer produced the forbidden all-zero shared secret", exc);
        }
        if (isAllZero(shared)) {
            Arrays.fill(shared, (byte) 0);
            throw new IllegalArgumentException(
                    "X25519 peer produced the forbidden all-zero shared secret");
        }
        return shared;
    }

    private static boolean isAllZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
