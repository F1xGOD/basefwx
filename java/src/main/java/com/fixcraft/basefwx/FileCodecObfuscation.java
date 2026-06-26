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

final class FileCodecObfuscation {
    private FileCodecObfuscation() {}

static final int PERF_OBFUSCATION_THRESHOLD = 1 << 20;

static boolean payloadObfuscationEnabled() {
        String raw = System.getenv("BASEFWX_OBFUSCATE");
        if (raw == null || raw.trim().isEmpty()) {
            return true;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

static boolean perfModeEnabled() {
        String raw = System.getenv("BASEFWX_PERF");
        if (raw == null || raw.trim().isEmpty()) {
            return false;
        }
        String v = raw.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

static boolean useFastObfuscation(long length) {
        return perfModeEnabled() && length >= PERF_OBFUSCATION_THRESHOLD;
    }

static byte[] obfuscateBytes(byte[] data, byte[] key) {
        return obfuscateBytes(data, key, useFastObfuscation(data.length));
    }

static byte[] obfuscateBytes(byte[] data, byte[] key, boolean fast) {
        if (data.length == 0) {
            return data;
        }
        byte[] out = data.clone();
        xorKeystreamInPlace(out, key, Constants.OBF_INFO_MASK);
        if (!fast) {
            byte[] info = buildInfoWithLength(Constants.OBF_INFO_PERM, data.length);
            byte[] seedBytes = Crypto.hkdfSha256(key, info, 16);
            long seed = seed64FromBytes(seedBytes);
            reverseInPlace(out);
            permuteInPlace(out, seed);
        }
        return out;
    }

static byte[] deobfuscateBytes(byte[] data, byte[] key) {
        return deobfuscateBytes(data, key, useFastObfuscation(data.length));
    }

static byte[] deobfuscateBytes(byte[] data, byte[] key, boolean fast) {
        if (data.length == 0) {
            return data;
        }
        byte[] out = data.clone();
        if (!fast) {
            byte[] info = buildInfoWithLength(Constants.OBF_INFO_PERM, data.length);
            byte[] seedBytes = Crypto.hkdfSha256(key, info, 16);
            long seed = seed64FromBytes(seedBytes);
            unpermuteInPlace(out, seed);
            reverseInPlace(out);
        }
        xorKeystreamInPlace(out, key, Constants.OBF_INFO_MASK);
        return out;
    }

static byte[] buildInfoWithLength(byte[] prefix, int length) {
        byte[] out = new byte[prefix.length + 8];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        long len = length & 0xFFFFFFFFFFFFFFFFL;
        for (int i = 7; i >= 0; i--) {
            out[prefix.length + i] = (byte) (len & 0xFF);
            len >>>= 8;
        }
        return out;
    }

static void xorKeystreamInPlace(byte[] buf, byte[] key, byte[] info) {
        if (buf.length == 0) {
            return;
        }
        byte[] blockKey = Crypto.hkdfSha256(key, info, 32);
        byte[] lenBytes = new byte[8];
        long len = buf.length & 0xFFFFFFFFFFFFFFFFL;
        for (int i = 7; i >= 0; i--) {
            lenBytes[i] = (byte) (len & 0xFF);
            len >>>= 8;
        }
        long ctr = 0;
        int offset = 0;
        while (offset < buf.length) {
            byte[] ctrBytes = new byte[8];
            long val = ctr;
            for (int i = 7; i >= 0; i--) {
                ctrBytes[i] = (byte) (val & 0xFF);
                val >>>= 8;
            }
            byte[] data = new byte[info.length + lenBytes.length + ctrBytes.length];
            System.arraycopy(info, 0, data, 0, info.length);
            System.arraycopy(lenBytes, 0, data, info.length, lenBytes.length);
            System.arraycopy(ctrBytes, 0, data, info.length + lenBytes.length, ctrBytes.length);
            byte[] block = Crypto.hmacSha256(blockKey, data);
            int take = Math.min(block.length, buf.length - offset);
            for (int i = 0; i < take; i++) {
                buf[offset + i] = (byte) (buf[offset + i] ^ block[i]);
            }
            offset += take;
            ctr += 1;
        }
    }

static long seed64FromBytes(byte[] seedBytes) {
        if (seedBytes.length < 8) {
            return 0L;
        }
        long out = 0L;
        int start = seedBytes.length - 8;
        for (int i = 0; i < 8; i++) {
            out = (out << 8) | (seedBytes[start + i] & 0xFFL);
        }
        return out;
    }

static void reverseInPlace(byte[] data) {
        for (int i = 0, j = data.length - 1; i < j; i++, j--) {
            byte tmp = data[i];
            data[i] = data[j];
            data[j] = tmp;
        }
    }

static final ThreadLocal<int[]> PERM_SWAP_CACHE = ThreadLocal.withInitial(() -> new int[0]);

static void permuteInPlace(byte[] data, long seed) {
        permuteInPlace(data, data.length, seed);
    }

static void permuteInPlace(byte[] data, int length, long seed) {
        int n = length;
        if (n < 2) {
            return;
        }
        if (n >= 4096) {
            Pcg64Rng rng = new Pcg64Rng(seed);
            for (int i = n - 1; i > 0; i--) {
                int j = (int) rng.randomInterval(i);
                if (j != i) {
                    byte tmp = data[i];
                    data[i] = data[j];
                    data[j] = tmp;
                }
            }
            return;
        }
        long[] state = new long[]{seed};
        for (int i = n - 1; i > 0; i--) {
            long rnd = splitMix64Next(state);
            int j = (int) Long.remainderUnsigned(rnd, i + 1L);
            if (j != i) {
                byte tmp = data[i];
                data[i] = data[j];
                data[j] = tmp;
            }
        }
    }

static void unpermuteInPlace(byte[] data, long seed) {
        unpermuteInPlace(data, data.length, seed);
    }

static void unpermuteInPlace(byte[] data, int length, long seed) {
        int n = length;
        if (n < 2) {
            return;
        }
        if (n >= 4096) {
            Pcg64Rng rng = new Pcg64Rng(seed);
            int[] swaps = PERM_SWAP_CACHE.get();
            if (swaps.length < n) {
                swaps = new int[n];
                PERM_SWAP_CACHE.set(swaps);
            }
            for (int i = n - 1; i > 0; i--) {
                swaps[i] = (int) rng.randomInterval(i);
            }
            for (int i = 1; i < n; i++) {
                int j = swaps[i];
                if (j != i) {
                    byte tmp = data[i];
                    data[i] = data[j];
                    data[j] = tmp;
                }
            }
            return;
        }
        int total = n - 1;
        int[] swapI = new int[total];
        int[] swapJ = new int[total];
        long[] state = new long[]{seed};
        int idx = 0;
        for (int i = n - 1; i > 0; i--) {
            long rnd = splitMix64Next(state);
            int j = (int) Long.remainderUnsigned(rnd, i + 1L);
            swapI[idx] = i;
            swapJ[idx] = j;
            idx++;
        }
        for (int k = idx - 1; k >= 0; k--) {
            int i = swapI[k];
            int j = swapJ[k];
            if (j != i) {
                byte tmp = data[i];
                data[i] = data[j];
                data[j] = tmp;
            }
        }
    }

static long splitMix64Next(long[] state) {
        long z = state[0] + 0x9E3779B97F4A7C15L;
        state[0] = z;
        long x = z;
        x = (x ^ (x >>> 30)) * 0xBF58476D1CE4E5B9L;
        x = (x ^ (x >>> 27)) * 0x94D049BB133111EBL;
        x ^= (x >>> 31);
        return x;
    }

static final class Pcg64Rng {
        private static final long MULT_HI = 2549297995355413924L;
        private static final long MULT_LO = 4865540595714422341L;
        private long stateHi = 0L;
        private long stateLo = 0L;
        private long incHi = 0L;
        private long incLo = 0L;
        private boolean hasUint32 = false;
        private int cachedUint32 = 0;

        Pcg64Rng(long seed) {
            long[] stateVals = seedSequenceState(seed);
            seed(stateVals[0], stateVals[1], stateVals[2], stateVals[3]);
            hasUint32 = false;
            cachedUint32 = 0;
            next64();
        }

        long next64() {
            long oldHi = stateHi;
            long oldLo = stateLo;
            step();
            long xorshifted = oldHi ^ oldLo;
            long rot = oldHi >>> 58;
            return Long.rotateRight(xorshifted, (int) rot);
        }

        int next32() {
            if (hasUint32) {
                hasUint32 = false;
                return cachedUint32;
            }
            long next = next64();
            hasUint32 = true;
            cachedUint32 = (int) (next >>> 32);
            return (int) next;
        }

        long randomInterval(long max) {
            if (max == 0) {
                return 0;
            }
            long mask = max;
            mask |= mask >>> 1;
            mask |= mask >>> 2;
            mask |= mask >>> 4;
            mask |= mask >>> 8;
            mask |= mask >>> 16;
            mask |= mask >>> 32;
            if (Long.compareUnsigned(max, 0xFFFFFFFFL) <= 0) {
                long value;
                do {
                    value = (next32() & 0xFFFFFFFFL) & mask;
                } while (Long.compareUnsigned(value, max) > 0);
                return value;
            }
            long value;
            do {
                value = next64() & mask;
            } while (Long.compareUnsigned(value, max) > 0);
            return value;
        }

        private void seed(long seedHigh, long seedLow, long incHigh, long incLow) {
            stateHi = 0L;
            stateLo = 0L;
            long initSeqHi = incHigh;
            long initSeqLo = incLow;
            incHi = (initSeqHi << 1) | (initSeqLo >>> 63);
            incLo = (initSeqLo << 1) | 1L;
            step();
            addState(seedHigh, seedLow);
            step();
        }

        private void step() {
            long prodLo = stateLo * MULT_LO;
            long prodHi = mulHighUnsigned(stateLo, MULT_LO);
            prodHi += stateLo * MULT_HI;
            prodHi += stateHi * MULT_LO;
            long lo = prodLo + incLo;
            long carry = Long.compareUnsigned(lo, prodLo) < 0 ? 1L : 0L;
            long hi = prodHi + incHi + carry;
            stateHi = hi;
            stateLo = lo;
        }

        private void addState(long addHi, long addLo) {
            long lo = stateLo + addLo;
            long carry = Long.compareUnsigned(lo, stateLo) < 0 ? 1L : 0L;
            stateLo = lo;
            stateHi = stateHi + addHi + carry;
        }

        private long mulHighUnsigned(long x, long y) {
            long x0 = x & 0xFFFFFFFFL;
            long x1 = x >>> 32;
            long y0 = y & 0xFFFFFFFFL;
            long y1 = y >>> 32;

            long z0 = x0 * y0;
            long t = x1 * y0 + (z0 >>> 32);
            long z1 = t & 0xFFFFFFFFL;
            long z2 = t >>> 32;
            t = x0 * y1 + z1;
            long high = x1 * y1 + z2 + (t >>> 32);
            return high;
        }

        private long[] seedSequenceState(long entropy) {
            int[] pool = seedPool(entropy);
            int[] state32 = new int[8];
            int hashConst = 0x8b51f9dd;
            for (int i = 0; i < state32.length; i++) {
                int dataVal = pool[i % pool.length];
                dataVal ^= hashConst;
                hashConst = (int) ((hashConst * 0x58f38dedL) & 0xFFFFFFFFL);
                dataVal = (int) ((dataVal * (long) hashConst) & 0xFFFFFFFFL);
                dataVal ^= (dataVal >>> 16);
                state32[i] = dataVal;
            }
            long[] state64 = new long[4];
            for (int i = 0; i < state64.length; i++) {
                long lo = state32[i * 2] & 0xFFFFFFFFL;
                long hi = state32[i * 2 + 1] & 0xFFFFFFFFL;
                state64[i] = lo | (hi << 32);
            }
            return state64;
        }

        private int[] seedPool(long entropy) {
            int[] pool = new int[4];
            int[] entropyArray = intToUint32Array(entropy);
            int[] hashConst = new int[]{0x43b0d7e5};
            for (int i = 0; i < pool.length; i++) {
                int value = i < entropyArray.length ? entropyArray[i] : 0;
                pool[i] = hashMix(value, hashConst);
            }
            for (int iSrc = 0; iSrc < pool.length; iSrc++) {
                for (int iDst = 0; iDst < pool.length; iDst++) {
                    if (iSrc == iDst) {
                        continue;
                    }
                    pool[iDst] = mix32(pool[iDst], hashMix(pool[iSrc], hashConst));
                }
            }
            for (int iSrc = pool.length; iSrc < entropyArray.length; iSrc++) {
                for (int iDst = 0; iDst < pool.length; iDst++) {
                    pool[iDst] = mix32(pool[iDst], hashMix(entropyArray[iSrc], hashConst));
                }
            }
            return pool;
        }

        private int[] intToUint32Array(long n) {
            if (n == 0) {
                return new int[]{0};
            }
            int[] tmp = new int[2];
            int count = 0;
            long value = n;
            while (value != 0) {
                tmp[count++] = (int) (value & 0xFFFFFFFFL);
                value >>>= 32;
            }
            int[] out = new int[count];
            System.arraycopy(tmp, 0, out, 0, count);
            return out;
        }

        private int hashMix(int value, int[] hashConst) {
            int v = value ^ hashConst[0];
            hashConst[0] = (int) ((hashConst[0] * 0x931e8875L) & 0xFFFFFFFFL);
            v = (int) ((v * (long) hashConst[0]) & 0xFFFFFFFFL);
            v ^= (v >>> 16);
            return v;
        }

        private int mix32(int x, int y) {
            long result = (0xca01f9ddL * (x & 0xFFFFFFFFL)) - (0x4973f715L * (y & 0xFFFFFFFFL));
            result &= 0xFFFFFFFFL;
            result ^= (result >>> 16);
            return (int) result;
        }
    }

static final class StreamObfuscator {
        private final Cipher ctrCipher;
        private final Mac permMac;
        private final byte[] permInfo;
        private final boolean fast;
        private long chunkIndex = 0L;

        private StreamObfuscator(Mac permMac, Cipher ctrCipher, boolean fast) {
            this.permMac = permMac;
            this.permInfo = new byte[Constants.STREAM_INFO_PERM.length + 8];
            System.arraycopy(Constants.STREAM_INFO_PERM, 0, permInfo, 0, Constants.STREAM_INFO_PERM.length);
            this.ctrCipher = ctrCipher;
            this.fast = fast;
        }

        static byte[] generateSalt() {
            return Crypto.randomBytes(Constants.STREAM_SALT_LEN);
        }

        static StreamObfuscator forPassword(byte[] password, byte[] salt, boolean fast) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password required for streaming obfuscation");
            }
            if (salt == null || salt.length < Constants.STREAM_SALT_LEN) {
                throw new IllegalArgumentException("Streaming obfuscation salt must be at least 16 bytes");
            }
            byte[] base = new byte[password.length + salt.length];
            System.arraycopy(password, 0, base, 0, password.length);
            System.arraycopy(salt, 0, base, password.length, salt.length);
            byte[] maskKey = Crypto.hkdfSha256(base, Constants.STREAM_INFO_KEY, 32);
            // lgtm[java/static-initialization-vector] - IV derived from HKDF with password+random salt, unique per stream
            byte[] iv = Crypto.hkdfSha256(base, Constants.STREAM_INFO_IV, 16);
            byte[] permMaterial = Crypto.hkdfSha256(base, Constants.STREAM_INFO_PERM, 32);
            byte[] permPrk = Crypto.hkdfPrkSha256(permMaterial);
            Mac permMac = Crypto.initHmac(permPrk);
            try {
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                // IV is derived from HKDF at line 2181 using password+salt, unique per stream
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(maskKey, "AES"), new IvParameterSpec(iv));
                return new StreamObfuscator(permMac, cipher, fast);
            } catch (GeneralSecurityException exc) {
                throw new IllegalStateException("AES-CTR init failed", exc);
            }
        }

        void encodeChunkInPlace(byte[] buffer) {
            encodeChunkInPlace(buffer, buffer.length);
        }

        void encodeChunkInPlace(byte[] buffer, int length) {
            if (length <= 0) {
                return;
            }
            if (fast) {
                applyCtrInPlace(buffer, length);
                chunkIndex += 1;
                return;
            }
            ChunkParams params = nextParams();
            applyCtrInPlace(buffer, length);
            if (params.swap) {
                swapNibbles(buffer, length);
            }
            if (params.rotation != 0) {
                rotateLeft(buffer, length, params.rotation);
            }
            permuteInPlace(buffer, length, params.seed);
        }

        void decodeChunkInPlace(byte[] buffer) {
            decodeChunkInPlace(buffer, buffer.length);
        }

        void decodeChunkInPlace(byte[] buffer, int length) {
            if (length <= 0) {
                return;
            }
            if (fast) {
                applyCtrInPlace(buffer, length);
                chunkIndex += 1;
                return;
            }
            ChunkParams params = nextParams();
            unpermuteInPlace(buffer, length, params.seed);
            if (params.rotation != 0) {
                rotateRight(buffer, length, params.rotation);
            }
            if (params.swap) {
                swapNibbles(buffer, length);
            }
            applyCtrInPlace(buffer, length);
        }

        private void applyCtrInPlace(byte[] buffer, int length) {
            if (length <= 0) {
                return;
            }
            try {
                int outLen = ctrCipher.update(buffer, 0, length, buffer, 0);
                if (outLen != length) {
                    throw new IllegalStateException("AES-CTR output length mismatch");
                }
            } catch (GeneralSecurityException exc) {
                throw new IllegalStateException("AES-CTR update failed", exc);
            }
        }

        private ChunkParams nextParams() {
            byte[] info = permInfo;
            long idx = chunkIndex;
            for (int i = 7; i >= 0; i--) {
                info[Constants.STREAM_INFO_PERM.length + i] = (byte) (idx & 0xFF);
                idx >>>= 8;
            }
            permMac.update(info);
            permMac.update((byte) 1);
            byte[] seedBytes = permMac.doFinal();
            ChunkParams params = new ChunkParams();
            params.seed = seed64FromBytes(seedBytes);
            params.rotation = seedBytes[0] & 0x07;
            params.swap = (seedBytes[1] & 0x01) != 0;
            chunkIndex += 1;
            return params;
        }

        private static void swapNibbles(byte[] buffer) {
            swapNibbles(buffer, buffer.length);
        }

        private static void swapNibbles(byte[] buffer, int length) {
            for (int i = 0; i < length; i++) {
                int b = buffer[i] & 0xFF;
                buffer[i] = (byte) ((b >>> 4) | ((b & 0x0F) << 4));
            }
        }

        private static void rotateLeft(byte[] buffer, int rotation) {
            rotateLeft(buffer, buffer.length, rotation);
        }

        private static void rotateLeft(byte[] buffer, int length, int rotation) {
            if (rotation == 0 || length == 0) {
                return;
            }
            for (int i = 0; i < length; i++) {
                int b = buffer[i] & 0xFF;
                buffer[i] = (byte) ((b << rotation) | (b >>> (8 - rotation)));
            }
        }

        private static void rotateRight(byte[] buffer, int rotation) {
            rotateRight(buffer, buffer.length, rotation);
        }

        private static void rotateRight(byte[] buffer, int length, int rotation) {
            if (rotation == 0 || length == 0) {
                return;
            }
            for (int i = 0; i < length; i++) {
                int b = buffer[i] & 0xFF;
                buffer[i] = (byte) ((b >>> rotation) | (b << (8 - rotation)));
            }
        }

        private static final class ChunkParams {
            long seed;
            int rotation;
            boolean swap;
        }
    }
}
