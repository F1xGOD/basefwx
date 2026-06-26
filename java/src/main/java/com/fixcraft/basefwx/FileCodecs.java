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

final class FileCodecs {
    private FileCodecs() {}

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

    static String resolveUserKdfLabel() {
        String raw = System.getenv("BASEFWX_USER_KDF");
        if (raw == null || raw.trim().isEmpty()) {
            return "pbkdf2";
        }
        return resolveKdfLabel(raw.trim().toLowerCase());
    }

    static String resolveKdfLabel(String label) {
        if (label == null || label.isEmpty() || "auto".equalsIgnoreCase(label)) {
            return "pbkdf2";
        }
        String normalized = label.toLowerCase();
        if (normalized.startsWith("argon2")) {
            // 3.6.5: Java now supports Argon2id (via BouncyCastle); see KeyWrap.resolveKdfLabel.
            return "argon2id";
        }
        if (!"pbkdf2".equals(normalized)) {
            throw new UnsupportedKdfException(normalized,
                    "Unsupported KDF label: " + normalized);
        }
        return normalized;
    }

    static int parseMetadataInt(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

    static int hardenPbkdf2Iterations(byte[] password, int iterations) {
        if (password == null || password.length == 0) {
            return iterations;
        }
        if (Constants.TEST_KDF_OVERRIDE) {
            return iterations;
        }
        if (password.length < Constants.SHORT_PASSWORD_MIN) {
            return Math.max(iterations, Constants.SHORT_PBKDF2_ITERS);
        }
        return iterations;
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
    static boolean isStreamMode(String metadataBlob) {
        if (metadataBlob == null || metadataBlob.isEmpty()) {
            return false;
        }
        String mode = metaValue(metadataBlob, "ENC-MODE");
        return "stream".equalsIgnoreCase(mode);
    }

    static String peekMetadataBlob(File input) {
        try (FileInputStream in = new FileInputStream(input)) {
            int lenUser = readU32(in, "Ciphertext payload truncated");
            skipFully(in, lenUser, "Ciphertext payload truncated");
            int lenMaster = readU32(in, "Ciphertext payload truncated");
            skipFully(in, lenMaster, "Ciphertext payload truncated");
            int lenPayload = readU32(in, "Ciphertext payload truncated");
            if (lenPayload < 4) {
                return "";
            }
            int metaLen = readU32(in, "Ciphertext payload truncated");
            if (metaLen <= 0) {
                return "";
            }
            byte[] meta = readExactBytes(in, metaLen, "Ciphertext payload truncated");
            return new String(meta, StandardCharsets.UTF_8);
        } catch (IOException | IllegalArgumentException exc) {
            return "";
        }
    }

    static byte[] buildStreamHeader(long inputSize,
                                            byte[] streamSalt,
                                            byte[] extBytes,
                                            int chunkSize) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(Constants.STREAM_MAGIC);
            writeU32(out, chunkSize);
            writeU64(out, inputSize);
            out.write(streamSalt);
            writeU16(out, extBytes.length);
            if (extBytes.length > 0) {
                out.write(extBytes);
            }
        } catch (IOException exc) {
            throw new IllegalStateException("Stream header build failed", exc);
        }
        return out.toByteArray();
    }

    static File resolveDecodedOutput(File input, File output, byte[] extBytes) {
        if (output != null) {
            return output;
        }
        String name = input.getName();
        if (name.endsWith(".fwx")) {
            name = name.substring(0, name.length() - 4);
        }
        String ext = "";
        if (extBytes.length > 0) {
            ext = new String(extBytes, StandardCharsets.UTF_8);
        }
        if (!ext.isEmpty()) {
            name += ext;
        }
        return new File(input.getParentFile(), name);
    }
    static File b512FileEncodeFileStream(File input,
                                                 File output,
                                                 String password,
                                                 boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for streaming b512 encode");
        }
        boolean useMasterEffective = false;
        if (useMaster) {
            try {
                java.security.PublicKey pub = EcKeys.loadMasterPublic(EcKeys.masterEcAutoCreateEnabled());
                useMasterEffective = pub != null;
            } catch (RuntimeException exc) {
                useMasterEffective = false;
            }
        }
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
            pw,
            useMasterEffective,
            Constants.B512_FILE_MASK_INFO,
            !useMasterEffective,
            Constants.B512_AEAD_INFO,
            new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
        );
        useMasterEffective = useMasterEffective && mask.usedMaster;
        String ext = BaseFwx.getExtension(input);
        byte[] extBytes = ext.isEmpty() ? new byte[0] : ext.getBytes(StandardCharsets.UTF_8);
        byte[] streamSalt = StreamObfuscator.generateSalt();
        boolean fastObf = useFastObfuscation(input.length());
        String metadata = buildMetadata("FWX512R", false, useMasterEffective, "AESGCM", "pbkdf2",
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
        byte[] aeadKey = Crypto.hkdfSha256(mask.maskKey, Constants.B512_AEAD_INFO, 32);
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        StreamObfuscator obfuscator = StreamObfuscator.forPassword(pw, streamSalt, fastObf);

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
            try (CryptoBackend.AeadEncryptor enc = backend.newGcmEncryptor(aeadKey, nonce, metadataBytes)) {
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
            throw new IllegalStateException("Streaming b512 encode failed", exc);
        }
        return outFile;
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
                Constants.B512_AEAD_INFO,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            byte[] aeadKey = Crypto.hkdfSha256(maskKey, Constants.B512_AEAD_INFO, 32);

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec = backend.newGcmDecryptor(aeadKey, nonce, metadataBytes)) {
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

    static File pb512FileEncodeFileStream(File input,
                                                  File output,
                                                  String password,
                                                  boolean useMaster) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        if (pw.length == 0) {
            throw new IllegalArgumentException("Password required for AES-heavy streaming mode");
        }
        String kdfLabel = resolveUserKdfLabel();
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
    static void readExact(InputStream input, byte[] buffer, int length, String error) throws IOException {
        int offset = 0;
        while (offset < length) {
            int read = input.read(buffer, offset, length - offset);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                int single = input.read();
                if (single < 0) {
                    break;
                }
                buffer[offset++] = (byte) single;
                continue;
            }
            offset += read;
        }
        if (offset != length) {
            throw new IllegalArgumentException(error);
        }
    }

    static void readExactChannel(FileChannel channel, ByteBuffer buffer, int length, String error) throws IOException {
        buffer.clear();
        buffer.limit(length);
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer);
            if (read < 0) {
                throw new IllegalArgumentException(error);
            }
        }
        buffer.flip();
    }

    static void writeFully(FileChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

    static byte[] readExactBytes(InputStream input, int length, String error) throws IOException {
        if (length <= 0) {
            return new byte[0];
        }
        byte[] buf = new byte[length];
        readExact(input, buf, length, error);
        return buf;
    }

    static void skipFully(InputStream input, int length, String error) throws IOException {
        if (length <= 0) {
            return;
        }
        byte[] buf = new byte[Math.min(8192, length)];
        int remaining = length;
        while (remaining > 0) {
            int take = Math.min(buf.length, remaining);
            int read = input.read(buf, 0, take);
            if (read < 0) {
                throw new IllegalArgumentException(error);
            }
            if (read == 0) {
                int single = input.read();
                if (single < 0) {
                    throw new IllegalArgumentException(error);
                }
                remaining -= 1;
                continue;
            }
            remaining -= read;
        }
    }

    static long resolvePayloadLengthFromFileSize(File input,
                                                         int lenUser,
                                                         int lenMaster,
                                                         int encodedPayloadLen) {
        long payloadLen = encodedPayloadLen & 0xFFFFFFFFL;
        long prefixLen = 4L + (lenUser & 0xFFFFFFFFL)
            + 4L + (lenMaster & 0xFFFFFFFFL)
            + 4L;
        long fileSize = input.length();
        if (fileSize < prefixLen) {
            return payloadLen;
        }
        long actualPayloadLen = fileSize - prefixLen;
        if (actualPayloadLen == payloadLen) {
            return payloadLen;
        }
        long mod = 1L << 32;
        if (actualPayloadLen > payloadLen && ((actualPayloadLen - payloadLen) % mod) == 0L) {
            return actualPayloadLen;
        }
        return payloadLen;
    }

    static int readU32(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 4, error);
        return BaseFwxUtil.readU32(buf, 0);
    }

    static int readU16(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 2, error);
        return ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);
    }

    static long readU64(InputStream input, String error) throws IOException {
        byte[] buf = readExactBytes(input, 8, error);
        long out = 0L;
        for (int i = 0; i < buf.length; i++) {
            out = (out << 8) | (buf[i] & 0xFFL);
        }
        return out;
    }

    static void writeU32(OutputStream output, int value) throws IOException {
        output.write((value >> 24) & 0xFF);
        output.write((value >> 16) & 0xFF);
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    static void writeU16(OutputStream output, int value) throws IOException {
        output.write((value >> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    static void writeU64(OutputStream output, long value) throws IOException {
        long v = value;
        for (int i = 7; i >= 0; i--) {
            output.write((int) ((v >> (i * 8)) & 0xFF));
        }
    }

    static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
    static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String aead,
                                        String kdfLabel) {
        return buildMetadata(method, strip, useMaster, aead, kdfLabel,
            null, null, null, null, null, null, null, null);
    }

    static String buildMetadata(String method,
                                        boolean strip,
                                        boolean useMaster,
                                        String aead,
                                        String kdfLabel,
                                        String mode,
                                        Boolean obfuscation,
                                        String obfMode,
                                        Integer kdfIters,
                                        Integer argonTime,
                                        Integer argonMem,
                                        Integer argonPar,
                                        String pack) {
        if (strip) {
            return "";
        }
        Map<String, String> info = new LinkedHashMap<>();
        info.put("ENC-TIME", Instant.now().toString());
        info.put("ENC-VERSION", Constants.ENGINE_VERSION);
        info.put("ENC-METHOD", method);
        info.put("ENC-MASTER", useMaster ? "yes" : "no");
        info.put("ENC-KEM", useMaster ? "EC" : "none");
        info.put("ENC-AEAD", aead);
        info.put("ENC-KDF", kdfLabel);
        if (mode != null && !mode.isEmpty()) {
            info.put("ENC-MODE", mode);
        }
        if (obfMode != null && !obfMode.isEmpty()) {
            info.put("ENC-OBF", obfMode);
        } else if (obfuscation != null) {
            info.put("ENC-OBF", obfuscation ? "yes" : "no");
        }
        if (kdfIters != null) {
            info.put("ENC-KDF-ITER", Integer.toString(kdfIters));
        }
        if (argonTime != null) {
            info.put("ENC-ARGON2-TC", Integer.toString(argonTime));
        }
        if (argonMem != null) {
            info.put("ENC-ARGON2-MEM", Integer.toString(argonMem));
        }
        if (argonPar != null) {
            info.put("ENC-ARGON2-PAR", Integer.toString(argonPar));
        }
        if (pack != null && !pack.isEmpty()) {
            info.put("ENC-P", pack);
        }
        String json = encodeJson(info);
        return Base64Codec.encode(json.getBytes(StandardCharsets.UTF_8));
    }

    static String encodeJson(Map<String, String> map) {
        StringBuilder out = new StringBuilder();
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append('\"').append(escapeJson(entry.getKey())).append("\":\"")
                .append(escapeJson(entry.getValue())).append('\"');
        }
        out.append('}');
        return out.toString();
    }

    static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static String[] splitMetadata(String payload) {
        int idx = payload.indexOf(Constants.META_DELIM);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx),
                payload.substring(idx + Constants.META_DELIM.length())};
        }
        return new String[]{"", payload};
    }

    static String metaValue(String metadataBlob, String key) {
        if (metadataBlob == null || metadataBlob.isEmpty()) {
            return "";
        }
        try {
            String json = new String(Base64Codec.decode(metadataBlob), StandardCharsets.UTF_8);
            return jsonValue(json, key);
        } catch (IllegalArgumentException exc) {
            return "";
        }
    }

    static String jsonValue(String json, String key) {
        int idx = skipJsonWhitespace(json, 0);
        if (idx >= json.length() || json.charAt(idx) != '{') {
            return "";
        }
        idx++;
        while (idx < json.length()) {
            idx = skipJsonWhitespace(json, idx);
            if (idx >= json.length()) {
                return "";
            }
            if (json.charAt(idx) == '}') {
                return "";
            }
            StringBuilder name = new StringBuilder();
            int next = parseJsonString(json, idx, name);
            if (next < 0) {
                return "";
            }
            idx = skipJsonWhitespace(json, next);
            if (idx >= json.length() || json.charAt(idx) != ':') {
                return "";
            }
            idx = skipJsonWhitespace(json, idx + 1);
            if (idx >= json.length()) {
                return "";
            }
            StringBuilder value = new StringBuilder();
            next = parseJsonString(json, idx, value);
            if (next < 0) {
                return "";
            }
            if (name.toString().equals(key)) {
                return value.toString();
            }
            idx = skipJsonWhitespace(json, next);
            if (idx >= json.length()) {
                return "";
            }
            char ch = json.charAt(idx);
            if (ch == ',') {
                idx++;
                continue;
            }
            if (ch == '}') {
                return "";
            }
            return "";
        }
        return "";
    }

    static int skipJsonWhitespace(String json, int idx) {
        int len = json.length();
        int pos = idx;
        while (pos < len) {
            char ch = json.charAt(pos);
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                pos++;
            } else {
                break;
            }
        }
        return pos;
    }

    static int parseJsonString(String json, int start, StringBuilder out) {
        int len = json.length();
        if (start >= len || json.charAt(start) != '"') {
            return -1;
        }
        int i = start + 1;
        while (i < len) {
            char ch = json.charAt(i);
            if (ch == '"') {
                return i + 1;
            }
            if (ch == '\\') {
                if (i + 1 >= len) {
                    return -1;
                }
                char esc = json.charAt(i + 1);
                if (esc == 'u') {
                    if (i + 5 >= len) {
                        return -1;
                    }
                    int code = 0;
                    for (int j = 0; j < 4; j++) {
                        int val = Character.digit(json.charAt(i + 2 + j), 16);
                        if (val < 0) {
                            return -1;
                        }
                        code = (code << 4) | val;
                    }
                    out.append((char) code);
                    i += 6;
                    continue;
                }
                switch (esc) {
                    case '"':
                        out.append('"');
                        break;
                    case '\\':
                        out.append('\\');
                        break;
                    case '/':
                        out.append('/');
                        break;
                    case 'b':
                        out.append('\b');
                        break;
                    case 'f':
                        out.append('\f');
                        break;
                    case 'n':
                        out.append('\n');
                        break;
                    case 'r':
                        out.append('\r');
                        break;
                    case 't':
                        out.append('\t');
                        break;
                    default:
                        out.append(esc);
                        break;
                }
                i += 2;
                continue;
            }
            out.append(ch);
            i++;
        }
        return -1;
    }

    static String[] splitWithDelims(String payload, String delim, String legacy, String label) {
        int idx = payload.indexOf(delim);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx), payload.substring(idx + delim.length())};
        }
        idx = payload.indexOf(legacy);
        if (idx >= 0) {
            return new String[]{payload.substring(0, idx), payload.substring(idx + legacy.length())};
        }
        throw new IllegalArgumentException("Malformed " + label + " payload");
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
            Constants.B512_AEAD_INFO,
            new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
        );
        useMasterEffective = useMasterEffective && mask.usedMaster;
        String ext = extension == null ? "" : extension;
        String b64Payload = Base64Codec.encode(data);
        String extToken = TextCodecs.b512EncodeString(ext, password, useMasterEffective);
        String dataToken = TextCodecs.b512EncodeString(b64Payload, password, useMasterEffective);
        String metadata = buildMetadata("FWX512R", stripMetadata, useMasterEffective,
            enableAead ? "AESGCM" : "NONE", "pbkdf2");
        String body = extToken + Constants.FWX_DELIM + dataToken;
        String payload = metadata.isEmpty() ? body : metadata + Constants.META_DELIM + body;
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        if (!enableAead) {
            return payloadBytes;
        }
        byte[] aeadKey = Crypto.hkdfSha256(mask.maskKey, Constants.B512_AEAD_INFO, 32);
        byte[] ctBlob = Crypto.aesGcmEncrypt(aeadKey, payloadBytes, Constants.B512_AEAD_INFO);
        return Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob, ctBlob));
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
        String content;
        try {
            List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
            byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                pw,
                useMasterEffective,
                Constants.B512_FILE_MASK_INFO,
                Constants.B512_AEAD_INFO,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
            );
            byte[] aeadKey = Crypto.hkdfSha256(maskKey, Constants.B512_AEAD_INFO, 32);
            byte[] payloadBytes = Crypto.aesGcmDecrypt(aeadKey, parts.get(2), Constants.B512_AEAD_INFO);
            content = new String(payloadBytes, StandardCharsets.UTF_8);
        } catch (RuntimeException exc) {
            content = new String(blob, StandardCharsets.UTF_8);
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
