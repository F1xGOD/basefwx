/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;

public final class Constants {
    private Constants() {}

    public static final byte[] FWXAES_MAGIC = "FWX1".getBytes(StandardCharsets.US_ASCII);
    public static final int FWXAES_ALGO = 0x01;
    public static final int FWXAES_KDF_PBKDF2 = 0x01;
    public static final int FWXAES_KDF_WRAP = 0x02;
    public static final int FWXAES_SALT_LEN = 16;
    public static final int FWXAES_IV_LEN = 12;
    public static final int FWXAES_KEY_LEN = 32;
    // 3.6.5: BASEFWX_TEST_KDF_ITERS is honored ONLY when the JVM is
    // launched with -Dbasefwx.testing=true (or the env var
    // BASEFWX_TESTING=1). The previous unconditional read meant a
    // production shell that happened to have BASEFWX_TEST_KDF_ITERS set
    // silently produced low-cost ciphertext indistinguishable on the wire.
    private static final boolean TESTING_BUILD =
            Boolean.getBoolean("basefwx.testing")
            || "1".equals(System.getenv("BASEFWX_TESTING"));
    private static final Integer TEST_KDF_ITERS =
            TESTING_BUILD ? envInt("BASEFWX_TEST_KDF_ITERS") : null;
    public static final boolean TEST_KDF_OVERRIDE = TEST_KDF_ITERS != null;
    public static final int FWXAES_PBKDF2_ITERS = resolveFwxAesIters();

    public static final int SHORT_PASSWORD_MIN = 12;
    public static final int SHORT_PBKDF2_ITERS = 1000000;

    public static final byte[] FWXAES_AAD = "fwxAES".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] FWXAES_MASK_INFO = "basefwx.fwxaes.mask.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] FWXAES_KEY_INFO = "basefwx.fwxaes.key.v1".getBytes(StandardCharsets.US_ASCII);

    public static final int USER_KDF_SALT_SIZE = 16;
    public static final int USER_KDF_ITERATIONS = resolveUserKdfIterations();

    // 3.6.5: Argon2id defaults for the user-KDF wrap path. Values mirror
    // basefwx::constants::kArgon2{TimeCost,MemoryCost} in constants.hpp.
    // Parallelism mirrors the C++ side's DefaultArgon2Parallelism() —
    // std::thread::hardware_concurrency() with a fallback of 4. This
    // matches the existing wire-format quirk where Argon2 parallelism is
    // chosen by the encrypting host's CPU count and is NOT carried in
    // the wrap header; cross-machine portability of Argon2-wrapped blobs
    // therefore requires both sides to share the same parallelism value
    // (either same hardware, or the caller pins ARGON2_PARALLELISM
    // explicitly via KdfOptions before encrypt/decrypt).
    public static final int ARGON2_TIME_COST = 4;
    public static final int ARGON2_MEMORY_KIB = 1 << 16;        // 64 MiB
    public static final int ARGON2_PARALLELISM = defaultArgon2Parallelism();
    // Short-password (<12 char) step-up to match C++ kShortArgon2*.
    public static final int SHORT_ARGON2_TIME_COST = 5;
    public static final int SHORT_ARGON2_MEMORY_KIB = 1 << 17;  // 128 MiB

    private static int defaultArgon2Parallelism() {
        int cores = Runtime.getRuntime().availableProcessors();
        return cores > 0 ? cores : 4;
    }

    public static final byte[] MASTER_EC_MAGIC = "EC1".getBytes(StandardCharsets.US_ASCII);
    public static final String MASTER_EC_CURVE = "secp521r1";
    public static final String MASTER_EC_PUBLIC_ENV = "BASEFWX_MASTER_EC_PUB";
    public static final String MASTER_EC_PRIVATE_ENV = "BASEFWX_MASTER_EC_PRIV";
    public static final String MASTER_EC_CREATE_IF_MISSING_ENV = "BASEFWX_MASTER_EC_CREATE_IF_MISSING";

    public static final byte[] B512_MASK_INFO = "basefwx.b512.mask.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PB512_MASK_INFO = "basefwx.pb512.mask.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] B512_STREAM_INFO = "basefwx.b512.stream.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] PB512_STREAM_INFO = "basefwx.pb512.stream.v1".getBytes(StandardCharsets.US_ASCII);

    public static final byte[] MASK_AAD_B512 = "b512".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] MASK_AAD_PB512 = "pb512".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] MASK_AAD_JMG = "jmg".getBytes(StandardCharsets.US_ASCII);

    public static final byte[] B512_FILE_MASK_INFO = "basefwx.b512file.mask.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] B512_AEAD_INFO = "basefwx.b512file.v1".getBytes(StandardCharsets.US_ASCII);
    public static final int STREAM_THRESHOLD = 250 * 1024;
    public static final int STREAM_CHUNK_SIZE = 1 << 20;
    public static final int HKDF_MAX_LEN = 255 * 32;
    public static final byte[] STREAM_MAGIC = "STRMOBF1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] STREAM_INFO_KEY = "basefwx.stream.obf.key.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] STREAM_INFO_IV = "basefwx.stream.obf.iv.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] STREAM_INFO_PERM = "basefwx.stream.obf.perm.v1".getBytes(StandardCharsets.US_ASCII);
    public static final int STREAM_SALT_LEN = 16;

    public static final byte[] IMAGECIPHER_STREAM_INFO = "basefwx.imagecipher.stream.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_ARCHIVE_INFO = "basefwx.imagecipher.archive.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_TRAILER_MAGIC = "JMG0".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_KEY_TRAILER_MAGIC = "JMG1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] JMG_KEY_MAGIC = "JMGK".getBytes(StandardCharsets.US_ASCII);
    public static final int JMG_KEY_VERSION_LEGACY = 1;
    public static final int JMG_KEY_VERSION = 2;
    public static final int JMG_SECURITY_PROFILE_LEGACY = 0;
    public static final int JMG_SECURITY_PROFILE_MAX = 1;
    public static final int JMG_SECURITY_PROFILE_DEFAULT = JMG_SECURITY_PROFILE_MAX;
    public static final byte[] JMG_MASK_INFO = "basefwx.jmg.mask.v1".getBytes(StandardCharsets.US_ASCII);

    public static final byte[] LIVE_FRAME_MAGIC = "LIVE".getBytes(StandardCharsets.US_ASCII);
    public static final int LIVE_FRAME_VERSION = 1;
    public static final int LIVE_FRAME_TYPE_HEADER = 1;
    public static final int LIVE_FRAME_TYPE_DATA = 2;
    public static final int LIVE_FRAME_TYPE_FIN = 3;
    public static final int LIVE_KEYMODE_PBKDF2 = 1;
    public static final int LIVE_KEYMODE_WRAP = 2;
    public static final int LIVE_NONCE_PREFIX_LEN = 4;
    public static final int LIVE_FRAME_HEADER_LEN = 18; // magic(4) + ver(1) + type(1) + seq(8) + body_len(4)
    public static final int LIVE_HEADER_FIXED_LEN = 12; // key_mode(1) + salt_len(1) + nonce_len(1) + reserved(1) + key_hdr_len(4) + iters(4)
    public static final int LIVE_MAX_BODY = 1_073_741_824;

    public static final String FWX_DELIM = "\u001f\u001e";
    public static final String FWX_HEAVY_DELIM = "\u001f\u001d";
    public static final String LEGACY_FWX_DELIM = "A8igTOmG";
    public static final String LEGACY_FWX_HEAVY_DELIM = "673827837628292873";
    public static final String META_DELIM = "::FWX-META::";

    public static final int AEAD_NONCE_LEN = 12;
    public static final int AEAD_TAG_LEN = 16;

    public static final byte[] OBF_INFO_MASK = "basefwx.obf.mask.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] OBF_INFO_PERM = "basefwx.obf.perm.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] KEM_INFO = "basefwx.kem.v1".getBytes(StandardCharsets.US_ASCII);

    public static final String MASTER_PQ_ALG = "ml-kem-768";
    // 3.6.5: the upstream baked ML-KEM-768 master public key has been
    // removed from this constant. Deployments that want a baked key
    // override it via -Dbasefwx.master.pq.public.b64=<base64-blob> on
    // the JVM command line (analogous to the C++ -DBASEFWX_MASTER_PQ_PUB_B64
    // CMake option). Empty by default — release artifacts ship with no
    // baked key and rely on runtime BASEFWX_MASTER_PQ_PUB=<path>.
    public static final String MASTER_PQ_PUBLIC_B64 =
            System.getProperty("basefwx.master.pq.public.b64", "");
    public static final String MASTER_PQ_PUBLIC_ENV = "BASEFWX_MASTER_PQ_PUB";
    // Retained as a string only so callers that print env-var names still
    // compile. The actual env-var is no longer consulted by PQ.java (the
    // baked-key opt-in was removed alongside the baked literal).
    public static final String MASTER_PQ_ALLOW_BAKED_ENV = "BASEFWX_MASTER_PQ_ALLOW_BAKED";

    public static final String ENGINE_VERSION = VersionInfo.engineVersion();

    private static final Integer HEAVY_PBKDF2_ENV = envInt("BASEFWX_HEAVY_PBKDF2_ITERS");
    public static final int HEAVY_PBKDF2_ITERATIONS = resolveHeavyPbkdf2Iterations();

    private static int resolveFwxAesIters() {
        int fallback = 600000;
        Integer env = envInt("BASEFWX_FWXAES_PBKDF2_ITERS");
        if (env != null) {
            return env;
        }
        if (TEST_KDF_ITERS != null) {
            return TEST_KDF_ITERS;
        }
        return fallback;
    }

    private static int resolveUserKdfIterations() {
        int fallback = 600000;
        Integer env = envInt("BASEFWX_USER_KDF_ITERS");
        if (env != null) {
            return env;
        }
        if (TEST_KDF_ITERS != null) {
            return TEST_KDF_ITERS;
        }
        return fallback;
    }

    private static int resolveHeavyPbkdf2Iterations() {
        int fallback = 2000000;
        if (HEAVY_PBKDF2_ENV != null) {
            return HEAVY_PBKDF2_ENV;
        }
        if (TEST_KDF_ITERS != null) {
            return TEST_KDF_ITERS;
        }
        return fallback;
    }

    private static Integer envInt(String name) {
        String raw = System.getenv(name);
        if (raw == null) {
            return null;
        }
        raw = raw.trim();
        if (raw.isEmpty()) {
            return null;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException exc) {
            return null;
        }
    }
}
