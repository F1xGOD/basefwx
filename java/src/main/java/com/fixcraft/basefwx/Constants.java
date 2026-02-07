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
    private static final Integer TEST_KDF_ITERS = envInt("BASEFWX_TEST_KDF_ITERS");
    public static final boolean TEST_KDF_OVERRIDE = TEST_KDF_ITERS != null;
    public static final int FWXAES_PBKDF2_ITERS = resolveFwxAesIters();

    public static final int SHORT_PASSWORD_MIN = 12;
    public static final int SHORT_PBKDF2_ITERS = 400000;

    public static final byte[] FWXAES_AAD = "fwxAES".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] FWXAES_MASK_INFO = "basefwx.fwxaes.mask.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] FWXAES_KEY_INFO = "basefwx.fwxaes.key.v1".getBytes(StandardCharsets.US_ASCII);

    public static final int USER_KDF_SALT_SIZE = 16;
    public static final int USER_KDF_ITERATIONS = resolveUserKdfIterations();

    public static final byte[] MASTER_EC_MAGIC = "EC1".getBytes(StandardCharsets.US_ASCII);
    public static final String MASTER_EC_CURVE = "secp521r1";
    public static final String MASTER_EC_PUBLIC_ENV = "BASEFWX_MASTER_EC_PUB";
    public static final String MASTER_EC_PRIVATE_ENV = "BASEFWX_MASTER_EC_PRIV";

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
    public static final byte[] JMG_KEY_MAGIC = "JMGK".getBytes(StandardCharsets.US_ASCII);
    public static final int JMG_KEY_VERSION = 1;
    public static final byte[] JMG_MASK_INFO = "basefwx.jmg.mask.v1".getBytes(StandardCharsets.US_ASCII);

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
    public static final String MASTER_PQ_PUBLIC_B64 = "eJwBoARf+/rkrYxhXn0CNFqTkzQUrIYloydzGrqpIuWXi+qnLO/XRnspzQBDwwTKLW3Ku6Zwii1AfriFM5t8PtugqMNFt/5HoHxIZLGkytTWKP3IKoP7EH2HFu14b5bagh+KIFTWoW12qZqLRNjJLBHZmzxasEIsN7AnsOiokMHxt4XwoLk5fscIhXSANBZpHUVEO+NkBhg5UnvzWkzAqPm6rEvCfE+CHxgFg1SjBJeFfVMyzpKpsUi6iCGXSl6nZuTkr10btfi8RHCEfxDrfhcJk0bsKMWEI6wVY23KQXXlmcJ4VydGZ/ZbjWhVbX6bo0DKqG5IlwpTDPJIwlumRpxbBog8JG10p8PTaRJEAKfiVo7jiD1Aki7hYqmyyBn2Q0RFy03Bm/Rpy1zlK3DahaaoMj1mJrJ5ff2FYYVsBQbrywcDUcdHUkIpUqwrrRyqdEIHq1T6AiKHmf2KHTXQnLuZpJ3Ih59bkH1GC2UzbEIWzFSImvQDkswCBW9cF0tFYCNnReiReb57XAjaW3smdOg1o9oyk2IbyptJtNe1teHoPsMJkBGin/ugUeFmEOa0f8lTEmK4u1/GxHrQxD65kxm2IHT4NPM8Z5oqQ9z0WthUE5MouNrZLK8EltZQzAcZJ/g7CesRi40qFecyD14hDPBcr6cEV6yqOXXrcDRQVCUhuYRyUNqrFe4JPks2kZlxXjABHMD1PHVzfJpsAtsTDJa2EdpoAkKRvfg2QOK6CpYix6zIyB1yGwdCG8L2QS9DQefDQntXDlwSIieqRrwmiWcba4mSgwfxsoH2SIbQPZKbtEA4XNGqen1CcldAw1w2mnO3otspreJEBZJjVSihGcoyVjWap9dWc0pLffeDC5mUyOTzWUQ3XBAxX817G9rIbFyMQ+4AdeP2zL/nk9s2wYuZT2MEbwTHW/6UJQXbRf+svg9Kq//ryl/YRiaxdK2xRkP7oaBBVbyyXxYUJEhXOD7cUar8HsGZlXmiDSxzCBZSJG+4ooAgOKfEx6liOvqHBQKrsG4ylg3JQqmKBUdXcf6cMImRqS4MFM23vQkSPqIckxGgkrJGDKLGg8DKsuOqUvkzexAWviAIJQZsJsqjUl2stBgnltsyysE2cdI5Poh7KgOFV27bfi4iCpFSXc46Aa2jjN0WFYAgfhcRXgvIanJ3L8/sPrR7QKvpTtPFSfdcBipqp8vRdYImF5HceU1TU+QwtOcmCKDmaDTBGtJLZDXYJ3/2VQAEr8Mhk1WxGQsWUikZBi9pHTTbh93gvl9gLaGlxlRCjwzSqcJVXF80UiVMA06hfDnzi9MFpIGZL0czax+1zwdLFsnnHLGLzm/YpgrUBIk0gTgMVhqiu0+JyagxwrXCsDmGbhj8PzJGUeR8xhoxzOtTMgtaFwekbEAss+JGzuZJeakDxhMJEvvbKabIFDeQLsImO4eaAslqXyNoSg7AtnDlHfzTTFvwk2/UppeXNmcEC9n1UyfyWNW6qAZRJe5zQkijzLfkGKWsR/ksjmUQwMHwOOWVQ8qqUapYxsmbZkosPBXRDNBhY6PNjfciD2hRoIqrd/pnkJ6cZd1FQyxge6FA3PMpHw==";
    public static final String MASTER_PQ_PUBLIC_ENV = "BASEFWX_MASTER_PQ_PUB";

    public static final String ENGINE_VERSION = "3.6.1";

    private static final Integer HEAVY_PBKDF2_ENV = envInt("BASEFWX_HEAVY_PBKDF2_ITERS");
    public static final int HEAVY_PBKDF2_ITERATIONS = resolveHeavyPbkdf2Iterations();

    private static int resolveFwxAesIters() {
        int fallback = 200000;
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
        int fallback = 200000;
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
        int fallback = 1000000;
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
