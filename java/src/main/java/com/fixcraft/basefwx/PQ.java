/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.security.auth.DestroyFailedException;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

/**
 * Post-Quantum cryptography support using ML-KEM-768 / ML-KEM-1024 (Kyber).
 * Default remains ML-KEM-768; opt into 1024 via {@code BASEFWX_MASTER_PQ_ALG}
 * after KATs vs liboqs pass (BC Kyber matches OQS ML-KEM for both sizes).
 */
public final class PQ {
    private PQ() {}

    private static final int MAX_KEY_BYTES = 4 * 1024 * 1024;

    public enum KemAlgorithm {
        ML_KEM_768("ml-kem-768", KyberParameters.kyber768, 1184, 2400, 1088),
        ML_KEM_1024("ml-kem-1024", KyberParameters.kyber1024, 1568, 3168, 1568);

        private final String wireName;
        private final KyberParameters parameters;
        private final int publicKeyBytes;
        private final int privateKeyBytes;
        private final int ciphertextBytes;

        KemAlgorithm(String wireName, KyberParameters parameters,
                     int publicKeyBytes, int privateKeyBytes, int ciphertextBytes) {
            this.wireName = wireName;
            this.parameters = parameters;
            this.publicKeyBytes = publicKeyBytes;
            this.privateKeyBytes = privateKeyBytes;
            this.ciphertextBytes = ciphertextBytes;
        }

        public String wireName() {
            return wireName;
        }

        KyberParameters parameters() {
            return parameters;
        }

        public static KemAlgorithm fromName(String name) {
            if (name == null || name.isEmpty()) {
                return ML_KEM_768;
            }
            String normalized = name.trim().toLowerCase(Locale.ROOT);
            if (("kyber768".equals(normalized) || "kyber-768".equals(normalized))
                    || Constants.MASTER_PQ_ALG_DEFAULT.equals(normalized)
                    || "ml-kem-768".equals(normalized)) {
                return ML_KEM_768;
            }
            if (("kyber1024".equals(normalized) || "kyber-1024".equals(normalized))
                    || Constants.MASTER_PQ_ALG_HIGH.equals(normalized)
                    || "ml-kem-1024".equals(normalized)) {
                return ML_KEM_1024;
            }
            throw new IllegalArgumentException("Unsupported ML-KEM algorithm: " + name);
        }
    }

    public static final class KemKeyPair {
        public final byte[] publicKey;
        public final byte[] privateKey;

        public KemKeyPair(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public void wipePrivate() {
            if (privateKey != null) {
                Arrays.fill(privateKey, (byte) 0);
            }
        }
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public static class KemResult {
        public final byte[] ciphertext;
        public final byte[] shared;

        public KemResult(byte[] ciphertext, byte[] shared) {
            this.ciphertext = ciphertext;
            this.shared = shared;
        }
    }

    /** Current algorithm from env (default ml-kem-768). */
    public static String currentKemAlgorithm() {
        return resolveKemAlgorithm().wireName();
    }

    public static boolean isSupportedKemAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            return false;
        }
        try {
            KemAlgorithm.fromName(algorithm);
            return true;
        } catch (IllegalArgumentException exc) {
            return false;
        }
    }

    static String configuredMasterKemAlgorithm() {
        try {
            return inferKemAlgorithmFromPublicKey(loadMasterPublicKey()).wireName();
        } catch (Exception exc) {
            throw new IllegalStateException(
                    "Unable to determine configured master ML-KEM algorithm", exc);
        }
    }

    static KemAlgorithm resolveKemAlgorithm() {
        String configured = System.getenv(Constants.MASTER_PQ_ALG_ENV);
        if (configured == null || configured.trim().isEmpty()) {
            if (Constants.envEnabled("BASEFWX_PQ_MAX")
                    || Constants.envEnabled("BASEFWX_PQ_1024")) {
                return KemAlgorithm.ML_KEM_1024;
            }
            return KemAlgorithm.ML_KEM_768;
        }
        return KemAlgorithm.fromName(configured);
    }

    static boolean strictPqOnly() {
        return Constants.envEnabled(Constants.PQ_STRICT_ENV)
                || Constants.envEnabled(Constants.PQ_ONLY_ENV);
    }

    public static byte[] loadMasterPrivateKey() throws IOException {
        String envPath = System.getenv(Constants.MASTER_PQ_PRIVATE_ENV);
        if (envPath != null && !envPath.isEmpty()) {
            Path path = expandUser(envPath);
            if (!Files.exists(path)) {
                throw new IOException("Master PQ private key not found at " + path);
            }
            return decodeKeyBytes(readKeyFileBytes(path));
        }
        String home = System.getProperty("user.home");
        if (home != null && !home.isEmpty()) {
            Path defaultPath = Paths.get(home, "master_pq.sk");
            if (Files.exists(defaultPath)) {
                return decodeKeyBytes(readKeyFileBytes(defaultPath));
            }
        }
        throw new IOException("No master_pq.sk private key found (set "
                + Constants.MASTER_PQ_PRIVATE_ENV + " or place at ~/master_pq.sk)");
    }

    static boolean isMasterPublicKeyConfigured() {
        String envPath = System.getenv(Constants.MASTER_PQ_PUBLIC_ENV);
        if (envPath != null && !envPath.isEmpty()) {
            return true;
        }
        String baked = Constants.MASTER_PQ_PUBLIC_B64;
        return baked != null && !baked.isEmpty();
    }

    public static byte[] loadMasterPublicKey() throws Exception {
        String envPath = System.getenv(Constants.MASTER_PQ_PUBLIC_ENV);
        if (envPath != null && !envPath.isEmpty()) {
            Path path = expandUser(envPath);
            if (!Files.exists(path)) {
                throw new IOException("Master PQ public key not found at " + path);
            }
            byte[] raw = readKeyFileBytes(path);
            return decodeKeyBytes(raw);
        }

        String baked = Constants.MASTER_PQ_PUBLIC_B64;
        if (baked != null && !baked.isEmpty()) {
            return decodeKeyBytes(baked.getBytes(StandardCharsets.UTF_8));
        }

        throw new IllegalStateException("Master PQ public key not configured. Set "
                + Constants.MASTER_PQ_PUBLIC_ENV + " or build with "
                + "-Dbasefwx.master.pq.public.b64=<base64-key>.");
    }

    public static byte[] decodeKeyBytes(byte[] raw) throws IOException {
        if (raw == null || raw.length == 0) {
            return raw;
        }
        if (raw.length > MAX_KEY_BYTES) {
            throw new IOException("Key material too large (>4 MiB)");
        }

        byte[] trimmed = trim(raw);
        byte[] decoded;
        try {
            String text = new String(trimmed, StandardCharsets.UTF_8);
            decoded = Base64.getDecoder().decode(text);
        } catch (Exception e) {
            decoded = trimmed;
        }

        byte[] inflated = tryZlibDecompress(decoded);
        if (inflated != null) {
            return inflated;
        }
        return decoded;
    }

    private static byte[] trim(byte[] data) {
        int start = 0;
        int end = data.length;
        while (start < end && Character.isWhitespace(data[start])) {
            start++;
        }
        while (end > start && Character.isWhitespace(data[end - 1])) {
            end--;
        }
        return Arrays.copyOfRange(data, start, end);
    }

    private static byte[] readKeyFileBytes(Path path) throws IOException {
        try (InputStream input = Files.newInputStream(path);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (read > MAX_KEY_BYTES - total) {
                    throw new IOException("Key file too large (>4 MiB): " + path);
                }
                output.write(buffer, 0, read);
                total += read;
            }
            return output.toByteArray();
        }
    }

    private static byte[] tryZlibDecompress(byte[] input) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(input);
             InflaterInputStream iis = new InflaterInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int len;
            while ((len = iis.read(buffer)) > 0) {
                if (len > MAX_KEY_BYTES - total) {
                    throw new IOException("Decoded key material too large (>4 MiB)");
                }
                baos.write(buffer, 0, len);
                total += len;
            }
            return baos.toByteArray();
        } catch (ZipException e) {
            return null;
        }
    }

    private static Path expandUser(String path) {
        if (path.startsWith("~/") || path.startsWith("~\\")) {
            String home = System.getProperty("user.home");
            if (home != null && !home.isEmpty()) {
                return Paths.get(home, path.substring(2));
            }
        }
        return Paths.get(path);
    }

    public static KemKeyPair generateKeyPair() {
        return generateKeyPair(resolveKemAlgorithm());
    }

    public static KemKeyPair generateKeyPair(KemAlgorithm algorithm) {
        KyberKeyPairGenerator generator = new KyberKeyPairGenerator();
        generator.init(new KyberKeyGenerationParameters(new SecureRandom(), algorithm.parameters()));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        KyberPublicKeyParameters pub = (KyberPublicKeyParameters) pair.getPublic();
        KyberPrivateKeyParameters priv = (KyberPrivateKeyParameters) pair.getPrivate();
        return new KemKeyPair(pub.getEncoded(), priv.getEncoded());
    }

    public static KemKeyPair generateKeyPair(String algorithm) {
        return generateKeyPair(KemAlgorithm.fromName(algorithm));
    }

    public static KemResult kemEncrypt(byte[] publicKeyBytes) throws Exception {
        return kemEncrypt(inferKemAlgorithmFromPublicKey(publicKeyBytes), publicKeyBytes);
    }

    public static KemResult kemEncrypt(KemAlgorithm algorithm, byte[] publicKeyBytes) throws Exception {
        KyberPublicKeyParameters pubKey =
                new KyberPublicKeyParameters(algorithm.parameters(), publicKeyBytes);
        KyberKEMGenerator kemGen = new KyberKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEnc = kemGen.generateEncapsulated(pubKey);
        try {
            return new KemResult(secretEnc.getEncapsulation(), secretEnc.getSecret());
        } finally {
            try {
                secretEnc.destroy();
            } catch (DestroyFailedException ignored) {
                // Caller wipes shared after HKDF.
            }
        }
    }

    public static KemResult kemEncrypt(String algorithm, byte[] publicKeyBytes) throws Exception {
        return kemEncrypt(KemAlgorithm.fromName(algorithm), publicKeyBytes);
    }

    public static byte[] kemDecrypt(byte[] privateKeyBytes, byte[] ciphertext) throws Exception {
        return kemDecrypt(
                inferKemAlgorithmFromCiphertext(privateKeyBytes, ciphertext),
                privateKeyBytes,
                ciphertext);
    }

    public static byte[] kemDecrypt(KemAlgorithm algorithm, byte[] privateKeyBytes, byte[] ciphertext)
            throws Exception {
        KyberPrivateKeyParameters privKey =
                new KyberPrivateKeyParameters(algorithm.parameters(), privateKeyBytes);
        KyberKEMExtractor kemExt = new KyberKEMExtractor(privKey);
        return kemExt.extractSecret(ciphertext);
    }

    public static byte[] kemDecrypt(String algorithm, byte[] privateKeyBytes, byte[] ciphertext)
            throws Exception {
        return kemDecrypt(KemAlgorithm.fromName(algorithm), privateKeyBytes, ciphertext);
    }

    static KemAlgorithm inferKemAlgorithmFromPublicKey(byte[] publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("ML-KEM public key must not be null");
        }
        for (KemAlgorithm algorithm : KemAlgorithm.values()) {
            if (publicKey.length == algorithm.publicKeyBytes) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException(
                "Invalid ML-KEM public key length; expected ML-KEM-768 or ML-KEM-1024");
    }

    private static KemAlgorithm inferKemAlgorithmFromCiphertext(
            byte[] privateKey, byte[] ciphertext) {
        if (privateKey == null || ciphertext == null) {
            throw new IllegalArgumentException(
                    "ML-KEM private key and ciphertext must not be null");
        }
        for (KemAlgorithm algorithm : KemAlgorithm.values()) {
            if (privateKey.length == algorithm.privateKeyBytes
                    && ciphertext.length == algorithm.ciphertextBytes) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException(
                "Invalid or mismatched ML-KEM private-key/ciphertext lengths");
    }
}
