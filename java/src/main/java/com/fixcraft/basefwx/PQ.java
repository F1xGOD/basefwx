/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
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
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.DestroyFailedException;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

/**
 * Post-Quantum cryptography support using ML-KEM-768 (Kyber).
 */
public final class PQ {
    private PQ() {}

    private static final int MAX_KEY_BYTES = 4 * 1024 * 1024;

    static {
        // Register Bouncy Castle providers
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

    /**
     * True when EC master blobs must be refused (PQ-only deployments).
     * Mirrors C++ {@code StrictPqOnly()} in keywrap.cpp.
     */
    static boolean strictPqOnly() {
        return envEnabled(Constants.PQ_STRICT_ENV) || envEnabled(Constants.PQ_ONLY_ENV);
    }

    private static boolean envEnabled(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            return false;
        }
        return "1".equals(value) || "true".equalsIgnoreCase(value)
                || "yes".equalsIgnoreCase(value);
    }

    /**
     * Load the master ML-KEM-768 private key from configuration.
     * Mirrors C++ {@code basefwx::pq::LoadMasterPrivateKey}.
     */
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

    /**
     * True when an operator explicitly configured a PQ master public key
     * (runtime env path or build-time baked literal). Mirrors C++ branches
     * that distinguish configured vs absent keys in LoadMasterPublicKey.
     */
    static boolean isMasterPublicKeyConfigured() {
        String envPath = System.getenv(Constants.MASTER_PQ_PUBLIC_ENV);
        if (envPath != null && !envPath.isEmpty()) {
            return true;
        }
        String baked = Constants.MASTER_PQ_PUBLIC_B64;
        return baked != null && !baked.isEmpty();
    }

    /**
     * Load the master ML-KEM-768 public key from configuration.
     *
     * <p>3.7.0: the upstream baked key has been removed; sourced in order:
     * <ol>
     *   <li>Runtime path via {@code BASEFWX_MASTER_PQ_PUB=<file>} (env).</li>
     *   <li>Build-time literal via {@code -Dbasefwx.master.pq.public.b64=<base64>}
     *       JVM system property — empty by default.</li>
     * </ol>
     * Throws when a key source is configured but missing or invalid.
     */
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

    /**
     * Decode key bytes (handle base64 encoding and zlib compression).
     */
    public static byte[] decodeKeyBytes(byte[] raw) throws IOException {
        if (raw == null || raw.length == 0) {
            return raw;
        }
        if (raw.length > MAX_KEY_BYTES) {
            throw new IOException("Key material too large (>4 MiB)");
        }

        // Try trimming whitespace
        byte[] trimmed = trim(raw);
        
        // Try base64 decode
        byte[] decoded = null;
        try {
            String text = new String(trimmed, StandardCharsets.UTF_8);
            decoded = Base64.getDecoder().decode(text);
        } catch (Exception e) {
            // Not base64, use raw
            decoded = trimmed;
        }

        // Try zlib decompress
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

    /**
     * Perform KEM encapsulation using ML-KEM-768 (Kyber768).
     * This matches the behavior of pqcrypto.kem.ml_kem_768.encrypt() in Python
     * and OQS_KEM_encaps() in C++.
     */
    public static KemResult kemEncrypt(byte[] publicKeyBytes) throws Exception {
        if (!Constants.MASTER_PQ_ALG.equals("ml-kem-768")) {
            throw new IllegalArgumentException("Only ml-kem-768 is supported");
        }

        // Use Bouncy Castle Kyber API for ML-KEM-768 (Kyber768)
        // Note: ML-KEM-768 is the NIST standardized version of Kyber768
        KyberParameters params = KyberParameters.kyber768;
        KyberPublicKeyParameters pubKey = 
            new KyberPublicKeyParameters(params, publicKeyBytes);
        
        KyberKEMGenerator kemGen = new KyberKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEnc = kemGen.generateEncapsulated(pubKey);

        try {
            byte[] ciphertext = secretEnc.getEncapsulation();
            byte[] sharedSecret = secretEnc.getSecret();
            return new KemResult(ciphertext, sharedSecret);
        } finally {
            try {
                secretEnc.destroy();
            } catch (DestroyFailedException ignored) {
                // The returned shared secret is wiped by KeyWrap after HKDF.
            }
        }
    }

    /**
     * Perform KEM decapsulation using ML-KEM-768 (Kyber768).
     * This matches the behavior of pqcrypto.kem.ml_kem_768.decrypt() in Python
     * and OQS_KEM_decaps() in C++.
     */
    public static byte[] kemDecrypt(byte[] privateKeyBytes, byte[] ciphertext) throws Exception {
        if (!Constants.MASTER_PQ_ALG.equals("ml-kem-768")) {
            throw new IllegalArgumentException("Only ml-kem-768 is supported");
        }

        // Use Bouncy Castle Kyber API for ML-KEM-768 (Kyber768)
        KyberParameters params = KyberParameters.kyber768;
        KyberPrivateKeyParameters privKey = 
            new KyberPrivateKeyParameters(params, privateKeyBytes);
        
        KyberKEMExtractor kemExt = new KyberKEMExtractor(privKey);
        byte[] sharedSecret = kemExt.extractSecret(ciphertext);

        return sharedSecret;
    }
}
