package com.fixcraft.basefwx;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;
import javax.crypto.KeyAgreement;

public final class EcKeys {
    private EcKeys() {}

    public static PublicKey loadMasterPublic(boolean createIfMissing) {
        File envPath = resolveEnvPath(Constants.MASTER_EC_PUBLIC_ENV);
        File defaultPath = defaultPublicPath();
        if (envPath != null && envPath.isFile()) {
            return readPublicKey(envPath);
        }
        if (defaultPath.isFile()) {
            return readPublicKey(defaultPath);
        }
        if (createIfMissing) {
            KeyPair pair = generateKeyPair();
            writePem(defaultPublicPath(), "PUBLIC KEY", pair.getPublic().getEncoded());
            writePem(defaultPrivatePath(), "PRIVATE KEY", pair.getPrivate().getEncoded());
            return pair.getPublic();
        }
        return null;
    }

    public static PrivateKey loadMasterPrivate() {
        File envPath = resolveEnvPath(Constants.MASTER_EC_PRIVATE_ENV);
        File defaultPath = defaultPrivatePath();
        if (envPath != null && envPath.isFile()) {
            return readPrivateKey(envPath);
        }
        if (defaultPath.isFile()) {
            return readPrivateKey(defaultPath);
        }
        throw new IllegalStateException("No master EC private key found");
    }

    public static EcKemResult kemEncrypt(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("EC public key required");
        }
        KeyPair ephemeral = generateKeyPair();
        byte[] shared = ecdh(ephemeral.getPrivate(), publicKey);
        byte[] encoded = encodePublicKey((ECPublicKey) ephemeral.getPublic());
        if (encoded.length > 0xFFFF) {
            throw new IllegalArgumentException("EC public key encoding too large");
        }
        int magicLen = Constants.MASTER_EC_MAGIC.length;
        byte[] masterBlob = new byte[magicLen + 2 + encoded.length];
        System.arraycopy(Constants.MASTER_EC_MAGIC, 0, masterBlob, 0, magicLen);
        int offset = magicLen;
        masterBlob[offset] = (byte) ((encoded.length >> 8) & 0xFF);
        masterBlob[offset + 1] = (byte) (encoded.length & 0xFF);
        System.arraycopy(encoded, 0, masterBlob, offset + 2, encoded.length);
        return new EcKemResult(masterBlob, shared);
    }

    public static byte[] kemDecrypt(byte[] masterBlob, PrivateKey privateKey) {
        int magicLen = Constants.MASTER_EC_MAGIC.length;
        if (masterBlob.length < magicLen + 2) {
            throw new IllegalArgumentException("Malformed EC master blob");
        }
        for (int i = 0; i < magicLen; i++) {
            if (masterBlob[i] != Constants.MASTER_EC_MAGIC[i]) {
                throw new IllegalArgumentException("Invalid EC master blob");
            }
        }
        int length = ((masterBlob[magicLen] & 0xFF) << 8) | (masterBlob[magicLen + 1] & 0xFF);
        int start = magicLen + 2;
        int end = start + length;
        if (end > masterBlob.length) {
            throw new IllegalArgumentException("Truncated EC master blob");
        }
        byte[] encoded = new byte[length];
        System.arraycopy(masterBlob, start, encoded, 0, length);
        ECPublicKey ephemeral = decodePublicKey(encoded);
        return ecdh(privateKey, ephemeral);
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec(Constants.MASTER_EC_CURVE));
            return gen.generateKeyPair();
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to generate EC key", exc);
        }
    }

    private static byte[] ecdh(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("ECDH failed", exc);
        }
    }

    private static ECPublicKey decodePublicKey(byte[] encoded) {
        try {
            ECParameterSpec params = curveParams();
            if (encoded.length < 1 || encoded[0] != 0x04) {
                throw new IllegalArgumentException("Unsupported EC point encoding");
            }
            int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
            if (encoded.length != 1 + (fieldSize * 2)) {
                throw new IllegalArgumentException("Unexpected EC point length");
            }
            byte[] xBytes = new byte[fieldSize];
            byte[] yBytes = new byte[fieldSize];
            System.arraycopy(encoded, 1, xBytes, 0, fieldSize);
            System.arraycopy(encoded, 1 + fieldSize, yBytes, 0, fieldSize);
            ECPoint point = new ECPoint(new java.math.BigInteger(1, xBytes), new java.math.BigInteger(1, yBytes));
            ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to decode EC public key", exc);
        }
    }

    private static byte[] encodePublicKey(ECPublicKey publicKey) {
        ECPoint point = publicKey.getW();
        ECParameterSpec params = publicKey.getParams();
        int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
        byte[] x = toFixed(point.getAffineX().toByteArray(), fieldSize);
        byte[] y = toFixed(point.getAffineY().toByteArray(), fieldSize);
        byte[] out = new byte[1 + (fieldSize * 2)];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, fieldSize);
        System.arraycopy(y, 0, out, 1 + fieldSize, fieldSize);
        return out;
    }

    private static byte[] toFixed(byte[] src, int len) {
        if (src.length == len) {
            return src;
        }
        byte[] out = new byte[len];
        if (src.length > len) {
            System.arraycopy(src, src.length - len, out, 0, len);
        } else {
            System.arraycopy(src, 0, out, len - src.length, src.length);
        }
        return out;
    }

    private static ECParameterSpec curveParams() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(Constants.MASTER_EC_CURVE));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to load EC parameters", exc);
        }
    }

    private static PublicKey readPublicKey(File path) {
        try {
            byte[] data = readAllBytes(path);
            byte[] decoded = decodePem(data);
            KeyFactory factory = KeyFactory.getInstance("EC");
            return factory.generatePublic(new X509EncodedKeySpec(decoded));
        } catch (IOException | GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to read EC public key", exc);
        }
    }

    private static PrivateKey readPrivateKey(File path) {
        try {
            byte[] data = readAllBytes(path);
            byte[] decoded = decodePem(data);
            KeyFactory factory = KeyFactory.getInstance("EC");
            PrivateKey key = factory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
            if (!(key instanceof ECPrivateKey)) {
                throw new IllegalArgumentException("Invalid EC private key");
            }
            return key;
        } catch (IOException | GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to read EC private key", exc);
        }
    }

    private static void writePem(File path, String type, byte[] encoded) {
        try {
            File parent = path.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            String b64 = Base64Codec.encode(encoded);
            StringBuilder builder = new StringBuilder();
            builder.append("-----BEGIN ").append(type).append("-----\n");
            for (int i = 0; i < b64.length(); i += 64) {
                int end = Math.min(i + 64, b64.length());
                builder.append(b64, i, end).append("\n");
            }
            builder.append("-----END ").append(type).append("-----\n");
            writeAllBytes(path, builder.toString().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to write EC key", exc);
        }
        if ("PRIVATE KEY".equals(type)) {
            try {
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(path.toPath(), perms);
            } catch (UnsupportedOperationException | IOException exc) {
                // Best-effort; ignore on non-POSIX filesystems.
            }
        }
    }

    private static byte[] decodePem(byte[] data) {
        String text = new String(data, StandardCharsets.US_ASCII);
        String[] lines = text.split("\r?\n");
        String type = null;
        boolean inBlock = false;
        StringBuilder b64 = new StringBuilder();
        for (String line : lines) {
            if (!inBlock) {
                if (line.startsWith("-----BEGIN ") && line.endsWith("-----")) {
                    type = line.substring(11, line.length() - 5);
                    inBlock = true;
                }
                continue;
            }
            if (line.startsWith("-----END ") && line.endsWith("-----")) {
                String endType = line.substring(9, line.length() - 5);
                if (type != null && type.equals(endType)) {
                    return Base64Codec.decode(b64.toString());
                }
                break;
            }
            b64.append(line.trim());
        }
        return data;
    }

    private static File resolveEnvPath(String envName) {
        String raw = System.getenv(envName);
        if (raw == null || raw.trim().isEmpty()) {
            return null;
        }
        return expandUser(raw.trim());
    }

    private static File defaultPublicPath() {
        return expandUser("~/master_ec_public.pem");
    }

    private static File defaultPrivatePath() {
        return expandUser("~/master_ec_private.pem");
    }

    private static File expandUser(String path) {
        if (path.startsWith("~/") || path.startsWith("~\\")) {
            String home = System.getProperty("user.home");
            if (home != null && !home.isEmpty()) {
                return new File(home, path.substring(2));
            }
        }
        return new File(path);
    }

    private static byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static void writeAllBytes(File file, byte[] data) throws IOException {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        }
    }

    public static final class EcKemResult {
        public final byte[] masterBlob;
        public final byte[] shared;

        private EcKemResult(byte[] masterBlob, byte[] shared) {
            this.masterBlob = masterBlob;
            this.shared = shared;
        }
    }
}
