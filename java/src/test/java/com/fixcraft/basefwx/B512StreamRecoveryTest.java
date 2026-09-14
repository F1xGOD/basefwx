/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class B512StreamRecoveryTest {
    private static final String PASSWORD = "b512-stream-recovery-password";
    private static final String WRONG_PASSWORD = "wrong-stream-recovery-password";
    private static final byte[] EXISTING =
            "existing destination".getBytes(StandardCharsets.US_ASCII);

    @Rule
    public TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void streamV2DomainMatchesCrossRuntimeVector() {
        byte[] maskKey = pattern(32, 1, 0);
        byte[] derived = Crypto.hkdfSha256(
                maskKey, Constants.B512_STREAM_OBF_INFO_V2, 32);
        try {
            assertArrayEquals(hex(
                    "f53aec8167a000ca3ae3d2e001444946"
                    + "f141697a01f07526f2d476d6afd76f04"), derived);
            assertArrayEquals("B512STR2".getBytes(StandardCharsets.US_ASCII),
                    Constants.B512_STREAM_MAGIC_V2);
            assertArrayEquals("STRMOBF1".getBytes(StandardCharsets.US_ASCII),
                    Constants.STREAM_MAGIC);
        } finally {
            Arrays.fill(maskKey, (byte) 0);
            Arrays.fill(derived, (byte) 0);
        }
    }

    @Test
    public void ecMasterAndPasswordRecoveryPreserveLegacyRefusals()
            throws Exception {
        runIsolated("ec", false);
    }

    @Test
    public void mlKem768RecoveryPreservesLegacyRefusals() throws Exception {
        runIsolated("ml-kem-768", false);
    }

    @Test
    public void mlKem1024StrictFastRecoveryPreservesLegacyRefusals()
            throws Exception {
        runIsolated("ml-kem-1024", true);
    }

    private void runIsolated(String algorithm, boolean strictFast)
            throws Exception {
        File root = temporary.newFolder(algorithm);
        File scratch = new File(root, "scratch");
        Files.createDirectory(scratch.toPath());
        File log = new File(root, "test.log");
        ProcessBuilder builder = new ProcessBuilder(
                new File(System.getProperty("java.home"), "bin/java").toString(),
                "-Dbasefwx.testing=true", "-Duser.home=" + root,
                "-Djava.io.tmpdir=" + scratch,
                "-cp", System.getProperty("java.class.path"),
                B512StreamRecoveryTest.class.getName(),
                root.toString(), algorithm);
        Map<String, String> environment = builder.environment();
        environment.keySet().removeIf(name -> name.startsWith("BASEFWX_"));
        environment.put("BASEFWX_TEST_KDF_ITERS", "1");
        environment.put("BASEFWX_PQ_STRICT", strictFast ? "1" : "0");
        environment.put("BASEFWX_PERF", strictFast ? "1" : "0");
        boolean ec = "ec".equals(algorithm);
        environment.put(ec ? Constants.MASTER_EC_PUBLIC_ENV
                        : Constants.MASTER_PQ_PUBLIC_ENV,
                new File(root, "recipient.pub").toString());
        environment.put(ec ? Constants.MASTER_EC_PRIVATE_ENV
                        : Constants.MASTER_PQ_PRIVATE_ENV,
                new File(root, "recipient.key").toString());
        builder.redirectErrorStream(true).redirectOutput(log);
        Process child = builder.start();
        try {
            assertTrue("B512 recovery child timed out",
                    child.waitFor(60, TimeUnit.SECONDS));
            byte[] diagnostic = Files.readAllBytes(log.toPath());
            assertEquals(new String(diagnostic, 0,
                    Math.min(diagnostic.length, 4096), StandardCharsets.UTF_8),
                    0, child.exitValue());
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                assertTrue("B512 recovery child did not terminate",
                        child.waitFor(5, TimeUnit.SECONDS));
            }
        }
    }

    // A fresh JVM isolates real recipient keys and policy from the test host.
    public static void main(String[] arguments) throws Exception {
        File root = new File(arguments[0]);
        String algorithm = arguments[1];
        provisionRecipient(root, algorithm);
        byte[] plaintext = pattern(Constants.STREAM_CHUNK_SIZE + 19, 17, 3);
        File source = new File(root, "source.bin");
        File encoded = new File(root, "encoded.fwx");
        File decoded = new File(root, "decoded.bin");
        Files.write(source.toPath(), plaintext);

        BaseFwx.b512FileEncodeFile(source, encoded, PASSWORD, true);
        assertWriterMarker(encoded);
        assertDecoded(encoded, decoded, PASSWORD, false, plaintext);
        assertDecoded(encoded, decoded, WRONG_PASSWORD, true, plaintext);
        assertDecoded(encoded, decoded, "", true, plaintext);
        assertRefusedPreservingFiles(encoded, decoded, WRONG_PASSWORD, false);

        byte[] damaged = Files.readAllBytes(encoded.toPath());
        damaged[damaged.length - 1] ^= 1;
        File tampered = new File(root, "tampered.fwx");
        Files.write(tampered.toPath(), damaged);
        assertRefusedPreservingFiles(tampered, decoded, "", true);

        byte[] legacyPlaintext = pattern(8193, 11, 9);
        File legacy = new File(root, "legacy.fwx");
        Files.write(legacy.toPath(), legacyFixture(
                legacyPlaintext, Constants.STREAM_MAGIC, false, false));
        assertDecoded(legacy, decoded, PASSWORD, false, legacyPlaintext);
        assertDecoded(legacy, decoded, PASSWORD, true, legacyPlaintext);
        assertRefusedPreservingFiles(legacy, decoded, WRONG_PASSWORD, true);
        assertRefusedPreservingFiles(legacy, decoded, "", true);
        assertRefusedPreservingFiles(legacy, legacy, WRONG_PASSWORD, true);

        File malformed = new File(root, "malformed.fwx");
        Files.write(malformed.toPath(), legacyFixture(
                legacyPlaintext, Constants.STREAM_MAGIC, true, false));
        assertRefusedPreservingFiles(malformed, decoded, PASSWORD, true);
        Files.write(malformed.toPath(), legacyFixture(
                legacyPlaintext, Constants.STREAM_MAGIC, false, true));
        assertRefusedPreservingFiles(malformed, decoded, PASSWORD, true);
        Files.write(malformed.toPath(), legacyFixture(legacyPlaintext,
                "B512STR3".getBytes(StandardCharsets.US_ASCII), false, false));
        assertRefusedPreservingFiles(malformed, decoded, PASSWORD, true);

        Files.write(decoded.toPath(), EXISTING);
        try {
            BaseFwx.b512FileEncodeFile(source, decoded, "", true);
            fail("B512 stream writer no longer requires a password");
        } catch (IllegalArgumentException expected) {
            assertArrayEquals(EXISTING, Files.readAllBytes(decoded.toPath()));
            assertArrayEquals(plaintext, Files.readAllBytes(source.toPath()));
        }

        // Reader password recovery must not consult encryption public keys.
        Files.delete(new File(root, "recipient.pub").toPath());
        Files.delete(new File(root, "recipient.key").toPath());
        assertDecoded(encoded, decoded, PASSWORD, false, plaintext);
        assertRefusedPreservingFiles(encoded, decoded, WRONG_PASSWORD, true);
        provisionRecipient(root, algorithm);
        assertDecoded(encoded, decoded, PASSWORD, false, plaintext);
        assertRefusedPreservingFiles(encoded, decoded, WRONG_PASSWORD, true);
        assertNoStagingFiles(root);
    }

    private static void assertWriterMarker(File encoded) throws Exception {
        List<byte[]> parts = Format.unpackLengthPrefixed(
                Files.readAllBytes(encoded.toPath()), 3);
        byte[] pw = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] mask = KeyWrap.recoverMaskKey(
                parts.get(0), parts.get(1), pw, false,
                Constants.B512_FILE_MASK_INFO, Constants.MASK_AAD_B512FILE,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        byte[] aead = KeyWrap.deriveKeyAndWipe(mask, Constants.B512_AEAD_INFO, 32);
        byte[] clear = null;
        try {
            byte[] payload = parts.get(2);
            int metaLength = BaseFwxUtil.readU32(payload, 0);
            byte[] metadata = Arrays.copyOfRange(payload, 4, 4 + metaLength);
            clear = Crypto.aesGcmDecrypt(aead,
                    Arrays.copyOfRange(payload, 4 + metaLength, payload.length),
                    metadata);
            int markerOffset = metaLength + Constants.META_DELIM.length();
            assertArrayEquals(Constants.B512_STREAM_MAGIC_V2,
                    Arrays.copyOfRange(clear, markerOffset, markerOffset + 8));
            assertFalse(Arrays.equals(Constants.STREAM_MAGIC,
                    Arrays.copyOfRange(clear, markerOffset, markerOffset + 8)));
        } finally {
            Arrays.fill(pw, (byte) 0);
            Arrays.fill(aead, (byte) 0);
            if (clear != null) Arrays.fill(clear, (byte) 0);
        }
    }

    private static byte[] legacyFixture(byte[] plaintext, byte[] magic,
                                        boolean omitUser, boolean mismatchUser)
            throws Exception {
        byte[] pw = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] aead = null;
        byte[] obfuscated = plaintext.clone();
        byte[] clear = null;
        try (KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                pw, true, Constants.B512_FILE_MASK_INFO, true,
                Constants.MASK_AAD_B512FILE,
                new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS))) {
            byte[] userBlob = mask.userBlob;
            if (omitUser) {
                userBlob = new byte[0];
            } else if (mismatchUser) {
                try (KeyWrap.MaskKeyResult other = KeyWrap.prepareMaskKey(
                        pw, false, Constants.B512_FILE_MASK_INFO, true,
                        Constants.MASK_AAD_B512FILE,
                        new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS))) {
                    userBlob = other.userBlob;
                }
            }
            byte[] salt = pattern(Constants.STREAM_SALT_LEN, 1, 32);
            boolean fast = FileCodecObfuscation.perfModeEnabled();
            String metadata = FileCodecMetadata.buildMetadata(
                    "FWX512R", false, true, mask.masterKem, "AESGCM", "pbkdf2",
                    "STREAM", null, fast ? "fast" : "yes", null,
                    null, null, null, null);
            byte[] meta = metadata.getBytes(StandardCharsets.UTF_8);
            byte[] header = FileCodecMetadata.buildStreamHeader(
                    plaintext.length, salt, new byte[0], 4096);
            System.arraycopy(magic, 0, header, 0, magic.length);
            try (FileCodecObfuscation.StreamObfuscator obfuscator =
                    FileCodecObfuscation.StreamObfuscator.forPassword(pw, salt, fast)) {
                for (int offset = 0; offset < obfuscated.length; offset += 4096) {
                    byte[] chunk = Arrays.copyOfRange(obfuscated, offset,
                            Math.min(obfuscated.length, offset + 4096));
                    try {
                        obfuscator.encodeChunkInPlace(chunk);
                        System.arraycopy(chunk, 0, obfuscated, offset, chunk.length);
                    } finally {
                        Arrays.fill(chunk, (byte) 0);
                    }
                }
            }
            clear = FileCodecIo.concat(meta,
                    Constants.META_DELIM.getBytes(StandardCharsets.US_ASCII),
                    header, obfuscated);
            aead = KeyWrap.deriveKeyAndWipe(mask.maskKey, Constants.B512_AEAD_INFO, 32);
            ByteArrayOutputStream payload = new ByteArrayOutputStream();
            FileCodecIo.writeU32(payload, meta.length);
            payload.write(meta);
            payload.write(Crypto.aesGcmEncrypt(aead, clear, meta));
            return Format.packLengthPrefixed(
                    Arrays.asList(userBlob, mask.masterBlob, payload.toByteArray()));
        } finally {
            Arrays.fill(pw, (byte) 0);
            Arrays.fill(obfuscated, (byte) 0);
            if (aead != null) Arrays.fill(aead, (byte) 0);
            if (clear != null) Arrays.fill(clear, (byte) 0);
        }
    }

    private static void assertDecoded(File input, File output, String password,
                                      boolean useMaster, byte[] plaintext)
            throws Exception {
        BaseFwx.b512FileDecodeFile(input, output, password, useMaster);
        assertArrayEquals(plaintext, Files.readAllBytes(output.toPath()));
        assertNoStagingFiles(input.getParentFile());
    }

    private static void assertRefusedPreservingFiles(File input, File output,
                                                    String password, boolean useMaster)
            throws Exception {
        byte[] original = Files.readAllBytes(input.toPath());
        if (!input.equals(output)) Files.write(output.toPath(), EXISTING);
        try {
            BaseFwx.b512FileDecodeFile(input, output, password, useMaster);
            fail("B512 stream accepted invalid recovery input");
        } catch (RuntimeException expected) {
            assertArrayEquals(original, Files.readAllBytes(input.toPath()));
            assertArrayEquals(input.equals(output) ? original : EXISTING,
                    Files.readAllBytes(output.toPath()));
            assertNoStagingFiles(input.getParentFile());
        }
    }

    private static void assertNoStagingFiles(File root) {
        String[] pending = root.list((directory, name) -> name.startsWith(".basefwx-"));
        assertTrue(pending != null && pending.length == 0);
        String[] scratch = new File(root, "scratch").list();
        assertTrue(scratch != null && scratch.length == 0);
    }

    private static void provisionRecipient(File root, String algorithm) throws Exception {
        File publicFile = new File(root, "recipient.pub");
        File privateFile = new File(root, "recipient.key");
        if ("ec".equals(algorithm)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(Constants.MASTER_EC_CURVE));
            KeyPair pair = generator.generateKeyPair();
            writePem(publicFile, "PUBLIC KEY", pair.getPublic().getEncoded());
            writePem(privateFile, "PRIVATE KEY", pair.getPrivate().getEncoded());
        } else {
            PQ.KemKeyPair pair = PQ.generateKeyPair(algorithm);
            try {
                BaseFwxUtil.writeFileBytes(publicFile, Base64.getEncoder().encode(pair.publicKey));
                byte[] privateBytes = Base64.getEncoder().encode(pair.privateKey);
                try {
                    BaseFwxUtil.writeFileBytes(privateFile, privateBytes);
                } finally {
                    Arrays.fill(privateBytes, (byte) 0);
                }
            } finally {
                pair.wipePrivate();
            }
        }
    }

    private static void writePem(File path, String type, byte[] encoded) throws Exception {
        byte[] base64 = null;
        byte[] pem = null;
        try {
            base64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encode(encoded);
            pem = FileCodecIo.concat(
                    ("-----BEGIN " + type + "-----\n").getBytes(StandardCharsets.US_ASCII),
                    base64,
                    ("\n-----END " + type + "-----\n").getBytes(StandardCharsets.US_ASCII));
            BaseFwxUtil.writeFileBytes(path, pem);
        } finally {
            Arrays.fill(encoded, (byte) 0);
            if (base64 != null) Arrays.fill(base64, (byte) 0);
            if (pem != null) Arrays.fill(pem, (byte) 0);
        }
    }

    private static byte[] pattern(int length, int multiplier, int offset) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; ++i) result[i] = (byte) (i * multiplier + offset);
        return result;
    }

    private static byte[] hex(String text) {
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; ++i) {
            bytes[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
