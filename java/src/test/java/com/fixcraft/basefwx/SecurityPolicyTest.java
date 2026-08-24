/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SecurityPolicyTest {
    private static final byte[] PASSWORD =
            "correct-password".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MASK_INFO =
            "basefwx.test.mask.v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AAD =
            "basefwx.test.aad.v1".getBytes(StandardCharsets.US_ASCII);

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static void assertWeakPasswordRejected(ThrowingAction action) throws Exception {
        if (Constants.TEST_KDF_OVERRIDE) {
            return;
        }
        try {
            action.run();
            fail("expected weak password rejection");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("at least"));
        }
    }

    private static void assertPeerPbkdf2Rejected(
            ThrowingAction action, String expectedMessage) throws Exception {
        try {
            action.run();
            fail("expected peer PBKDF2 rejection");
        } catch (IllegalArgumentException expected) {
            assertTrue(
                    expected.getMessage(),
                    expected.getMessage().contains(expectedMessage));
        }
    }

    private int runJavaCliWithEnv(
            String envName,
            String envValue,
            File log,
            String... args) throws Exception {
        java.util.ArrayList<String> command =
                new java.util.ArrayList<String>();
        File javaBin = new File(
                new File(System.getProperty("java.home"), "bin"),
                System.getProperty("os.name").toLowerCase().contains("win")
                        ? "java.exe" : "java");
        command.add(javaBin.getAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("com.fixcraft.basefwx.cli.BaseFwxCli");
        command.addAll(Arrays.asList(args));
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        processBuilder.redirectOutput(log);
        processBuilder.environment().put("BASEFWX_USER_KDF", "pbkdf2");
        processBuilder.environment().put(
                "BASEFWX_USER_KDF_ITERS", "10000");
        processBuilder.environment().put(
                "BASEFWX_HEAVY_PBKDF2_ITERS", "10000");
        processBuilder.environment().put(
                "BASEFWX_FWXAES_PBKDF2_ITERS", "10000");
        processBuilder.environment().put(envName, envValue);
        return processBuilder.start().waitFor();
    }

    private static byte[] maliciousFwxAesHeader(int iterations) {
        byte[] blob = new byte[
                16
                + Constants.FWXAES_SALT_LEN
                + Constants.FWXAES_IV_LEN
                + Constants.AEAD_TAG_LEN];
        System.arraycopy(
                Constants.FWXAES_MAGIC, 0, blob, 0, Constants.FWXAES_MAGIC.length);
        blob[4] = (byte) Constants.FWXAES_ALGO;
        blob[5] = (byte) Constants.FWXAES_KDF_PBKDF2;
        blob[6] = (byte) Constants.FWXAES_SALT_LEN;
        blob[7] = (byte) Constants.FWXAES_IV_LEN;
        BaseFwxUtil.writeU32(blob, 8, iterations);
        BaseFwxUtil.writeU32(blob, 12, Constants.AEAD_TAG_LEN);
        return blob;
    }

    private static byte[] maliciousHugeFwxAesRawHeader(int kdf) {
        byte[] blob = new byte[16];
        System.arraycopy(
                Constants.FWXAES_MAGIC, 0, blob, 0,
                Constants.FWXAES_MAGIC.length);
        blob[4] = (byte) Constants.FWXAES_ALGO;
        blob[5] = (byte) kdf;
        blob[6] = (byte) (kdf == Constants.FWXAES_KDF_PBKDF2
                ? Constants.FWXAES_SALT_LEN : 0);
        blob[7] = (byte) Constants.FWXAES_IV_LEN;
        BaseFwxUtil.writeU32(
                blob,
                8,
                kdf == Constants.FWXAES_KDF_PBKDF2
                    ? Constants.USER_KDF_ITERATIONS : 0);
        BaseFwxUtil.writeU32(blob, 12, Integer.MAX_VALUE);
        return blob;
    }

    private static byte[] maliciousLiveHeader(int iterations) {
        int bodyLen = Constants.LIVE_HEADER_FIXED_LEN
                + 1
                + Constants.LIVE_NONCE_PREFIX_LEN;
        byte[] frame = new byte[Constants.LIVE_FRAME_HEADER_LEN + bodyLen];
        System.arraycopy(
                Constants.LIVE_FRAME_MAGIC, 0, frame, 0,
                Constants.LIVE_FRAME_MAGIC.length);
        frame[4] = (byte) Constants.LIVE_FRAME_VERSION;
        frame[5] = (byte) Constants.LIVE_FRAME_TYPE_HEADER;
        BaseFwxUtil.writeU32(frame, 14, bodyLen);
        int bodyOffset = Constants.LIVE_FRAME_HEADER_LEN;
        frame[bodyOffset] = (byte) Constants.LIVE_KEYMODE_PBKDF2;
        frame[bodyOffset + 1] = 1;
        frame[bodyOffset + 2] = (byte) Constants.LIVE_NONCE_PREFIX_LEN;
        BaseFwxUtil.writeU32(frame, bodyOffset + 8, iterations);
        frame[bodyOffset + Constants.LIVE_HEADER_FIXED_LEN] = (byte) 0xA5;
        return frame;
    }

    private static byte[] maliciousLiveOuterHeader(int bodyLength) {
        byte[] frame = new byte[Constants.LIVE_FRAME_HEADER_LEN];
        System.arraycopy(
                Constants.LIVE_FRAME_MAGIC, 0, frame, 0,
                Constants.LIVE_FRAME_MAGIC.length);
        frame[4] = (byte) Constants.LIVE_FRAME_VERSION;
        frame[5] = (byte) Constants.LIVE_FRAME_TYPE_HEADER;
        BaseFwxUtil.writeU32(frame, 14, bodyLength);
        return frame;
    }

    private static byte[] maliciousLengthPrefixedBlob(
            String mode, int iterations) {
        String metadata = FileCodecs.buildMetadata(
                "AES-HEAVY", false, false, "none", "AESGCM", "pbkdf2",
                mode, false, "no", iterations, null, null, null, null);
        byte[] metadataBytes = metadata.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[4 + metadataBytes.length];
        BaseFwxUtil.writeU32(payload, 0, metadataBytes.length);
        System.arraycopy(metadataBytes, 0, payload, 4, metadataBytes.length);
        return Format.packLengthPrefixed(
                Arrays.asList(new byte[0], new byte[0], payload));
    }

    private static byte[] maliciousStreamingFile(int iterations) {
        String metadata = FileCodecs.buildMetadata(
                "AES-HEAVY", false, false, "none", "AESGCM", "pbkdf2",
                "STREAM", false, "no", iterations, null, null, null, null);
        byte[] metadataBytes = metadata.getBytes(StandardCharsets.UTF_8);
        int payloadLen = 4 + metadataBytes.length
                + Constants.AEAD_NONCE_LEN
                + Constants.AEAD_TAG_LEN;
        byte[] blob = new byte[12 + payloadLen];
        BaseFwxUtil.writeU32(blob, 0, 0);
        BaseFwxUtil.writeU32(blob, 4, 0);
        BaseFwxUtil.writeU32(blob, 8, payloadLen);
        BaseFwxUtil.writeU32(blob, 12, metadataBytes.length);
        System.arraycopy(metadataBytes, 0, blob, 16, metadataBytes.length);
        return blob;
    }

    private static byte[] legacyB512UserWrap(byte[] maskKey) {
        byte[] label = "pbkdf2".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = new byte[Constants.USER_KDF_SALT_SIZE];
        Arrays.fill(salt, (byte) 0x5A);
        KeyWrap.KdfOptions kdf = new KeyWrap.KdfOptions(
                "pbkdf2", Constants.USER_KDF_ITERATIONS);
        byte[] userKey = FileCodecKdf.deriveUserKey(
                PASSWORD, salt, "pbkdf2", kdf);
        try {
            byte[] wrapped = Crypto.aesGcmEncrypt(
                    userKey, maskKey, Constants.B512_AEAD_INFO);
            byte[] userBlob = new byte[
                    1 + label.length + salt.length + wrapped.length];
            userBlob[0] = (byte) label.length;
            System.arraycopy(label, 0, userBlob, 1, label.length);
            System.arraycopy(
                    salt, 0, userBlob, 1 + label.length, salt.length);
            System.arraycopy(
                    wrapped, 0, userBlob,
                    1 + label.length + salt.length, wrapped.length);
            return userBlob;
        } finally {
            Arrays.fill(userKey, (byte) 0);
        }
    }

    @Test
    public void booleanSpellingsMatchCppContract() {
        for (String value : new String[] {"1", "true", "TRUE", "yes", "YeS", "on", "ON"}) {
            assertTrue(value, Constants.envEnabledValue(value));
        }
        for (String value : new String[] {null, "", "0", "false", "off", "garbage"}) {
            assertFalse(String.valueOf(value), Constants.envEnabledValue(value));
        }
    }

    @Test
    public void maskKeyResultCloseWipesOwnedKey() {
        KeyWrap.MaskKeyResult prepared = KeyWrap.prepareMaskKey(
                PASSWORD,
                false,
                MASK_INFO,
                true,
                AAD,
                new KeyWrap.KdfOptions("pbkdf2", 1));
        byte[] ownedMaskKey = prepared.maskKey;

        prepared.close();

        assertArrayEquals(new byte[ownedMaskKey.length], ownedMaskKey);
    }

    @Test
    public void maskKeyDerivationWipesOnSuccessAndFailure() {
        byte[] successMaskKey = new byte[32];
        Arrays.fill(successMaskKey, (byte) 0x5A);
        byte[] derived = KeyWrap.deriveKeyAndWipe(
                successMaskKey, Constants.FWXAES_KEY_INFO, 32);
        try {
            assertArrayEquals(new byte[successMaskKey.length], successMaskKey);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }

        byte[] failingMaskKey = new byte[32];
        Arrays.fill(failingMaskKey, (byte) 0x5A);
        try {
            KeyWrap.deriveKeyAndWipe(
                    failingMaskKey,
                    Constants.FWXAES_KEY_INFO,
                    Constants.HKDF_MAX_LEN + 1);
            fail("expected oversized HKDF output rejection");
        } catch (IllegalArgumentException expected) {
            // The rejection is the injected derivation failure.
        }
        assertArrayEquals(new byte[failingMaskKey.length], failingMaskKey);
    }

    @Test
    public void wrongMasterFallsBackToIndependentPasswordWrap() {
        KeyWrap.KdfOptions kdf = new KeyWrap.KdfOptions("pbkdf2", 1);
        KeyWrap.MaskKeyResult prepared = KeyWrap.prepareMaskKey(
                PASSWORD, false, MASK_INFO, true, AAD, kdf);
        byte[] recovered = KeyWrap.recoverMaskKey(
                prepared.userBlob,
                "corrupt-pq-master-blob".getBytes(StandardCharsets.US_ASCII),
                PASSWORD,
                true,
                MASK_INFO,
                AAD,
                kdf);
        assertArrayEquals(prepared.maskKey, recovered);
    }

    @Test
    public void disabledMasterStillUsesIndependentPasswordWrap() {
        KeyWrap.KdfOptions kdf = new KeyWrap.KdfOptions("pbkdf2", 1);
        KeyWrap.MaskKeyResult prepared = KeyWrap.prepareMaskKey(
                PASSWORD, false, MASK_INFO, true, AAD, kdf);
        byte[] recovered = KeyWrap.recoverMaskKey(
                prepared.userBlob,
                "unused-master-blob".getBytes(StandardCharsets.US_ASCII),
                PASSWORD,
                false,
                MASK_INFO,
                AAD,
                kdf);
        assertArrayEquals(prepared.maskKey, recovered);
    }

    @Test
    public void lengthPrefixedCodecUsesPasswordWhenMasterRecoveryFails() {
        String password = new String(PASSWORD, StandardCharsets.UTF_8);
        String metadata = FileCodecs.buildMetadata(
                "AES-TEST", false, false, "none", "AESGCM", "pbkdf2",
                null, false, null, 1, null, null, null, null);
        byte[] blob = LengthPrefixedCodec.encryptAesPayloadBytes(
                "payload".getBytes(StandardCharsets.UTF_8),
                password,
                false,
                metadata,
                "pbkdf2",
                1,
                false,
                false);
        List<byte[]> parts = Format.unpackLengthPrefixed(blob, 3);
        parts.set(
                1,
                "corrupt-pq-master-blob".getBytes(StandardCharsets.US_ASCII));

        byte[] recovered = LengthPrefixedCodec.decryptAesPayloadBytes(
                Format.packLengthPrefixed(parts), password, true);
        assertArrayEquals(
                "payload".getBytes(StandardCharsets.UTF_8), recovered);
    }

    @Test
    public void passwordOnlyFwxAesRawRejectsWeakPassword() throws Exception {
        assertWeakPasswordRejected(() -> BaseFwx.fwxAesEncryptRawBytes(
                "payload".getBytes(StandardCharsets.UTF_8),
                "short".getBytes(StandardCharsets.UTF_8),
                false));
    }

    @Test
    public void passwordOnlyFwxAesStreamRejectsWeakPassword() throws Exception {
        assertWeakPasswordRejected(() -> BaseFwx.fwxAesEncryptStream(
                new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayOutputStream(),
                "short",
                false));
    }

    @Test
    public void passwordOnlyFwxAesNioFileRejectsWeakPassword() throws Exception {
        File input = tmp.newFile("weak-password-input.bin");
        File output = tmp.newFile("weak-password-output.fwx");
        Files.write(input.toPath(), "payload".getBytes(StandardCharsets.UTF_8));
        assertWeakPasswordRejected(() ->
                BaseFwx.fwxAesEncryptFileNio(input, output, "short", false));
    }

    @Test
    public void passwordOnlyFwxAesLiveRejectsWeakPassword() throws Exception {
        assertWeakPasswordRejected(() -> new LiveCipher.LiveEncryptor("short", false));
    }

    @Test
    public void peerPbkdf2MaximumAndStrictMetadataParsing() throws Exception {
        int max = Constants.PEER_PBKDF2_ITERATIONS_MAX;
        FileCodecKdf.requirePeerPbkdf2WithinLimits(max);
        assertEquals(max, FileCodecs.parsePeerPbkdf2Iterations(
                Integer.toString(max), Constants.USER_KDF_ITERATIONS));

        for (String value : new String[] {
                "0",
                "01",
                "-1",
                "4000000x",
                "4000000 ",
                "4000001",
                "2147483648",
                "4294967296",
                "999999999999999999999999"
        }) {
            assertPeerPbkdf2Rejected(
                    () -> FileCodecs.parsePeerPbkdf2Iterations(
                            value, Constants.USER_KDF_ITERATIONS),
                    "Peer");
        }

        assertPeerPbkdf2Rejected(
                () -> KeyWrap.prepareMaskKey(
                        PASSWORD,
                        false,
                        MASK_INFO,
                        true,
                        AAD,
                        new KeyWrap.KdfOptions("pbkdf2", max + 1)),
                "exceeds maximum");
    }

    @Test
    public void wireKdfLabelsAndEcFramesAreExact() throws Exception {
        assertEquals("pbkdf2", FileCodecKdf.resolvePeerKdfLabel("pbkdf2"));
        assertEquals("argon2id", FileCodecKdf.resolvePeerKdfLabel("argon2"));
        assertEquals("argon2id", FileCodecKdf.resolvePeerKdfLabel("argon2id"));
        for (String label : new String[] {
                "", "auto", "argon2evil", "PBKDF2", " pbkdf2"
        }) {
            try {
                FileCodecKdf.resolvePeerKdfLabel(label);
                fail("invalid peer KDF label accepted: " + label);
            } catch (UnsupportedKdfException expected) {
                assertTrue(expected.getMessage().contains("peer KDF"));
            }
        }

        byte[] valid = new byte[
                Constants.MASTER_EC_MAGIC.length
                        + 2 + Constants.MASTER_EC_POINT_LEN];
        System.arraycopy(
                Constants.MASTER_EC_MAGIC, 0, valid, 0,
                Constants.MASTER_EC_MAGIC.length);
        int offset = Constants.MASTER_EC_MAGIC.length;
        valid[offset + 1] = (byte) Constants.MASTER_EC_POINT_LEN;
        valid[offset + 2] = 0x04;
        assertTrue(EcKeys.isEcMasterBlob(valid));
        assertFalse(EcKeys.isEcMasterBlob(
                Arrays.copyOf(valid, valid.length + 1)));
        byte[] collision = new byte[1088];
        System.arraycopy(
                Constants.MASTER_EC_MAGIC, 0, collision, 0,
                Constants.MASTER_EC_MAGIC.length);
        assertFalse(EcKeys.isEcMasterBlob(collision));

        String autoMetadata = FileCodecs.buildMetadata(
                "TEST", false, false, "none", "AESGCM", "pbkdf2");
        byte[] decoded = Base64Codec.decode(autoMetadata);
        String autoJson = new String(decoded, StandardCharsets.UTF_8)
                .replace("\"ENC-KDF\":\"pbkdf2\"",
                        "\"ENC-KDF\":\"auto\"");
        byte[] autoMetadataBytes = Base64Codec.encode(
                autoJson.getBytes(StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[4 + autoMetadataBytes.length];
        BaseFwxUtil.writeU32(payload, 0, autoMetadataBytes.length);
        System.arraycopy(
                autoMetadataBytes, 0, payload, 4,
                autoMetadataBytes.length);
        try {
            LengthPrefixedCodec.decryptAesPayloadBytes(
                    Format.packLengthPrefixed(Arrays.asList(
                            new byte[0], new byte[0], payload)),
                    new String(PASSWORD, StandardCharsets.UTF_8),
                    false);
            fail("wire ENC-KDF=auto was accepted");
        } catch (UnsupportedKdfException expected) {
            assertTrue(expected.getMessage().contains("peer KDF"));
        }
    }

    @Test
    public void emptyPasswordRequiresEffectiveMasterSelection() {
        try {
            LengthPrefixedCodec.encryptAesPayloadBytes(
                    "payload".getBytes(StandardCharsets.UTF_8),
                    "",
                    true,
                    "",
                    "pbkdf2",
                    1,
                    false,
                    false,
                    null,
                    null,
                    null,
                    KeyWrap.MasterKeySelection.none());
            fail("empty password without an effective master key was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(
                    expected.getMessage(),
                    expected.getMessage().contains(
                            "without password or master key"));
        }
    }

    @Test
    public void metadataAndPreReadLengthCapsFailClosed() throws Exception {
        try {
            LengthPrefixedCodec.encryptAesPayloadBytes(
                    "payload".getBytes(StandardCharsets.UTF_8),
                    "",
                    true,
                    "",
                    "argon2evil",
                    1,
                    false,
                    false,
                    null,
                    null,
                    null,
                    KeyWrap.MasterKeySelection.none());
            fail("unknown master-only producer KDF was accepted");
        } catch (UnsupportedKdfException expected) {
            assertTrue(expected.getMessage().contains("Unsupported KDF"));
        }

        char[] oversizedChars = new char[Constants.METADATA_MAX + 1];
        Arrays.fill(oversizedChars, 'x');
        try {
            LengthPrefixedCodec.encryptAesPayloadBytes(
                    "payload".getBytes(StandardCharsets.UTF_8),
                    new String(PASSWORD, StandardCharsets.UTF_8),
                    false,
                    new String(oversizedChars),
                    "pbkdf2",
                    1,
                    false,
                    false,
                    null,
                    null,
                    null,
                    KeyWrap.MasterKeySelection.none());
            fail("oversized producer metadata was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("1 MiB"));
        }

        File hostile = tmp.newFile("hostile-length.fwx");
        byte[] hostileHeader = new byte[16];
        Arrays.fill(hostileHeader, 0, 4, (byte) 0xFF);
        Files.write(hostile.toPath(), hostileHeader);
        try {
            FileCodecs.peekMetadataBlob(hostile);
            fail("high-bit user length was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("high bit"));
        }

        File sparse = tmp.newFile("oversized-nonstream.fwx");
        try (RandomAccessFile handle = new RandomAccessFile(sparse, "rw")) {
            handle.setLength((long) Constants.LENGTH_PREFIXED_MAX + 1L);
        }
        try {
            BaseFwx.pb512FileDecodeFile(
                    sparse,
                    tmp.newFile("unused-output.bin"),
                    new String(PASSWORD, StandardCharsets.UTF_8),
                    false);
            fail("oversized non-stream file was read");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("length"));
        }
    }

    @Test
    public void metadataPreviewOnlyDispatchesAuthenticatedStreamCandidates()
            throws Exception {
        byte[] noncePayload = new byte[
                4 + Constants.AEAD_NONCE_LEN + Constants.AEAD_TAG_LEN];
        Arrays.fill(noncePayload, 0, 4, (byte) 0xFF);
        byte[] packedNonceCandidate = Format.packLengthPrefixed(Arrays.asList(
                new byte[0], new byte[0], noncePayload));
        File nonceCandidate = tmp.newFile("simple-nonce-candidate.fwx");
        Files.write(nonceCandidate.toPath(), packedNonceCandidate);
        assertEquals("", FileCodecs.peekMetadataBlob(nonceCandidate));

        File trailingCandidate = tmp.newFile("trailing-container-data.fwx");
        Files.write(
                trailingCandidate.toPath(),
                Arrays.copyOf(packedNonceCandidate, packedNonceCandidate.length + 1));
        try {
            FileCodecs.peekMetadataBlob(trailingCandidate);
            fail("length-prefixed container with trailing data was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("remaining file"));
        }

        File nonStreamCandidate =
                tmp.newFile("non-stream-metadata-candidate.fwx");
        Files.write(
                nonStreamCandidate.toPath(),
                maliciousLengthPrefixedBlob(null, 1));
        assertEquals("", FileCodecs.peekMetadataBlob(nonStreamCandidate));

        File streamCandidate = tmp.newFile("stream-metadata-candidate.fwx");
        Files.write(streamCandidate.toPath(), maliciousStreamingFile(1));
        assertTrue(FileCodecs.peekMetadataBlob(streamCandidate).length() > 0);
    }

    @Test
    public void argonMetadataDecimalGrammarIsStrict() {
        assertEquals(
                Integer.valueOf(Constants.ARGON2_TIME_COST_MAX),
                FileCodecs.parseMetadataIntOrNull(
                        Integer.toString(Constants.ARGON2_TIME_COST_MAX)));
        for (String value : new String[] {
                "0", "01", "-1", "+1", "1 ", "1x",
                "999999999999999999999999"
        }) {
            try {
                FileCodecs.parseMetadataIntOrNull(value);
                fail("invalid peer Argon2 decimal accepted: " + value);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("Peer Argon2"));
            }
        }
    }

    @Test
    public void peerPbkdf2MaximumAppliesToRawStreamAndLiveHeaders() throws Exception {
        int overMax = Constants.PEER_PBKDF2_ITERATIONS_MAX + 1;
        byte[] header = maliciousFwxAesHeader(overMax);
        assertPeerPbkdf2Rejected(
                () -> FwxAesCodec.fwxAesDecryptRawBytes(
                        header, PASSWORD, false),
                "exceeds maximum");
        assertPeerPbkdf2Rejected(
                () -> BaseFwx.fwxAesDecryptStream(
                        new ByteArrayInputStream(header),
                        new ByteArrayOutputStream(),
                        new String(PASSWORD, StandardCharsets.UTF_8),
                        false),
                "exceeds maximum");
        try (LiveCipher.LiveDecryptor decryptor =
                     new LiveCipher.LiveDecryptor(
                             new String(PASSWORD, StandardCharsets.UTF_8), false)) {
            assertPeerPbkdf2Rejected(
                    () -> decryptor.update(maliciousLiveHeader(overMax)),
                    "exceeds maximum");
        }
    }

    @Test
    public void liveRejectsOversizedKeyHeaderFromOuterHeaderOnly()
            throws Exception {
        try (LiveCipher.LiveDecryptor decryptor =
                     new LiveCipher.LiveDecryptor(
                             new String(
                                     PASSWORD,
                                     StandardCharsets.UTF_8),
                             false)) {
            try {
                decryptor.update(maliciousLiveOuterHeader(
                        Constants.LIVE_MAX_HEADER_BODY + 1));
                fail("oversized partial live key header was accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains(
                        "key header too large"));
            }
        }
    }

    @Test
    public void liveRejectsForgedHugePlaintextLengthBeforeAllocation()
            throws Exception {
        String password =
                new String(PASSWORD, StandardCharsets.UTF_8);
        byte[] header;
        byte[] dataFrame;
        try (LiveCipher.LiveEncryptor encryptor =
                     new LiveCipher.LiveEncryptor(password, false)) {
            header = encryptor.start();
            dataFrame = encryptor.update(new byte[] {0x5A});
        }
        BaseFwxUtil.writeU32(
                dataFrame,
                Constants.LIVE_FRAME_HEADER_LEN,
                Integer.MAX_VALUE);

        try (LiveCipher.LiveDecryptor decryptor =
                     new LiveCipher.LiveDecryptor(password, false)) {
            decryptor.update(header);
            try {
                decryptor.update(dataFrame);
                fail("forged huge live plaintext length was accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(
                        expected.getMessage(),
                        expected.getMessage().contains(
                                "Live frame length mismatch"));
            }
        }
    }

    @Test
    public void rawFwxAesHugeCiphertextLengthsRejectBeforeAllocation() {
        for (int kdf : new int[] {
                Constants.FWXAES_KDF_WRAP,
                Constants.FWXAES_KDF_PBKDF2
        }) {
            try {
                FwxAesCodec.fwxAesDecryptRawBytes(
                        maliciousHugeFwxAesRawHeader(kdf),
                        PASSWORD,
                        false);
                fail("huge raw fwxAES ciphertext length was accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(
                        expected.getMessage(),
                        expected.getMessage().contains(
                                "fwxAES blob truncated"));
            }
        }
    }

    @Test
    public void fwxAesPublicStreamDecryptsLargePayloadAndPublishesOnlyAfterAuth()
            throws Exception {
        byte[] plaintext = new byte[
                3 * Constants.STREAM_CHUNK_SIZE + 29];
        for (int i = 0; i < plaintext.length; ++i) {
            plaintext[i] = (byte) (i * 29 + 11);
        }
        String password =
                new String(PASSWORD, StandardCharsets.UTF_8);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        BaseFwx.fwxAesEncryptStream(
                new ByteArrayInputStream(plaintext),
                encrypted,
                password,
                false);

        ByteArrayOutputStream restored = new ByteArrayOutputStream();
        BaseFwx.fwxAesDecryptStream(
                new ByteArrayInputStream(encrypted.toByteArray()),
                restored,
                password,
                false);
        assertArrayEquals(plaintext, restored.toByteArray());

        byte[] tampered = encrypted.toByteArray();
        tampered[tampered.length - 1] ^= 0x01;
        byte[] sentinel =
                "existing observing destination"
                        .getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream observingDestination =
                new ByteArrayOutputStream();
        observingDestination.write(sentinel);
        try {
            BaseFwx.fwxAesDecryptStream(
                    new ByteArrayInputStream(tampered),
                    observingDestination,
                    password,
                    false);
            fail("bad large fwxAES stream tag was accepted");
        } catch (RuntimeException expected) {
            assertTrue(expected.getMessage() != null);
        }
        assertArrayEquals(
                sentinel, observingDestination.toByteArray());
    }

    @Test
    public void badFwxAesFileTagPreservesExistingDestination()
            throws Exception {
        File source = tmp.newFile("fwxaes-auth-source.bin");
        File encrypted = tmp.newFile("fwxaes-auth-source.fwx");
        File destination = tmp.newFile(
                "fwxaes-auth-destination.bin");
        byte[] plaintext = new byte[
                3 * Constants.STREAM_CHUNK_SIZE + 29];
        for (int i = 0; i < plaintext.length; ++i) {
            plaintext[i] = (byte) (i * 31 + 7);
        }
        byte[] sentinel =
                "existing authenticated destination"
                        .getBytes(StandardCharsets.UTF_8);
        Files.write(source.toPath(), plaintext);
        Files.write(destination.toPath(), sentinel);
        BaseFwx.fwxAesEncryptFile(
                source,
                encrypted,
                new String(PASSWORD, StandardCharsets.UTF_8),
                false);
        try (RandomAccessFile handle =
                     new RandomAccessFile(encrypted, "rw")) {
            handle.seek(handle.length() - 1L);
            int value = handle.read();
            handle.seek(handle.length() - 1L);
            handle.write(value ^ 1);
        }
        String[] before = tmp.getRoot().list();
        Arrays.sort(before);

        try {
            BaseFwx.fwxAesDecryptFile(
                    encrypted,
                    destination,
                    new String(PASSWORD, StandardCharsets.UTF_8),
                    false);
            fail("bad fwxAES file tag was accepted");
        } catch (RuntimeException expected) {
            assertTrue(expected.getMessage() != null);
        }

        assertArrayEquals(
                sentinel, Files.readAllBytes(destination.toPath()));
        String[] after = tmp.getRoot().list();
        Arrays.sort(after);
        assertArrayEquals(before, after);
    }

    @Test
    public void peerPbkdf2MaximumAppliesToSimpleAndStreamingFileCodecs()
            throws Exception {
        int overMax = Constants.PEER_PBKDF2_ITERATIONS_MAX + 1;
        assertPeerPbkdf2Rejected(
                () -> LengthPrefixedCodec.decryptAesPayloadBytes(
                        maliciousLengthPrefixedBlob(null, overMax),
                        new String(PASSWORD, StandardCharsets.UTF_8),
                        false),
                "exceeds maximum");

        File input = tmp.newFile("peer-pbkdf2-over-max.fwx");
        File output = tmp.newFile("peer-pbkdf2-output.bin");
        Files.write(input.toPath(), maliciousStreamingFile(overMax));
        assertPeerPbkdf2Rejected(
                () -> BaseFwx.pb512FileDecodeFile(
                        input,
                        output,
                        new String(PASSWORD, StandardCharsets.UTF_8),
                        false),
                "exceeds maximum");
    }

    @Test
    public void writerPbkdf2MaximumPlusOneFailsBeforePayloadOutput()
            throws Exception {
        int overMax = Constants.PEER_PBKDF2_ITERATIONS_MAX + 1;
        assertPeerPbkdf2Rejected(
                () -> LengthPrefixedCodec.encryptAesPayloadBytes(
                        "payload".getBytes(StandardCharsets.UTF_8),
                        new String(PASSWORD, StandardCharsets.UTF_8),
                        false,
                        "",
                        "pbkdf2",
                        overMax,
                        false,
                        false),
                "exceeds maximum");

        File input = tmp.newFile("writer-over-max-input.bin");
        Files.write(input.toPath(), "payload".getBytes(StandardCharsets.UTF_8));
        File streamOutput =
                new File(tmp.getRoot(), "writer-over-max-stream.fwx");
        File streamLog = new File(tmp.getRoot(), "writer-over-max-stream.log");
        int streamExit = runJavaCliWithEnv(
                "BASEFWX_FWXAES_PBKDF2_ITERS",
                Integer.toString(overMax),
                streamLog,
                "fwxaes-stream-enc",
                input.getAbsolutePath(),
                streamOutput.getAbsolutePath(),
                new String(PASSWORD, StandardCharsets.UTF_8),
                "--no-master");
        assertTrue("over-max stream writer unexpectedly succeeded",
                streamExit != 0);
        assertTrue("over-max stream writer emitted payload bytes",
                !streamOutput.exists() || Files.size(streamOutput.toPath()) == 0L);

        File heavyOutput =
                new File(tmp.getRoot(), "writer-over-max-heavy.fwx");
        File heavyLog = new File(tmp.getRoot(), "writer-over-max-heavy.log");
        int heavyExit = runJavaCliWithEnv(
                "BASEFWX_HEAVY_PBKDF2_ITERS",
                Integer.toString(overMax),
                heavyLog,
                "pb512file-enc",
                input.getAbsolutePath(),
                heavyOutput.getAbsolutePath(),
                new String(PASSWORD, StandardCharsets.UTF_8),
                "--no-master");
        assertTrue("over-max PB512 writer unexpectedly succeeded",
                heavyExit != 0);
        assertTrue("over-max PB512 writer emitted payload bytes",
                !heavyOutput.exists() || Files.size(heavyOutput.toPath()) == 0L);
        assertTrue("over-max PB512 writer removed its input", input.exists());
    }

    @Test
    public void pb512StreamingObfuscationOffPublishesMatchingMetadataAndBytes()
            throws Exception {
        byte[] payload = new byte[3 * 1024 * 1024 + 29];
        for (int i = 0; i < payload.length; ++i) {
            payload[i] = (byte) (i * 31 + 7);
        }
        File input = tmp.newFile("pb512-obf-off-input.bin");
        Files.write(input.toPath(), payload);
        File encrypted =
                new File(tmp.getRoot(), "pb512-obf-off.fwx");
        File encodeLog =
                new File(tmp.getRoot(), "pb512-obf-off-encode.log");
        assertEquals(
                0,
                runJavaCliWithEnv(
                        "BASEFWX_OBFUSCATE",
                        "0",
                        encodeLog,
                        "pb512file-enc",
                        input.getAbsolutePath(),
                        encrypted.getAbsolutePath(),
                        new String(PASSWORD, StandardCharsets.UTF_8),
                        "--no-master",
                        "--keep-input"));
        String metadata = FileCodecs.peekMetadataBlob(encrypted);
        assertEquals("v1", FileCodecs.metaValue(metadata, "ENC-KSEP"));
        assertEquals("no", FileCodecs.metaValue(metadata, "ENC-OBF"));

        File decoded =
                new File(tmp.getRoot(), "pb512-obf-off-decoded.bin");
        File decodeLog =
                new File(tmp.getRoot(), "pb512-obf-off-decode.log");
        assertEquals(
                0,
                runJavaCliWithEnv(
                        "BASEFWX_OBFUSCATE",
                        "1",
                        decodeLog,
                        "pb512file-dec",
                        encrypted.getAbsolutePath(),
                        decoded.getAbsolutePath(),
                        new String(PASSWORD, StandardCharsets.UTF_8),
                        "--no-master"));
        assertArrayEquals(payload, Files.readAllBytes(decoded.toPath()));
    }

    @Test
    public void supportedKemAliasesAndSelectedKeySizesAreCanonical()
            throws Exception {
        for (String value : new String[] {
                "ml-kem-768", " ML-KEM-768 ", "kyber768", " Kyber-768 ",
                "ml-kem-1024", "kyber1024", " kyber-1024 "
        }) {
            assertTrue(value, PQ.isSupportedKemAlgorithm(value));
        }
        for (String value : new String[] {null, "", " ", "ml-kem-512"}) {
            assertFalse(String.valueOf(value),
                    PQ.isSupportedKemAlgorithm(value));
        }

        PQ.KemKeyPair pair768 =
                PQ.generateKeyPair(PQ.KemAlgorithm.ML_KEM_768.wireName());
        PQ.KemKeyPair pair1024 =
                PQ.generateKeyPair(PQ.KemAlgorithm.ML_KEM_1024.wireName());
        try {
            assertEquals(
                    "ml-kem-768",
                    PQ.inferKemAlgorithmFromPublicKey(
                            pair768.publicKey).wireName());
            assertEquals(
                    "ml-kem-1024",
                    PQ.inferKemAlgorithmFromPublicKey(
                            pair1024.publicKey).wireName());
        } finally {
            pair768.wipePrivate();
            pair1024.wipePrivate();
        }

        for (String label : new String[] {
                "ml-kem-768", "ml-kem-1024", "EC"
        }) {
            String metadata = FileCodecs.buildMetadata(
                    "TEST", false, true, label, "AESGCM", "pbkdf2");
            assertEquals(label, FileCodecs.metaValue(metadata, "ENC-KEM"));
        }
        assertEquals(
                "none",
                FileCodecs.metaValue(
                        FileCodecs.buildMetadata(
                                "TEST", false, false, "none",
                                "AESGCM", "pbkdf2"),
                        "ENC-KEM"));
    }

    @Test
    public void java37B512UserWrapAadRetryIsAuthenticationFailureOnly() {
        KeyWrap.KdfOptions kdf = new KeyWrap.KdfOptions("pbkdf2", 1);
        KeyWrap.MaskKeyResult prepared = KeyWrap.prepareMaskKey(
                PASSWORD,
                false,
                Constants.B512_FILE_MASK_INFO,
                true,
                Constants.B512_AEAD_INFO,
                kdf);
        byte[] recovered = KeyWrap.recoverMaskKey(
                prepared.userBlob,
                new byte[0],
                PASSWORD,
                false,
                Constants.B512_FILE_MASK_INFO,
                Constants.MASK_AAD_B512FILE,
                kdf,
                Constants.B512_AEAD_INFO);
        assertArrayEquals(prepared.maskKey, recovered);

        try {
            KeyWrap.recoverMaskKey(
                    prepared.userBlob,
                    new byte[0],
                    "wrong-password".getBytes(StandardCharsets.UTF_8),
                    false,
                    Constants.B512_FILE_MASK_INFO,
                    Constants.MASK_AAD_B512FILE,
                    kdf,
                    Constants.B512_AEAD_INFO);
            fail("wrong password unexpectedly accepted");
        } catch (Crypto.AuthenticationException expected) {
            // Both the canonical and exact legacy user-wrap AAD failed.
        }

        try {
            KeyWrap.recoverMaskKey(
                    new byte[] {(byte) 0xFF},
                    new byte[0],
                    PASSWORD,
                    false,
                    Constants.B512_FILE_MASK_INFO,
                    Constants.MASK_AAD_B512FILE,
                    kdf,
                    Constants.B512_AEAD_INFO);
            fail("malformed keywrap unexpectedly accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("truncated"));
        }
    }

    @Test
    public void java37B512UserWrapFixturesDecodeBytesAndDirectStream()
            throws Exception {
        String password = new String(PASSWORD, StandardCharsets.UTF_8);
        KeyWrap.KdfOptions kdf = new KeyWrap.KdfOptions(
                "pbkdf2", Constants.USER_KDF_ITERATIONS);

        byte[] canonical = B512FileCodec.b512FileEncodeBytes(
                "fixture-bytes".getBytes(StandardCharsets.UTF_8),
                ".txt",
                password,
                false,
                false,
                true);
        List<byte[]> parts = Format.unpackLengthPrefixed(canonical, 3);
        byte[] maskKey = KeyWrap.recoverMaskKey(
                parts.get(0),
                parts.get(1),
                PASSWORD,
                false,
                Constants.B512_FILE_MASK_INFO,
                Constants.MASK_AAD_B512FILE,
                kdf);
        byte[] legacyUser = legacyB512UserWrap(maskKey);
        assertEquals(parts.get(0).length, legacyUser.length);
        BaseFwx.DecodedFile decoded =
                B512FileCodec.b512FileDecodeBytes(
                        Format.packLengthPrefixed(Arrays.asList(
                                legacyUser, parts.get(1), parts.get(2))),
                        password,
                        false);
        assertArrayEquals(
                "fixture-bytes".getBytes(StandardCharsets.UTF_8),
                decoded.data);

        File source = tmp.newFile("legacy-stream-source.txt");
        File encoded = tmp.newFile("legacy-stream.fwx");
        File output = tmp.newFile("legacy-stream-output.txt");
        Files.write(
                source.toPath(),
                "fixture-stream".getBytes(StandardCharsets.UTF_8));
        B512FileCodec.b512FileEncodeFileStream(
                source, encoded, password, false);
        byte[] stream = Files.readAllBytes(encoded.toPath());
        int lenUser = BaseFwxUtil.readU32(stream, 0);
        int userStart = 4;
        int userEnd = userStart + lenUser;
        int lenMaster = BaseFwxUtil.readU32(stream, userEnd);
        int masterStart = userEnd + 4;
        int masterEnd = masterStart + lenMaster;
        byte[] streamUser = Arrays.copyOfRange(
                stream, userStart, userEnd);
        byte[] streamMaster = Arrays.copyOfRange(
                stream, masterStart, masterEnd);
        byte[] streamMaskKey = KeyWrap.recoverMaskKey(
                streamUser,
                streamMaster,
                PASSWORD,
                false,
                Constants.B512_FILE_MASK_INFO,
                Constants.MASK_AAD_B512FILE,
                kdf);
        byte[] streamLegacyUser = legacyB512UserWrap(streamMaskKey);
        assertEquals(lenUser, streamLegacyUser.length);
        System.arraycopy(
                streamLegacyUser, 0, stream, userStart, lenUser);
        Files.write(encoded.toPath(), stream);

        BaseFwx.b512FileDecodeFile(
                encoded, output, password, false);
        assertArrayEquals(
                "fixture-stream".getBytes(StandardCharsets.UTF_8),
                Files.readAllBytes(output.toPath()));
    }

    @Test
    public void b512BinaryAuthenticationFailuresNeverDowngradeToRawText() {
        String password = new String(PASSWORD, StandardCharsets.UTF_8);
        byte[] raw = B512FileCodec.b512FileEncodeBytes(
                "payload".getBytes(StandardCharsets.UTF_8),
                ".txt",
                password,
                false,
                false,
                false);
        BaseFwx.DecodedFile rawDecoded =
                B512FileCodec.b512FileDecodeBytes(raw, password, false);
        assertArrayEquals(
                "payload".getBytes(StandardCharsets.UTF_8),
                rawDecoded.data);

        byte[] binary = B512FileCodec.b512FileEncodeBytes(
                "payload".getBytes(StandardCharsets.UTF_8),
                ".txt",
                password,
                false,
                false,
                true);
        List<byte[]> parts = Format.unpackLengthPrefixed(binary, 3);

        byte[] corruptedUser = Arrays.copyOf(
                parts.get(0), parts.get(0).length);
        corruptedUser[corruptedUser.length - 1] ^= 1;
        try {
            B512FileCodec.b512FileDecodeBytes(
                    Format.packLengthPrefixed(Arrays.asList(
                            corruptedUser, parts.get(1), parts.get(2))),
                    password,
                    false);
            fail("corrupted binary user wrap downgraded to raw text");
        } catch (Crypto.AuthenticationException expected) {
            // Terminal after structural binary recognition.
        }

        byte[] corruptedPayload = Arrays.copyOf(
                parts.get(2), parts.get(2).length);
        corruptedPayload[corruptedPayload.length - 1] ^= 1;
        try {
            B512FileCodec.b512FileDecodeBytes(
                    Format.packLengthPrefixed(Arrays.asList(
                            parts.get(0), parts.get(1), corruptedPayload)),
                    password,
                    false);
            fail("corrupted binary payload downgraded to raw text");
        } catch (Crypto.AuthenticationException expected) {
            // Terminal after structural binary recognition.
        }
    }

    @Test
    public void shortPasswordStepUpProfileIsFrozenAndApplied() {
        assertEquals(12, Constants.SHORT_PASSWORD_MIN);
        assertEquals(1000000, Constants.SHORT_PBKDF2_ITERS);
        assertEquals(5, Constants.SHORT_ARGON2_TIME_COST);
        assertEquals(1 << 17, Constants.SHORT_ARGON2_MEMORY_KIB);
        assertEquals(4, Constants.SHORT_ARGON2_PARALLELISM);

        KeyWrap.KdfOptions options =
                new KeyWrap.KdfOptions("argon2id", 1);
        options.argon2TimeCost = Constants.ARGON2_TIME_COST;
        options.argon2MemoryKib = Constants.ARGON2_MEMORY_KIB;
        options.argon2Parallelism = 1;
        byte[] shortPassword = "short".getBytes(StandardCharsets.UTF_8);

        int[] params =
                FileCodecKdf.hardenArgon2Params(shortPassword, options);
        KeyWrap.KdfOptions wrapped =
                KeyWrap.hardenKdfOptions(shortPassword, options);
        if (!Constants.TEST_KDF_OVERRIDE) {
            assertEquals(Constants.SHORT_ARGON2_PARALLELISM, params[2]);
            assertEquals(
                    Constants.SHORT_ARGON2_PARALLELISM,
                    wrapped.argon2Parallelism);
        }

        byte[] normalPassword =
                "normal-password".getBytes(StandardCharsets.UTF_8);
        assertEquals(
                1,
                FileCodecKdf.hardenArgon2Params(
                        normalPassword, options)[2]);
        assertEquals(
                1,
                KeyWrap.hardenKdfOptions(
                        normalPassword, options).argon2Parallelism);
    }

    @Test
    public void ecDefaultKeyFilesAreBoundedToFourMiB() throws Exception {
        String originalHome = System.getProperty("user.home");
        File fakeHome = tmp.newFolder("ec-home");
        try {
            System.setProperty("user.home", fakeHome.getAbsolutePath());
            File publicKey = new File(fakeHome, "master_ec_public.pem");
            File privateKey = new File(fakeHome, "master_ec_private.pem");
            byte[] oversized = new byte[4 * 1024 * 1024 + 1];
            Files.write(publicKey.toPath(), oversized);
            try {
                EcKeys.loadMasterPublic(false);
                fail("oversized EC public key accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getCause().getMessage().contains("4 MiB"));
            }
            Files.delete(publicKey.toPath());
            Files.write(privateKey.toPath(), oversized);
            try {
                EcKeys.loadMasterPrivate();
                fail("oversized EC private key accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getCause().getMessage().contains("4 MiB"));
            }
        } finally {
            if (originalHome == null) {
                System.clearProperty("user.home");
            } else {
                System.setProperty("user.home", originalHome);
            }
        }
    }
}
