/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.media;

import com.fixcraft.basefwx.Constants;
import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class MediaTrailerCodecSecurityTest {
    @Test
    public void hostileInnerJmgLengthRejectsBeforeAllocationOrOutput()
            throws Exception {
        File directory = Files.createTempDirectory(
                "basefwx-media-hostile-header-").toFile();
        try {
            File carrier = new File(directory, "hostile-jmg.bin");
            File destination = new File(directory, "destination.bin");
            byte[] sentinel = "existing authenticated destination"
                    .getBytes(StandardCharsets.UTF_8);
            Files.write(destination.toPath(), sentinel);

            byte[] blob = new byte[
                    Constants.JMG_KEY_MAGIC.length + 1 + 4];
            System.arraycopy(
                    Constants.JMG_KEY_MAGIC,
                    0,
                    blob,
                    0,
                    Constants.JMG_KEY_MAGIC.length);
            blob[Constants.JMG_KEY_MAGIC.length] =
                    (byte) Constants.JMG_KEY_VERSION;
            writeU32(
                    blob,
                    Constants.JMG_KEY_MAGIC.length + 1,
                    Integer.MAX_VALUE);
            byte[] length = new byte[4];
            writeU32(length, 0, blob.length);
            try (FileOutputStream out = new FileOutputStream(carrier)) {
                out.write(new byte[] {1, 2, 3, 4});
                out.write(Constants.IMAGECIPHER_TRAILER_MAGIC);
                out.write(length);
                out.write(blob);
                out.write(Constants.IMAGECIPHER_TRAILER_MAGIC);
                out.write(length);
            }
            String[] before = sortedChildren(directory);

            try {
                MediaTrailerCodec.decryptTrailerStream(
                        carrier,
                        "media-trailer-test-password"
                                .getBytes(StandardCharsets.UTF_8),
                        false,
                        destination);
                fail("hostile JMG payload length was accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getCause().getMessage().contains(
                        "Invalid JMG key header length"));
            }

            assertArrayEquals(
                    sentinel, Files.readAllBytes(destination.toPath()));
            assertArrayEquals(before, sortedChildren(directory));
        } finally {
            deleteRecursively(directory);
        }
    }

    @Test
    public void badTagPreservesExistingDestinationAndLeaksNoTempFile()
            throws Exception {
        File directory = Files.createTempDirectory(
                "basefwx-media-trailer-test-").toFile();
        try {
            File carrier = new File(directory, "carrier.bin");
            File original = new File(directory, "original.bin");
            File destination = new File(directory, "destination.bin");
            byte[] password = "media-trailer-test-password"
                    .getBytes(StandardCharsets.UTF_8);
            byte[] payload =
                    new byte[3 * Constants.STREAM_CHUNK_SIZE + 37];
            for (int i = 0; i < payload.length; ++i) {
                payload[i] = (byte) (i * 17 + 29);
            }
            byte[] sentinel = "existing authenticated destination"
                    .getBytes(StandardCharsets.UTF_8);
            Files.write(carrier.toPath(), new byte[] {1, 2, 3, 4});
            Files.write(original.toPath(), payload);
            Files.write(destination.toPath(), sentinel);

            MediaTrailerCodec.appendTrailerStream(
                    carrier,
                    password,
                    false,
                    original,
                    null,
                    new byte[0],
                    Constants.IMAGECIPHER_ARCHIVE_INFO);
            int footerLength =
                    Constants.IMAGECIPHER_TRAILER_MAGIC.length + 4;
            try (RandomAccessFile file =
                         new RandomAccessFile(carrier, "rw")) {
                long tagByte = file.length() - footerLength - 1L;
                file.seek(tagByte);
                int value = file.read();
                file.seek(tagByte);
                file.write(value ^ 0x01);
            }
            String[] before = sortedChildren(directory);

            boolean decrypted = MediaTrailerCodec.decryptTrailerStream(
                    carrier, password, false, destination);

            assertFalse(decrypted);
            assertArrayEquals(sentinel, Files.readAllBytes(
                    destination.toPath()));
            assertArrayEquals(before, sortedChildren(directory));
        } finally {
            deleteRecursively(directory);
        }
    }

    private static String[] sortedChildren(File directory) {
        String[] names = directory.list();
        if (names == null) {
            return new String[0];
        }
        Arrays.sort(names);
        return names;
    }

    private static void writeU32(
            byte[] output, int offset, int value) {
        output[offset] = (byte) ((value >>> 24) & 0xFF);
        output[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        output[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        output[offset + 3] = (byte) (value & 0xFF);
    }

    private static void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
    }
}
