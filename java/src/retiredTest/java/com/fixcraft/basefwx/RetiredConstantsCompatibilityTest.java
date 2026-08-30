/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.nio.charset.StandardCharsets;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/** Pins the public constants retained by the compatibility artifact. */
public class RetiredConstantsCompatibilityTest {
    @Test
    public void historicalConstantsRemainSourceAndReflectionAccessible()
            throws Exception {
        assertArrayEquals(ascii("jmg"), Constants.MASK_AAD_JMG);
        assertArrayEquals(
                ascii("basefwx.imagecipher.stream.v1"),
                Constants.IMAGECIPHER_STREAM_INFO);
        assertArrayEquals(
                ascii("basefwx.imagecipher.archive.v1"),
                Constants.IMAGECIPHER_ARCHIVE_INFO);
        assertArrayEquals(ascii("JMG0"), Constants.IMAGECIPHER_TRAILER_MAGIC);
        assertArrayEquals(
                ascii("JMG1"), Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
        assertArrayEquals(ascii("JMGK"), Constants.JMG_KEY_MAGIC);
        assertEquals(1, Constants.JMG_KEY_VERSION_LEGACY);
        assertEquals(2, Constants.JMG_KEY_VERSION);
        assertEquals(0, Constants.JMG_SECURITY_PROFILE_LEGACY);
        assertEquals(1, Constants.JMG_SECURITY_PROFILE_MAX);
        assertEquals(1, Constants.JMG_SECURITY_PROFILE_DEFAULT);
        assertArrayEquals(
                ascii("basefwx.jmg.mask.v1"), Constants.JMG_MASK_INFO);

        assertArrayEquals(
                ascii("basefwx.jmg.mask.v1"),
                (byte[]) Constants.class.getDeclaredField(
                        "JMG_MASK_INFO").get(null));
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
