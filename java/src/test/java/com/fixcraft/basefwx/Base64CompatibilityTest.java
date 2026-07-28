/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class Base64CompatibilityTest {
    private static final byte[] VALUES_62_AND_63 =
            new byte[] {(byte) 0xFB, (byte) 0xFF};

    @Test
    public void emitsCanonicalStandardAlphabet() {
        assertEquals("+/8=", Base64Codec.encode(VALUES_62_AND_63));
    }

    @Test
    public void acceptsStandardAndLegacyUrlSafeAlphabets() {
        assertArrayEquals(VALUES_62_AND_63, Base64Codec.decode("+/8="));
        assertArrayEquals(VALUES_62_AND_63, Base64Codec.decode("-_8="));
        assertTrue(Base64Codec.looksLikeBase64("-_8="));
    }
}
