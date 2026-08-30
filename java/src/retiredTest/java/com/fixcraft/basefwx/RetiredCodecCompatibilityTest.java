/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/** Pins historical APIs and exact bytes in the compatibility JAR. */
public class RetiredCodecCompatibilityTest {
    private static final String INPUT = "basefwx";
    private static final String B256 =
            "4PK6OP9A65TJISRC9CQM2UP85944EG984PF4CAI7AOK2KI3JDDBG4";
    private static final String A512 =
            "22659442R15AKJ4EAI3593KGGI159442R15AKJ4EAI35154GAI7BSKKKI2JFLR7QTH"
            + "8593KCH2V5554GKRTEOK4GK216TUNCNP999456A28A10JEL968SL46L968SL46A2A90"
            + "L4EIAL50J5CL968SL46NP999456A2A90L4EAI791142IAL50J5CIAL50J5C3";

    @Test
    public void historicalMethodsRemainSourceAndReflectionAccessible()
            throws Exception {
        assertEquals(B256, BaseFwx.b256Encode(INPUT));
        assertEquals(INPUT, BaseFwx.b256Decode(B256));
        assertEquals(B256, Codec.b256Encode(INPUT));
        assertEquals(INPUT, Codec.b256Decode(B256));
        assertEquals(A512, BaseFwx.a512Encode(INPUT));
        assertEquals(INPUT, BaseFwx.a512Decode(A512));
        assertEquals(
                "47d28c46896d43b415dde8a79eed97da6ac6686127f595fa28bce0a0492df42d",
                BaseFwx.bi512Encode(INPUT));
        assertEquals(
                "a2a622418b25e4ec8c9a08f61b979fe8bb17272d34983bbbed44740fffd3c4b4",
                BaseFwx.uhash513(INPUT));
        assertEquals(
                String.class,
                BaseFwx.class.getMethod(
                        "b256Encode", String.class).getReturnType());
    }
}
