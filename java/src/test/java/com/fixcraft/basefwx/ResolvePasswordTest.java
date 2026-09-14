/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Locks the 3.7.0+ ResolvePassword URI semantics (parity with C++
 * basefwx::ResolvePassword): bare strings are always literal; file://
 * reads; password:// forces a non-reference literal; and no successful
 * resolution yields another password reference.
 */
public class ResolvePasswordTest {
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void bareStringThatNamesExistingFileIsLiteral() throws Exception {
        File pwFile = tmp.newFile("pwfile.txt");
        Files.write(pwFile.toPath(), "file-secret-contents\n".getBytes(StandardCharsets.UTF_8));
        String bare = pwFile.getAbsolutePath();
        byte[] resolved = BaseFwx.resolvePasswordBytes(bare, false);
        assertEquals(bare, new String(resolved, StandardCharsets.UTF_8));
        assertArrayEquals(
                resolved,
                BaseFwx.resolvePasswordBytes(
                        new String(resolved, StandardCharsets.UTF_8), false));
    }

    @Test
    public void fileUriReadsContents() throws Exception {
        File pwFile = tmp.newFile("pwfile2.txt");
        byte[] secret = "file-secret-contents\n".getBytes(StandardCharsets.UTF_8);
        Files.write(pwFile.toPath(), secret);
        byte[] resolved = BaseFwx.resolvePasswordBytes("file://" + pwFile.getAbsolutePath(), false);
        assertArrayEquals(secret, resolved);
        assertArrayEquals(
                resolved,
                BaseFwx.resolvePasswordBytes(
                        new String(resolved, StandardCharsets.UTF_8), false));
    }

    @Test
    public void passwordUriForcesLiteral() throws Exception {
        File pwFile = tmp.newFile("pwfile3.txt");
        Files.write(pwFile.toPath(), "file-secret-contents\n".getBytes(StandardCharsets.UTF_8));
        String bare = pwFile.getAbsolutePath();
        byte[] resolved = BaseFwx.resolvePasswordBytes("password://" + bare, false);
        assertEquals(bare, new String(resolved, StandardCharsets.UTF_8));
        assertArrayEquals(
                resolved,
                BaseFwx.resolvePasswordBytes(
                        new String(resolved, StandardCharsets.UTF_8), false));
    }

    @Test
    public void nestedPasswordReferencesFailClosed() {
        assertAmbiguousReferenceRejected("password://file:///tmp/not-read");
        assertAmbiguousReferenceRejected("password://password://inner-secret");
    }

    @Test
    public void passwordFilesContainingReferencesFailClosed() throws Exception {
        File pwFile = tmp.newFile("nested-password.txt");
        String[] nestedContents = {
            "password://inner-secret",
            "file:///tmp/not-read"
        };
        for (String nested : nestedContents) {
            Files.write(pwFile.toPath(), nested.getBytes(StandardCharsets.UTF_8));
            assertAmbiguousReferenceRejected("file://" + pwFile.getAbsolutePath());
        }
    }

    @Test
    public void publicCodecEntryRejectsNestedReference() {
        try {
            BaseFwx.b512Encode("payload", "password://file:///tmp/not-read", false);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("refused as ambiguous"));
        }
    }

    @Test
    public void missingFileUriFailsClosed() {
        try {
            BaseFwx.resolvePasswordBytes("file:///no/such/basefwx-pw-file", false);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    private static void assertAmbiguousReferenceRejected(String password) {
        try {
            BaseFwx.resolvePasswordBytes(password, false);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("refused as ambiguous"));
        }
    }
}
