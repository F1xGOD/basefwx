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
import static org.junit.Assert.fail;

/**
 * Locks the 3.7.0+ ResolvePassword URI semantics (parity with C++
 * basefwx::ResolvePassword): bare strings are always literal; file://
 * reads; password:// forces literal.
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
    }

    @Test
    public void fileUriReadsContents() throws Exception {
        File pwFile = tmp.newFile("pwfile2.txt");
        byte[] secret = "file-secret-contents\n".getBytes(StandardCharsets.UTF_8);
        Files.write(pwFile.toPath(), secret);
        byte[] resolved = BaseFwx.resolvePasswordBytes("file://" + pwFile.getAbsolutePath(), false);
        assertArrayEquals(secret, resolved);
    }

    @Test
    public void passwordUriForcesLiteral() throws Exception {
        File pwFile = tmp.newFile("pwfile3.txt");
        Files.write(pwFile.toPath(), "file-secret-contents\n".getBytes(StandardCharsets.UTF_8));
        String bare = pwFile.getAbsolutePath();
        byte[] resolved = BaseFwx.resolvePasswordBytes("password://" + bare, false);
        assertEquals(bare, new String(resolved, StandardCharsets.UTF_8));
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
}
