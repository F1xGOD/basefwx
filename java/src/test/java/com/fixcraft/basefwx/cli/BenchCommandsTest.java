/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BenchCommandsTest {
    private interface IoAction {
        void run() throws IOException;
    }

    private static IOException expectIOException(IoAction action) {
        try {
            action.run();
            fail("expected IOException");
            return null;
        } catch (IOException expected) {
            return expected;
        }
    }

    @Test
    public void comparingOutputAcceptsExactContent() throws Exception {
        byte[] expected = "exact-output".getBytes(StandardCharsets.UTF_8);
        try (BenchCommands.ComparingOutputStream output =
                     new BenchCommands.ComparingOutputStream(
                             new ByteArrayInputStream(expected))) {
            output.write(expected, 0, 5);
            for (int i = 5; i < expected.length; i++) {
                output.write(expected[i]);
            }
            output.verifyComplete();
            assertEquals(expected.length, output.verifiedByteCount());
        }
    }

    @Test
    public void comparingOutputRejectsMismatch() throws Exception {
        byte[] expected = "expected".getBytes(StandardCharsets.UTF_8);
        try (BenchCommands.ComparingOutputStream output =
                     new BenchCommands.ComparingOutputStream(
                             new ByteArrayInputStream(expected))) {
            IOException failure = expectIOException(
                    () -> output.write(
                            "expeXted".getBytes(StandardCharsets.UTF_8)));
            assertTrue(failure.getMessage().contains("mismatch"));
        }
    }

    @Test
    public void comparingOutputRejectsShortOutput() throws Exception {
        byte[] expected = "expected".getBytes(StandardCharsets.UTF_8);
        try (BenchCommands.ComparingOutputStream output =
                     new BenchCommands.ComparingOutputStream(
                             new ByteArrayInputStream(expected))) {
            output.write(expected, 0, expected.length - 1);
            IOException failure =
                    expectIOException(output::verifyComplete);
            assertTrue(failure.getMessage().contains("shorter"));
        }
    }

    @Test
    public void comparingOutputRejectsExtraOutput() throws Exception {
        byte[] expected = "expected".getBytes(StandardCharsets.UTF_8);
        try (BenchCommands.ComparingOutputStream output =
                     new BenchCommands.ComparingOutputStream(
                             new ByteArrayInputStream(expected))) {
            output.write(expected);
            IOException failure = expectIOException(() -> output.write('!'));
            assertTrue(failure.getMessage().contains("longer"));
        }
    }

    @Test
    public void parallelWorkerFailurePropagates() {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            BenchCommands.runParallel(pool, 2, workerId -> {
                if (workerId == 1) {
                    throw new IllegalStateException("worker failed");
                }
                return 1L;
            });
            fail("expected worker failure");
        } catch (IllegalStateException expected) {
            assertEquals("worker failed", expected.getMessage());
        } finally {
            pool.shutdownNow();
        }
    }
}
