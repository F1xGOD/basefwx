/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class BenchCommands {
    private static final int STREAM_BUFFER_SIZE = 64 * 1024;
    private static volatile int BENCH_SINK = 0;

    private BenchCommands() {}

    @FunctionalInterface
    interface BenchWorker {
        long run(int workerId);
    }

    static void consume(long value) {
        BENCH_SINK ^= (int) value;
    }

    static final class ComparingOutputStream extends OutputStream {
        private final InputStream expected;
        private final byte[] expectedBuffer =
                new byte[STREAM_BUFFER_SIZE];
        private final byte[] singleByte = new byte[1];
        private long verifiedBytes;
        private boolean closed;

        ComparingOutputStream(InputStream expected) {
            if (expected == null) {
                throw new NullPointerException("expected");
            }
            this.expected = expected;
        }

        @Override
        public void write(int value) throws IOException {
            singleByte[0] = (byte) value;
            write(singleByte, 0, 1);
        }

        @Override
        public void write(byte[] data, int offset, int length)
                throws IOException {
            if (data == null) {
                throw new NullPointerException("data");
            }
            if ((offset | length) < 0
                    || length > data.length - offset) {
                throw new IndexOutOfBoundsException();
            }
            ensureOpen();

            int inputOffset = offset;
            int remaining = length;
            while (remaining > 0) {
                int chunk = Math.min(remaining, expectedBuffer.length);
                int expectedBytes = readExpected(chunk);
                if (expectedBytes != chunk) {
                    throw new IOException(
                            "Decrypted output longer than expected input"
                            + " at byte " + (verifiedBytes + expectedBytes));
                }
                for (int i = 0; i < chunk; i++) {
                    if (data[inputOffset + i] != expectedBuffer[i]) {
                        throw new IOException(
                                "Decrypted output mismatch at byte "
                                + (verifiedBytes + i));
                    }
                }
                verifiedBytes += chunk;
                inputOffset += chunk;
                remaining -= chunk;
            }
        }

        void verifyComplete() throws IOException {
            ensureOpen();
            if (expected.read() != -1) {
                throw new IOException(
                        "Decrypted output shorter than expected input"
                        + " at byte " + verifiedBytes);
            }
        }

        long verifiedByteCount() {
            return verifiedBytes;
        }

        private int readExpected(int length) throws IOException {
            int total = 0;
            while (total < length) {
                int count = expected.read(
                        expectedBuffer, total, length - total);
                if (count < 0) {
                    break;
                }
                if (count == 0) {
                    int value = expected.read();
                    if (value < 0) {
                        break;
                    }
                    expectedBuffer[total] = (byte) value;
                    count = 1;
                }
                total += count;
            }
            return total;
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("Comparing output stream is closed");
            }
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                closed = true;
                expected.close();
            }
        }
    }

    /** @return 0 handled, 1 usage, -1 not handled */
    static int handle(String command, String[] args, int argc, boolean useMaster) {
        switch (command) {
            case "bench-text":
                return benchText(args, argc, useMaster);
            case "bench-hash":
                return benchHash(args, argc);
            case "bench-fwxaes":
                return benchFwxaes(args, argc, useMaster);
            case "bench-fwxaes-par":
                return benchFwxaesPar(args, argc, useMaster);
            case "bench-an7":
            case "bench-dean7":
                return benchAn7(command, args, argc, useMaster);
            case "bench-live":
                return benchLive(args, argc, useMaster);
            case "bench-b512file":
                return benchB512file(args, argc, useMaster);
            case "bench-pb512file":
                return benchPb512file(args, argc, useMaster);
            default:
                return -1;
        }
    }

    private static int benchText(String[] args, int argc, boolean useMaster) {
        if (argc < 4) {
            return 1;
        }
        String method = args[1].toLowerCase();
        File textFile = new File(args[2]);
        String benchPass = args[3];
        final String methodFinal = method;
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        String text = readText(textFile);
        confirmSingleThreadCli(workers);

        BenchWorker worker = (idx) -> {
            String enc = CodecCommands.encodeText(methodFinal, text, benchPassFinal, useMasterFlag);
            String dec = CodecCommands.decodeText(methodFinal, enc, benchPassFinal, useMasterFlag);
            BENCH_SINK ^= dec.length();
            return dec.length();
        };
        long ns = workers > 1
            ? benchParallelMedian(warmup, iters, workers, worker)
            : benchMedian(warmup, iters, () -> worker.run(0));
        System.out.println("BENCH_NS=" + ns);
        return 0;
    }

    private static int benchHash(String[] args, int argc) {
        if (argc < 3) {
            return 1;
        }
        String method = args[1].toLowerCase();
        File textFile = new File(args[2]);
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        String text = readText(textFile);
        confirmSingleThreadCli(workers);
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        BenchWorker worker;
        if (method.equals("hash512")) {
            worker = (idx) -> {
                String digest = BaseFwx.hash512Bytes(textBytes);
                BENCH_SINK ^= digest.length();
                return digest.length();
            };
        } else {
            worker = (idx) -> {
                String digest = CodecCommands.hashText(method, text);
                BENCH_SINK ^= digest.length();
                return digest.length();
            };
        }
        long ns = workers > 1
            ? benchParallelMedian(warmup, iters, workers, worker)
            : benchMedian(warmup, iters, () -> worker.run(0));
        System.out.println("BENCH_NS=" + ns);
        return 0;
    }

    private static int benchFwxaes(String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File input = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        byte[] data = readAllBytes(input);
        byte[] benchPassBytes = BaseFwx.resolvePasswordBytes(benchPassFinal, useMasterFlag);
        try {
            long ns = benchMedian(warmup, iters, () -> {
                byte[] blob = BaseFwx.fwxAesEncryptRawBytes(data, benchPassBytes, useMasterFlag);
                byte[] plain = BaseFwx.fwxAesDecryptRawBytes(blob, benchPassBytes, useMasterFlag);
                BENCH_SINK ^= plain.length;
            });
            System.out.println("BENCH_NS=" + ns);
            return 0;
        } finally {
            Arrays.fill(benchPassBytes, (byte) 0);
        }
    }

    private static int benchFwxaesPar(String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File input = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        confirmSingleThreadCli(workers);
        byte[] data = readAllBytes(input);
        byte[] benchPassBytes = BaseFwx.resolvePasswordBytes(benchPassFinal, useMasterFlag);
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        try {
            BenchWorker worker = (idx) -> {
                byte[] blob = BaseFwx.fwxAesEncryptRawBytes(
                        data, benchPassBytes, useMasterFlag);
                byte[] plain = BaseFwx.fwxAesDecryptRawBytes(
                        blob, benchPassBytes, useMasterFlag);
                BENCH_SINK ^= plain.length;
                return plain.length;
            };
            for (int i = 0; i < warmup; i++) {
                runParallel(pool, workers, worker);
            }
            long[] samples = new long[iters];
            long bytesPerRun = 0;
            for (int i = 0; i < iters; i++) {
                long start = System.nanoTime();
                bytesPerRun = runParallel(pool, workers, worker);
                long end = System.nanoTime();
                samples[i] = end - start;
            }
            long median = medianOf(samples);
            System.out.println("BENCH_NS=" + median);
            if (bytesPerRun > 0 && median > 0) {
                double seconds = median / 1_000_000_000.0;
                double gib = bytesPerRun / (double) (1L << 30);
                double throughput = gib / seconds;
                System.out.println("THROUGHPUT_GiBps=" +
                                   String.format(Locale.US, "%.3f", throughput) +
                                   " WORKERS=" + workers);
            }
            return 0;
        } finally {
            pool.shutdown();
            Arrays.fill(benchPassBytes, (byte) 0);
        }
    }

    private static int benchAn7(String command, String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File input = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        final String benchCommand = command;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        confirmSingleThreadCli(workers);

        File[] tempDirs = new File[workers];
        File[] seedFwx = new File[workers];
        File[] seedAn7 = new File[workers];
        try {
            for (int i = 0; i < workers; i++) {
                try {
                    tempDirs[i] = Files.createTempDirectory("basefwx-bench-an7-" + i).toFile();
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to create bench temp dir", exc);
                }
                File workerInput = new File(tempDirs[i], input.getName());
                try {
                    Files.copy(input.toPath(), workerInput.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to copy bench input", exc);
                }
                seedFwx[i] = new File(tempDirs[i], "seed_" + i + ".fwx");
                BaseFwx.fwxAesEncryptFile(workerInput, seedFwx[i], benchPassFinal, useMasterFlag);
                workerInput.delete();

                seedAn7[i] = new File(tempDirs[i], "seed_" + i + ".an7");
                BaseFwx.an7File(seedFwx[i], benchPassFinal, seedAn7[i], true, false);
            }

            BenchWorker worker = (idx) -> {
                File out = new File(
                    tempDirs[idx],
                    ("bench-an7".equals(benchCommand) ? "an7_" : "dean7_") + idx + ".out"
                );
                out.delete();
                long size;
                if ("bench-an7".equals(benchCommand)) {
                    File produced = BaseFwx.an7File(seedFwx[idx], benchPassFinal, out, true, false);
                    size = produced.length();
                    produced.delete();
                } else {
                    BaseFwx.An7Result result = BaseFwx.dean7File(seedAn7[idx], benchPassFinal, out, true);
                    size = result.outputPath.length();
                    result.outputPath.delete();
                }
                BENCH_SINK ^= (int) size;
                return size;
            };

            long ns = workers > 1
                ? benchParallelMedian(warmup, iters, workers, worker)
                : benchMedian(warmup, iters, () -> worker.run(0));
            System.out.println("BENCH_NS=" + ns);
            return 0;
        } finally {
            for (int i = 0; i < workers; i++) {
                cleanupPath(tempDirs[i]);
            }
        }
    }

    private static int benchLive(String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File input = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        confirmSingleThreadCli(workers);
        if (!input.isFile()) {
            throw new RuntimeException(
                    "bench-live input is not a file: "
                    + input.getAbsolutePath());
        }

        File[] tempDirs = new File[workers];
        File[] encryptedFiles = new File[workers];
        Throwable benchmarkFailure = null;
        try {
            for (int i = 0; i < workers; i++) {
                try {
                    tempDirs[i] = createPrivateTempDirectory(
                            "basefwx-bench-live-" + i + "-");
                    encryptedFiles[i] =
                            new File(
                                    tempDirs[i],
                                    "ciphertext.live.fwx");
                    createPrivateFile(encryptedFiles[i]);
                } catch (IOException exc) {
                    throw new RuntimeException(
                            "Failed to create private bench-live"
                            + " temporary storage",
                            exc);
                }
            }

            BenchWorker worker = (idx) -> {
                File encryptedFile = encryptedFiles[idx];
                try {
                    try (InputStream source = new BufferedInputStream(
                                 new FileInputStream(input),
                                 STREAM_BUFFER_SIZE);
                         OutputStream encryptedOutput =
                                 new BufferedOutputStream(
                                         new FileOutputStream(
                                                 encryptedFile),
                                         STREAM_BUFFER_SIZE)) {
                        BaseFwx.fwxAesLiveEncryptStream(
                                source,
                                encryptedOutput,
                                benchPassFinal,
                                useMasterFlag);
                    }

                    long decryptedBytes;
                    try (InputStream encryptedInput =
                                 new BufferedInputStream(
                                         new FileInputStream(
                                                 encryptedFile),
                                         STREAM_BUFFER_SIZE);
                         ComparingOutputStream verifiedOutput =
                                 new ComparingOutputStream(
                                         new BufferedInputStream(
                                                 new FileInputStream(input),
                                                 STREAM_BUFFER_SIZE))) {
                        decryptedBytes =
                                BaseFwx.fwxAesLiveDecryptStream(
                                        encryptedInput,
                                        verifiedOutput,
                                        benchPassFinal,
                                        useMasterFlag);
                        verifiedOutput.verifyComplete();
                        if (decryptedBytes
                                != verifiedOutput
                                        .verifiedByteCount()) {
                            throw new IOException(
                                    "bench-live byte count mismatch:"
                                    + " decrypt returned "
                                    + decryptedBytes
                                    + " but verified "
                                    + verifiedOutput
                                            .verifiedByteCount());
                        }
                    }
                    BENCH_SINK ^= (int) decryptedBytes;
                    return decryptedBytes;
                } catch (IOException | RuntimeException exc) {
                    throw new RuntimeException(
                            "bench-live roundtrip failed for worker "
                            + idx,
                            exc);
                }
            };
            long ns = workers > 1
                ? benchParallelMedian(
                        warmup, iters, workers, worker)
                : benchMedian(
                        warmup, iters, () -> worker.run(0));
            System.out.println("BENCH_NS=" + ns);
            System.out.println(
                    "BENCH_VERIFIED_BYTES="
                    + (input.length() * (long) workers));
            return 0;
        } catch (RuntimeException | Error failure) {
            benchmarkFailure = failure;
            throw failure;
        } finally {
            RuntimeException cleanupFailure = null;
            for (int i = 0; i < workers; i++) {
                try {
                    cleanupBenchLivePath(tempDirs[i]);
                } catch (RuntimeException failure) {
                    if (cleanupFailure == null) {
                        cleanupFailure = failure;
                    } else {
                        cleanupFailure.addSuppressed(failure);
                    }
                }
            }
            if (cleanupFailure != null) {
                if (benchmarkFailure != null) {
                    benchmarkFailure.addSuppressed(cleanupFailure);
                } else {
                    throw cleanupFailure;
                }
            }
        }
    }

    private static int benchB512file(String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File input = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        confirmSingleThreadCli(workers);
        String name = input.getName();
        int dot = name.lastIndexOf('.');
        String ext = dot >= 0 ? name.substring(dot) : "";
        File[] tempDirs = new File[workers];
        File[] inputs = new File[workers];
        File[] encFiles = new File[workers];
        File[] decFiles = new File[workers];
        try {
            for (int i = 0; i < workers; i++) {
                try {
                    tempDirs[i] = Files.createTempDirectory("basefwx-bench-" + i).toFile();
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to create bench temp dir", exc);
                }
                inputs[i] = new File(tempDirs[i], input.getName());
                try {
                    Files.copy(input.toPath(), inputs[i].toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to copy bench input", exc);
                }
                encFiles[i] = new File(tempDirs[i], "bench.fwx");
                decFiles[i] = new File(tempDirs[i], "bench_dec" + ext);
            }
            BenchWorker worker = (idx) -> {
                File encFile = encFiles[idx];
                File decFile = decFiles[idx];
                BaseFwx.b512FileEncodeFile(inputs[idx], encFile, benchPassFinal, useMasterFlag);
                BaseFwx.b512FileDecodeFile(encFile, decFile, benchPassFinal, useMasterFlag);
                long size = decFile.length();
                BENCH_SINK ^= (int) size;
                encFile.delete();
                decFile.delete();
                return size;
            };
            long ns = workers > 1
                ? benchParallelMedian(warmup, iters, workers, worker)
                : benchMedian(warmup, iters, () -> worker.run(0));
            System.out.println("BENCH_NS=" + ns);
            return 0;
        } finally {
            for (int i = 0; i < workers; i++) {
                if (tempDirs[i] != null) {
                    cleanupPath(tempDirs[i]);
                }
            }
        }
    }

    private static int benchPb512file(String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File input = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();
        confirmSingleThreadCli(workers);
        String name = input.getName();
        int dot = name.lastIndexOf('.');
        String ext = dot >= 0 ? name.substring(dot) : "";
        File[] tempDirs = new File[workers];
        File[] inputs = new File[workers];
        File[] encFiles = new File[workers];
        File[] decFiles = new File[workers];
        try {
            for (int i = 0; i < workers; i++) {
                try {
                    tempDirs[i] = Files.createTempDirectory("basefwx-bench-" + i).toFile();
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to create bench temp dir", exc);
                }
                inputs[i] = new File(tempDirs[i], input.getName());
                try {
                    Files.copy(input.toPath(), inputs[i].toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to copy bench input", exc);
                }
                encFiles[i] = new File(tempDirs[i], "bench.fwx");
                decFiles[i] = new File(tempDirs[i], "bench_dec" + ext);
            }
            BenchWorker worker = (idx) -> {
                File encFile = encFiles[idx];
                File decFile = decFiles[idx];
                BaseFwx.pb512FileEncodeFile(inputs[idx], encFile, benchPassFinal, useMasterFlag);
                BaseFwx.pb512FileDecodeFile(encFile, decFile, benchPassFinal, useMasterFlag);
                long size = decFile.length();
                BENCH_SINK ^= (int) size;
                encFile.delete();
                decFile.delete();
                return size;
            };
            long ns = workers > 1
                ? benchParallelMedian(warmup, iters, workers, worker)
                : benchMedian(warmup, iters, () -> worker.run(0));
            System.out.println("BENCH_NS=" + ns);
            return 0;
        } finally {
            for (int i = 0; i < workers; i++) {
                if (tempDirs[i] != null) {
                    cleanupPath(tempDirs[i]);
                }
            }
        }
    }

    private static byte[] readAllBytes(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (java.io.IOException exc) {
            throw new RuntimeException("Failed to read file: " + file.getPath(), exc);
        }
    }

    private static String readText(File file) {
        byte[] data = readAllBytes(file);
        return new String(data, StandardCharsets.UTF_8);
    }

    private static void cleanupPath(File path) {
        if (path == null || !path.exists()) {
            return;
        }
        if (path.isDirectory()) {
            File[] children = path.listFiles();
            if (children != null) {
                for (File child : children) {
                    cleanupPath(child);
                }
            }
        }
        path.delete();
    }

    private static File createPrivateTempDirectory(String prefix)
            throws IOException {
        Set<PosixFilePermission> permissions = EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE);
        FileAttribute<Set<PosixFilePermission>> attribute =
                PosixFilePermissions.asFileAttribute(permissions);
        try {
            return Files.createTempDirectory(prefix, attribute).toFile();
        } catch (UnsupportedOperationException exc) {
            throw new IOException(
                    "bench-live requires atomic owner-only"
                    + " temporary-directory permissions",
                    exc);
        }
    }

    private static void createPrivateFile(File file) throws IOException {
        Set<PosixFilePermission> permissions = EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE);
        FileAttribute<Set<PosixFilePermission>> attribute =
                PosixFilePermissions.asFileAttribute(permissions);
        try {
            Files.createFile(file.toPath(), attribute);
        } catch (UnsupportedOperationException exc) {
            throw new IOException(
                    "bench-live requires atomic owner-only"
                    + " temporary-file permissions",
                    exc);
        }
    }

    private static void cleanupBenchLivePath(File path) {
        if (path == null || !path.exists()) {
            return;
        }
        try {
            Files.walkFileTree(
                    path.toPath(),
                    new SimpleFileVisitor<Path>() {
                        @Override
                        public FileVisitResult visitFile(
                                Path file,
                                BasicFileAttributes attributes)
                                throws IOException {
                            Files.delete(file);
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult postVisitDirectory(
                                Path directory,
                                IOException failure)
                                throws IOException {
                            if (failure != null) {
                                throw failure;
                            }
                            Files.delete(directory);
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException exc) {
            throw new RuntimeException(
                    "Failed to remove bench-live temporary storage: "
                    + path.getAbsolutePath(),
                    exc);
        }
    }

    private static int readEnvInt(String name, int defaultValue, int minValue) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed >= minValue ? parsed : defaultValue;
        } catch (NumberFormatException exc) {
            return defaultValue;
        }
    }

    static int benchWarmup() {
        return readEnvInt("BASEFWX_BENCH_WARMUP", 2, 0);
    }

    static int benchIters() {
        return readEnvInt("BASEFWX_BENCH_ITERS", 50, 1);
    }

    private static boolean benchParallelEnabled() {
        String raw = System.getenv("BASEFWX_BENCH_PARALLEL");
        if (raw == null || raw.isEmpty()) {
            return true;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        return !(value.equals("0") || value.equals("false") || value.equals("off") || value.equals("no"));
    }

    static int benchWorkers() {
        if (!benchParallelEnabled()) {
            return 1;
        }
        int defaultWorkers = Runtime.getRuntime().availableProcessors();
        if (defaultWorkers <= 0) {
            defaultWorkers = 1;
        }
        return readEnvInt("BASEFWX_BENCH_WORKERS", defaultWorkers, 1);
    }

    static void confirmSingleThreadCli(int workers) {
        String forceSingle = System.getenv("BASEFWX_FORCE_SINGLE_THREAD");
        int available = Runtime.getRuntime().availableProcessors();
        boolean forced = "1".equals(forceSingle) && available > 1;
        boolean nonInteractive = "1".equals(System.getenv("BASEFWX_ALLOW_SINGLE_THREAD"))
                || "1".equals(System.getenv("BASEFWX_NONINTERACTIVE"));
        if (forced) {
            com.fixcraft.basefwx.RuntimeLog.warn("MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION");
            com.fixcraft.basefwx.RuntimeLog.warn("SINGLE-THREAD MODE MAY REDUCE SECURITY MARGIN");
            if (nonInteractive) {
                return;
            }
            System.err.print("Type YES to continue with single-thread mode: ");
            String resp;
            try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
                resp = scanner.nextLine();
            }
            if (!"YES".equals(resp != null ? resp.trim() : "")) {
                throw new RuntimeException("Aborted: multi-thread disabled by user override");
            }
        }
    }

    private static long medianOf(long[] samples) {
        Arrays.sort(samples);
        int mid = samples.length / 2;
        if ((samples.length & 1) == 1) {
            return samples[mid];
        }
        long low = samples[mid - 1];
        long high = samples[mid];
        return low + (high - low) / 2;
    }

    static long benchMedian(int warmup, int iters, Runnable run) {
        if (warmup < 0) {
            warmup = 0;
        }
        if (iters < 1) {
            iters = 1;
        }
        for (int i = 0; i < warmup; i++) {
            run.run();
        }
        long[] samples = new long[iters];
        for (int i = 0; i < iters; i++) {
            long start = System.nanoTime();
            run.run();
            long end = System.nanoTime();
            samples[i] = end - start;
        }
        return medianOf(samples);
    }

    static long runParallel(
            ExecutorService pool,
            int workers,
            BenchWorker worker) {
        CountDownLatch latch = new CountDownLatch(workers);
        final long[] totalBytes = new long[1];
        AtomicReference<Throwable> workerFailure =
                new AtomicReference<Throwable>();
        for (int i = 0; i < workers; i++) {
            final int idx = i;
            pool.execute(() -> {
                try {
                    long bytes = worker.run(idx);
                    synchronized (totalBytes) {
                        totalBytes[0] += bytes;
                    }
                } catch (Throwable exc) {
                    workerFailure.compareAndSet(null, exc);
                } finally {
                    latch.countDown();
                }
            });
        }
        boolean interrupted = false;
        while (true) {
            try {
                latch.await();
                break;
            } catch (InterruptedException exc) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Parallel benchmark interrupted");
        }
        Throwable failure = workerFailure.get();
        if (failure instanceof RuntimeException) {
            throw (RuntimeException) failure;
        }
        if (failure instanceof Error) {
            throw (Error) failure;
        }
        if (failure != null) {
            throw new RuntimeException(
                    "Parallel benchmark worker failed", failure);
        }
        return totalBytes[0];
    }

    static long benchParallelMedian(int warmup, int iters, int workers, BenchWorker worker) {
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        try {
            for (int i = 0; i < warmup; i++) {
                runParallel(pool, workers, worker);
            }
            long[] samples = new long[iters];
            for (int i = 0; i < iters; i++) {
                long start = System.nanoTime();
                runParallel(pool, workers, worker);
                long end = System.nanoTime();
                samples[i] = end - start;
            }
            return medianOf(samples);
        } finally {
            pool.shutdown();
        }
    }

}
