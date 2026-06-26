/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;
import com.fixcraft.basefwx.BaseFwxImage;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

final class BenchCommands {
    private static volatile int BENCH_SINK = 0;

    private BenchCommands() {}

    @FunctionalInterface
    interface BenchWorker {
        long run(int workerId);
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
            case "bench-jmg":
                return benchJmg(args, argc, useMaster);
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
        } else if (method.equals("uhash513")) {
            worker = (idx) -> {
                String digest = BaseFwx.uhash513Bytes(textBytes);
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
        long ns = benchMedian(warmup, iters, () -> {
            byte[] blob = BaseFwx.fwxAesEncryptRawBytes(data, benchPassBytes, useMasterFlag);
            byte[] plain = BaseFwx.fwxAesDecryptRawBytes(blob, benchPassBytes, useMasterFlag);
            BENCH_SINK ^= plain.length;
        });
        System.out.println("BENCH_NS=" + ns);
        return 0;
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
            for (int i = 0; i < warmup; i++) {
                benchFwxaesParallel(pool, workers, data, benchPassBytes, useMasterFlag);
            }
            long[] samples = new long[iters];
            long bytesPerRun = 0;
            for (int i = 0; i < iters; i++) {
                long start = System.nanoTime();
                bytesPerRun = benchFwxaesParallel(pool, workers, data, benchPassBytes, useMasterFlag);
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
        final byte[] data = readAllBytes(input);
        BenchWorker worker = (idx) -> {
            try {
                java.io.ByteArrayInputStream src = new java.io.ByteArrayInputStream(data);
                java.io.ByteArrayOutputStream encOut = new java.io.ByteArrayOutputStream(
                    data.length + (data.length / 16) + 512
                );
                BaseFwx.fwxAesLiveEncryptStream(src, encOut, benchPassFinal, useMasterFlag);
                byte[] encrypted = encOut.toByteArray();

                java.io.ByteArrayInputStream encIn = new java.io.ByteArrayInputStream(encrypted);
                java.io.ByteArrayOutputStream decOut = new java.io.ByteArrayOutputStream(data.length);
                BaseFwx.fwxAesLiveDecryptStream(encIn, decOut, benchPassFinal, useMasterFlag);
                long size = decOut.size();
                BENCH_SINK ^= (int) size;
                return size;
            } catch (RuntimeException exc) {
                throw new RuntimeException("bench-live roundtrip failed", exc);
            }
        };
        long ns = workers > 1
            ? benchParallelMedian(warmup, iters, workers, worker)
            : benchMedian(warmup, iters, () -> worker.run(0));
        System.out.println("BENCH_NS=" + ns);
        return 0;
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
                if (encFiles[i] != null) {
                    encFiles[i].delete();
                }
                if (decFiles[i] != null) {
                    decFiles[i].delete();
                }
                if (tempDirs[i] != null) {
                    tempDirs[i].delete();
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
                if (encFiles[i] != null) {
                    encFiles[i].delete();
                }
                if (decFiles[i] != null) {
                    decFiles[i].delete();
                }
                if (tempDirs[i] != null) {
                    tempDirs[i].delete();
                }
            }
        }
    }

    private static int benchJmg(String[] args, int argc, boolean useMaster) {
        if (argc < 3) {
            return 1;
        }
        File mediaFile = new File(args[1]);
        String benchPass = args[2];
        final String benchPassFinal = benchPass;
        final boolean useMasterFlag = useMaster;
        int warmup = benchWarmup();
        int iters = benchIters();
        int workers = benchWorkers();

        if (!mediaFile.exists()) {
            throw new RuntimeException("Media file not found: " + mediaFile.getAbsolutePath());
        }

        confirmSingleThreadCli(workers);
        File[] tempDirs = new File[workers];
        File[] encFiles = new File[workers];
        File[] decFiles = new File[workers];

        try {
            String baseName = mediaFile.getName();
            String ext = "";
            int dotIdx = baseName.lastIndexOf('.');
            if (dotIdx > 0) {
                ext = baseName.substring(dotIdx);
            }

            for (int i = 0; i < workers; i++) {
                try {
                    tempDirs[i] = Files.createTempDirectory("basefwx-bench-jmg-" + i).toFile();
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("Failed to create temp directory for bench-jmg worker " + i, exc);
                }
                encFiles[i] = new File(tempDirs[i], "bench_enc" + ext);
                decFiles[i] = new File(tempDirs[i], "bench_dec" + ext);
            }

            BenchWorker worker = (idx) -> {
                File encFile = encFiles[idx];
                File decFile = decFiles[idx];
                BaseFwxImage.jmgEncryptFile(mediaFile, encFile, benchPassFinal, useMasterFlag, false, true);
                BaseFwxImage.jmgDecryptFile(encFile, decFile, benchPassFinal, useMasterFlag);
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
                if (encFiles[i] != null && encFiles[i].exists()) {
                    encFiles[i].delete();
                }
                if (decFiles[i] != null && decFiles[i].exists()) {
                    decFiles[i].delete();
                }
                if (tempDirs[i] != null && tempDirs[i].exists()) {
                    tempDirs[i].delete();
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

    private static int benchWarmup() {
        return readEnvInt("BASEFWX_BENCH_WARMUP", 2, 0);
    }

    private static int benchIters() {
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

    private static int benchWorkers() {
        if (!benchParallelEnabled()) {
            return 1;
        }
        int defaultWorkers = Runtime.getRuntime().availableProcessors();
        if (defaultWorkers <= 0) {
            defaultWorkers = 1;
        }
        return readEnvInt("BASEFWX_BENCH_WORKERS", defaultWorkers, 1);
    }

    private static void confirmSingleThreadCli(int workers) {
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

    private static long benchMedian(int warmup, int iters, Runnable run) {
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

    private static long runParallel(ExecutorService pool, int workers, BenchWorker worker) {
        CountDownLatch latch = new CountDownLatch(workers);
        final long[] totalBytes = new long[1];
        for (int i = 0; i < workers; i++) {
            final int idx = i;
            pool.execute(() -> {
                try {
                    long bytes = worker.run(idx);
                    synchronized (totalBytes) {
                        totalBytes[0] += bytes;
                    }
                } finally {
                    latch.countDown();
                }
            });
        }
        try {
            latch.await();
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Parallel benchmark interrupted", exc);
        }
        return totalBytes[0];
    }

    private static long benchParallelMedian(int warmup, int iters, int workers, BenchWorker worker) {
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

    private static long benchFwxaesParallel(ExecutorService pool,
                                            int workers,
                                            byte[] data,
                                            byte[] password,
                                            boolean useMaster) {
        CountDownLatch latch = new CountDownLatch(workers);
        final long[] totalBytes = new long[1];
        for (int i = 0; i < workers; i++) {
            pool.execute(() -> {
                try {
                    byte[] blob = BaseFwx.fwxAesEncryptRawBytes(data, password, useMaster);
                    byte[] plain = BaseFwx.fwxAesDecryptRawBytes(blob, password, useMaster);
                    BENCH_SINK ^= plain.length;
                    synchronized (totalBytes) {
                        totalBytes[0] += plain.length;
                    }
                } finally {
                    latch.countDown();
                }
            });
        }
        try {
            latch.await();
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Parallel benchmark interrupted", exc);
        }
        return totalBytes[0];
    }
}
