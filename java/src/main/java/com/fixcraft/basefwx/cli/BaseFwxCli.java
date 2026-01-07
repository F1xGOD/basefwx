package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class BaseFwxCli {
    private static volatile int BENCH_SINK = 0;

    private BaseFwxCli() {}

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
        int available = Runtime.getRuntime().availableProcessors();
        String envWorkers = System.getenv("BASEFWX_BENCH_WORKERS");
        boolean parallelOff = !benchParallelEnabled();
        boolean forcedOne = parallelOff || (envWorkers != null && envWorkers.trim().equals("1"));
        if (workers == 1 && available > 1 && forcedOne) {
            String orange = "\u001b[38;5;208m";
            String reset = "\u001b[0m";
            System.out.println(orange + "WARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION" + reset);
            System.out.println(orange + "WARN: SINGLE-THREAD MODE MAY REDUCE SECURITY MARGIN" + reset);
            System.out.print("Type YES to continue with single-thread mode: ");
            String resp = new java.util.Scanner(System.in).nextLine();
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

    @FunctionalInterface
    private interface BenchWorker {
        long run(int workerId);
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
        // Use a simple AtomicLong instead of LongAdder for low contention scenarios
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

    private static String encodeText(String method, String text, String password, boolean useMaster) {
        switch (method) {
            case "b64":
                return BaseFwx.b64Encode(text);
            case "b256":
                return BaseFwx.b256Encode(text);
            case "a512":
                return BaseFwx.a512Encode(text);
            case "b512":
                return BaseFwx.b512Encode(text, password, useMaster);
            case "pb512":
                return BaseFwx.pb512Encode(text, password, useMaster);
            default:
                throw new IllegalArgumentException("Unsupported method " + method);
        }
    }

    private static String decodeText(String method, String text, String password, boolean useMaster) {
        switch (method) {
            case "b64":
                return BaseFwx.b64Decode(text);
            case "b256":
                return BaseFwx.b256Decode(text);
            case "a512":
                return BaseFwx.a512Decode(text);
            case "b512":
                return BaseFwx.b512Decode(text, password, useMaster);
            case "pb512":
                return BaseFwx.pb512Decode(text, password, useMaster);
            default:
                throw new IllegalArgumentException("Unsupported method " + method);
        }
    }

    private static String hashText(String method, String text) {
        switch (method) {
            case "hash512":
                return BaseFwx.hash512(text);
            case "uhash513":
                return BaseFwx.uhash513(text);
            case "bi512":
                return BaseFwx.bi512Encode(text);
            case "b1024":
                return BaseFwx.b1024Encode(text);
            default:
                throw new IllegalArgumentException("Unsupported hash method " + method);
        }
    }

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            usage();
            return;
        }
        String command = args[0];
        boolean useMaster = true;
        int argc = args.length;
        for (String arg : args) {
            if ("--no-master".equalsIgnoreCase(arg)) {
                useMaster = false;
            }
        }

        try {
            switch (command) {
                case "fwxaes-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File inEnc = new File(args[1]);
                    File outEnc = new File(args[2]);
                    String passEnc = args[3];
                    BaseFwx.fwxAesEncryptFile(inEnc, outEnc, passEnc, useMaster);
                    return;
                case "fwxaes-stream-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                         java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                        BaseFwx.fwxAesEncryptStream(inStream, outStream, args[3], useMaster);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("fwxAES stream encrypt failed", exc);
                    }
                    return;
                case "fwxaes-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File inDec = new File(args[1]);
                    File outDec = new File(args[2]);
                    String passDec = args[3];
                    BaseFwx.fwxAesDecryptFile(inDec, outDec, passDec, useMaster);
                    return;
                case "fwxaes-stream-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                         java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                        BaseFwx.fwxAesDecryptStream(inStream, outStream, args[3], useMaster);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("fwxAES stream decrypt failed", exc);
                    }
                    return;
                case "b512-enc":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b512Encode(args[1], args[2], useMaster));
                    return;
                case "b512-dec":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b512Decode(args[1], args[2], useMaster));
                    return;
                case "pb512-enc":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.pb512Encode(args[1], args[2], useMaster));
                    return;
                case "pb512-dec":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.pb512Decode(args[1], args[2], useMaster));
                    return;
                case "b512file-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File b512In = new File(args[1]);
                    File b512Out = new File(args[2]);
                    String b512Pass = args[3];
                    BaseFwx.b512FileEncodeFile(b512In, b512Out, b512Pass, useMaster);
                    return;
                case "b512file-bytes-rt":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File b512BytesIn = new File(args[1]);
                    File b512BytesOut = new File(args[2]);
                    String b512BytesPass = args[3];
                    try {
                        byte[] data = java.nio.file.Files.readAllBytes(b512BytesIn.toPath());
                        String name = b512BytesIn.getName();
                        int dot = name.lastIndexOf('.');
                        String ext = dot >= 0 ? name.substring(dot) : "";
                        byte[] blob = BaseFwx.b512FileEncodeBytes(data, ext, b512BytesPass, useMaster);
                        BaseFwx.DecodedFile decoded = BaseFwx.b512FileDecodeBytes(blob, b512BytesPass, useMaster);
                        java.nio.file.Files.write(b512BytesOut.toPath(), decoded.data);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("b512file bytes roundtrip failed", exc);
                    }
                    return;
                case "b512file-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File b512DecIn = new File(args[1]);
                    File b512DecOut = new File(args[2]);
                    String b512DecPass = args[3];
                    BaseFwx.b512FileDecodeFile(b512DecIn, b512DecOut, b512DecPass, useMaster);
                    return;
                case "pb512file-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File pb512In = new File(args[1]);
                    File pb512Out = new File(args[2]);
                    String pb512Pass = args[3];
                    BaseFwx.pb512FileEncodeFile(pb512In, pb512Out, pb512Pass, useMaster);
                    return;
                case "pb512file-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File pb512DecIn = new File(args[1]);
                    File pb512DecOut = new File(args[2]);
                    String pb512DecPass = args[3];
                    BaseFwx.pb512FileDecodeFile(pb512DecIn, pb512DecOut, pb512DecPass, useMaster);
                    return;
                case "pb512file-bytes-rt":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File pb512BytesIn = new File(args[1]);
                    File pb512BytesOut = new File(args[2]);
                    String pb512BytesPass = args[3];
                    try {
                        byte[] data = java.nio.file.Files.readAllBytes(pb512BytesIn.toPath());
                        String name = pb512BytesIn.getName();
                        int dot = name.lastIndexOf('.');
                        String ext = dot >= 0 ? name.substring(dot) : "";
                        byte[] blob = BaseFwx.pb512FileEncodeBytes(data, ext, pb512BytesPass, useMaster);
                        BaseFwx.DecodedFile decoded = BaseFwx.pb512FileDecodeBytes(blob, pb512BytesPass, useMaster);
                        java.nio.file.Files.write(pb512BytesOut.toPath(), decoded.data);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("pb512file bytes roundtrip failed", exc);
                    }
                    return;
                case "jmge": {
                    JmgArgs opts = parseJmgArgs(args, 1);
                    BaseFwx.jmgEncryptFile(opts.input, opts.output, opts.password, useMaster, opts.keepMeta, opts.keepInput);
                    return;
                }
                case "jmgd": {
                    JmgArgs opts = parseJmgArgs(args, 1);
                    BaseFwx.jmgDecryptFile(opts.input, opts.output, opts.password, useMaster);
                    return;
                }
                case "bench-text": {
                    if (argc < 4) {
                        usage();
                        return;
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
                    confirmSingleThreadCli((int) workers);

                    BenchWorker worker = (idx) -> {
                        String enc = encodeText(methodFinal, text, benchPassFinal, useMasterFlag);
                        String dec = decodeText(methodFinal, enc, benchPassFinal, useMasterFlag);
                        BENCH_SINK ^= dec.length();
                        return dec.length();
                    };
                    long ns = workers > 1
                        ? benchParallelMedian(warmup, iters, workers, worker)
                        : benchMedian(warmup, iters, () -> worker.run(0));
                    System.out.println("BENCH_NS=" + ns);
                    return;
                }
                case "bench-hash": {
                    if (argc < 3) {
                        usage();
                        return;
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
                            String digest = hashText(method, text);
                            BENCH_SINK ^= digest.length();
                            return digest.length();
                        };
                    }
                    long ns = workers > 1
                        ? benchParallelMedian(warmup, iters, workers, worker)
                        : benchMedian(warmup, iters, () -> worker.run(0));
                    System.out.println("BENCH_NS=" + ns);
                    return;
                }
                case "bench-fwxaes": {
                    if (argc < 3) {
                        usage();
                        return;
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
                    return;
                }
                case "bench-fwxaes-par": {
                    if (argc < 3) {
                        usage();
                        return;
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
                        return;
                    } finally {
                        pool.shutdown();
                    }
                }
                case "bench-b512file": {
                    if (argc < 3) {
                        usage();
                        return;
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
                        return;
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
                case "bench-pb512file": {
                    if (argc < 3) {
                        usage();
                        return;
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
                        return;
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
                case "b256-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b256Encode(args[1]));
                    return;
                case "b256-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b256Decode(args[1]));
                    return;
                case "b64-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b64Encode(args[1]));
                    return;
                case "b64-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b64Decode(args[1]));
                    return;
                case "hash512":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.hash512(args[1]));
                    return;
                case "uhash513":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.uhash513(args[1]));
                    return;
                case "a512-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.a512Encode(args[1]));
                    return;
                case "a512-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.a512Decode(args[1]));
                    return;
                case "bi512-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.bi512Encode(args[1]));
                    return;
                case "b1024-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b1024Encode(args[1]));
                    return;
                default:
                    usage();
            }
        } catch (RuntimeException exc) {
            System.err.println("Error: " + exc.getMessage());
            System.exit(1);
        }
    }

    private static void usage() {
        System.out.println("BaseFWX Java CLI");
        System.out.println("  fwxaes-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-dec <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-stream-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-stream-dec <in> <out> <password> [--no-master]");
        System.out.println("  b64-enc <text>");
        System.out.println("  b64-dec <text>");
        System.out.println("  hash512 <text>");
        System.out.println("  uhash513 <text>");
        System.out.println("  a512-enc <text>");
        System.out.println("  a512-dec <text>");
        System.out.println("  bi512-enc <text>");
        System.out.println("  b1024-enc <text>");
        System.out.println("  b512-enc <text> <password> [--no-master]");
        System.out.println("  b512-dec <text> <password> [--no-master]");
        System.out.println("  pb512-enc <text> <password> [--no-master]");
        System.out.println("  pb512-dec <text> <password> [--no-master]");
        System.out.println("  b512file-enc <in> <out> <password> [--no-master]");
        System.out.println("  b512file-bytes-rt <in> <out> <password> [--no-master]");
        System.out.println("  b512file-dec <in> <out> <password> [--no-master]");
        System.out.println("  pb512file-enc <in> <out> <password> [--no-master]");
        System.out.println("  pb512file-bytes-rt <in> <out> <password> [--no-master]");
        System.out.println("  pb512file-dec <in> <out> <password> [--no-master]");
        System.out.println("  jmge <in> <out> <password> [--keep-meta] [--keep-input] [--no-master]");
        System.out.println("  jmgd <in> <out> <password> [--no-master]");
        System.out.println("  b256-enc <text>");
        System.out.println("  b256-dec <text>");
        System.out.println("  bench-text <method> <text-file> <password> [--no-master]");
        System.out.println("  bench-hash <method> <text-file>");
        System.out.println("  bench-fwxaes <file> <password> [--no-master]");
        System.out.println("  bench-fwxaes-par <file> <password> [--no-master]");
        System.out.println("  bench-b512file <file> <password> [--no-master]");
        System.out.println("  bench-pb512file <file> <password> [--no-master]");
    }

    private static JmgArgs parseJmgArgs(String[] args, int startIndex) {
        JmgArgs parsed = new JmgArgs();
        java.util.List<String> positional = new java.util.ArrayList<>();
        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];
            if ("--keep-meta".equalsIgnoreCase(arg)) {
                parsed.keepMeta = true;
                continue;
            }
            if ("--keep-input".equalsIgnoreCase(arg)) {
                parsed.keepInput = true;
                continue;
            }
            if ("--no-master".equalsIgnoreCase(arg)) {
                continue;
            }
            if ("-p".equalsIgnoreCase(arg) || "--password".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing password value");
                }
                parsed.password = args[++i];
                continue;
            }
            if ("-o".equalsIgnoreCase(arg) || "--out".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing output value");
                }
                parsed.output = new File(args[++i]);
                continue;
            }
            positional.add(arg);
        }
        if (positional.isEmpty()) {
            throw new IllegalArgumentException("Missing input path");
        }
        parsed.input = new File(positional.get(0));
        if (parsed.output == null) {
            if (positional.size() >= 3) {
                parsed.output = new File(positional.get(1));
                if (parsed.password == null || parsed.password.isEmpty()) {
                    parsed.password = positional.get(2);
                }
                if (positional.size() > 3) {
                    throw new IllegalArgumentException("Too many arguments for jMG command");
                }
            } else if (positional.size() == 2) {
                if (parsed.password == null || parsed.password.isEmpty()) {
                    parsed.password = positional.get(1);
                } else {
                    parsed.output = new File(positional.get(1));
                }
            }
        } else if (positional.size() >= 2) {
            if (parsed.password == null || parsed.password.isEmpty()) {
                parsed.password = positional.get(1);
            }
            if (positional.size() > 2) {
                throw new IllegalArgumentException("Too many arguments for jMG command");
            }
        }
        if (parsed.output == null) {
            parsed.output = parsed.input;
        }
        if (parsed.password == null) {
            parsed.password = "";
        }
        return parsed;
    }

    private static final class JmgArgs {
        File input;
        File output;
        String password = "";
        boolean keepMeta = false;
        boolean keepInput = false;
    }
}
