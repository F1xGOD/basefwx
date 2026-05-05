package com.fixcraft.basefwx;

import java.security.SecureRandom;

/**
 * Standalone fwxAES microbenchmark for the pure-Java and JNI backends.
 * Args: {@code <payload_bytes> <iterations>} (defaults: 4 MiB, 5).
 */
public final class FwxAESBenchmark {

    private FwxAESBenchmark() {}

    public static void main(String[] args) {
        int size = args.length >= 1 ? Integer.parseInt(args[0]) : 4 * 1024 * 1024;
        int iters = args.length >= 2 ? Integer.parseInt(args[1]) : 5;
        String password = "benchmark-password";

        byte[] payload = new byte[size];
        new SecureRandom().nextBytes(payload);

        System.out.println("basefwx FwxAESBenchmark");
        System.out.println("  payload: " + bytesHuman(size));
        System.out.println("  iterations: " + iters);
        System.out.println();

        FwxAES warmup = FwxAES.create(false);
        for (int i = 0; i < 2; i++) {
            warmup.decryptRaw(warmup.encryptRaw(payload, password), password);
        }

        Result java = bench("pure-java", false, payload, password, iters);
        Result jni = null;
        if (NativeCryptoBackend.tryCreate() != null
            || CryptoBackends.usingNative()) {
            jni = bench("jni", true, payload, password, iters);
        } else {
            System.out.println("jni: skipped (basefwxcrypto shared library not available)");
        }

        System.out.println();
        System.out.println("results");
        printResult(java);
        if (jni != null) {
            printResult(jni);
            double ratio = java.encryptMs / jni.encryptMs;
            System.out.printf("  speedup (encrypt): jni is %.2fx pure-java%n", ratio);
        }
    }

    private static Result bench(String label, boolean preferNative, byte[] payload,
                                String password, int iters) {
        FwxAES aes = FwxAES.create(preferNative);
        if (preferNative && !aes.isNative()) {
            label = label + "(fallback)";
        }
        long encTotal = 0;
        long decTotal = 0;
        byte[] blob = null;
        for (int i = 0; i < iters; i++) {
            long t0 = System.nanoTime();
            blob = aes.encryptRaw(payload, password);
            long t1 = System.nanoTime();
            byte[] back = aes.decryptRaw(blob, password);
            long t2 = System.nanoTime();
            if (back.length != payload.length) {
                throw new IllegalStateException("round-trip length mismatch");
            }
            encTotal += (t1 - t0);
            decTotal += (t2 - t1);
        }
        if (blob == null) {
            throw new IllegalStateException("benchmark produced no output");
        }
        Result r = new Result();
        r.label = label;
        r.encryptMs = encTotal / 1_000_000.0 / iters;
        r.decryptMs = decTotal / 1_000_000.0 / iters;
        r.encryptThroughputMiBs = (payload.length / 1024.0 / 1024.0) / (r.encryptMs / 1000.0);
        r.decryptThroughputMiBs = (payload.length / 1024.0 / 1024.0) / (r.decryptMs / 1000.0);
        return r;
    }

    private static void printResult(Result r) {
        System.out.printf("  %-18s encrypt %.2f ms (%.1f MiB/s)   decrypt %.2f ms (%.1f MiB/s)%n",
            r.label, r.encryptMs, r.encryptThroughputMiBs, r.decryptMs, r.decryptThroughputMiBs);
    }

    private static String bytesHuman(long n) {
        if (n < 1024) return n + " B";
        if (n < 1024L * 1024) return String.format("%.1f KiB", n / 1024.0);
        if (n < 1024L * 1024 * 1024) return String.format("%.1f MiB", n / 1024.0 / 1024.0);
        return String.format("%.2f GiB", n / 1024.0 / 1024.0 / 1024.0);
    }

    private static final class Result {
        String label;
        double encryptMs;
        double decryptMs;
        double encryptThroughputMiBs;
        double decryptThroughputMiBs;
    }
}
