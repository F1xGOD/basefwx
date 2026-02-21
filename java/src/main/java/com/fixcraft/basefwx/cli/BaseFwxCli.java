package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;
import com.fixcraft.basefwx.MediaCipher;
import com.fixcraft.basefwx.RuntimeLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Locale;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class BaseFwxCli {
    private static volatile int BENCH_SINK = 0;

    private static final class GlobalOptions {
        final boolean verbose;
        final boolean noLog;
        final String[] args;

        GlobalOptions(boolean verbose, boolean noLog, String[] args) {
            this.verbose = verbose;
            this.noLog = noLog;
            this.args = args;
        }
    }

    private static final class CommandTelemetry implements AutoCloseable {
        private final boolean enabled;
        private final boolean expectGpu;
        private final Thread worker;
        private volatile boolean running = true;
        private long prevTotal = 0L;
        private long prevIdle = 0L;

        CommandTelemetry(boolean enabled, boolean expectGpu) {
            this.enabled = enabled;
            this.expectGpu = expectGpu;
            if (!enabled) {
                this.worker = null;
                return;
            }
            this.worker = new Thread(this::loop, "basefwx-cli-telemetry");
            this.worker.setDaemon(true);
            this.worker.start();
        }

        private void loop() {
            while (running) {
                try {
                    Thread.sleep(5000L);
                } catch (InterruptedException exc) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (!running) {
                    return;
                }
                RuntimeLog.info(sampleMetrics());
            }
        }

        private String sampleMetrics() {
            StringBuilder sb = new StringBuilder("📊 [basefwx.stats]");
            Double cpu = sampleCpuPercent();
            if (cpu != null) {
                sb.append(" CPU ").append(String.format(Locale.US, "%.0f%%", cpu));
            }
            Double ram = sampleRamPercent();
            if (ram != null) {
                sb.append(" \\ RAM ").append(String.format(Locale.US, "%.0f%%", ram));
            }
            if (expectGpu) {
                double[] gpu = sampleGpu();
                if (!Double.isNaN(gpu[0])) {
                    sb.append(" \\ GPU ").append(String.format(Locale.US, "%.0f%%", gpu[0]));
                }
                if (!Double.isNaN(gpu[1])) {
                    sb.append(" \\ ").append(String.format(Locale.US, "%.0fC", gpu[1]));
                    return sb.toString();
                }
            }
            Double temp = sampleCpuTemp();
            if (temp != null) {
                sb.append(" \\ ").append(String.format(Locale.US, "%.0fC", temp));
            }
            return sb.toString();
        }

        private Double sampleCpuPercent() {
            try {
                java.lang.management.OperatingSystemMXBean baseBean = ManagementFactory.getOperatingSystemMXBean();
                if (baseBean instanceof com.sun.management.OperatingSystemMXBean) {
                    com.sun.management.OperatingSystemMXBean osBean =
                        (com.sun.management.OperatingSystemMXBean) baseBean;
                    double load = osBean.getCpuLoad();
                    if (load >= 0.0d) {
                        return Math.max(0.0d, Math.min(100.0d, load * 100.0d));
                    }
                }
            } catch (Exception ignored) {
            }
            // Linux fallback via /proc/stat
            try {
                List<String> lines = Files.readAllLines(java.nio.file.Paths.get("/proc/stat"), StandardCharsets.UTF_8);
                if (lines.isEmpty() || !lines.get(0).startsWith("cpu ")) {
                    return null;
                }
                String[] parts = lines.get(0).trim().split("\\s+");
                if (parts.length < 6) {
                    return null;
                }
                long user = Long.parseLong(parts[1]);
                long nice = Long.parseLong(parts[2]);
                long system = Long.parseLong(parts[3]);
                long idle = Long.parseLong(parts[4]);
                long iowait = Long.parseLong(parts[5]);
                long irq = parts.length > 6 ? Long.parseLong(parts[6]) : 0L;
                long softirq = parts.length > 7 ? Long.parseLong(parts[7]) : 0L;
                long steal = parts.length > 8 ? Long.parseLong(parts[8]) : 0L;
                long total = user + nice + system + idle + iowait + irq + softirq + steal;
                long idleTotal = idle + iowait;
                if (prevTotal == 0L || total <= prevTotal) {
                    prevTotal = total;
                    prevIdle = idleTotal;
                    return null;
                }
                long deltaTotal = total - prevTotal;
                long deltaIdle = idleTotal - prevIdle;
                prevTotal = total;
                prevIdle = idleTotal;
                if (deltaTotal <= 0L) {
                    return null;
                }
                double usage = 100.0d * (1.0d - (double) deltaIdle / (double) deltaTotal);
                return Math.max(0.0d, Math.min(100.0d, usage));
            } catch (Exception ignored) {
                return null;
            }
        }

        private Double sampleRamPercent() {
            try {
                java.lang.management.OperatingSystemMXBean baseBean = ManagementFactory.getOperatingSystemMXBean();
                if (baseBean instanceof com.sun.management.OperatingSystemMXBean) {
                    com.sun.management.OperatingSystemMXBean osBean =
                        (com.sun.management.OperatingSystemMXBean) baseBean;
                    long total = osBean.getTotalMemorySize();
                    long free = osBean.getFreeMemorySize();
                    if (total > 0L) {
                        return Math.max(0.0d, Math.min(100.0d, ((double) (total - free) * 100.0d) / (double) total));
                    }
                }
            } catch (Exception ignored) {
            }
            return null;
        }

        private double[] sampleGpu() {
            double[] out = new double[] {Double.NaN, Double.NaN};
            Process process = null;
            try {
                process = new ProcessBuilder(
                    "nvidia-smi",
                    "--query-gpu=utilization.gpu,temperature.gpu",
                    "--format=csv,noheader,nounits"
                ).redirectErrorStream(true).start();
                List<Double> util = new ArrayList<Double>();
                List<Double> temp = new ArrayList<Double>();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String[] parts = line.split(",");
                        if (parts.length < 2) {
                            continue;
                        }
                        try {
                            util.add(Double.parseDouble(parts[0].trim()));
                        } catch (NumberFormatException ignored) {
                        }
                        try {
                            double t = Double.parseDouble(parts[1].trim());
                            if (t > 0.0d) {
                                temp.add(t);
                            }
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
                process.waitFor(2, TimeUnit.SECONDS);
                if (!util.isEmpty()) {
                    double sum = 0.0d;
                    for (double value : util) {
                        sum += value;
                    }
                    out[0] = sum / util.size();
                }
                if (!temp.isEmpty()) {
                    double sum = 0.0d;
                    for (double value : temp) {
                        sum += value;
                    }
                    out[1] = sum / temp.size();
                }
            } catch (Exception ignored) {
            } finally {
                if (process != null) {
                    process.destroy();
                }
            }
            return out;
        }

        private Double sampleCpuTemp() {
            try {
                Path root = java.nio.file.Paths.get("/sys/class/thermal");
                if (!Files.exists(root)) {
                    return null;
                }
                double sum = 0.0d;
                int count = 0;
                try (java.nio.file.DirectoryStream<Path> zones = Files.newDirectoryStream(root, "thermal_zone*")) {
                    for (Path entry : zones) {
                        Path temp = entry.resolve("temp");
                        if (!Files.isRegularFile(temp)) {
                            continue;
                        }
                        try {
                            String raw = new String(Files.readAllBytes(temp), StandardCharsets.UTF_8).trim();
                            if (raw.isEmpty()) {
                                continue;
                            }
                            double value = Double.parseDouble(raw);
                            if (value > 1000.0d) {
                                value /= 1000.0d;
                            }
                            if (value >= 5.0d && value <= 130.0d) {
                                sum += value;
                                count += 1;
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
                if (count == 0) {
                    return null;
                }
                return sum / (double) count;
            } catch (Exception ignored) {
                return null;
            }
        }

        @Override
        public void close() {
            running = false;
            if (worker != null) {
                worker.interrupt();
                try {
                    worker.join(300L);
                } catch (InterruptedException exc) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

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
        // Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
        String forceSingle = System.getenv("BASEFWX_FORCE_SINGLE_THREAD");
        int available = Runtime.getRuntime().availableProcessors();
        boolean forced = "1".equals(forceSingle) && available > 1;
        boolean nonInteractive = "1".equals(System.getenv("BASEFWX_ALLOW_SINGLE_THREAD"))
                || "1".equals(System.getenv("BASEFWX_NONINTERACTIVE"));
        if (forced) {
            RuntimeLog.warn("MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION");
            RuntimeLog.warn("SINGLE-THREAD MODE MAY REDUCE SECURITY MARGIN");
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
            case "n10":
                return BaseFwx.n10Encode(text);
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
            case "n10":
                return BaseFwx.n10Decode(text);
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

    private static GlobalOptions parseGlobalOptions(String[] args) {
        boolean verbose = false;
        boolean noLog = false;
        List<String> cleaned = new ArrayList<String>(args.length);
        for (String arg : args) {
            if ("--verbose".equals(arg) || "-v".equals(arg)) {
                verbose = true;
                continue;
            }
            if ("--no-log".equals(arg)) {
                noLog = true;
                continue;
            }
            cleaned.add(arg);
        }
        return new GlobalOptions(verbose, noLog, cleaned.toArray(new String[0]));
    }

    private static boolean truthy(String raw) {
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase(Locale.US);
        return "1".equals(value) || "true".equals(value) || "yes".equals(value) || "on".equals(value);
    }

    private static String aesAccelState() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.US);
        if (arch.contains("x86") || arch.contains("amd64")) {
            return "aesni";
        }
        if (arch.contains("arm") || arch.contains("aarch")) {
            return "arm-crypto";
        }
        return "cpu";
    }

    private static String parallelText() {
        if (truthy(System.getenv("BASEFWX_FORCE_SINGLE_THREAD"))) {
            return "OFF";
        }
        int workers = Runtime.getRuntime().availableProcessors();
        if (workers <= 1) {
            return "OFF";
        }
        return "ON(" + workers + "w)";
    }

    private static String[] hwPlanForCommand(String command) {
        String encode = "CPU";
        String decode = "CPU";
        String pixels = "CPU";
        String reason = "command uses CPU crypto path";
        if ("jmge".equals(command) || "jmgd".equals(command) || "bench-jmg".equals(command)) {
            String hw = MediaCipher.selectedHwaccelForCli().toLowerCase(Locale.US);
            if ("nvenc".equals(hw)) {
                encode = "NVENC";
                decode = "NVENC";
                reason = "BASEFWX_HWACCEL selected NVIDIA media acceleration";
            } else if ("qsv".equals(hw)) {
                encode = "QSV";
                decode = "QSV";
                reason = "BASEFWX_HWACCEL selected Intel QSV media acceleration";
            } else if ("vaapi".equals(hw)) {
                encode = "VAAPI";
                decode = "VAAPI";
                reason = "BASEFWX_HWACCEL selected VAAPI media acceleration";
            } else {
                reason = "media acceleration unavailable, CPU fallback in effect";
            }
        }
        return new String[] {encode, decode, pixels, reason};
    }

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            usage();
            return;
        }
        GlobalOptions globals = parseGlobalOptions(args);
        RuntimeLog.configureFromCli(globals.verbose, globals.noLog);
        args = globals.args;
        if (args.length == 0) {
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

        String[] hw = hwPlanForCommand(command);
        RuntimeLog.hwLine(
            "🎛 [basefwx.hw] op=" + command
                + " encode=" + hw[0]
                + " decode=" + hw[1]
                + " pixels=" + hw[2]
                + " parallel=" + parallelText()
                + " crypto=CPU"
                + " aes_accel=" + aesAccelState()
        );
        RuntimeLog.hwReason(hw[3] + "; AES operations remain on CPU (JCE/OpenSSL-backed providers)");
        boolean expectGpu = "NVENC".equals(hw[0]) || "QSV".equals(hw[0]) || "VAAPI".equals(hw[0]);
        CommandTelemetry telemetry = new CommandTelemetry(RuntimeLog.shouldLog(), expectGpu);

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
                case "fwxaes-live-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                         java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                        BaseFwx.fwxAesLiveEncryptStream(inStream, outStream, args[3], useMaster);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("fwxAES live encrypt failed", exc);
                    }
                    return;
                case "fwxaes-live-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                         java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                        BaseFwx.fwxAesLiveDecryptStream(inStream, outStream, args[3], useMaster);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("fwxAES live decrypt failed", exc);
                    }
                    return;
                case "b512-enc":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b512Encode(args[1], args[2], useMaster));
                    return;
                case "n10-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.n10Encode(args[1]));
                    return;
                case "n10-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.n10Decode(args[1]));
                    return;
                case "n10file-enc":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    try {
                        byte[] data = java.nio.file.Files.readAllBytes(new File(args[1]).toPath());
                        String digits = BaseFwx.n10EncodeBytes(data);
                        java.nio.file.Files.write(new File(args[2]).toPath(), digits.getBytes(StandardCharsets.UTF_8));
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("n10 file encode failed", exc);
                    }
                    return;
                case "n10file-dec":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    try {
                        String digits = new String(java.nio.file.Files.readAllBytes(new File(args[1]).toPath()), StandardCharsets.UTF_8);
                        byte[] decoded = BaseFwx.n10DecodeBytes(digits);
                        java.nio.file.Files.write(new File(args[2]).toPath(), decoded);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("n10 file decode failed", exc);
                    }
                    return;
                case "kFMe": {
                    KfmArgs opts = parseKfmArgs(args, 1);
                    File out = BaseFwx.kFMe(opts.input, opts.output, opts.bwMode);
                    System.out.println(out.getPath());
                    return;
                }
                case "kFMd": {
                    KfmArgs opts = parseKfmArgs(args, 1);
                    File out = BaseFwx.kFMd(opts.input, opts.output, opts.bwMode);
                    System.out.println(out.getPath());
                    return;
                }
                case "kFAe": {
                    KfmArgs opts = parseKfmArgs(args, 1);
                    File out = BaseFwx.kFAe(opts.input, opts.output, opts.bwMode);
                    System.out.println(out.getPath());
                    return;
                }
                case "kFAd": {
                    KfmArgs opts = parseKfmArgs(args, 1);
                    File out = BaseFwx.kFAd(opts.input, opts.output);
                    System.out.println(out.getPath());
                    return;
                }
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
                    BaseFwx.jmgEncryptFile(
                        opts.input,
                        opts.output,
                        opts.password,
                        useMaster,
                        opts.keepMeta,
                        opts.keepInput,
                        opts.archiveOriginal
                    );
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
                case "bench-live": {
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
                    File[] encFiles = new File[workers];
                    File[] decFiles = new File[workers];
                    try {
                        for (int i = 0; i < workers; i++) {
                            try {
                                tempDirs[i] = Files.createTempDirectory("basefwx-bench-live-" + i).toFile();
                            } catch (java.io.IOException exc) {
                                throw new RuntimeException("Failed to create bench temp dir", exc);
                            }
                            encFiles[i] = new File(tempDirs[i], "bench.live");
                            decFiles[i] = new File(tempDirs[i], "bench_dec" + ext);
                        }
                        BenchWorker worker = (idx) -> {
                            File encFile = encFiles[idx];
                            File decFile = decFiles[idx];
                            try (java.io.FileInputStream src = new java.io.FileInputStream(input);
                                 java.io.FileOutputStream encOut = new java.io.FileOutputStream(encFile)) {
                                BaseFwx.fwxAesLiveEncryptStream(src, encOut, benchPassFinal, useMasterFlag);
                            } catch (java.io.IOException exc) {
                                throw new RuntimeException("bench-live encrypt failed", exc);
                            }
                            try (java.io.FileInputStream encIn = new java.io.FileInputStream(encFile);
                                 java.io.FileOutputStream decOut = new java.io.FileOutputStream(decFile)) {
                                BaseFwx.fwxAesLiveDecryptStream(encIn, decOut, benchPassFinal, useMasterFlag);
                            } catch (java.io.IOException exc) {
                                throw new RuntimeException("bench-live decrypt failed", exc);
                            }
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
                case "bench-jmg": {
                    if (argc < 3) {
                        usage();
                        return;
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
                        // Create temporary directories for each worker
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
                            // Encrypt
                            BaseFwx.jmgEncryptFile(mediaFile, encFile, benchPassFinal, useMasterFlag, false, true);
                            // Decrypt
                            BaseFwx.jmgDecryptFile(encFile, decFile, benchPassFinal, useMasterFlag);
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
                        // Cleanup temporary files
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
        } finally {
            telemetry.close();
        }
    }

    private static void usage() {
        System.out.println("BaseFWX Java CLI");
        System.out.println("  [global] --verbose|-v --no-log");
        System.out.println("  fwxaes-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-dec <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-stream-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-stream-dec <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-live-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-live-dec <in> <out> <password> [--no-master]");
        System.out.println("  b64-enc <text>");
        System.out.println("  b64-dec <text>");
        System.out.println("  n10-enc <text>");
        System.out.println("  n10-dec <digits>");
        System.out.println("  n10file-enc <in> <out>");
        System.out.println("  n10file-dec <in> <out>");
        System.out.println("  kFMe <in> [--out <out>] [--bw]");
        System.out.println("  kFMd <in> [--out <out>] [--bw]");
        System.out.println("  kFAe <in> [--out <out>] [--bw]   (deprecated alias)");
        System.out.println("  kFAd <in> [--out <out>]          (deprecated alias)");
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
        System.out.println("  jmge <in> <out> <password> [--keep-meta] [--keep-input] [--no-archive] [--no-master]");
        System.out.println("  jmgd <in> <out> <password> [--no-master]");
        System.out.println("  b256-enc <text>");
        System.out.println("  b256-dec <text>");
        System.out.println("  bench-text <method> <text-file> <password> [--no-master]");
        System.out.println("  bench-hash <method> <text-file>");
        System.out.println("  bench-fwxaes <file> <password> [--no-master]");
        System.out.println("  bench-fwxaes-par <file> <password> [--no-master]");
        System.out.println("  bench-live <file> <password> [--no-master]");
        System.out.println("  bench-b512file <file> <password> [--no-master]");
        System.out.println("  bench-pb512file <file> <password> [--no-master]");
        System.out.println("  bench-jmg <media> <password> [--no-master]");
    }

    private static KfmArgs parseKfmArgs(String[] args, int startIndex) {
        KfmArgs parsed = new KfmArgs();
        java.util.List<String> positional = new java.util.ArrayList<>();
        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];
            if ("--no-master".equalsIgnoreCase(arg)) {
                continue;
            }
            if ("--bw".equalsIgnoreCase(arg)) {
                parsed.bwMode = true;
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
        if (parsed.output == null && positional.size() >= 2) {
            parsed.output = new File(positional.get(1));
        }
        if (positional.size() > 2) {
            throw new IllegalArgumentException("Too many kFM arguments");
        }
        return parsed;
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
            if ("--no-archive".equalsIgnoreCase(arg)) {
                parsed.archiveOriginal = false;
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

    private static final class KfmArgs {
        File input;
        File output;
        boolean bwMode = false;
    }

    private static final class JmgArgs {
        File input;
        File output;
        String password = "";
        boolean keepMeta = false;
        boolean keepInput = false;
        boolean archiveOriginal = true;
    }
}
