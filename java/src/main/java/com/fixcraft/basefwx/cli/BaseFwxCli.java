/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;
import com.fixcraft.basefwx.RuntimeLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public final class BaseFwxCli {
    private BaseFwxCli() {}

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

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            usage();
            return;
        }
        CliOptions.GlobalOptions globals = CliOptions.parseGlobalOptions(args);
        RuntimeLog.configureFromCli(globals.verbose, globals.noLog);
        args = globals.args;
        if (args.length == 0) {
            usage();
            return;
        }

        String command = args[0];
        if ("--version".equals(command) || "-V".equals(command) || "version".equals(command)) {
            CliOptions.printVersionInfo();
            return;
        }

        boolean useMaster = false;
        int argc = args.length;
        for (String arg : args) {
            if ("--use-master".equalsIgnoreCase(arg)) {
                useMaster = true;
            } else if ("--no-master".equalsIgnoreCase(arg)) {
                useMaster = false;
            }
        }

        String[] hw = CliOptions.hwPlanForCommand(command);
        RuntimeLog.hwLine(
            "🎛 [basefwx.hw] op=" + command
                + " encode=" + hw[0]
                + " decode=" + hw[1]
                + " pixels=" + hw[2]
                + " parallel=" + CliOptions.parallelText()
                + " crypto=CPU"
                + " aes_accel=" + CliOptions.aesAccelState()
        );
        RuntimeLog.hwReason(hw[3] + "; AES operations remain on CPU (JCE/OpenSSL-backed providers)");
        boolean expectGpu = "NVENC".equals(hw[0]) || "QSV".equals(hw[0]) || "VAAPI".equals(hw[0]);
        CommandTelemetry telemetry = new CommandTelemetry(RuntimeLog.shouldLog(), expectGpu);

        try {
            int code = dispatchCommand(command, args, argc, useMaster);
            if (code == 1) {
                usage();
            }
        } catch (RuntimeException exc) {
            System.err.println("Error: " + exc.getMessage());
            System.exit(1);
        } finally {
            telemetry.close();
        }
    }

    /** @return 0 success, 1 usage, -1 unknown command (usage) */
    private static int dispatchCommand(String command, String[] args, int argc, boolean useMaster) {
        int code = CodecCommands.handle(command, args, argc, useMaster);
        if (code >= 0) {
            return code;
        }
        code = FileCommands.handle(command, args, argc, useMaster);
        if (code >= 0) {
            return code;
        }
        code = MediaCommands.handle(command, args, argc, useMaster);
        if (code >= 0) {
            return code;
        }
        code = BenchCommands.handle(command, args, argc, useMaster);
        if (code >= 0) {
            return code;
        }
        return dispatchCoreCommand(command, args, argc, useMaster);
    }

    private static int dispatchCoreCommand(String command, String[] args, int argc, boolean useMaster) {
        switch (command) {
            case "fwxaes-enc":
                if (argc < 4) {
                    return 1;
                }
                BaseFwx.fwxAesEncryptFile(new File(args[1]), new File(args[2]), args[3], useMaster);
                return 0;
            case "fwxaes-stream-enc":
                if (argc < 4) {
                    return 1;
                }
                try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                     java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                    BaseFwx.fwxAesEncryptStream(inStream, outStream, args[3], useMaster);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("fwxAES stream encrypt failed", exc);
                }
                return 0;
            case "fwxaes-dec":
                if (argc < 4) {
                    return 1;
                }
                BaseFwx.fwxAesDecryptFile(new File(args[1]), new File(args[2]), args[3], useMaster);
                return 0;
            case "an7": {
                CliOptions.An7Args opts = CliOptions.parseAn7Args(args, 1, true);
                File out = BaseFwx.an7File(
                    opts.input,
                    opts.password,
                    opts.output,
                    opts.keepInput,
                    opts.forceAny
                );
                System.out.println(out.getPath());
                return 0;
            }
            case "dean7": {
                CliOptions.An7Args opts = CliOptions.parseAn7Args(args, 1, false);
                BaseFwx.An7Result result = BaseFwx.dean7File(
                    opts.input,
                    opts.password,
                    opts.output,
                    opts.keepInput
                );
                System.out.println(result.outputPath.getPath());
                return 0;
            }
            case "fwxaes-stream-dec":
                if (argc < 4) {
                    return 1;
                }
                try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                     java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                    BaseFwx.fwxAesDecryptStream(inStream, outStream, args[3], useMaster);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("fwxAES stream decrypt failed", exc);
                }
                return 0;
            case "fwxaes-live-enc":
                if (argc < 4) {
                    return 1;
                }
                try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                     java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                    BaseFwx.fwxAesLiveEncryptStream(inStream, outStream, args[3], useMaster);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("fwxAES live encrypt failed", exc);
                }
                return 0;
            case "fwxaes-live-dec":
                if (argc < 4) {
                    return 1;
                }
                try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                     java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                    BaseFwx.fwxAesLiveDecryptStream(inStream, outStream, args[3], useMaster);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("fwxAES live decrypt failed", exc);
                }
                return 0;
            default:
                return 1;
        }
    }

    private static void usage() {
        System.out.println("BaseFWX Java CLI");
        System.out.println("  [global] --verbose|-v --no-log --version|-V");
        System.out.println("  version");
        System.out.println("  fwxaes-enc <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  fwxaes-dec <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  an7 <in.fwx> -p <password> [--out <path>] [--keep-input] [--force-any]");
        System.out.println("  dean7 <in> -p <password> [--out <path>] [--keep-input]");
        System.out.println("  fwxaes-stream-enc <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  fwxaes-stream-dec <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  fwxaes-live-enc <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  fwxaes-live-dec <in> <out> <password> [--use-master|--no-master]");
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
        System.out.println("  b512-enc <text> <password> [--use-master|--no-master]");
        System.out.println("  b512-dec <text> <password> [--use-master|--no-master]");
        System.out.println("  pb512-enc <text> <password> [--use-master|--no-master]");
        System.out.println("  pb512-dec <text> <password> [--use-master|--no-master]");
        System.out.println("  b512file-enc <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  b512file-bytes-rt <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  b512file-dec <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  pb512file-enc <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  pb512file-bytes-rt <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  pb512file-dec <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  jmge <in> <out> <password> [--keep-meta] [--keep-input] [--no-archive] [--use-master|--no-master]");
        System.out.println("  jmgd <in> <out> <password> [--use-master|--no-master]");
        System.out.println("  b256-enc <text>");
        System.out.println("  b256-dec <text>");
        System.out.println("  bench-text <method> <text-file> <password> [--use-master|--no-master]");
        System.out.println("  bench-hash <method> <text-file>");
        System.out.println("  bench-fwxaes <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-fwxaes-par <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-an7 <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-dean7 <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-live <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-b512file <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-pb512file <file> <password> [--use-master|--no-master]");
        System.out.println("  bench-jmg <media> <password> [--use-master|--no-master]");
    }
}
