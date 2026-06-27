/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.Constants;
import com.fixcraft.basefwx.MediaCipher;
import com.fixcraft.basefwx.VersionInfo;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class CliOptions {
    private CliOptions() {}

    static final class GlobalOptions {
        final boolean verbose;
        final boolean noLog;
        final String[] args;

        GlobalOptions(boolean verbose, boolean noLog, String[] args) {
            this.verbose = verbose;
            this.noLog = noLog;
            this.args = args;
        }
    }

    static final class KfmArgs {
        File input;
        File output;
        boolean bwMode = false;
    }

    static final class JmgArgs {
        File input;
        File output;
        String password = "";
        boolean keepMeta = false;
        boolean keepInput = false;
        boolean archiveOriginal = true;
    }

    static final class An7Args {
        File input;
        File output;
        String password = "";
        boolean keepInput = false;
        boolean forceAny = false;
    }

    static GlobalOptions parseGlobalOptions(String[] args) {
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

    static void printVersionInfo() {
        System.out.println("basefwx_java " + Constants.ENGINE_VERSION);
        String buildUtc = VersionInfo.buildUtc();
        System.out.println("build_time: " + humanizeUtcTimestamp(buildUtc) + " (" + buildUtc + ")");
        System.out.println("build_origin: " + buildOriginLabel());
        System.out.println("os: " + System.getProperty("os.name", "unknown"));
        System.out.println("arch: " + runtimeArch());
        System.out.println("linkage: java");
        System.out.println("java: " + System.getProperty("java.version", "unknown"));
        System.out.println("gpg_fingerprint: " + VersionInfo.gpgFingerprint());
        System.out.println("gpg_signature: not checked (release signatures are detached)");
        // 3.7.0: Argon2id is supported in the Java runtime via BouncyCastle's
        // Argon2BytesGenerator (always available as a runtime dep), so the
        // feature flag flips on. OQS / LZMA remain OFF in Java; configure
        // them out-of-band on the C++ side if you need full coverage.
        System.out.println("features: argon2=ON oqs=OFF lzma=OFF");
    }

    static String[] hwPlanForCommand(String command) {
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

    static boolean truthy(String raw) {
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase(Locale.US);
        return "1".equals(value) || "true".equals(value) || "yes".equals(value) || "on".equals(value);
    }

    static String aesAccelState() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.US);
        if (arch.contains("x86") || arch.contains("amd64")) {
            return "aesni";
        }
        if (arch.contains("arm") || arch.contains("aarch")) {
            return "arm-crypto";
        }
        return "cpu";
    }

    static String parallelText() {
        if (truthy(System.getenv("BASEFWX_FORCE_SINGLE_THREAD"))) {
            return "OFF";
        }
        int workers = Runtime.getRuntime().availableProcessors();
        if (workers <= 1) {
            return "OFF";
        }
        return "ON(" + workers + "w)";
    }

    static KfmArgs parseKfmArgs(String[] args, int startIndex) {
        KfmArgs parsed = new KfmArgs();
        java.util.List<String> positional = new java.util.ArrayList<>();
        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];
            if ("--no-master".equalsIgnoreCase(arg) || "--use-master".equalsIgnoreCase(arg)) {
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

    static JmgArgs parseJmgArgs(String[] args, int startIndex) {
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
            if ("--no-master".equalsIgnoreCase(arg) || "--use-master".equalsIgnoreCase(arg)) {
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

    static An7Args parseAn7Args(String[] args, int startIndex, boolean allowForceAny) {
        An7Args parsed = new An7Args();
        java.util.List<String> positional = new java.util.ArrayList<>();
        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];
            if ("--keep-input".equalsIgnoreCase(arg)) {
                parsed.keepInput = true;
                continue;
            }
            if ("--force-any".equalsIgnoreCase(arg)) {
                if (!allowForceAny) {
                    throw new IllegalArgumentException("--force-any is only valid for an7");
                }
                parsed.forceAny = true;
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
            if ("--no-master".equalsIgnoreCase(arg) || "--use-master".equalsIgnoreCase(arg)) {
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
        if (parsed.password == null || parsed.password.isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
        if (positional.size() > 2) {
            throw new IllegalArgumentException("Too many arguments");
        }
        return parsed;
    }

    private static String humanizeUtcTimestamp(String value) {
        if (value == null || value.length() < 20 || value.charAt(4) != '-' || value.charAt(7) != '-' || value.charAt(10) != 'T') {
            return value == null ? "unknown" : value;
        }
        String human = value.substring(0, 10) + " " + value.substring(11);
        if (human.endsWith("Z")) {
            human = human.substring(0, human.length() - 1) + " UTC";
        }
        return human;
    }

    private static String runtimeArch() {
        String arch = System.getProperty("os.arch", "unknown").toLowerCase(Locale.ROOT);
        if (arch.equals("x86_64") || arch.equals("amd64")) {
            return "amd64";
        }
        if (arch.equals("aarch64") || arch.equals("arm64")) {
            return "arm64";
        }
        if (arch.startsWith("arm")) {
            return "arm";
        }
        if (arch.matches("i[3-6]86") || arch.equals("x86")) {
            return "x86";
        }
        return arch;
    }

    private static String buildOriginLabel() {
        String origin = VersionInfo.buildOrigin();
        if ("github".equalsIgnoreCase(origin)) {
            return "GitHub Actions";
        }
        return "local/manual";
    }
}
