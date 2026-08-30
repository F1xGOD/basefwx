/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.Constants;
import com.fixcraft.basefwx.PQ;
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
        System.out.println(
                "features: argon2=ON pq=" + PQ.currentKemAlgorithm()
                + " lzma=OFF retired_media="
                + (profileEnabled() ? "ON" : "OFF"));
    }

    static String[] hwPlanForCommand(String command) {
        String[] profilePlan = profileHwPlanForCommand(command);
        if (profilePlan != null) {
            return profilePlan;
        }
        return new String[]{
            "CPU", "CPU", "CPU", "command uses CPU crypto path"
        };
    }

    static boolean truthy(String raw) {
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase(Locale.US);
        return "1".equals(value) || "true".equals(value) || "yes".equals(value) || "on".equals(value);
    }

    // BASEFWX_PROFILE_METHODS_BEGIN
    private static boolean profileEnabled() {
        return false;
    }

    private static String[] profileHwPlanForCommand(String command) {
        return null;
    }
    // BASEFWX_PROFILE_METHODS_END

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
