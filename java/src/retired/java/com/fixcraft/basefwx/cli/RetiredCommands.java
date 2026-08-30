/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;
import com.fixcraft.basefwx.BaseFwxImage;
import com.fixcraft.basefwx.MediaCipher;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class RetiredCommands {
    private RetiredCommands() {}

    private static final class KfmArgs {
        File input;
        File output;
        boolean bwMode;
    }

    private static final class JmgArgs {
        File input;
        File output;
        String password = "";
        boolean keepMeta;
        boolean keepInput;
        boolean archiveOriginal = true;
    }

    /** @return 0 handled, 1 usage, -1 not handled */
    public static int handle(String command, String[] args, int argc, boolean useMaster) {
        switch (command) {
            case "b256-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.b256Encode(args[1]));
                return 0;
            case "b256-dec":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.b256Decode(args[1]));
                return 0;
            case "a512-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.a512Encode(args[1]));
                return 0;
            case "a512-dec":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.a512Decode(args[1]));
                return 0;
            case "bi512-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.bi512Encode(args[1]));
                return 0;
            case "uhash513":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.uhash513(args[1]));
                return 0;
            case "kFMe": {
                KfmArgs opts = parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFMe(opts.input, opts.output, opts.bwMode);
                System.out.println(out.getPath());
                return 0;
            }
            case "kFMd": {
                KfmArgs opts = parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFMd(opts.input, opts.output, opts.bwMode);
                System.out.println(out.getPath());
                return 0;
            }
            case "kFAe": {
                KfmArgs opts = parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFAe(opts.input, opts.output, opts.bwMode);
                System.out.println(out.getPath());
                return 0;
            }
            case "kFAd": {
                KfmArgs opts = parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFAd(opts.input, opts.output);
                System.out.println(out.getPath());
                return 0;
            }
            case "jmge": {
                JmgArgs opts = parseJmgArgs(args, 1);
                BaseFwxImage.jmgEncryptFile(
                    opts.input,
                    opts.output,
                    opts.password,
                    useMaster,
                    opts.keepMeta,
                    opts.keepInput,
                    opts.archiveOriginal
                );
                return 0;
            }
            case "jmgd": {
                JmgArgs opts = parseJmgArgs(args, 1);
                BaseFwxImage.jmgDecryptFile(opts.input, opts.output, opts.password, useMaster);
                return 0;
            }
            default:
                return -1;
        }
    }

    public static String[] hwPlanForCommand(String command) {
        String encode = "CPU";
        String decode = "CPU";
        String reason = "command uses CPU crypto path";
        if ("jmge".equals(command) || "jmgd".equals(command)) {
            String hw = MediaCipher.selectedHwaccelForCli()
                    .toLowerCase(Locale.US);
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
        return new String[]{encode, decode, "CPU", reason};
    }

    public static void printUsage() {
        System.out.println("Retired compatibility commands:");
        System.out.println("  b256-enc <text>");
        System.out.println("  b256-dec <text>");
        System.out.println("  a512-enc <text>");
        System.out.println("  a512-dec <text>");
        System.out.println("  bi512-enc <text>");
        System.out.println("  uhash513 <text>");
        System.out.println("  kFMe <in> [--out <out>] [--bw]");
        System.out.println("  kFMd <in> [--out <out>] [--bw]");
        System.out.println("  kFAe <in> [--out <out>] [--bw]   (deprecated alias)");
        System.out.println("  kFAd <in> [--out <out>]          (deprecated alias)");
        System.out.println("  jmge <in> <out> <password> [--keep-meta] [--keep-input] [--no-archive] [--use-master|--no-master]");
        System.out.println("  jmgd <in> <out> <password> [--use-master|--no-master]");
    }

    private static KfmArgs parseKfmArgs(
            String[] args, int startIndex) {
        KfmArgs parsed = new KfmArgs();
        List<String> positional = new ArrayList<String>();
        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];
            if ("--no-master".equalsIgnoreCase(arg)
                    || "--use-master".equalsIgnoreCase(arg)) {
                continue;
            }
            if ("--bw".equalsIgnoreCase(arg)) {
                parsed.bwMode = true;
                continue;
            }
            if ("-o".equalsIgnoreCase(arg)
                    || "--out".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException(
                            "Missing output value");
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

    private static JmgArgs parseJmgArgs(
            String[] args, int startIndex) {
        JmgArgs parsed = new JmgArgs();
        List<String> positional = new ArrayList<String>();
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
            if ("--no-master".equalsIgnoreCase(arg)
                    || "--use-master".equalsIgnoreCase(arg)) {
                continue;
            }
            if ("-p".equalsIgnoreCase(arg)
                    || "--password".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException(
                            "Missing password value");
                }
                parsed.password = args[++i];
                continue;
            }
            if ("-o".equalsIgnoreCase(arg)
                    || "--out".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException(
                            "Missing output value");
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
                    throw new IllegalArgumentException(
                            "Too many arguments for jMG command");
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
                throw new IllegalArgumentException(
                        "Too many arguments for jMG command");
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
}
