/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwxImage;

import java.io.File;

final class MediaCommands {
    private MediaCommands() {}

    /** @return 0 handled, 1 usage, -1 not handled */
    static int handle(String command, String[] args, int argc, boolean useMaster) {
        switch (command) {
            case "kFMe": {
                CliOptions.KfmArgs opts = CliOptions.parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFMe(opts.input, opts.output, opts.bwMode);
                System.out.println(out.getPath());
                return 0;
            }
            case "kFMd": {
                CliOptions.KfmArgs opts = CliOptions.parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFMd(opts.input, opts.output, opts.bwMode);
                System.out.println(out.getPath());
                return 0;
            }
            case "kFAe": {
                CliOptions.KfmArgs opts = CliOptions.parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFAe(opts.input, opts.output, opts.bwMode);
                System.out.println(out.getPath());
                return 0;
            }
            case "kFAd": {
                CliOptions.KfmArgs opts = CliOptions.parseKfmArgs(args, 1);
                File out = BaseFwxImage.kFAd(opts.input, opts.output);
                System.out.println(out.getPath());
                return 0;
            }
            case "jmge": {
                CliOptions.JmgArgs opts = CliOptions.parseJmgArgs(args, 1);
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
                CliOptions.JmgArgs opts = CliOptions.parseJmgArgs(args, 1);
                BaseFwxImage.jmgDecryptFile(opts.input, opts.output, opts.password, useMaster);
                return 0;
            }
            default:
                return -1;
        }
    }
}
