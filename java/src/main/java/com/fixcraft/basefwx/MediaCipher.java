/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.io.File;
import java.util.Locale;

public final class MediaCipher {
    private MediaCipher() {}

    private static final String ENABLE_JMG_VIDEO_ENV = "BASEFWX_ENABLE_JMG_VIDEO";

    static boolean isJmgVideoEnabled() {
        String raw = System.getenv(ENABLE_JMG_VIDEO_ENV);
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase(Locale.US);
        return "1".equals(value) || "true".equals(value) || "yes".equals(value) || "on".equals(value);
    }

    public static String selectedHwaccelForCli() {
        String hw = FfmpegRunner.selectHwaccel();
        return hw == null ? "cpu" : hw;
    }

    public static int mediaWorkersForCli() {
        return FfmpegRunner.mediaWorkers();
    }

    public static File encryptMedia(File input,
                                    File output,
                                    String password,
                                    boolean keepMeta,
                                    boolean keepInput,
                                    boolean useMaster) {
        return encryptMedia(input, output, password, keepMeta, keepInput, useMaster, true);
    }

    public static File encryptMedia(File input,
                                    File output,
                                    String password,
                                    boolean keepMeta,
                                    boolean keepInput,
                                    boolean useMaster,
                                    boolean archiveOriginal) {
        return MediaCipherEngine.encryptMedia(
            input, output, password, keepMeta, keepInput, useMaster, archiveOriginal
        );
    }

    public static File decryptMedia(File input,
                                    File output,
                                    String password,
                                    boolean useMaster) {
        return MediaCipherEngine.decryptMedia(input, output, password, useMaster);
    }
}
