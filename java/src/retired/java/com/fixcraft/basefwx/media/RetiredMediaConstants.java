/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.media;

import java.nio.charset.StandardCharsets;

/** Wire constants exposed only by the retired-media compatibility artifact. */
public abstract class RetiredMediaConstants {
    protected RetiredMediaConstants() {}

    public static final byte[] MASK_AAD_JMG = "jmg".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_STREAM_INFO =
            "basefwx.imagecipher.stream.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_ARCHIVE_INFO =
            "basefwx.imagecipher.archive.v1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_TRAILER_MAGIC =
            "JMG0".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] IMAGECIPHER_KEY_TRAILER_MAGIC =
            "JMG1".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] JMG_KEY_MAGIC = "JMGK".getBytes(StandardCharsets.US_ASCII);
    public static final int JMG_KEY_VERSION_LEGACY = 1;
    public static final int JMG_KEY_VERSION = 2;
    public static final int JMG_SECURITY_PROFILE_LEGACY = 0;
    public static final int JMG_SECURITY_PROFILE_MAX = 1;
    public static final int JMG_SECURITY_PROFILE_DEFAULT = JMG_SECURITY_PROFILE_MAX;
    public static final byte[] JMG_MASK_INFO =
            "basefwx.jmg.mask.v1".getBytes(StandardCharsets.US_ASCII);
}
