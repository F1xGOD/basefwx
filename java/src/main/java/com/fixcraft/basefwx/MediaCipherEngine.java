/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.File;
import java.util.Set;

final class MediaCipherEngine {
    private MediaCipherEngine() {}

    static final long TRAILER_FALLBACK_MAX = 64L * 1024 * 1024;
    static final Set<String> IMAGE_EXTS = MediaCipherUtil.buildSet(
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp",
        ".tif", ".tiff", ".heic", ".heif", ".avif", ".ico"
    );
    @SuppressWarnings("unused")
    static final Set<String> VIDEO_EXTS = MediaCipherUtil.buildSet(
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".flv", ".wmv",
        ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".m2ts"
    );
    @SuppressWarnings("unused")
    static final Set<String> AUDIO_EXTS = MediaCipherUtil.buildSet(
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".alac"
    );

    static File encryptMedia(File input,
                             File output,
                             String password,
                             boolean keepMeta,
                             boolean keepInput,
                             boolean useMaster,
                             boolean archiveOriginal) {
        MediaCipherUtil.ensureExists(input);
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        File outputPath = output != null ? output : input;
        File tempOutput = outputPath;
        if (MediaCipherUtil.samePath(input, outputPath)) {
            tempOutput = MediaCipherUtil.withMarker(outputPath, "._jmg");
        }
        String ext = MediaCipherUtil.extensionLower(input);
        boolean appendArchiveTrailer = false;
        boolean appendKeyTrailer = false;
        byte[] archiveKey = null;
        byte[] trailerHeader = new byte[0];
        int trailerProfile = Constants.JMG_SECURITY_PROFILE_LEGACY;
        File result;
        if (IMAGE_EXTS.contains(ext)) {
            result = MediaImageCipher.encryptImage(input, tempOutput, pw, useMaster, true, archiveOriginal);
        } else {
            MediaProbe.MediaInfo info;
            try {
                info = MediaProbe.probeStreams(input);
            } catch (RuntimeException exc) {
                info = new MediaProbe.MediaInfo();
            }
            if (info.video != null && !MediaCipher.isJmgVideoEnabled()) {
                throw videoDisabled();
            }
            if (info.video != null) {
                MediaTrailerCodec.JmgKeys keys = MediaTrailerCodec.prepareJmgKeys(pw, useMaster);
                FfmpegRunner.scrambleVideo(input, tempOutput, password, keepMeta, keys.baseKey, keys.profileId, info);
                archiveKey = keys.archiveKey;
                trailerHeader = keys.header;
                trailerProfile = keys.profileId;
                appendArchiveTrailer = archiveOriginal;
                appendKeyTrailer = !archiveOriginal;
                result = tempOutput;
            } else if (info.audio != null) {
                MediaTrailerCodec.JmgKeys keys = MediaTrailerCodec.prepareJmgKeys(pw, useMaster);
                FfmpegRunner.scrambleAudio(input, tempOutput, password, keepMeta, keys.baseKey, keys.profileId, info);
                archiveKey = keys.archiveKey;
                trailerHeader = keys.header;
                trailerProfile = keys.profileId;
                appendArchiveTrailer = archiveOriginal;
                appendKeyTrailer = !archiveOriginal;
                result = tempOutput;
            } else {
                File fallback = output != null ? output : new File(input.getParentFile(), input.getName() + ".fwx");
                BaseFwx.fwxAesEncryptFile(input, fallback, password, useMaster);
                return fallback;
            }
        }

        if (appendArchiveTrailer) {
            MediaTrailerCodec.appendTrailerStream(
                result,
                pw,
                useMaster,
                input,
                archiveKey,
                trailerHeader,
                MediaTrailerCodec.jmgArchiveInfoForProfile(trailerProfile)
            );
        } else if (appendKeyTrailer) {
            MediaTrailerCodec.appendKeyTrailer(result, trailerHeader);
        }

        if (!MediaCipherUtil.samePath(result, outputPath)) {
            MediaCipherUtil.moveReplace(result, outputPath);
            result = outputPath;
        }
        if (!keepInput && !MediaCipherUtil.samePath(input, result)) {
            input.delete();
        }
        return result;
    }

    static File decryptMedia(File input,
                             File output,
                             String password,
                             boolean useMaster) {
        MediaCipherUtil.ensureExists(input);
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        File outputPath = output != null ? output : input;
        File tempOutput = outputPath;
        if (MediaCipherUtil.samePath(input, outputPath)) {
            tempOutput = MediaCipherUtil.withMarker(outputPath, "._jmgdec");
        }

        String ext = MediaCipherUtil.extensionLower(input);
        File result = null;
        if (IMAGE_EXTS.contains(ext)) {
            result = MediaImageCipher.decryptImage(input, tempOutput, pw, useMaster);
        } else {
            try {
                MediaProbe.MediaInfo gateInfo = MediaProbe.probeStreams(input);
                if (gateInfo.video != null && !MediaCipher.isJmgVideoEnabled()) {
                    throw videoDisabled();
                }
            } catch (RuntimeException exc) {
                String msg = exc.getMessage();
                if (msg != null && msg.contains("jMG video mode is temporarily disabled")) {
                    throw exc;
                }
            }
            if (MediaTrailerCodec.decryptTrailerStream(input, pw, useMaster, tempOutput)) {
                result = tempOutput;
            } else {
                if (input.length() <= TRAILER_FALLBACK_MAX) {
                    byte[] data = MediaCipherUtil.readFileBytes(input);
                    byte[] plain = MediaTrailerCodec.decryptTrailer(data, pw, useMaster);
                    if (plain != null) {
                        MediaCipherUtil.writeFileBytes(tempOutput, plain);
                        result = tempOutput;
                    }
                }
                if (result == null) {
                    MediaProbe.MediaInfo info;
                    try {
                        info = MediaProbe.probeStreams(input);
                    } catch (RuntimeException exc) {
                        info = new MediaProbe.MediaInfo();
                    }
                    if (info.video != null && !MediaCipher.isJmgVideoEnabled()) {
                        throw videoDisabled();
                    }
                    int[] trailerProfileHolder = new int[] {Constants.JMG_SECURITY_PROFILE_LEGACY};
                    byte[] baseKeyFromTrailer = MediaTrailerCodec.loadBaseKeyFromKeyTrailer(
                        input, pw, useMaster, trailerProfileHolder
                    );
                    if (baseKeyFromTrailer == null && input.length() <= TRAILER_FALLBACK_MAX) {
                        baseKeyFromTrailer = MediaTrailerCodec.loadBaseKeyFromKeyTrailerBytes(
                            MediaCipherUtil.readFileBytes(input), pw, useMaster, trailerProfileHolder
                        );
                    }
                    if (baseKeyFromTrailer != null) {
                        MediaTrailerCodec.warnNoArchivePayload();
                    }
                    if (info.video != null) {
                        FfmpegRunner.unscrambleVideo(
                            input, tempOutput, password, info, baseKeyFromTrailer, trailerProfileHolder[0]
                        );
                        result = tempOutput;
                    } else if (info.audio != null) {
                        FfmpegRunner.unscrambleAudio(
                            input, tempOutput, password, info, baseKeyFromTrailer, trailerProfileHolder[0]
                        );
                        result = tempOutput;
                    } else if (MediaCipherUtil.looksLikeFwx(input)) {
                        File fallbackOut = output != null ? output : MediaCipherUtil.stripFwxSuffix(input);
                        BaseFwx.fwxAesDecryptFile(input, fallbackOut, password, useMaster);
                        return fallbackOut;
                    } else {
                        throw new IllegalArgumentException("Unsupported media format");
                    }
                }
            }
        }

        if (!MediaCipherUtil.samePath(result, outputPath)) {
            MediaCipherUtil.moveReplace(result, outputPath);
            result = outputPath;
        }
        return result;
    }

    private static RuntimeException videoDisabled() {
        return new RuntimeException(
            "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable."
        );
    }
}
