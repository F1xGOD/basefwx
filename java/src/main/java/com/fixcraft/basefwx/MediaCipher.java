package com.fixcraft.basefwx;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class MediaCipher {
    private MediaCipher() {}

    private static final double VIDEO_GROUP_SECONDS = 1.0;
    private static final int VIDEO_GROUP_MAX_FRAMES = 12;
    private static final int VIDEO_BLOCK_SIZE = 2;
    private static final int VIDEO_MASK_BITS = 6;
    private static final int VIDEO_MASK_BITS_MAX = 8;
    private static final double AUDIO_BLOCK_SECONDS = 0.15;
    private static final double AUDIO_GROUP_SECONDS = 1.0;
    private static final int AUDIO_MASK_BITS = 13;
    private static final int AUDIO_MASK_BITS_MAX = 16;
    private static final double JMG_TARGET_GROWTH = 1.1;
    private static final double JMG_MAX_GROWTH = 2.0;
    private static final long JMG_MIN_AUDIO_BPS = 64_000;
    private static final long JMG_MIN_VIDEO_BPS = 200_000;
    private static final long TRAILER_FALLBACK_MAX = 64L * 1024 * 1024;

    private static final String HWACCEL_ENV = "BASEFWX_HWACCEL";
    private static final String VAAPI_DEVICE_ENV = "BASEFWX_VAAPI_DEVICE";
    private static final String MEDIA_WORKERS_ENV = "BASEFWX_MEDIA_WORKERS";
    private static final String ENABLE_JMG_VIDEO_ENV = "BASEFWX_ENABLE_JMG_VIDEO";

    private static final Set<String> IMAGE_EXTS = buildSet(
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp",
        ".tif", ".tiff", ".heic", ".heif", ".avif", ".ico"
    );
    @SuppressWarnings("unused")  // Reserved for future API use
    private static final Set<String> VIDEO_EXTS = buildSet(
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".flv", ".wmv",
        ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".m2ts"
    );
    @SuppressWarnings("unused")  // Reserved for future API use
    private static final Set<String> AUDIO_EXTS = buildSet(
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".alac"
    );

    private static volatile String hwaccelCache = null;
    private static volatile boolean hwaccelReady = false;
    private static volatile Set<String> encoderCache = null;

    private static boolean truthyEnv(String name) {
        String raw = System.getenv(name);
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase(Locale.US);
        return "1".equals(value) || "true".equals(value) || "yes".equals(value) || "on".equals(value);
    }

    static boolean isJmgVideoEnabled() {
        return truthyEnv(ENABLE_JMG_VIDEO_ENV);
    }

    public static String selectedHwaccelForCli() {
        String hw = selectHwaccel();
        return hw == null ? "cpu" : hw;
    }

    public static int mediaWorkersForCli() {
        return mediaWorkers();
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
        ensureExists(input);
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        File outputPath = output != null ? output : input;
        File tempOutput = outputPath;
        if (samePath(input, outputPath)) {
            tempOutput = withMarker(outputPath, "._jmg");
        }
        String ext = extensionLower(input);
        boolean appendArchiveTrailer = false;
        boolean appendKeyTrailer = false;
        byte[] archiveKey = null;
        byte[] trailerHeader = new byte[0];
        int trailerProfile = Constants.JMG_SECURITY_PROFILE_LEGACY;
        File result;
        if (IMAGE_EXTS.contains(ext)) {
            result = encryptImage(input, tempOutput, pw, useMaster, true, archiveOriginal);
        } else {
            MediaInfo info;
            try {
                info = probeStreams(input);
            } catch (RuntimeException exc) {
                info = new MediaInfo();
            }
            if (info.video != null && !isJmgVideoEnabled()) {
                throw new RuntimeException(
                    "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable."
                );
            }
            if (info.video != null) {
                JmgKeys keys = prepareJmgKeys(pw, useMaster);
                scrambleVideo(input, tempOutput, password, keepMeta, keys.baseKey, keys.profileId, info);
                archiveKey = keys.archiveKey;
                trailerHeader = keys.header;
                trailerProfile = keys.profileId;
                appendArchiveTrailer = archiveOriginal;
                appendKeyTrailer = !archiveOriginal;
                result = tempOutput;
            } else if (info.audio != null) {
                JmgKeys keys = prepareJmgKeys(pw, useMaster);
                scrambleAudio(input, tempOutput, password, keepMeta, keys.baseKey, keys.profileId, info);
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
            appendTrailerStream(
                result,
                pw,
                useMaster,
                input,
                archiveKey,
                trailerHeader,
                jmgArchiveInfoForProfile(trailerProfile)
            );
        } else if (appendKeyTrailer) {
            appendKeyTrailer(result, trailerHeader);
        }

        if (!samePath(result, outputPath)) {
            moveReplace(result, outputPath);
            result = outputPath;
        }
        if (!keepInput && !samePath(input, result)) {
            input.delete();
        }
        return result;
    }

    public static File decryptMedia(File input,
                                    File output,
                                    String password,
                                    boolean useMaster) {
        ensureExists(input);
        byte[] pw = BaseFwx.resolvePasswordBytes(password, useMaster);
        File outputPath = output != null ? output : input;
        File tempOutput = outputPath;
        if (samePath(input, outputPath)) {
            tempOutput = withMarker(outputPath, "._jmgdec");
        }

        String ext = extensionLower(input);
        File result = null;
        if (IMAGE_EXTS.contains(ext)) {
            result = decryptImage(input, tempOutput, pw, useMaster);
        } else {
            try {
                MediaInfo gateInfo = probeStreams(input);
                if (gateInfo.video != null && !isJmgVideoEnabled()) {
                    throw new RuntimeException(
                        "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable."
                    );
                }
            } catch (RuntimeException exc) {
                String msg = exc.getMessage();
                if (msg != null && msg.contains("jMG video mode is temporarily disabled")) {
                    throw exc;
                }
            }
            if (decryptTrailerStream(input, pw, useMaster, tempOutput)) {
                result = tempOutput;
            } else {
                if (input.length() <= TRAILER_FALLBACK_MAX) {
                    byte[] data = readFileBytes(input);
                    byte[] plain = decryptTrailer(data, pw, useMaster);
                    if (plain != null) {
                        writeFileBytes(tempOutput, plain);
                        result = tempOutput;
                    }
                }
                if (result == null) {
                    MediaInfo info;
                    try {
                        info = probeStreams(input);
                    } catch (RuntimeException exc) {
                        info = new MediaInfo();
                    }
                    if (info.video != null && !isJmgVideoEnabled()) {
                        throw new RuntimeException(
                            "jMG video mode is temporarily disabled. Use fwxAES for video, or set BASEFWX_ENABLE_JMG_VIDEO=1 to re-enable."
                        );
                    }
                    int[] trailerProfileHolder = new int[] {Constants.JMG_SECURITY_PROFILE_LEGACY};
                    byte[] baseKeyFromTrailer = loadBaseKeyFromKeyTrailer(input, pw, useMaster, trailerProfileHolder);
                    if (baseKeyFromTrailer == null && input.length() <= TRAILER_FALLBACK_MAX) {
                        baseKeyFromTrailer = loadBaseKeyFromKeyTrailerBytes(
                            readFileBytes(input), pw, useMaster, trailerProfileHolder
                        );
                    }
                    if (baseKeyFromTrailer != null) {
                        warnNoArchivePayload();
                    }
                    if (info.video != null) {
                        unscrambleVideo(
                            input,
                            tempOutput,
                            password,
                            info,
                            baseKeyFromTrailer,
                            trailerProfileHolder[0]
                        );
                        result = tempOutput;
                    } else if (info.audio != null) {
                        unscrambleAudio(
                            input,
                            tempOutput,
                            password,
                            info,
                            baseKeyFromTrailer,
                            trailerProfileHolder[0]
                        );
                        result = tempOutput;
                    } else if (looksLikeFwx(input)) {
                        File fallbackOut = output != null ? output : stripFwxSuffix(input);
                        BaseFwx.fwxAesDecryptFile(input, fallbackOut, password, useMaster);
                        return fallbackOut;
                    } else {
                        throw new IllegalArgumentException("Unsupported media format");
                    }
                }
            }
        }

        if (!samePath(result, outputPath)) {
            moveReplace(result, outputPath);
            result = outputPath;
        }
        return result;
    }

    private static File encryptImage(File input,
                                     File output,
                                     byte[] password,
                                     boolean useMaster,
                                     boolean includeTrailer,
                                     boolean archiveOriginal) {
        if (!includeTrailer && password.length == 0) {
            throw new IllegalArgumentException("Password required for image encryption without trailer");
        }
        byte[] original = readFileBytes(input);
        String format = formatFromPath(input);
        ImageData data = loadImage(original, input);
        int numPixels = data.width * data.height;

        byte[] materialOverride = null;
        byte[] archiveKey = null;
        byte[] trailerHeader = new byte[0];
        int trailerProfile = Constants.JMG_SECURITY_PROFILE_LEGACY;
        if (includeTrailer) {
            JmgKeys keys = prepareJmgKeys(password, useMaster);
            materialOverride = keys.material;
            archiveKey = keys.archiveKey;
            trailerHeader = keys.header;
            trailerProfile = keys.profileId;
        }

        MaskState state = buildMaskState(password, numPixels, data.channels, materialOverride);
        byte[] flat = Arrays.copyOf(data.pixels, data.pixels.length);
        xorInPlace(flat, state.mask);
        applyRotations(flat, numPixels, data.channels, state.rotations, false);
        flat = applyPermutation(flat, numPixels, data.channels, state.perm);

        ImageData scrambled = new ImageData(data.width, data.height, data.channels, flat, format);
        writeImage(scrambled, output);

        if (includeTrailer) {
            if (archiveOriginal) {
                byte[] archiveBlob = Crypto.aesGcmEncrypt(
                    archiveKey,
                    original,
                    jmgArchiveInfoForProfile(trailerProfile)
                );
                byte[] trailerBlob = concat(trailerHeader, archiveBlob);
                appendBalancedTrailer(output, Constants.IMAGECIPHER_TRAILER_MAGIC, trailerBlob);
            } else {
                appendBalancedTrailer(output, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC, trailerHeader);
            }
        }
        return output;
    }

    private static File decryptImage(File input,
                                     File output,
                                     byte[] password,
                                     boolean useMaster) {
        byte[] fileBytes = readFileBytes(input);
        TrailerSplit split = splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_TRAILER_MAGIC);
        byte[] payload = split.payload;
        byte[] trailer = split.trailer;
        byte[] keyTrailer = null;
        if (trailer == null) {
            TrailerSplit keySplit = splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
            keyTrailer = keySplit.trailer;
            payload = keySplit.payload;
        }
        String format = formatFromPath(input);
        byte[] materialOverride = null;

        if (trailer != null) {
            byte[] archiveKey = null;
            int headerLen = 0;
            byte[] archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
            JmgHeader header = parseJmgHeader(trailer, password, useMaster);
            byte[] archiveBlob;
            if (header != null) {
                headerLen = header.headerLen;
                archiveKey = header.archiveKey;
                materialOverride = header.material;
                archiveInfo = jmgArchiveInfoForProfile(header.profileId);
                archiveBlob = Arrays.copyOfRange(trailer, headerLen, trailer.length);
            } else {
                byte[] material = deriveMediaMaterial(password);
                archiveKey = Crypto.hkdfSha256(material, Constants.IMAGECIPHER_ARCHIVE_INFO, 32);
                archiveBlob = trailer;
            }
            try {
                byte[] original = Crypto.aesGcmDecrypt(archiveKey, archiveBlob, archiveInfo);
                writeFileBytes(output, original);
                return output;
            } catch (RuntimeException exc) {
                // Fall through to deterministic decode.
            }
        }

        if (keyTrailer != null) {
            JmgHeader header = parseJmgHeader(keyTrailer, password, useMaster);
            if (header == null) {
                throw new IllegalArgumentException("Invalid JMG key trailer");
            }
            if (header.headerLen != keyTrailer.length) {
                throw new IllegalArgumentException("Invalid JMG key trailer payload");
            }
            materialOverride = header.material;
            warnNoArchivePayload();
        }

        ImageData data = loadImage(payload, input);
        int numPixels = data.width * data.height;
        MaskState state = buildMaskState(password, numPixels, data.channels, materialOverride);

        byte[] flat = Arrays.copyOf(data.pixels, data.pixels.length);
        flat = applyInversePermutation(flat, numPixels, data.channels, state.perm);
        applyRotations(flat, numPixels, data.channels, state.rotations, true);
        xorInPlace(flat, state.mask);

        ImageData restored = new ImageData(data.width, data.height, data.channels, flat, format);
        writeImage(restored, output);
        return output;
    }

    private static void scrambleVideo(File input,
                                      File output,
                                      String password,
                                      boolean keepMeta,
                                      byte[] baseKey,
                                      int securityProfile,
                                      MediaInfo info) {
        if (info.video == null) {
            throw new IllegalArgumentException("No video stream found");
        }
        int width = info.video.width;
        int height = info.video.height;
        double fps = info.video.fps;
        long[] bps = estimateBitrates(input, info);
        long videoBps = bps[0];
        long audioBps = bps[1];

        File tempDir = createTempDir();
        File rawVideo = new File(tempDir, "video.raw");
        File rawVideoOut = new File(tempDir, "video.scr.raw");
        File rawAudio = null;
        File rawAudioOut = null;
        int sampleRate = 0;
        int channels = 0;
        try {
            ensureParent(output);
            List<String> cmdVideo = ffmpegBaseCommand();
            cmdVideo.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:v:0", "-f", "rawvideo",
                "-pix_fmt", "rgb24", rawVideo.getPath()));
            runFfmpeg(cmdVideo, null);

            if (info.audio != null) {
                rawAudio = new File(tempDir, "audio.raw");
                rawAudioOut = new File(tempDir, "audio.scr.raw");
                sampleRate = info.audio.sampleRate > 0 ? info.audio.sampleRate : 48000;
                channels = info.audio.channels > 0 ? info.audio.channels : 2;
                List<String> cmdAudio = ffmpegBaseCommand();
                cmdAudio.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:a:0", "-f", "s16le",
                    "-acodec", "pcm_s16le", "-ar", String.valueOf(sampleRate), "-ac", String.valueOf(channels),
                    rawAudio.getPath()));
                runFfmpeg(cmdAudio, null);
            }

            scrambleVideoRaw(rawVideo, rawVideoOut, width, height, fps, baseKey, securityProfile);
            if (rawAudio != null && rawAudioOut != null) {
                scrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);
            }

            List<String> cmdBase = ffmpegBaseCommand();
            cmdBase.addAll(Arrays.asList("-f", "rawvideo", "-pix_fmt", "rgb24", "-s",
                width + "x" + height, "-r", String.format(Locale.US, "%.6f", fps > 0 ? fps : 30.0),
                "-i", rawVideoOut.getPath()));
            if (rawAudioOut != null) {
                cmdBase.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                    String.valueOf(channels), "-i", rawAudioOut.getPath(), "-shortest"));
            }
            if (keepMeta) {
                Map<String, String> tags = probeMetadata(input);
                for (String meta : encryptMetadata(tags, password)) {
                    cmdBase.addAll(Arrays.asList("-metadata", meta));
                }
            } else {
                cmdBase.addAll(Arrays.asList("-map_metadata", "-1"));
            }

            String hwaccel = selectHwaccel();
            List<String> videoArgs = ffmpegVideoCodecArgs(output, videoBps, hwaccel);
            List<String> cpuVideoArgs = ffmpegVideoCodecArgs(output, videoBps, null);
            List<String> cmd = new ArrayList<>(cmdBase);
            cmd.addAll(videoArgs);
            if (rawAudioOut != null) {
                cmd.addAll(ffmpegAudioCodecArgs(output, audioBps));
            }
            cmd.addAll(ffmpegContainerArgs(output));
            cmd.add(output.getPath());
            if (hwaccel != null && !videoArgs.equals(cpuVideoArgs)) {
                List<String> fallback = new ArrayList<>(cmdBase);
                fallback.addAll(cpuVideoArgs);
                if (rawAudioOut != null) {
                    fallback.addAll(ffmpegAudioCodecArgs(output, audioBps));
                }
                fallback.addAll(ffmpegContainerArgs(output));
                fallback.add(output.getPath());
                runFfmpeg(cmd, fallback);
            } else {
                runFfmpeg(cmd, null);
            }
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void scrambleAudio(File input,
                                      File output,
                                      String password,
                                      boolean keepMeta,
                                      byte[] baseKey,
                                      int securityProfile,
                                      MediaInfo info) {
        if (info.audio == null) {
            throw new IllegalArgumentException("No audio stream found");
        }
        int sampleRate = info.audio.sampleRate > 0 ? info.audio.sampleRate : 48000;
        int channels = info.audio.channels > 0 ? info.audio.channels : 2;
        long[] bps = estimateBitrates(input, info);
        long audioBps = bps[1];

        File tempDir = createTempDir();
        File rawAudio = new File(tempDir, "audio.raw");
        File rawAudioOut = new File(tempDir, "audio.scr.raw");
        try {
            ensureParent(output);
            List<String> cmdAudio = ffmpegBaseCommand();
            cmdAudio.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:a:0", "-f", "s16le",
                "-acodec", "pcm_s16le", "-ar", String.valueOf(sampleRate), "-ac", String.valueOf(channels),
                rawAudio.getPath()));
            runFfmpeg(cmdAudio, null);

            scrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);

            List<String> cmd = ffmpegBaseCommand();
            cmd.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                String.valueOf(channels), "-i", rawAudioOut.getPath()));
            if (keepMeta) {
                Map<String, String> tags = probeMetadata(input);
                for (String meta : encryptMetadata(tags, password)) {
                    cmd.addAll(Arrays.asList("-metadata", meta));
                }
            } else {
                cmd.addAll(Arrays.asList("-map_metadata", "-1"));
            }
            cmd.addAll(ffmpegAudioCodecArgs(output, audioBps));
            cmd.addAll(ffmpegContainerArgs(output));
            cmd.add(output.getPath());
            runFfmpeg(cmd, null);
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void unscrambleVideo(File input,
                                        File output,
                                        String password,
                                        MediaInfo info,
                                        byte[] baseKeyOverride,
                                        int securityProfile) {
        if (info.video == null) {
            throw new IllegalArgumentException("No video stream found");
        }
        int width = info.video.width;
        int height = info.video.height;
        double fps = info.video.fps;
        long[] bps = estimateBitrates(input, info);
        long videoBps = bps[0];
        long audioBps = bps[1];
        int sampleRate = 0;
        int channels = 0;

        File tempDir = createTempDir();
        File rawVideo = new File(tempDir, "video.raw");
        File rawVideoOut = new File(tempDir, "video.unscr.raw");
        File rawAudio = null;
        File rawAudioOut = null;
        try {
            ensureParent(output);
            List<String> cmdVideo = ffmpegBaseCommand();
            cmdVideo.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:v:0", "-f", "rawvideo",
                "-pix_fmt", "rgb24", rawVideo.getPath()));
            runFfmpeg(cmdVideo, null);

            if (info.audio != null) {
                rawAudio = new File(tempDir, "audio.raw");
                rawAudioOut = new File(tempDir, "audio.unscr.raw");
                sampleRate = info.audio.sampleRate > 0 ? info.audio.sampleRate : 48000;
                channels = info.audio.channels > 0 ? info.audio.channels : 2;
                List<String> cmdAudio = ffmpegBaseCommand();
                cmdAudio.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:a:0", "-f", "s16le",
                    "-acodec", "pcm_s16le", "-ar", String.valueOf(sampleRate), "-ac",
                    String.valueOf(channels), rawAudio.getPath()));
                runFfmpeg(cmdAudio, null);
            }

            byte[] baseKey = baseKeyOverride != null ? Arrays.copyOf(baseKeyOverride, baseKeyOverride.length) : deriveBaseKey(password);
            unscrambleVideoRaw(rawVideo, rawVideoOut, width, height, fps, baseKey, securityProfile);
            if (rawAudio != null && rawAudioOut != null) {
                unscrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);
            }

            List<String> cmdBase = ffmpegBaseCommand();
            cmdBase.addAll(Arrays.asList("-f", "rawvideo", "-pix_fmt", "rgb24", "-s",
                width + "x" + height, "-r", String.format(Locale.US, "%.6f", fps > 0 ? fps : 30.0),
                "-i", rawVideoOut.getPath()));
            if (rawAudioOut != null) {
                cmdBase.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                    String.valueOf(channels), "-i", rawAudioOut.getPath(), "-shortest"));
            }
            Map<String, String> tags = probeMetadata(input);
            List<String> decoded = decryptMetadata(tags, password);
            if (!decoded.isEmpty()) {
                for (String meta : decoded) {
                    cmdBase.addAll(Arrays.asList("-metadata", meta));
                }
            } else {
                cmdBase.addAll(Arrays.asList("-map_metadata", "-1"));
            }
            String hwaccel = selectHwaccel();
            List<String> videoArgs = ffmpegVideoCodecArgs(output, videoBps, hwaccel);
            List<String> cpuVideoArgs = ffmpegVideoCodecArgs(output, videoBps, null);
            List<String> cmd = new ArrayList<>(cmdBase);
            cmd.addAll(videoArgs);
            if (rawAudioOut != null) {
                cmd.addAll(ffmpegAudioCodecArgs(output, audioBps));
            }
            cmd.addAll(ffmpegContainerArgs(output));
            cmd.add(output.getPath());
            if (hwaccel != null && !videoArgs.equals(cpuVideoArgs)) {
                List<String> fallback = new ArrayList<>(cmdBase);
                fallback.addAll(cpuVideoArgs);
                if (rawAudioOut != null) {
                    fallback.addAll(ffmpegAudioCodecArgs(output, audioBps));
                }
                fallback.addAll(ffmpegContainerArgs(output));
                fallback.add(output.getPath());
                runFfmpeg(cmd, fallback);
            } else {
                runFfmpeg(cmd, null);
            }
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void unscrambleAudio(File input,
                                        File output,
                                        String password,
                                        MediaInfo info,
                                        byte[] baseKeyOverride,
                                        int securityProfile) {
        if (info.audio == null) {
            throw new IllegalArgumentException("No audio stream found");
        }
        int sampleRate = info.audio.sampleRate > 0 ? info.audio.sampleRate : 48000;
        int channels = info.audio.channels > 0 ? info.audio.channels : 2;
        long[] bps = estimateBitrates(input, info);
        long audioBps = bps[1];

        File tempDir = createTempDir();
        File rawAudio = new File(tempDir, "audio.raw");
        File rawAudioOut = new File(tempDir, "audio.unscr.raw");
        try {
            ensureParent(output);
            List<String> cmdAudio = ffmpegBaseCommand();
            cmdAudio.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:a:0", "-f", "s16le",
                "-acodec", "pcm_s16le", "-ar", String.valueOf(sampleRate), "-ac",
                String.valueOf(channels), rawAudio.getPath()));
            runFfmpeg(cmdAudio, null);

            byte[] baseKey = baseKeyOverride != null ? Arrays.copyOf(baseKeyOverride, baseKeyOverride.length) : deriveBaseKey(password);
            unscrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);

            List<String> cmd = ffmpegBaseCommand();
            cmd.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                String.valueOf(channels), "-i", rawAudioOut.getPath()));
            Map<String, String> tags = probeMetadata(input);
            List<String> decoded = decryptMetadata(tags, password);
            if (!decoded.isEmpty()) {
                for (String meta : decoded) {
                    cmd.addAll(Arrays.asList("-metadata", meta));
                }
            } else {
                cmd.addAll(Arrays.asList("-map_metadata", "-1"));
            }
            cmd.addAll(ffmpegAudioCodecArgs(output, audioBps));
            cmd.addAll(ffmpegContainerArgs(output));
            cmd.add(output.getPath());
            runFfmpeg(cmd, null);
        } finally {
            deleteRecursive(tempDir);
        }
    }

    private static void scrambleVideoRaw(File input,
                                         File output,
                                         int width,
                                         int height,
                                         double fps,
                                         byte[] baseKey,
                                         int securityProfile) {
        int frameSize = width * height * 3;
        if (frameSize <= 0) {
            throw new IllegalArgumentException("Invalid video dimensions");
        }
        int groupFrames = Math.max(2, (int) Math.round((fps > 0.0 ? fps : 30.0) * VIDEO_GROUP_SECONDS));
        groupFrames = Math.min(groupFrames, VIDEO_GROUP_MAX_FRAMES);
        final String frameLabel = jmgProfileLabel("jmg-frame", securityProfile);
        final String frameBlockLabel = jmgProfileLabel("jmg-fblk", securityProfile);
        final String frameGroupLabel = jmgProfileLabel("jmg-fgrp", securityProfile);
        final int videoMaskBits = jmgVideoMaskBits(securityProfile);

        int workers = mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupFrames)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), frameSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), frameSize)) {
            long frameIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> frames = new ArrayList<>(groupFrames);
                for (int i = 0; i < groupFrames; i++) {
                    byte[] frame = new byte[frameSize];
                    int read = readFully(in, frame, frameSize);
                    if (read < frameSize) {
                        break;
                    }
                    frames.add(frame);
                    frameIndex++;
                }
                if (frames.isEmpty()) {
                    break;
                }

                long groupStart = frameIndex - frames.size();
                byte[][] processed = new byte[frames.size()][];
                processParallel(pool, frames.size(), idx -> {
                    long frameId = groupStart + idx;
                    byte[] material = unitMaterial(baseKey, frameLabel, frameId, 48);
                    byte[] key = Arrays.copyOfRange(material, 0, 32);
                    byte[] iv = Arrays.copyOfRange(material, 32, 48);
                    byte[] masked = videoMaskTransform(frames.get(idx), key, iv, videoMaskBits);
                    byte[] seedBytes = unitMaterial(baseKey, frameBlockLabel, frameId, 16);
                    long seed = bytesToSeed(seedBytes);
                    processed[idx] = shuffleFrameBlocks(masked, width, height, 3, seed, VIDEO_BLOCK_SIZE);
                });

                long seedIndex = (groupIndex * 0x9E3779B97F4A7C15L) ^ groupStart;
                byte[] seedBytes = unitMaterial(baseKey, frameGroupLabel, seedIndex, 16);
                long seed = bytesToSeed(seedBytes);
                int[] perm = permuteIndices(processed.length, seed);
                for (int idx : perm) {
                    out.write(processed[idx]);
                }
                groupIndex++;
            }
        } catch (IOException exc) {
            throw new IllegalStateException("Video scramble failed", exc);
        } finally {
            shutdownPool(pool);
        }
    }

    private static void unscrambleVideoRaw(File input,
                                           File output,
                                           int width,
                                           int height,
                                           double fps,
                                           byte[] baseKey,
                                           int securityProfile) {
        int frameSize = width * height * 3;
        if (frameSize <= 0) {
            throw new IllegalArgumentException("Invalid video dimensions");
        }
        int groupFrames = Math.max(2, (int) Math.round((fps > 0.0 ? fps : 30.0) * VIDEO_GROUP_SECONDS));
        groupFrames = Math.min(groupFrames, VIDEO_GROUP_MAX_FRAMES);
        final String frameLabel = jmgProfileLabel("jmg-frame", securityProfile);
        final String frameBlockLabel = jmgProfileLabel("jmg-fblk", securityProfile);
        final String frameGroupLabel = jmgProfileLabel("jmg-fgrp", securityProfile);
        final int videoMaskBits = jmgVideoMaskBits(securityProfile);

        int workers = mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupFrames)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), frameSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), frameSize)) {
            long frameIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> frames = new ArrayList<>(groupFrames);
                for (int i = 0; i < groupFrames; i++) {
                    byte[] frame = new byte[frameSize];
                    int read = readFully(in, frame, frameSize);
                    if (read < frameSize) {
                        break;
                    }
                    frames.add(frame);
                    frameIndex++;
                }
                if (frames.isEmpty()) {
                    break;
                }

                long groupStart = frameIndex - frames.size();
                long seedIndex = (groupIndex * 0x9E3779B97F4A7C15L) ^ groupStart;
                byte[] seedBytes = unitMaterial(baseKey, frameGroupLabel, seedIndex, 16);
                long seed = bytesToSeed(seedBytes);
                int[] perm = permuteIndices(frames.size(), seed);
                byte[][] ordered = new byte[frames.size()][];
                for (int dest = 0; dest < perm.length; dest++) {
                    int src = perm[dest];
                    ordered[src] = frames.get(dest);
                }

                byte[][] restored = new byte[ordered.length][];
                processParallel(pool, ordered.length, idx -> {
                    long frameId = groupStart + idx;
                    byte[] seedLocal = unitMaterial(baseKey, frameBlockLabel, frameId, 16);
                    long seedBlock = bytesToSeed(seedLocal);
                    byte[] unshuffled = unshuffleFrameBlocks(ordered[idx], width, height, 3, seedBlock, VIDEO_BLOCK_SIZE);
                    byte[] material = unitMaterial(baseKey, frameLabel, frameId, 48);
                    byte[] key = Arrays.copyOfRange(material, 0, 32);
                    byte[] iv = Arrays.copyOfRange(material, 32, 48);
                    restored[idx] = videoMaskTransform(unshuffled, key, iv, videoMaskBits);
                });
                for (byte[] frame : restored) {
                    out.write(frame);
                }
                groupIndex++;
            }
        } catch (IOException exc) {
            throw new IllegalStateException("Video unscramble failed", exc);
        } finally {
            shutdownPool(pool);
        }
    }

    private static void scrambleAudioRaw(File input,
                                         File output,
                                         int sampleRate,
                                         int channels,
                                         byte[] baseKey,
                                         int securityProfile) {
        if (sampleRate <= 0 || channels <= 0) {
            throw new IllegalArgumentException("Invalid audio stream parameters");
        }
        int samplesPerBlock = Math.max(1, (int) Math.round(sampleRate * AUDIO_BLOCK_SECONDS));
        int blockSize = samplesPerBlock * channels * 2;
        int groupBlocks = Math.max(2, (int) Math.round(AUDIO_GROUP_SECONDS / AUDIO_BLOCK_SECONDS));
        final String audioBlockLabel = jmgProfileLabel("jmg-ablock", securityProfile);
        final String audioSampleLabel = jmgProfileLabel("jmg-asamp", securityProfile);
        final String audioGroupLabel = jmgProfileLabel("jmg-agrp", securityProfile);
        final int audioMaskBits = jmgAudioMaskBits(securityProfile);

        int workers = mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupBlocks)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), blockSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), blockSize)) {
            long blockIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> blocks = new ArrayList<>(groupBlocks);
                for (int i = 0; i < groupBlocks; i++) {
                    byte[] block = new byte[blockSize];
                    int read = readFully(in, block, blockSize);
                    if (read <= 0) {
                        break;
                    }
                    if (read < blockSize) {
                        block = Arrays.copyOf(block, read);
                    }
                    blocks.add(block);
                    blockIndex++;
                }
                if (blocks.isEmpty()) {
                    break;
                }

                long groupStart = blockIndex - blocks.size();
                byte[][] processed = new byte[blocks.size()][];
                processParallel(pool, blocks.size(), idx -> {
                    long blockId = groupStart + idx;
                    byte[] material = unitMaterial(baseKey, audioBlockLabel, blockId, 48);
                    byte[] key = Arrays.copyOfRange(material, 0, 32);
                    byte[] iv = Arrays.copyOfRange(material, 32, 48);
                    byte[] masked = audioMaskTransform(blocks.get(idx), key, iv, audioMaskBits);
                    byte[] seedBytes = unitMaterial(baseKey, audioSampleLabel, blockId, 16);
                    long seed = bytesToSeed(seedBytes);
                    processed[idx] = shuffleAudioSamples(masked, seed);
                });

                long seedIndex = (groupIndex * 0x9E3779B97F4A7C15L) ^ groupStart;
                byte[] seedBytes = unitMaterial(baseKey, audioGroupLabel, seedIndex, 16);
                long seed = bytesToSeed(seedBytes);
                int[] perm = permuteIndices(processed.length, seed);
                for (int idx : perm) {
                    out.write(processed[idx]);
                }
                groupIndex++;
            }
        } catch (IOException exc) {
            throw new IllegalStateException("Audio scramble failed", exc);
        } finally {
            shutdownPool(pool);
        }
    }

    private static void unscrambleAudioRaw(File input,
                                           File output,
                                           int sampleRate,
                                           int channels,
                                           byte[] baseKey,
                                           int securityProfile) {
        if (sampleRate <= 0 || channels <= 0) {
            throw new IllegalArgumentException("Invalid audio stream parameters");
        }
        int samplesPerBlock = Math.max(1, (int) Math.round(sampleRate * AUDIO_BLOCK_SECONDS));
        int blockSize = samplesPerBlock * channels * 2;
        int groupBlocks = Math.max(2, (int) Math.round(AUDIO_GROUP_SECONDS / AUDIO_BLOCK_SECONDS));
        final String audioBlockLabel = jmgProfileLabel("jmg-ablock", securityProfile);
        final String audioSampleLabel = jmgProfileLabel("jmg-asamp", securityProfile);
        final String audioGroupLabel = jmgProfileLabel("jmg-agrp", securityProfile);
        final int audioMaskBits = jmgAudioMaskBits(securityProfile);

        int workers = mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupBlocks)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), blockSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), blockSize)) {
            long blockIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> blocks = new ArrayList<>(groupBlocks);
                for (int i = 0; i < groupBlocks; i++) {
                    byte[] block = new byte[blockSize];
                    int read = readFully(in, block, blockSize);
                    if (read <= 0) {
                        break;
                    }
                    if (read < blockSize) {
                        block = Arrays.copyOf(block, read);
                    }
                    blocks.add(block);
                    blockIndex++;
                }
                if (blocks.isEmpty()) {
                    break;
                }

                long groupStart = blockIndex - blocks.size();
                long seedIndex = (groupIndex * 0x9E3779B97F4A7C15L) ^ groupStart;
                byte[] seedBytes = unitMaterial(baseKey, audioGroupLabel, seedIndex, 16);
                long seed = bytesToSeed(seedBytes);
                int[] perm = permuteIndices(blocks.size(), seed);
                byte[][] ordered = new byte[blocks.size()][];
                for (int dest = 0; dest < perm.length; dest++) {
                    int src = perm[dest];
                    ordered[src] = blocks.get(dest);
                }

                byte[][] restored = new byte[ordered.length][];
                processParallel(pool, ordered.length, idx -> {
                    long blockId = groupStart + idx;
                    byte[] seedLocal = unitMaterial(baseKey, audioSampleLabel, blockId, 16);
                    long seedBlock = bytesToSeed(seedLocal);
                    byte[] unshuffled = unshuffleAudioSamples(ordered[idx], seedBlock);
                    byte[] material = unitMaterial(baseKey, audioBlockLabel, blockId, 48);
                    byte[] key = Arrays.copyOfRange(material, 0, 32);
                    byte[] iv = Arrays.copyOfRange(material, 32, 48);
                    restored[idx] = audioMaskTransform(unshuffled, key, iv, audioMaskBits);
                });
                for (byte[] block : restored) {
                    out.write(block);
                }
                groupIndex++;
            }
        } catch (IOException exc) {
            throw new IllegalStateException("Audio unscramble failed", exc);
        } finally {
            shutdownPool(pool);
        }
    }

    private static void appendTrailerStream(File output,
                                            byte[] password,
                                            boolean useMaster,
                                            File original,
                                            byte[] archiveKey,
                                            byte[] keyHeader,
                                            byte[] archiveInfo) {
        if (archiveInfo == null || archiveInfo.length == 0) {
            archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
        }
        if (archiveKey == null) {
            byte[] material = deriveMediaMaterial(password);
            archiveKey = Crypto.hkdfSha256(material, archiveInfo, 32);
        }
        long size = original.length();
        long blobLen = (long) keyHeader.length + Constants.AEAD_NONCE_LEN + size + Constants.AEAD_TAG_LEN;
        if (blobLen > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Trailer too large");
        }
        byte[] nonce = Crypto.randomBytes(Constants.AEAD_NONCE_LEN);
        byte[] lenBytes = writeU32((int) blobLen);
        try (FileInputStream in = new FileInputStream(original);
             BufferedInputStream bufIn = new BufferedInputStream(in, Constants.STREAM_CHUNK_SIZE);
             FileOutputStream out = new FileOutputStream(output, true);
             BufferedOutputStream bufOut = new BufferedOutputStream(out, Constants.STREAM_CHUNK_SIZE)) {
            bufOut.write(Constants.IMAGECIPHER_TRAILER_MAGIC);
            bufOut.write(lenBytes);
            if (keyHeader.length > 0) {
                bufOut.write(keyHeader);
            }
            bufOut.write(nonce);

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadEncryptor enc = backend.newGcmEncryptor(
                archiveKey, nonce, archiveInfo)) {
                byte[] inBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE + Constants.AEAD_TAG_LEN];
                int read;
                while ((read = bufIn.read(inBuf)) != -1) {
                    int outLen = enc.update(inBuf, 0, read, outBuf, 0);
                    if (outLen > 0) {
                        bufOut.write(outBuf, 0, outLen);
                    }
                }
                int finalLen = enc.doFinal(outBuf, 0);
                if (finalLen < Constants.AEAD_TAG_LEN) {
                    throw new IllegalStateException("AES-GCM final block too short");
                }
                int ctLen = finalLen - Constants.AEAD_TAG_LEN;
                if (ctLen > 0) {
                    bufOut.write(outBuf, 0, ctLen);
                }
                bufOut.write(outBuf, ctLen, Constants.AEAD_TAG_LEN);
            }
            bufOut.write(Constants.IMAGECIPHER_TRAILER_MAGIC);
            bufOut.write(lenBytes);
            bufOut.flush();
        } catch (IOException | RuntimeException | java.security.GeneralSecurityException exc) {
            throw new IllegalStateException("Failed to append trailer", exc);
        }
    }

    private static boolean decryptTrailerStream(File input,
                                                byte[] password,
                                                boolean useMaster,
                                                File output) {
        boolean headerSeen = false;
        try (RandomAccessFile raf = new RandomAccessFile(input, "r")) {
            byte[] magic = Constants.IMAGECIPHER_TRAILER_MAGIC;
            int footerLen = magic.length + 4;
            long size = raf.length();
            if (size < footerLen) {
                return false;
            }
            raf.seek(size - footerLen);
            byte[] footer = new byte[footerLen];
            raf.readFully(footer);
            if (!startsWith(footer, 0, magic)) {
                return false;
            }
            long blobLen = readU32(footer, magic.length);
            long trailerStart = size - footerLen - blobLen - footerLen;
            if (trailerStart < 0) {
                return false;
            }
            raf.seek(trailerStart);
            byte[] header = new byte[footerLen];
            raf.readFully(header);
            if (!startsWith(header, 0, magic)) {
                return false;
            }
            long headerLen = readU32(header, magic.length);
            if (headerLen != blobLen) {
                return false;
            }
            long blobStart = trailerStart + footerLen;
            raf.seek(blobStart);

            byte[] prefix = new byte[Constants.JMG_KEY_MAGIC.length];
            raf.readFully(prefix);

            byte[] archiveKey;
            byte[] archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
            long headerBytes = 0;
            byte[] nonce;
            long cipherBodyLen;
            if (Arrays.equals(prefix, Constants.JMG_KEY_MAGIC)) {
                headerSeen = true;
                int version = raf.read();
                if (version < 0) {
                    return false;
                }
                if (version != Constants.JMG_KEY_VERSION_LEGACY && version != Constants.JMG_KEY_VERSION) {
                    throw new IllegalArgumentException("Unsupported JMG key header version");
                }
                byte[] payloadLenBytes = new byte[4];
                raf.readFully(payloadLenBytes);
                long payloadLen = readU32(payloadLenBytes, 0);
                headerBytes = Constants.JMG_KEY_MAGIC.length + 1 + 4 + payloadLen;
                byte[] payload = new byte[(int) payloadLen];
                raf.readFully(payload);
                int profileId = Constants.JMG_SECURITY_PROFILE_LEGACY;
                byte[] keyPayload = payload;
                if (version == Constants.JMG_KEY_VERSION) {
                    if (payload.length < 1) {
                        throw new IllegalArgumentException("Truncated JMG key header profile");
                    }
                    profileId = normalizeJmgProfile(payload[0] & 0xFF);
                    keyPayload = Arrays.copyOfRange(payload, 1, payload.length);
                }
                List<byte[]> parts = Format.unpackLengthPrefixed(keyPayload, 2);
                byte[] maskKey = KeyWrap.recoverMaskKey(parts.get(0), parts.get(1), password, useMaster,
                    Constants.JMG_MASK_INFO, Constants.MASK_AAD_JMG, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
                archiveInfo = jmgArchiveInfoForProfile(profileId);
                archiveKey = Crypto.hkdfSha256(maskKey, archiveInfo, 32);
                nonce = new byte[Constants.AEAD_NONCE_LEN];
                raf.readFully(nonce);
                cipherBodyLen = blobLen - headerBytes - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            } else {
                archiveKey = Crypto.hkdfSha256(deriveMediaMaterial(password), Constants.IMAGECIPHER_ARCHIVE_INFO, 32);
                nonce = new byte[Constants.AEAD_NONCE_LEN];
                System.arraycopy(prefix, 0, nonce, 0, prefix.length);
                raf.readFully(nonce, prefix.length, Constants.AEAD_NONCE_LEN - prefix.length);
                cipherBodyLen = blobLen - Constants.AEAD_NONCE_LEN - Constants.AEAD_TAG_LEN;
            }
            if (cipherBodyLen < 0) {
                return false;
            }

            CryptoBackend backend = CryptoBackends.get();
            try (CryptoBackend.AeadDecryptor dec = backend.newGcmDecryptor(
                archiveKey, nonce, archiveInfo)) {
                try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output),
                    Constants.STREAM_CHUNK_SIZE)) {
                    byte[] inBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                    byte[] outBuf = new byte[Constants.STREAM_CHUNK_SIZE];
                    long remaining = cipherBodyLen;
                    while (remaining > 0) {
                        int toRead = (int) Math.min(inBuf.length, remaining);
                        int read = raf.read(inBuf, 0, toRead);
                        if (read <= 0) {
                            return false;
                        }
                        int outLen = dec.update(inBuf, 0, read, outBuf, 0);
                        if (outLen > 0) {
                            out.write(outBuf, 0, outLen);
                        }
                        remaining -= read;
                    }
                    byte[] tag = new byte[Constants.AEAD_TAG_LEN];
                    raf.readFully(tag);
                    int finalLen = dec.doFinal(tag, 0, tag.length, outBuf, 0);
                    if (finalLen > 0) {
                        out.write(outBuf, 0, finalLen);
                    }
                }
            }
            return true;
        } catch (Exception exc) {
            if (headerSeen) {
                throw new IllegalStateException("Failed to decrypt trailer", exc);
            }
            return false;
        }
    }

    private static byte[] decryptTrailer(byte[] fileBytes,
                                         byte[] password,
                                         boolean useMaster) {
        TrailerSplit split = splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_TRAILER_MAGIC);
        if (split.trailer == null) {
            return null;
        }
        byte[] trailer = split.trailer;
        JmgHeader header = parseJmgHeader(trailer, password, useMaster);
        byte[] archiveKey;
        byte[] archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
        byte[] archiveBlob;
        if (header != null) {
            archiveKey = header.archiveKey;
            archiveInfo = jmgArchiveInfoForProfile(header.profileId);
            archiveBlob = Arrays.copyOfRange(trailer, header.headerLen, trailer.length);
        } else {
            archiveKey = Crypto.hkdfSha256(deriveMediaMaterial(password), Constants.IMAGECIPHER_ARCHIVE_INFO, 32);
            archiveBlob = trailer;
        }
        try {
            return Crypto.aesGcmDecrypt(archiveKey, archiveBlob, archiveInfo);
        } catch (RuntimeException exc) {
            return null;
        }
    }

    private static TrailerSplit splitTrailer(byte[] data) {
        return splitTrailerForMagic(data, Constants.IMAGECIPHER_TRAILER_MAGIC);
    }

    private static TrailerSplit splitTrailerForMagic(byte[] data, byte[] magic) {
        int footerLen = magic.length + 4;
        byte[] payload = data;
        byte[] trailer = null;
        if (data.length >= footerLen) {
            int footerIdx = data.length - footerLen;
            if (startsWith(data, footerIdx, magic)) {
                long len = readU32(data, footerIdx + magic.length);
                long trailerStart = data.length - footerLen - len - footerLen;
                if (trailerStart >= 0) {
                    int headerPos = (int) trailerStart;
                    if (startsWith(data, headerPos, magic)
                        && readU32(data, headerPos + magic.length) == len) {
                        int blobStart = headerPos + footerLen;
                        int blobEnd = (int) (blobStart + len);
                        payload = Arrays.copyOfRange(data, 0, headerPos);
                        trailer = Arrays.copyOfRange(data, blobStart, blobEnd);
                    }
                }
            }
        }
        if (trailer == null) {
            int markerIdx = lastIndexOf(data, magic);
            if (markerIdx >= 0 && markerIdx + footerLen <= data.length) {
                long len = readU32(data, markerIdx + magic.length);
                int blobStart = markerIdx + footerLen;
                int blobEnd = (int) (blobStart + len);
                if (blobEnd == data.length) {
                    payload = Arrays.copyOfRange(data, 0, markerIdx);
                    trailer = Arrays.copyOfRange(data, blobStart, blobEnd);
                }
            }
        }
        return new TrailerSplit(payload, trailer);
    }

    private static void appendKeyTrailer(File output, byte[] keyHeader) {
        if (keyHeader == null || keyHeader.length == 0) {
            throw new IllegalArgumentException("Missing JMG key header for no-archive mode");
        }
        appendBalancedTrailer(output, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC, keyHeader);
    }

    private static byte[] loadBaseKeyFromKeyTrailer(File path,
                                                    byte[] password,
                                                    boolean useMaster,
                                                    int[] profileOut) {
        TrailerInfo info = extractBalancedTrailerInfo(path, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
        if (info == null) {
            return null;
        }
        byte[] blob = new byte[(int) info.blobLen];
        try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
            raf.seek(info.blobStart);
            raf.readFully(blob);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read JMG key trailer", exc);
        }
        JmgHeader header = parseJmgHeader(blob, password, useMaster);
        if (header == null) {
            throw new IllegalArgumentException("Invalid JMG key trailer");
        }
        if (header.headerLen != blob.length) {
            throw new IllegalArgumentException("Invalid JMG key trailer payload");
        }
        if (profileOut != null && profileOut.length > 0) {
            profileOut[0] = header.profileId;
        }
        return header.baseKey;
    }

    private static byte[] loadBaseKeyFromKeyTrailerBytes(byte[] fileBytes,
                                                         byte[] password,
                                                         boolean useMaster,
                                                         int[] profileOut) {
        TrailerSplit split = splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
        if (split.trailer == null) {
            return null;
        }
        JmgHeader header = parseJmgHeader(split.trailer, password, useMaster);
        if (header == null) {
            throw new IllegalArgumentException("Invalid JMG key trailer");
        }
        if (header.headerLen != split.trailer.length) {
            throw new IllegalArgumentException("Invalid JMG key trailer payload");
        }
        if (profileOut != null && profileOut.length > 0) {
            profileOut[0] = header.profileId;
        }
        return header.baseKey;
    }

    private static TrailerInfo extractBalancedTrailerInfo(File path, byte[] magic) {
        int footerLen = magic.length + 4;
        long size;
        try {
            size = path.length();
        } catch (Exception exc) {
            return null;
        }
        if (size < footerLen) {
            return null;
        }
        try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
            raf.seek(size - footerLen);
            byte[] footer = new byte[footerLen];
            raf.readFully(footer);
            if (!startsWith(footer, 0, magic)) {
                return null;
            }
            long blobLen = readU32(footer, magic.length);
            long trailerStart = size - footerLen - blobLen - footerLen;
            if (trailerStart < 0) {
                return null;
            }
            raf.seek(trailerStart);
            byte[] header = new byte[footerLen];
            raf.readFully(header);
            if (!startsWith(header, 0, magic)) {
                return null;
            }
            if (readU32(header, magic.length) != blobLen) {
                return null;
            }
            return new TrailerInfo(trailerStart + footerLen, blobLen, trailerStart);
        } catch (IOException exc) {
            return null;
        }
    }

    private static int normalizeJmgProfile(int profileId) {
        if (profileId == Constants.JMG_SECURITY_PROFILE_LEGACY
            || profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return profileId;
        }
        throw new IllegalArgumentException("Unsupported JMG security profile id");
    }

    private static byte[] jmgStreamInfoForProfile(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return "basefwx.imagecipher.stream.v1.max".getBytes(StandardCharsets.US_ASCII);
        }
        return Constants.IMAGECIPHER_STREAM_INFO;
    }

    private static byte[] jmgArchiveInfoForProfile(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return "basefwx.imagecipher.archive.v1.max".getBytes(StandardCharsets.US_ASCII);
        }
        return Constants.IMAGECIPHER_ARCHIVE_INFO;
    }

    private static String jmgProfileLabel(String label, int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return label + ".max";
        }
        return label;
    }

    private static int jmgVideoMaskBits(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return VIDEO_MASK_BITS_MAX;
        }
        return VIDEO_MASK_BITS;
    }

    private static int jmgAudioMaskBits(int profileId) {
        profileId = normalizeJmgProfile(profileId);
        if (profileId == Constants.JMG_SECURITY_PROFILE_MAX) {
            return AUDIO_MASK_BITS_MAX;
        }
        return AUDIO_MASK_BITS;
    }

    private static JmgKeys prepareJmgKeys(byte[] password, boolean useMaster) {
        return prepareJmgKeys(password, useMaster, Constants.JMG_SECURITY_PROFILE_DEFAULT);
    }

    private static JmgKeys prepareJmgKeys(byte[] password, boolean useMaster, int securityProfile) {
        securityProfile = normalizeJmgProfile(securityProfile);
        KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(password, useMaster, Constants.JMG_MASK_INFO,
            false, Constants.MASK_AAD_JMG, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        byte[] material = Crypto.hkdfSha256(mask.maskKey, jmgStreamInfoForProfile(securityProfile), 64);
        byte[] baseKey = Arrays.copyOfRange(material, 0, 32);
        byte[] archiveKey = Crypto.hkdfSha256(mask.maskKey, jmgArchiveInfoForProfile(securityProfile), 32);
        byte[] header = buildJmgHeader(mask.userBlob, mask.masterBlob, securityProfile);
        return new JmgKeys(baseKey, archiveKey, material, header, securityProfile);
    }

    private static JmgHeader parseJmgHeader(byte[] blob, byte[] password, boolean useMaster) {
        int headerMin = Constants.JMG_KEY_MAGIC.length + 1 + 4;
        if (blob.length < headerMin) {
            return null;
        }
        if (!startsWith(blob, 0, Constants.JMG_KEY_MAGIC)) {
            return null;
        }
        int version = blob[Constants.JMG_KEY_MAGIC.length] & 0xFF;
        if (version != Constants.JMG_KEY_VERSION_LEGACY && version != Constants.JMG_KEY_VERSION) {
            throw new IllegalArgumentException("Unsupported JMG key header version");
        }
        long payloadLen = readU32(blob, Constants.JMG_KEY_MAGIC.length + 1);
        int headerLen = (int) (headerMin + payloadLen);
        if (blob.length < headerLen) {
            throw new IllegalArgumentException("Truncated JMG key header");
        }
        byte[] payload = Arrays.copyOfRange(blob, headerMin, headerLen);
        int profileId = Constants.JMG_SECURITY_PROFILE_LEGACY;
        byte[] keyPayload = payload;
        if (version == Constants.JMG_KEY_VERSION) {
            if (payload.length < 1) {
                throw new IllegalArgumentException("Truncated JMG key header profile");
            }
            profileId = normalizeJmgProfile(payload[0] & 0xFF);
            keyPayload = Arrays.copyOfRange(payload, 1, payload.length);
        }
        List<byte[]> parts = Format.unpackLengthPrefixed(keyPayload, 2);
        byte[] maskKey = KeyWrap.recoverMaskKey(parts.get(0), parts.get(1), password, useMaster,
            Constants.JMG_MASK_INFO, Constants.MASK_AAD_JMG, new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS));
        byte[] material = Crypto.hkdfSha256(maskKey, jmgStreamInfoForProfile(profileId), 64);
        byte[] baseKey = Arrays.copyOfRange(material, 0, 32);
        byte[] archiveKey = Crypto.hkdfSha256(maskKey, jmgArchiveInfoForProfile(profileId), 32);
        return new JmgHeader(headerLen, baseKey, archiveKey, material, profileId);
    }

    private static byte[] buildJmgHeader(byte[] userBlob, byte[] masterBlob, int securityProfile) {
        securityProfile = normalizeJmgProfile(securityProfile);
        byte[] packed = Format.packLengthPrefixed(Arrays.asList(userBlob, masterBlob));
        byte[] payload = new byte[packed.length + 1];
        payload[0] = (byte) securityProfile;
        System.arraycopy(packed, 0, payload, 1, packed.length);
        int total = Constants.JMG_KEY_MAGIC.length + 1 + 4 + payload.length;
        byte[] out = new byte[total];
        int offset = 0;
        System.arraycopy(Constants.JMG_KEY_MAGIC, 0, out, offset, Constants.JMG_KEY_MAGIC.length);
        offset += Constants.JMG_KEY_MAGIC.length;
        out[offset++] = (byte) Constants.JMG_KEY_VERSION;
        writeU32(out, offset, payload.length);
        offset += 4;
        System.arraycopy(payload, 0, out, offset, payload.length);
        return out;
    }

    private static byte[] deriveMediaMaterial(byte[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password required for media key derivation");
        }
        int iters = imageKdfIterations(password);
        return Crypto.pbkdf2HmacSha256(password, Constants.IMAGECIPHER_STREAM_INFO, iters, 64);
    }

    private static byte[] deriveBaseKey(String password) {
        byte[] pw = BaseFwx.resolvePasswordBytes(password, true);
        byte[] material = deriveMediaMaterial(pw);
        return Arrays.copyOfRange(material, 0, 32);
    }

    private static byte[] unitMaterial(byte[] baseKey, String label, long index, int length) {
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[labelBytes.length + 8];
        System.arraycopy(labelBytes, 0, info, 0, labelBytes.length);
        writeU64(info, labelBytes.length, index);
        return Crypto.hkdfSha256(baseKey, info, length);
    }

    private static long bytesToSeed(byte[] seedBytes) {
        long seed = 0L;
        for (byte b : seedBytes) {
            seed = (seed << 8) | (b & 0xFFL);
        }
        return seed;
    }

    private static MaskState buildMaskState(byte[] password,
                                            int numPixels,
                                            int channels,
                                            byte[] materialOverride) {
        byte[] material = materialOverride;
        if (material == null) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password required for image encryption");
            }
            int iters = imageKdfIterations(password);
            material = Crypto.pbkdf2HmacSha256(password, Constants.IMAGECIPHER_STREAM_INFO, iters, 64);
        }
        byte[] key = Arrays.copyOfRange(material, 0, 32);
        byte[] iv = Arrays.copyOfRange(material, 32, 48);
        byte[] seedBytes = Arrays.copyOfRange(material, 48, 64);

        long s0 = readU64(seedBytes, 0);
        long s1 = readU64(seedBytes, 8);
        if (s0 == 0 && s1 == 0) {
            s1 = 1;
        }
        Xoroshiro128Plus rng = new Xoroshiro128Plus(s0, s1);

        int total = numPixels * channels;
        byte[] mask = aesCtrTransform(key, iv, new byte[total]);
        byte[] rotations = new byte[0];
        if (channels > 1) {
            rotations = new byte[numPixels];
            for (int i = 0; i < numPixels; i++) {
                rotations[i] = (byte) rng.nextBounded(channels);
            }
        }
        int[] perm = new int[numPixels];
        for (int i = 0; i < numPixels; i++) {
            perm[i] = i;
        }
        if (numPixels > 1) {
            for (int i = numPixels - 1; i > 0; i--) {
                int j = (int) rng.nextBounded(i + 1L);
                int tmp = perm[i];
                perm[i] = perm[j];
                perm[j] = tmp;
            }
        }
        return new MaskState(mask, rotations, perm);
    }

    private static byte[] applyPermutation(byte[] data, int numPixels, int channels, int[] perm) {
        byte[] out = new byte[data.length];
        for (int dest = 0; dest < numPixels; dest++) {
            int src = perm[dest];
            System.arraycopy(data, src * channels, out, dest * channels, channels);
        }
        return out;
    }

    private static byte[] applyInversePermutation(byte[] data, int numPixels, int channels, int[] perm) {
        int[] inv = new int[numPixels];
        for (int i = 0; i < numPixels; i++) {
            inv[perm[i]] = i;
        }
        byte[] out = new byte[data.length];
        for (int dest = 0; dest < numPixels; dest++) {
            int src = inv[dest];
            System.arraycopy(data, src * channels, out, dest * channels, channels);
        }
        return out;
    }

    private static void xorInPlace(byte[] data, byte[] mask) {
        for (int i = 0; i < data.length; i++) {
            data[i] ^= mask[i];
        }
    }

    private static void applyRotations(byte[] data,
                                       int numPixels,
                                       int channels,
                                       byte[] rotations,
                                       boolean invert) {
        if (channels <= 1) {
            return;
        }
        byte[] tmp = new byte[channels];
        for (int i = 0; i < numPixels; i++) {
            int rot = rotations[i] & 0xFF;
            if (rot == 0) {
                continue;
            }
            int base = i * channels;
            for (int c = 0; c < channels; c++) {
                int idx = invert
                    ? (c + channels - rot) % channels
                    : (c + rot) % channels;
                tmp[c] = data[base + idx];
            }
            System.arraycopy(tmp, 0, data, base, channels);
        }
    }

    private static byte[] shuffleFrameBlocks(byte[] frame,
                                             int width,
                                             int height,
                                             int channels,
                                             long seed,
                                             int blockSize) {
        int blocksX = (width + blockSize - 1) / blockSize;
        int blocksY = (height + blockSize - 1) / blockSize;
        int totalBlocks = blocksX * blocksY;
        int[] perm = permuteIndices(totalBlocks, seed);
        byte[] out = new byte[frame.length];
        for (int destIdx = 0; destIdx < totalBlocks; destIdx++) {
            int srcIdx = perm[destIdx];
            int dx = (destIdx % blocksX) * blockSize;
            int dy = (destIdx / blocksX) * blockSize;
            int sx = (srcIdx % blocksX) * blockSize;
            int sy = (srcIdx / blocksX) * blockSize;
            int copyW = Math.min(blockSize, Math.min(width - dx, width - sx));
            int copyH = Math.min(blockSize, Math.min(height - dy, height - sy));
            for (int row = 0; row < copyH; row++) {
                int srcOff = ((sy + row) * width + sx) * channels;
                int dstOff = ((dy + row) * width + dx) * channels;
                int bytes = copyW * channels;
                System.arraycopy(frame, srcOff, out, dstOff, bytes);
            }
        }
        return out;
    }

    private static byte[] unshuffleFrameBlocks(byte[] frame,
                                               int width,
                                               int height,
                                               int channels,
                                               long seed,
                                               int blockSize) {
        int blocksX = (width + blockSize - 1) / blockSize;
        int blocksY = (height + blockSize - 1) / blockSize;
        int totalBlocks = blocksX * blocksY;
        int[] perm = permuteIndices(totalBlocks, seed);
        byte[] out = new byte[frame.length];
        for (int destIdx = 0; destIdx < totalBlocks; destIdx++) {
            int srcIdx = perm[destIdx];
            int dx = (destIdx % blocksX) * blockSize;
            int dy = (destIdx / blocksX) * blockSize;
            int sx = (srcIdx % blocksX) * blockSize;
            int sy = (srcIdx / blocksX) * blockSize;
            int copyW = Math.min(blockSize, Math.min(width - dx, width - sx));
            int copyH = Math.min(blockSize, Math.min(height - dy, height - sy));
            for (int row = 0; row < copyH; row++) {
                int srcOff = ((dy + row) * width + dx) * channels;
                int dstOff = ((sy + row) * width + sx) * channels;
                int bytes = copyW * channels;
                System.arraycopy(frame, srcOff, out, dstOff, bytes);
            }
        }
        return out;
    }

    private static byte[] shuffleAudioSamples(byte[] block, long seed) {
        if (block.length == 0) {
            return block;
        }
        int len = block.length;
        byte tail = 0;
        boolean hasTail = (len % 2) != 0;
        if (hasTail) {
            tail = block[len - 1];
            block = Arrays.copyOf(block, len - 1);
        }
        int samples = block.length / 2;
        if (samples <= 1) {
            return hasTail ? concat(block, new byte[]{tail}) : block;
        }
        int[] perm = permuteIndices(samples, seed);
        byte[] out = new byte[block.length + (hasTail ? 1 : 0)];
        for (int destIdx = 0; destIdx < samples; destIdx++) {
            int srcIdx = perm[destIdx];
            int srcOff = srcIdx * 2;
            int dstOff = destIdx * 2;
            out[dstOff] = block[srcOff];
            out[dstOff + 1] = block[srcOff + 1];
        }
        if (hasTail) {
            out[out.length - 1] = tail;
        }
        return out;
    }

    private static byte[] unshuffleAudioSamples(byte[] block, long seed) {
        if (block.length == 0) {
            return block;
        }
        int len = block.length;
        byte tail = 0;
        boolean hasTail = (len % 2) != 0;
        if (hasTail) {
            tail = block[len - 1];
            block = Arrays.copyOf(block, len - 1);
        }
        int samples = block.length / 2;
        if (samples <= 1) {
            return hasTail ? concat(block, new byte[]{tail}) : block;
        }
        int[] perm = permuteIndices(samples, seed);
        byte[] out = new byte[block.length + (hasTail ? 1 : 0)];
        for (int destIdx = 0; destIdx < samples; destIdx++) {
            int srcIdx = perm[destIdx];
            int srcOff = srcIdx * 2;
            int dstOff = destIdx * 2;
            out[srcOff] = block[dstOff];
            out[srcOff + 1] = block[dstOff + 1];
        }
        if (hasTail) {
            out[out.length - 1] = tail;
        }
        return out;
    }

    private static byte[] audioMaskTransform(byte[] data, byte[] key, byte[] iv, int maskBits) {
        if (data.length == 0) {
            return data;
        }
        int evenLen = data.length & ~1;
        byte[] head = data;
        byte tail = 0;
        boolean hasTail = data.length != evenLen;
        if (hasTail) {
            tail = data[data.length - 1];
            head = Arrays.copyOf(data, evenLen);
        }
        byte[] keystream = aesCtrTransform(key, iv, new byte[evenLen]);
        if (maskBits < 0) {
            maskBits = 0;
        } else if (maskBits > 16) {
            maskBits = 16;
        }
        int mask = maskBits == 16 ? 0xFFFF : (1 << maskBits) - 1;
        for (int i = 0; i < evenLen; i += 2) {
            int sample = (head[i] & 0xFF) | ((head[i + 1] & 0xFF) << 8);
            int ks = (keystream[i] & 0xFF) | ((keystream[i + 1] & 0xFF) << 8);
            int mixed = sample ^ (ks & mask);
            head[i] = (byte) (mixed & 0xFF);
            head[i + 1] = (byte) ((mixed >>> 8) & 0xFF);
        }
        if (!hasTail) {
            return head;
        }
        byte[] out = new byte[evenLen + 1];
        System.arraycopy(head, 0, out, 0, evenLen);
        out[out.length - 1] = tail;
        return out;
    }

    private static byte[] videoMaskTransform(byte[] data, byte[] key, byte[] iv, int maskBits) {
        if (data.length == 0) {
            return data;
        }
        byte[] keystream = aesCtrTransform(key, iv, new byte[data.length]);
        byte[] out = Arrays.copyOf(data, data.length);
        if (maskBits < 0) {
            maskBits = 0;
        } else if (maskBits > 8) {
            maskBits = 8;
        }
        int mask = maskBits == 8 ? 0xFF : (1 << maskBits) - 1;
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (out[i] ^ (keystream[i] & mask));
        }
        return out;
    }

    private static int[] permuteIndices(int count, long seed) {
        int[] order = new int[count];
        for (int i = 0; i < count; i++) {
            order[i] = i;
        }
        if (count <= 1) {
            return order;
        }
        long[] state = new long[]{seed};
        for (int i = count - 1; i > 0; i--) {
            long rnd = splitMix64(state);
            int j = (int) Long.remainderUnsigned(rnd, i + 1L);
            if (j != i) {
                int tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }
        }
        return order;
    }

    private static long splitMix64(long[] state) {
        long z = state[0] + 0x9E3779B97F4A7C15L;
        state[0] = z;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    private static byte[] aesCtrTransform(byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (Exception exc) {
            throw new IllegalStateException("AES-CTR failed", exc);
        }
    }

    private static MediaInfo probeStreams(File path) {
        ensureFfmpeg();
        Map<String, String> format = probeFormat(path);
        MediaInfo info = new MediaInfo();
        info.duration = parseDouble(format.get("duration"));
        info.bitRate = parseLong(format.get("bit_rate"));

        Map<String, String> video = probeStream(path, "v:0",
            "width,height,avg_frame_rate,r_frame_rate,bit_rate");
        if (!video.isEmpty()) {
            VideoInfo v = new VideoInfo();
            v.width = (int) parseLong(video.get("width"));
            v.height = (int) parseLong(video.get("height"));
            double fps = parseRate(video.get("avg_frame_rate"));
            if (fps <= 0) {
                fps = parseRate(video.get("r_frame_rate"));
            }
            v.fps = fps;
            v.bitRate = parseLong(video.get("bit_rate"));
            info.video = v;
        }

        Map<String, String> audio = probeStream(path, "a:0", "sample_rate,channels,bit_rate");
        if (!audio.isEmpty()) {
            AudioInfo a = new AudioInfo();
            a.sampleRate = (int) parseLong(audio.get("sample_rate"));
            a.channels = (int) parseLong(audio.get("channels"));
            a.bitRate = parseLong(audio.get("bit_rate"));
            info.audio = a;
        }
        return info;
    }

    private static Map<String, String> probeStream(File path, String selector, String entries) {
        List<String> cmd = new ArrayList<>();
        cmd.add("ffprobe");
        cmd.add("-v");
        cmd.add("error");
        cmd.add("-select_streams");
        cmd.add(selector);
        cmd.add("-show_entries");
        cmd.add("stream=" + entries);
        cmd.add("-of");
        cmd.add("default=nw=1");
        cmd.add(path.getPath());
        String output = runCommand(cmd, false);
        if (output == null) {
            return Collections.emptyMap();
        }
        return parseKeyValues(output);
    }

    private static Map<String, String> probeFormat(File path) {
        List<String> cmd = new ArrayList<>();
        cmd.add("ffprobe");
        cmd.add("-v");
        cmd.add("error");
        cmd.add("-show_entries");
        cmd.add("format=duration,bit_rate");
        cmd.add("-of");
        cmd.add("default=nw=1");
        cmd.add(path.getPath());
        String output = runCommand(cmd, false);
        if (output == null) {
            return Collections.emptyMap();
        }
        return parseKeyValues(output);
    }

    private static Map<String, String> probeMetadata(File path) {
        List<String> cmd = new ArrayList<>();
        cmd.add("ffprobe");
        cmd.add("-v");
        cmd.add("error");
        cmd.add("-show_entries");
        cmd.add("format_tags");
        cmd.add("-of");
        cmd.add("default=nw=1");
        cmd.add(path.getPath());
        String output = runCommand(cmd, false);
        if (output == null) {
            return Collections.emptyMap();
        }
        Map<String, String> tags = new HashMap<>();
        for (String line : output.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.startsWith("TAG:")) {
                trimmed = trimmed.substring(4);
            }
            int idx = trimmed.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = trimmed.substring(0, idx).trim();
            String value = trimmed.substring(idx + 1).trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                tags.put(key, value);
            }
        }
        return tags;
    }

    private static List<String> encryptMetadata(Map<String, String> tags, String password) {
        if (tags.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> encoded = new ArrayList<>();
        for (Map.Entry<String, String> entry : tags.entrySet()) {
            try {
                String enc = BaseFwx.b512Encode(entry.getValue(), password, false);
                encoded.add(entry.getKey() + "=" + enc);
            } catch (RuntimeException exc) {
                // Skip tags we cannot encode.
            }
        }
        return encoded;
    }

    private static List<String> decryptMetadata(Map<String, String> tags, String password) {
        if (tags.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> decoded = new ArrayList<>();
        for (Map.Entry<String, String> entry : tags.entrySet()) {
            try {
                String dec = BaseFwx.b512Decode(entry.getValue(), password, false);
                decoded.add(entry.getKey() + "=" + dec);
            } catch (RuntimeException exc) {
                // Skip tags we cannot decode.
            }
        }
        return decoded;
    }

    private static long[] estimateBitrates(File path, MediaInfo info) {
        long totalBps = info.bitRate;
        double duration = info.duration;
        if (totalBps <= 0 && duration > 0.0) {
            totalBps = (long) ((path.length() * 8.0) / duration);
        }
        long videoBps = info.video != null ? info.video.bitRate : 0;
        long audioBps = info.audio != null ? info.audio.bitRate : 0;
        if (totalBps > 0) {
            long targetTotal = (long) (totalBps * JMG_TARGET_GROWTH);
            long maxTotal = (long) (totalBps * JMG_MAX_GROWTH);
            if (targetTotal <= 0) {
                targetTotal = totalBps;
            }
            if (targetTotal > maxTotal) {
                targetTotal = maxTotal;
            }
            if (info.video != null && videoBps <= 0) {
                if (audioBps > 0) {
                    videoBps = Math.max(1, targetTotal - audioBps);
                } else {
                    videoBps = Math.max(JMG_MIN_VIDEO_BPS, (long) (targetTotal * 0.85));
                }
            }
            if (info.audio != null && audioBps <= 0) {
                audioBps = Math.max(JMG_MIN_AUDIO_BPS, (long) (targetTotal * 0.15));
            }
            if (videoBps > 0) {
                videoBps = Math.min(videoBps, maxTotal);
            }
            if (audioBps > 0) {
                audioBps = Math.min(audioBps, maxTotal);
            }
        }
        return new long[]{videoBps > 0 ? videoBps : -1, audioBps > 0 ? audioBps : -1};
    }

    private static List<String> ffmpegVideoCodecArgs(File output, long targetBitrate, String hwaccel) {
        String ext = extensionLower(output);
        if (targetBitrate > 0) {
            long kbps = Math.max(100, targetBitrate / 1000);
            if (".webm".equals(ext)) {
                return Arrays.asList("-c:v", "libvpx-vp9", "-b:v", kbps + "k", "-crf", "33", "-pix_fmt", "yuv420p");
            }
            if ("nvenc".equals(hwaccel)) {
                return Arrays.asList("-c:v", "h264_nvenc", "-preset", "p4", "-b:v", kbps + "k",
                    "-maxrate", kbps + "k", "-bufsize", (kbps * 2) + "k", "-pix_fmt", "yuv420p");
            }
            if ("qsv".equals(hwaccel)) {
                return Arrays.asList("-c:v", "h264_qsv", "-b:v", kbps + "k", "-maxrate", kbps + "k",
                    "-bufsize", (kbps * 2) + "k", "-pix_fmt", "yuv420p");
            }
            if ("vaapi".equals(hwaccel)) {
                String device = envOrDefault(VAAPI_DEVICE_ENV, "/dev/dri/renderD128");
                return Arrays.asList("-vaapi_device", device, "-vf", "format=nv12,hwupload",
                    "-c:v", "h264_vaapi", "-b:v", kbps + "k", "-maxrate", kbps + "k", "-bufsize",
                    (kbps * 2) + "k");
            }
            return Arrays.asList("-c:v", "libx264", "-preset", "veryfast", "-b:v", kbps + "k",
                "-maxrate", kbps + "k", "-bufsize", (kbps * 2) + "k", "-pix_fmt", "yuv420p");
        }
        if (".webm".equals(ext)) {
            return Arrays.asList("-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "32", "-pix_fmt", "yuv420p");
        }
        if ("nvenc".equals(hwaccel)) {
            return Arrays.asList("-c:v", "h264_nvenc", "-preset", "p4", "-cq", "23", "-pix_fmt", "yuv420p");
        }
        if ("qsv".equals(hwaccel)) {
            return Arrays.asList("-c:v", "h264_qsv", "-global_quality", "23", "-pix_fmt", "yuv420p");
        }
        if ("vaapi".equals(hwaccel)) {
            String device = envOrDefault(VAAPI_DEVICE_ENV, "/dev/dri/renderD128");
            return Arrays.asList("-vaapi_device", device, "-vf", "format=nv12,hwupload",
                "-c:v", "h264_vaapi", "-qp", "23");
        }
        return Arrays.asList("-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p");
    }

    private static List<String> ffmpegAudioCodecArgs(File output, long targetBitrate) {
        String ext = extensionLower(output);
        long kbps = targetBitrate > 0 ? Math.max(48, targetBitrate / 1000) : 0;
        if (".mp3".equals(ext)) {
            return Arrays.asList("-c:a", "libmp3lame", "-b:a", (kbps > 0 ? kbps : 192) + "k");
        }
        if (".flac".equals(ext)) {
            return Arrays.asList("-c:a", "flac");
        }
        if (".wav".equals(ext) || ".aiff".equals(ext) || ".aif".equals(ext)) {
            return Arrays.asList("-c:a", "pcm_s16le");
        }
        if (".ogg".equals(ext) || ".opus".equals(ext) || ".webm".equals(ext)) {
            return Arrays.asList("-c:a", "libopus", "-b:a", (kbps > 0 ? kbps : 96) + "k");
        }
        if (".m4a".equals(ext) || ".aac".equals(ext)) {
            return Arrays.asList("-c:a", "aac", "-b:a", (kbps > 0 ? kbps : 160) + "k");
        }
        return Arrays.asList("-c:a", "aac", "-b:a", (kbps > 0 ? kbps : 160) + "k");
    }

    private static List<String> ffmpegContainerArgs(File output) {
        String ext = extensionLower(output);
        if (".mp4".equals(ext) || ".m4v".equals(ext) || ".mov".equals(ext) || ".m4a".equals(ext)) {
            return Arrays.asList("-movflags", "+faststart");
        }
        return Collections.emptyList();
    }

    private static String selectHwaccel() {
        if (hwaccelReady) {
            return hwaccelCache;
        }
        hwaccelReady = true;
        String raw = envOrDefault(HWACCEL_ENV, "auto").trim().toLowerCase(Locale.US);
        if (raw.isEmpty() || "1".equals(raw) || "true".equals(raw) || "yes".equals(raw)) {
            raw = "auto";
        }
        if ("0".equals(raw) || "off".equals(raw) || "false".equals(raw) || "no".equals(raw)) {
            hwaccelCache = null;
            return null;
        }
        Set<String> encoders = ffmpegEncoderSet();
        String prefer = null;
        if ("cuda".equals(raw) || "nvenc".equals(raw) || "nvidia".equals(raw)) {
            prefer = "nvenc";
        } else if ("qsv".equals(raw) || "intel".equals(raw)) {
            prefer = "qsv";
        } else if ("vaapi".equals(raw)) {
            prefer = "vaapi";
        }
        if (prefer != null) {
            String target = "h264_" + prefer;
            if (encoders.contains(target)) {
                hwaccelCache = prefer;
                return prefer;
            }
            hwaccelCache = null;
            return null;
        }
        if ("auto".equals(raw)) {
            if (encoders.contains("h264_nvenc")) {
                hwaccelCache = "nvenc";
                return "nvenc";
            }
            if (encoders.contains("h264_qsv")) {
                hwaccelCache = "qsv";
                return "qsv";
            }
            if (encoders.contains("h264_vaapi")) {
                hwaccelCache = "vaapi";
                return "vaapi";
            }
        }
        hwaccelCache = null;
        return null;
    }

    private static Set<String> ffmpegEncoderSet() {
        Set<String> cached = encoderCache;
        if (cached != null) {
            return cached;
        }
        Set<String> encoders = new HashSet<>();
        List<String> cmd = Arrays.asList("ffmpeg", "-hide_banner", "-encoders");
        String output = runCommand(cmd, true);
        if (output != null) {
            for (String line : output.split("\\r?\\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("--")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+");
                if (parts.length >= 2) {
                    encoders.add(parts[1]);
                }
            }
        }
        encoderCache = encoders;
        return encoders;
    }

    private static void ensureFfmpeg() {
        if (toolAvailable("ffmpeg") && toolAvailable("ffprobe")) {
            return;
        }
        throw new IllegalStateException("ffmpeg/ffprobe are required for audio/video processing");
    }

    private static boolean toolAvailable(String name) {
        try {
            Process process = new ProcessBuilder(name, "-version")
                .redirectErrorStream(true)
                .start();
            process.waitFor(3, TimeUnit.SECONDS);
            return process.exitValue() == 0;
        } catch (Exception exc) {
            return false;
        }
    }

    private static List<String> ffmpegBaseCommand() {
        List<String> cmd = new ArrayList<>();
        cmd.add("ffmpeg");
        cmd.add("-y");
        int threads = mediaWorkers();
        if (threads > 0) {
            cmd.add("-threads");
            cmd.add(Integer.toString(threads));
        }
        return cmd;
    }

    private static void runFfmpeg(List<String> cmd, List<String> fallback) {
        RuntimeException failure = null;
        try {
            runCommand(cmd, true);
            return;
        } catch (RuntimeException exc) {
            failure = exc;
        }
        if (fallback != null) {
            runCommand(fallback, true);
            return;
        }
        throw failure;
    }

    private static String runCommand(List<String> cmd, boolean throwOnFailure) {
        ProcessBuilder builder = new ProcessBuilder(cmd);
        builder.redirectErrorStream(true);
        try {
            Process process = builder.start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = process.getInputStream()) {
                byte[] buf = new byte[4096];
                int read;
                int remaining = 64 * 1024;
                while ((read = in.read(buf)) != -1) {
                    if (remaining <= 0) {
                        continue;
                    }
                    int take = Math.min(read, remaining);
                    out.write(buf, 0, take);
                    remaining -= take;
                }
            }
            int code = process.waitFor();
            String output = out.toString(StandardCharsets.UTF_8.name()).trim();
            if (code != 0 && throwOnFailure) {
                throw new RuntimeException(output.isEmpty() ? "ffmpeg failed" : output);
            }
            return code == 0 ? output : null;
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            if (throwOnFailure) {
                throw new RuntimeException("ffmpeg failed", exc);
            }
            return null;
        } catch (IOException exc) {
            if (throwOnFailure) {
                throw new RuntimeException("ffmpeg failed", exc);
            }
            return null;
        }
    }

    private static int mediaWorkers() {
        String raw = System.getenv(MEDIA_WORKERS_ENV);
        if (raw != null && !raw.trim().isEmpty()) {
            try {
                int parsed = Integer.parseInt(raw.trim());
                if (parsed > 0) {
                    return parsed;
                }
            } catch (NumberFormatException exc) {
                // ignore
            }
        }
        int workers = Runtime.getRuntime().availableProcessors();
        return workers > 0 ? workers : 1;
    }

    private static void processParallel(ExecutorService pool, int count, IndexedRunnable task) {
        if (count <= 0) {
            return;
        }
        if (pool == null || count == 1) {
            for (int i = 0; i < count; i++) {
                task.run(i);
            }
            return;
        }
        CountDownLatch latch = new CountDownLatch(count);
        AtomicReference<RuntimeException> failure = new AtomicReference<>();
        for (int i = 0; i < count; i++) {
            final int idx = i;
            pool.execute(() -> {
                try {
                    task.run(idx);
                } catch (RuntimeException exc) {
                    failure.compareAndSet(null, exc);
                } finally {
                    latch.countDown();
                }
            });
        }
        try {
            latch.await();
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Parallel operation interrupted", exc);
        }
        if (failure.get() != null) {
            throw failure.get();
        }
    }

    private static void shutdownPool(ExecutorService pool) {
        if (pool == null) {
            return;
        }
        pool.shutdown();
        try {
            if (!pool.awaitTermination(10, TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }
    }

    private static int readFully(InputStream in, byte[] buffer, int len) throws IOException {
        int offset = 0;
        while (offset < len) {
            int read = in.read(buffer, offset, len - offset);
            if (read == -1) {
                break;
            }
            offset += read;
        }
        return offset;
    }

    private static ImageData loadImage(byte[] data, File hint) {
        try {
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(data));
            if (img == null) {
                throw new IllegalArgumentException("Unsupported image input: " + hint.getPath());
            }
            int width = img.getWidth();
            int height = img.getHeight();
            boolean hasAlpha = img.getColorModel().hasAlpha();
            boolean gray = img.getColorModel().getNumColorComponents() == 1;
            int channels = gray ? 1 : (hasAlpha ? 4 : 3);
            int[] argb = img.getRGB(0, 0, width, height, null, 0, width);
            byte[] pixels = new byte[width * height * channels];
            int offset = 0;
            for (int value : argb) {
                int a = (value >>> 24) & 0xFF;
                int r = (value >>> 16) & 0xFF;
                int g = (value >>> 8) & 0xFF;
                int b = value & 0xFF;
                if (channels == 1) {
                    pixels[offset++] = (byte) r;
                } else if (channels == 3) {
                    pixels[offset++] = (byte) r;
                    pixels[offset++] = (byte) g;
                    pixels[offset++] = (byte) b;
                } else {
                    pixels[offset++] = (byte) r;
                    pixels[offset++] = (byte) g;
                    pixels[offset++] = (byte) b;
                    pixels[offset++] = (byte) a;
                }
            }
            return new ImageData(width, height, channels, pixels, formatFromPath(hint));
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to decode image", exc);
        }
    }

    private static void writeImage(ImageData data, File output) {
        String format = data.format.isEmpty() ? "png" : data.format;
        int width = data.width;
        int height = data.height;
        int channels = data.channels;
        byte[] pixels = data.pixels;
        BufferedImage out;
        if (("jpg".equals(format) || "jpeg".equals(format)) && channels == 4) {
            channels = 3;
            byte[] trimmed = new byte[width * height * 3];
            for (int i = 0, j = 0; i < pixels.length; i += 4) {
                trimmed[j++] = pixels[i];
                trimmed[j++] = pixels[i + 1];
                trimmed[j++] = pixels[i + 2];
            }
            pixels = trimmed;
        }
        if (channels == 1) {
            out = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
        } else if (channels == 4) {
            out = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        } else {
            out = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        }
        int[] argb = new int[width * height];
        int offset = 0;
        for (int i = 0; i < argb.length; i++) {
            int r;
            int g;
            int b;
            int a = 0xFF;
            if (channels == 1) {
                r = pixels[offset++] & 0xFF;
                g = r;
                b = r;
            } else if (channels == 3) {
                r = pixels[offset++] & 0xFF;
                g = pixels[offset++] & 0xFF;
                b = pixels[offset++] & 0xFF;
            } else {
                r = pixels[offset++] & 0xFF;
                g = pixels[offset++] & 0xFF;
                b = pixels[offset++] & 0xFF;
                a = pixels[offset++] & 0xFF;
            }
            argb[i] = (a << 24) | (r << 16) | (g << 8) | b;
        }
        out.setRGB(0, 0, width, height, argb, 0, width);

        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        File temp = new File(output.getParentFile(), output.getName() + "._tmp");
        try {
            if (!ImageIO.write(out, format, temp)) {
                throw new IllegalStateException("Unsupported image format: " + format);
            }
            moveReplace(temp, output);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to write image", exc);
        } finally {
            temp.delete();
        }
    }

    private static String formatFromPath(File file) {
        String ext = extensionLower(file);
        if (!ext.isEmpty()) {
            return ext.substring(1);
        }
        return "png";
    }

    private static void appendBalancedTrailer(File output, byte[] magic, byte[] blob) {
        if (blob == null || blob.length == 0) {
            return;
        }
        byte[] lenBytes = writeU32(blob.length);
        try (FileOutputStream out = new FileOutputStream(output, true)) {
            out.write(magic);
            out.write(lenBytes);
            out.write(blob);
            out.write(magic);
            out.write(lenBytes);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to append trailer", exc);
        }
    }

    private static void warnNoArchivePayload() {
        RuntimeLog.warn(
            "jMG no-archive payload detected; restored media may not be byte-identical to the original input."
        );
    }

    private static boolean looksLikeFwx(File input) {
        String name = input.getName().toLowerCase(Locale.US);
        if (name.endsWith(".fwx")) {
            return true;
        }
        try (FileInputStream in = new FileInputStream(input)) {
            byte[] header = new byte[Constants.FWXAES_MAGIC.length];
            int read = in.read(header);
            if (read != header.length) {
                return false;
            }
            return Arrays.equals(header, Constants.FWXAES_MAGIC);
        } catch (IOException exc) {
            return false;
        }
    }

    private static File stripFwxSuffix(File input) {
        String name = input.getName();
        if (name.toLowerCase(Locale.US).endsWith(".fwx")) {
            name = name.substring(0, name.length() - 4);
        } else {
            name = name + ".out";
        }
        return new File(input.getParentFile(), name);
    }

    private static File withMarker(File file, String marker) {
        String name = file.getName();
        int dot = name.lastIndexOf('.');
        String newName;
        if (dot >= 0) {
            newName = name.substring(0, dot) + marker + name.substring(dot);
        } else {
            newName = name + marker;
        }
        return new File(file.getParentFile(), newName);
    }

    private static String extensionLower(File file) {
        String name = file.getName();
        int idx = name.lastIndexOf('.');
        if (idx < 0) {
            return "";
        }
        return name.substring(idx).toLowerCase(Locale.US);
    }

    private static void ensureExists(File file) {
        if (file == null || !file.isFile()) {
            throw new IllegalArgumentException("Input file not found: " + (file == null ? "null" : file.getPath()));
        }
    }

    private static void ensureParent(File file) {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
    }

    private static File createTempDir() {
        try {
            return Files.createTempDirectory("basefwx-media-").toFile();
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to create temp dir", exc);
        }
    }

    private static void deleteRecursive(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }

    private static void moveReplace(File src, File dest) {
        try {
            Files.move(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to move output", exc);
        }
    }

    private static byte[] readFileBytes(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to read file bytes", exc);
        }
    }

    private static void writeFileBytes(File file, byte[] data) {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to write file bytes", exc);
        }
    }

    private static int lastIndexOf(byte[] data, byte[] needle) {
        if (needle.length == 0 || data.length < needle.length) {
            return -1;
        }
        for (int i = data.length - needle.length; i >= 0; i--) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static boolean startsWith(byte[] data, int offset, byte[] prefix) {
        if (data.length < offset + prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] writeU32(int value) {
        byte[] out = new byte[4];
        writeU32(out, 0, value);
        return out;
    }

    private static void writeU32(byte[] out, int offset, int value) {
        out[offset] = (byte) ((value >>> 24) & 0xFF);
        out[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        out[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        out[offset + 3] = (byte) (value & 0xFF);
    }

    private static long readU32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
            | ((long) (data[offset + 1] & 0xFF) << 16)
            | ((long) (data[offset + 2] & 0xFF) << 8)
            | ((long) (data[offset + 3] & 0xFF));
    }

    private static void writeU64(byte[] out, int offset, long value) {
        out[offset] = (byte) ((value >>> 56) & 0xFF);
        out[offset + 1] = (byte) ((value >>> 48) & 0xFF);
        out[offset + 2] = (byte) ((value >>> 40) & 0xFF);
        out[offset + 3] = (byte) ((value >>> 32) & 0xFF);
        out[offset + 4] = (byte) ((value >>> 24) & 0xFF);
        out[offset + 5] = (byte) ((value >>> 16) & 0xFF);
        out[offset + 6] = (byte) ((value >>> 8) & 0xFF);
        out[offset + 7] = (byte) (value & 0xFF);
    }

    private static long readU64(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 56)
            | ((long) (data[offset + 1] & 0xFF) << 48)
            | ((long) (data[offset + 2] & 0xFF) << 40)
            | ((long) (data[offset + 3] & 0xFF) << 32)
            | ((long) (data[offset + 4] & 0xFF) << 24)
            | ((long) (data[offset + 5] & 0xFF) << 16)
            | ((long) (data[offset + 6] & 0xFF) << 8)
            | ((long) (data[offset + 7] & 0xFF));
    }

    private static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        return value.trim();
    }

    private static int imageKdfIterations(byte[] password) {
        int iters = Math.max(200_000, Constants.USER_KDF_ITERATIONS);
        if (password != null && password.length > 0 && !Constants.TEST_KDF_OVERRIDE) {
            if (password.length < Constants.SHORT_PASSWORD_MIN && iters < Constants.SHORT_PBKDF2_ITERS) {
                iters = Constants.SHORT_PBKDF2_ITERS;
            }
        }
        return iters;
    }

    private static double parseRate(String rate) {
        if (rate == null || rate.isEmpty() || "0/0".equals(rate)) {
            return 0.0;
        }
        if (rate.contains("/")) {
            String[] parts = rate.split("/", 2);
            try {
                double num = Double.parseDouble(parts[0]);
                double den = Double.parseDouble(parts[1]);
                if (den == 0.0) {
                    return 0.0;
                }
                return num / den;
            } catch (NumberFormatException exc) {
                return 0.0;
            }
        }
        try {
            return Double.parseDouble(rate);
        } catch (NumberFormatException exc) {
            return 0.0;
        }
    }

    private static double parseDouble(String raw) {
        if (raw == null || raw.isEmpty()) {
            return 0.0;
        }
        try {
            return Double.parseDouble(raw);
        } catch (NumberFormatException exc) {
            return 0.0;
        }
    }

    private static long parseLong(String raw) {
        if (raw == null || raw.isEmpty()) {
            return 0L;
        }
        try {
            return (long) Double.parseDouble(raw);
        } catch (NumberFormatException exc) {
            return 0L;
        }
    }

    private static Map<String, String> parseKeyValues(String output) {
        Map<String, String> map = new HashMap<>();
        for (String line : output.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int idx = trimmed.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = trimmed.substring(0, idx).trim();
            String value = trimmed.substring(idx + 1).trim();
            map.put(key, value);
        }
        return map;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        if (a.length == 0) {
            return Arrays.copyOf(b, b.length);
        }
        if (b.length == 0) {
            return Arrays.copyOf(a, a.length);
        }
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static Set<String> buildSet(String... values) {
        Set<String> out = new HashSet<>();
        Collections.addAll(out, values);
        return Collections.unmodifiableSet(out);
    }

    private static boolean samePath(File a, File b) {
        try {
            return a.getCanonicalFile().equals(b.getCanonicalFile());
        } catch (IOException exc) {
            return a.getAbsolutePath().equals(b.getAbsolutePath());
        }
    }

    private static final class JmgKeys {
        final byte[] baseKey;
        final byte[] archiveKey;
        final byte[] material;
        final byte[] header;
        final int profileId;

        JmgKeys(byte[] baseKey, byte[] archiveKey, byte[] material, byte[] header, int profileId) {
            this.baseKey = baseKey;
            this.archiveKey = archiveKey;
            this.material = material;
            this.header = header;
            this.profileId = profileId;
        }
    }

    private static final class JmgHeader {
        final int headerLen;
        final byte[] baseKey;
        final byte[] archiveKey;
        final byte[] material;
        final int profileId;

        JmgHeader(int headerLen, byte[] baseKey, byte[] archiveKey, byte[] material, int profileId) {
            this.headerLen = headerLen;
            this.archiveKey = archiveKey;
            this.baseKey = baseKey;
            this.material = material;
            this.profileId = profileId;
        }
    }

    private static final class MaskState {
        final byte[] mask;
        final byte[] rotations;
        final int[] perm;

        MaskState(byte[] mask, byte[] rotations, int[] perm) {
            this.mask = mask;
            this.rotations = rotations;
            this.perm = perm;
        }
    }

    private static final class ImageData {
        final int width;
        final int height;
        final int channels;
        final byte[] pixels;
        final String format;

        ImageData(int width, int height, int channels, byte[] pixels, String format) {
            this.width = width;
            this.height = height;
            this.channels = channels;
            this.pixels = pixels;
            this.format = format == null ? "" : format.toLowerCase(Locale.US);
        }
    }

    private static final class TrailerSplit {
        final byte[] payload;
        final byte[] trailer;

        TrailerSplit(byte[] payload, byte[] trailer) {
            this.payload = payload;
            this.trailer = trailer;
        }
    }

    private static final class TrailerInfo {
        final long blobStart;
        final long blobLen;
        final long trailerStart;

        TrailerInfo(long blobStart, long blobLen, long trailerStart) {
            this.blobStart = blobStart;
            this.blobLen = blobLen;
            this.trailerStart = trailerStart;
        }
    }

    private static final class MediaInfo {
        VideoInfo video;
        AudioInfo audio;
        double duration;
        long bitRate;
    }

    private static final class VideoInfo {
        int width;
        int height;
        double fps;
        long bitRate;
    }

    private static final class AudioInfo {
        int sampleRate;
        int channels;
        long bitRate;
    }

    private interface IndexedRunnable {
        void run(int index);
    }

    private static final class Xoroshiro128Plus {
        private long s0;
        private long s1;

        Xoroshiro128Plus(long s0, long s1) {
            this.s0 = s0;
            this.s1 = s1;
        }

        long next() {
            long result = s0 + s1;
            long t = s1 ^ s0;
            s0 = rotl(s0, 55) ^ t ^ (t << 14);
            s1 = rotl(t, 36);
            return result;
        }

        long nextBounded(long bound) {
            if (bound == 0) {
                return 0;
            }
            long threshold = Long.remainderUnsigned(-bound, bound);
            while (true) {
                long value = next();
                if (Long.compareUnsigned(value, threshold) >= 0) {
                    return Long.remainderUnsigned(value, bound);
                }
            }
        }

        private static long rotl(long x, int k) {
            return (x << k) | (x >>> (64 - k));
        }
    }
}
