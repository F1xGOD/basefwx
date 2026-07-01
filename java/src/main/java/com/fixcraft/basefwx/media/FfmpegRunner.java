/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.media;

import com.fixcraft.basefwx.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class FfmpegRunner {
    private FfmpegRunner() {}

    static final String HWACCEL_ENV = "BASEFWX_HWACCEL";
    static final String VAAPI_DEVICE_ENV = "BASEFWX_VAAPI_DEVICE";
    static final String MEDIA_WORKERS_ENV = "BASEFWX_MEDIA_WORKERS";
    static volatile String hwaccelCache = null;
    static volatile boolean hwaccelReady = false;
    static volatile Set<String> encoderCache = null;

    static void scrambleVideo(File input,
                                      File output,
                                      String password,
                                      boolean keepMeta,
                                      byte[] baseKey,
                                      int securityProfile,
                                      MediaProbe.MediaInfo info) {
        if (info.video == null) {
            throw new IllegalArgumentException("No video stream found");
        }
        int width = info.video.width;
        int height = info.video.height;
        double fps = info.video.fps;
        long[] bps = MediaProbe.estimateBitrates(input, info);
        long videoBps = bps[0];
        long audioBps = bps[1];

        File tempDir = MediaCipherUtil.createTempDir();
        File rawVideo = new File(tempDir, "video.raw");
        File rawVideoOut = new File(tempDir, "video.scr.raw");
        File rawAudio = null;
        File rawAudioOut = null;
        int sampleRate = 0;
        int channels = 0;
        try {
            MediaCipherUtil.ensureParent(output);
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

            MediaRawTransforms.scrambleVideoRaw(rawVideo, rawVideoOut, width, height, fps, baseKey, securityProfile);
            if (rawAudio != null && rawAudioOut != null) {
                MediaRawTransforms.scrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);
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
                Map<String, String> tags = MediaProbe.probeMetadata(input);
                for (String meta : MediaProbe.encryptMetadata(tags, password)) {
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
            MediaCipherUtil.deleteRecursive(tempDir);
        }
    }

    static void scrambleAudio(File input,
                                      File output,
                                      String password,
                                      boolean keepMeta,
                                      byte[] baseKey,
                                      int securityProfile,
                                      MediaProbe.MediaInfo info) {
        if (info.audio == null) {
            throw new IllegalArgumentException("No audio stream found");
        }
        int sampleRate = info.audio.sampleRate > 0 ? info.audio.sampleRate : 48000;
        int channels = info.audio.channels > 0 ? info.audio.channels : 2;
        long[] bps = MediaProbe.estimateBitrates(input, info);
        long audioBps = bps[1];

        File tempDir = MediaCipherUtil.createTempDir();
        File rawAudio = new File(tempDir, "audio.raw");
        File rawAudioOut = new File(tempDir, "audio.scr.raw");
        try {
            MediaCipherUtil.ensureParent(output);
            List<String> cmdAudio = ffmpegBaseCommand();
            cmdAudio.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:a:0", "-f", "s16le",
                "-acodec", "pcm_s16le", "-ar", String.valueOf(sampleRate), "-ac", String.valueOf(channels),
                rawAudio.getPath()));
            runFfmpeg(cmdAudio, null);

            MediaRawTransforms.scrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);

            List<String> cmd = ffmpegBaseCommand();
            cmd.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                String.valueOf(channels), "-i", rawAudioOut.getPath()));
            if (keepMeta) {
                Map<String, String> tags = MediaProbe.probeMetadata(input);
                for (String meta : MediaProbe.encryptMetadata(tags, password)) {
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
            MediaCipherUtil.deleteRecursive(tempDir);
        }
    }

    static void unscrambleVideo(File input,
                                        File output,
                                        String password,
                                        MediaProbe.MediaInfo info,
                                        byte[] baseKeyOverride,
                                        int securityProfile) {
        if (info.video == null) {
            throw new IllegalArgumentException("No video stream found");
        }
        int width = info.video.width;
        int height = info.video.height;
        double fps = info.video.fps;
        long[] bps = MediaProbe.estimateBitrates(input, info);
        long videoBps = bps[0];
        long audioBps = bps[1];
        int sampleRate = 0;
        int channels = 0;

        File tempDir = MediaCipherUtil.createTempDir();
        File rawVideo = new File(tempDir, "video.raw");
        File rawVideoOut = new File(tempDir, "video.unscr.raw");
        File rawAudio = null;
        File rawAudioOut = null;
        try {
            MediaCipherUtil.ensureParent(output);
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

            byte[] baseKey = baseKeyOverride != null ? Arrays.copyOf(baseKeyOverride, baseKeyOverride.length) : MediaTrailerCodec.deriveBaseKey(password);
            MediaRawTransforms.unscrambleVideoRaw(rawVideo, rawVideoOut, width, height, fps, baseKey, securityProfile);
            if (rawAudio != null && rawAudioOut != null) {
                MediaRawTransforms.unscrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);
            }

            List<String> cmdBase = ffmpegBaseCommand();
            cmdBase.addAll(Arrays.asList("-f", "rawvideo", "-pix_fmt", "rgb24", "-s",
                width + "x" + height, "-r", String.format(Locale.US, "%.6f", fps > 0 ? fps : 30.0),
                "-i", rawVideoOut.getPath()));
            if (rawAudioOut != null) {
                cmdBase.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                    String.valueOf(channels), "-i", rawAudioOut.getPath(), "-shortest"));
            }
            Map<String, String> tags = MediaProbe.probeMetadata(input);
            List<String> decoded = MediaProbe.decryptMetadata(tags, password);
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
            MediaCipherUtil.deleteRecursive(tempDir);
        }
    }

    static void unscrambleAudio(File input,
                                        File output,
                                        String password,
                                        MediaProbe.MediaInfo info,
                                        byte[] baseKeyOverride,
                                        int securityProfile) {
        if (info.audio == null) {
            throw new IllegalArgumentException("No audio stream found");
        }
        int sampleRate = info.audio.sampleRate > 0 ? info.audio.sampleRate : 48000;
        int channels = info.audio.channels > 0 ? info.audio.channels : 2;
        long[] bps = MediaProbe.estimateBitrates(input, info);
        long audioBps = bps[1];

        File tempDir = MediaCipherUtil.createTempDir();
        File rawAudio = new File(tempDir, "audio.raw");
        File rawAudioOut = new File(tempDir, "audio.unscr.raw");
        try {
            MediaCipherUtil.ensureParent(output);
            List<String> cmdAudio = ffmpegBaseCommand();
            cmdAudio.addAll(Arrays.asList("-i", input.getPath(), "-map", "0:a:0", "-f", "s16le",
                "-acodec", "pcm_s16le", "-ar", String.valueOf(sampleRate), "-ac",
                String.valueOf(channels), rawAudio.getPath()));
            runFfmpeg(cmdAudio, null);

            byte[] baseKey = baseKeyOverride != null ? Arrays.copyOf(baseKeyOverride, baseKeyOverride.length) : MediaTrailerCodec.deriveBaseKey(password);
            MediaRawTransforms.unscrambleAudioRaw(rawAudio, rawAudioOut, sampleRate, channels, baseKey, securityProfile);

            List<String> cmd = ffmpegBaseCommand();
            cmd.addAll(Arrays.asList("-f", "s16le", "-ar", String.valueOf(sampleRate), "-ac",
                String.valueOf(channels), "-i", rawAudioOut.getPath()));
            Map<String, String> tags = MediaProbe.probeMetadata(input);
            List<String> decoded = MediaProbe.decryptMetadata(tags, password);
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
            MediaCipherUtil.deleteRecursive(tempDir);
        }
    }

    static List<String> ffmpegVideoCodecArgs(File output, long targetBitrate, String hwaccel) {
        String ext = MediaCipherUtil.extensionLower(output);
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
                String device = MediaCipherUtil.envOrDefault(VAAPI_DEVICE_ENV, "/dev/dri/renderD128");
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
            String device = MediaCipherUtil.envOrDefault(VAAPI_DEVICE_ENV, "/dev/dri/renderD128");
            return Arrays.asList("-vaapi_device", device, "-vf", "format=nv12,hwupload",
                "-c:v", "h264_vaapi", "-qp", "23");
        }
        return Arrays.asList("-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p");
    }

    static List<String> ffmpegAudioCodecArgs(File output, long targetBitrate) {
        String ext = MediaCipherUtil.extensionLower(output);
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

    static List<String> ffmpegContainerArgs(File output) {
        String ext = MediaCipherUtil.extensionLower(output);
        if (".mp4".equals(ext) || ".m4v".equals(ext) || ".mov".equals(ext) || ".m4a".equals(ext)) {
            return Arrays.asList("-movflags", "+faststart");
        }
        return Collections.emptyList();
    }

    public static String selectHwaccel() {
        if (hwaccelReady) {
            return hwaccelCache;
        }
        hwaccelReady = true;
        String raw = MediaCipherUtil.envOrDefault(HWACCEL_ENV, "auto").trim().toLowerCase(Locale.US);
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

    static Set<String> ffmpegEncoderSet() {
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

    static void ensureFfmpeg() {
        if (toolAvailable("ffmpeg") && toolAvailable("ffprobe")) {
            return;
        }
        throw new IllegalStateException("ffmpeg/ffprobe are required for audio/video processing");
    }

    static boolean toolAvailable(String name) {
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

    static List<String> ffmpegBaseCommand() {
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

    static void runFfmpeg(List<String> cmd, List<String> fallback) {
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

    static String runCommand(List<String> cmd, boolean throwOnFailure) {
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

    public static int mediaWorkers() {
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

    static void processParallel(ExecutorService pool, int count, IndexedRunnable task) {
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

    static void shutdownPool(ExecutorService pool) {
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

    static int readFully(InputStream in, byte[] buffer, int len) throws IOException {
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

    interface IndexedRunnable {
        void run(int index);
    }

}