/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class MediaProbe {
    private MediaProbe() {}

    static final double JMG_TARGET_GROWTH = 1.1;
    static final double JMG_MAX_GROWTH = 2.0;
    static final long JMG_MIN_AUDIO_BPS = 64_000;
    static final long JMG_MIN_VIDEO_BPS = 200_000;

    static MediaInfo probeStreams(File path) {
        FfmpegRunner.ensureFfmpeg();
        Map<String, String> format = probeFormat(path);
        MediaInfo info = new MediaInfo();
        info.duration = MediaCipherUtil.parseDouble(format.get("duration"));
        info.bitRate = MediaCipherUtil.parseLong(format.get("bit_rate"));

        Map<String, String> video = probeStream(path, "v:0",
            "width,height,avg_frame_rate,r_frame_rate,bit_rate");
        if (!video.isEmpty()) {
            VideoInfo v = new VideoInfo();
            v.width = (int) MediaCipherUtil.parseLong(video.get("width"));
            v.height = (int) MediaCipherUtil.parseLong(video.get("height"));
            double fps = MediaCipherUtil.parseRate(video.get("avg_frame_rate"));
            if (fps <= 0) {
                fps = MediaCipherUtil.parseRate(video.get("r_frame_rate"));
            }
            v.fps = fps;
            v.bitRate = MediaCipherUtil.parseLong(video.get("bit_rate"));
            info.video = v;
        }

        Map<String, String> audio = probeStream(path, "a:0", "sample_rate,channels,bit_rate");
        if (!audio.isEmpty()) {
            AudioInfo a = new AudioInfo();
            a.sampleRate = (int) MediaCipherUtil.parseLong(audio.get("sample_rate"));
            a.channels = (int) MediaCipherUtil.parseLong(audio.get("channels"));
            a.bitRate = MediaCipherUtil.parseLong(audio.get("bit_rate"));
            info.audio = a;
        }
        return info;
    }

    static Map<String, String> probeStream(File path, String selector, String entries) {
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
        String output = FfmpegRunner.runCommand(cmd, false);
        if (output == null) {
            return Collections.emptyMap();
        }
        return MediaCipherUtil.parseKeyValues(output);
    }

    static Map<String, String> probeFormat(File path) {
        List<String> cmd = new ArrayList<>();
        cmd.add("ffprobe");
        cmd.add("-v");
        cmd.add("error");
        cmd.add("-show_entries");
        cmd.add("format=duration,bit_rate");
        cmd.add("-of");
        cmd.add("default=nw=1");
        cmd.add(path.getPath());
        String output = FfmpegRunner.runCommand(cmd, false);
        if (output == null) {
            return Collections.emptyMap();
        }
        return MediaCipherUtil.parseKeyValues(output);
    }

    static Map<String, String> probeMetadata(File path) {
        List<String> cmd = new ArrayList<>();
        cmd.add("ffprobe");
        cmd.add("-v");
        cmd.add("error");
        cmd.add("-show_entries");
        cmd.add("format_tags");
        cmd.add("-of");
        cmd.add("default=nw=1");
        cmd.add(path.getPath());
        String output = FfmpegRunner.runCommand(cmd, false);
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

    static List<String> encryptMetadata(Map<String, String> tags, String password) {
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

    static List<String> decryptMetadata(Map<String, String> tags, String password) {
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

    static long[] estimateBitrates(File path, MediaInfo info) {
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

    static final class MediaInfo {
        VideoInfo video;
        AudioInfo audio;
        double duration;
        long bitRate;
    }

    static final class VideoInfo {
        int width;
        int height;
        double fps;
        long bitRate;
    }

    static final class AudioInfo {
        int sampleRate;
        int channels;
        long bitRate;
    }

}