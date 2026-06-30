/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.media;

import com.fixcraft.basefwx.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class MediaRawTransforms {
    private MediaRawTransforms() {}

    static final double VIDEO_GROUP_SECONDS = 1.0;
    static final int VIDEO_GROUP_MAX_FRAMES = 12;
    static final int VIDEO_BLOCK_SIZE = 2;
    static final int VIDEO_MASK_BITS = 6;
    static final int VIDEO_MASK_BITS_MAX = 8;
    static final double AUDIO_BLOCK_SECONDS = 0.15;
    static final double AUDIO_GROUP_SECONDS = 1.0;
    static final int AUDIO_MASK_BITS = 13;
    static final int AUDIO_MASK_BITS_MAX = 16;

    static void scrambleVideoRaw(File input,
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
        final String frameLabel = MediaTrailerCodec.jmgProfileLabel("jmg-frame", securityProfile);
        final String frameBlockLabel = MediaTrailerCodec.jmgProfileLabel("jmg-fblk", securityProfile);
        final String frameGroupLabel = MediaTrailerCodec.jmgProfileLabel("jmg-fgrp", securityProfile);
        final int videoMaskBits = MediaTrailerCodec.jmgVideoMaskBits(securityProfile);

        int workers = FfmpegRunner.mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupFrames)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), frameSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), frameSize)) {
            long frameIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> frames = new ArrayList<>(groupFrames);
                for (int i = 0; i < groupFrames; i++) {
                    byte[] frame = new byte[frameSize];
                    int read = FfmpegRunner.readFully(in, frame, frameSize);
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
                FfmpegRunner.processParallel(pool, frames.size(), idx -> {
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
            FfmpegRunner.shutdownPool(pool);
        }
    }

    static void unscrambleVideoRaw(File input,
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
        final String frameLabel = MediaTrailerCodec.jmgProfileLabel("jmg-frame", securityProfile);
        final String frameBlockLabel = MediaTrailerCodec.jmgProfileLabel("jmg-fblk", securityProfile);
        final String frameGroupLabel = MediaTrailerCodec.jmgProfileLabel("jmg-fgrp", securityProfile);
        final int videoMaskBits = MediaTrailerCodec.jmgVideoMaskBits(securityProfile);

        int workers = FfmpegRunner.mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupFrames)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), frameSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), frameSize)) {
            long frameIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> frames = new ArrayList<>(groupFrames);
                for (int i = 0; i < groupFrames; i++) {
                    byte[] frame = new byte[frameSize];
                    int read = FfmpegRunner.readFully(in, frame, frameSize);
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
                FfmpegRunner.processParallel(pool, ordered.length, idx -> {
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
            FfmpegRunner.shutdownPool(pool);
        }
    }

    static void scrambleAudioRaw(File input,
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
        final String audioBlockLabel = MediaTrailerCodec.jmgProfileLabel("jmg-ablock", securityProfile);
        final String audioSampleLabel = MediaTrailerCodec.jmgProfileLabel("jmg-asamp", securityProfile);
        final String audioGroupLabel = MediaTrailerCodec.jmgProfileLabel("jmg-agrp", securityProfile);
        final int audioMaskBits = MediaTrailerCodec.jmgAudioMaskBits(securityProfile);

        int workers = FfmpegRunner.mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupBlocks)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), blockSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), blockSize)) {
            long blockIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> blocks = new ArrayList<>(groupBlocks);
                for (int i = 0; i < groupBlocks; i++) {
                    byte[] block = new byte[blockSize];
                    int read = FfmpegRunner.readFully(in, block, blockSize);
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
                FfmpegRunner.processParallel(pool, blocks.size(), idx -> {
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
            FfmpegRunner.shutdownPool(pool);
        }
    }

    static void unscrambleAudioRaw(File input,
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
        final String audioBlockLabel = MediaTrailerCodec.jmgProfileLabel("jmg-ablock", securityProfile);
        final String audioSampleLabel = MediaTrailerCodec.jmgProfileLabel("jmg-asamp", securityProfile);
        final String audioGroupLabel = MediaTrailerCodec.jmgProfileLabel("jmg-agrp", securityProfile);
        final int audioMaskBits = MediaTrailerCodec.jmgAudioMaskBits(securityProfile);

        int workers = FfmpegRunner.mediaWorkers();
        ExecutorService pool = workers > 1 ? Executors.newFixedThreadPool(Math.min(workers, groupBlocks)) : null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(input), blockSize);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output), blockSize)) {
            long blockIndex = 0;
            long groupIndex = 0;
            while (true) {
                List<byte[]> blocks = new ArrayList<>(groupBlocks);
                for (int i = 0; i < groupBlocks; i++) {
                    byte[] block = new byte[blockSize];
                    int read = FfmpegRunner.readFully(in, block, blockSize);
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
                FfmpegRunner.processParallel(pool, ordered.length, idx -> {
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
            FfmpegRunner.shutdownPool(pool);
        }
    }

    static byte[] unitMaterial(byte[] baseKey, String label, long index, int length) {
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[labelBytes.length + 8];
        System.arraycopy(labelBytes, 0, info, 0, labelBytes.length);
        MediaCipherUtil.writeU64(info, labelBytes.length, index);
        return Crypto.hkdfSha256(baseKey, info, length);
    }

    static long bytesToSeed(byte[] seedBytes) {
        long seed = 0L;
        for (byte b : seedBytes) {
            seed = (seed << 8) | (b & 0xFFL);
        }
        return seed;
    }

    static byte[] shuffleFrameBlocks(byte[] frame,
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

    static byte[] unshuffleFrameBlocks(byte[] frame,
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

    static byte[] shuffleAudioSamples(byte[] block, long seed) {
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
            return hasTail ? MediaCipherUtil.concat(block, new byte[]{tail}) : block;
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

    static byte[] unshuffleAudioSamples(byte[] block, long seed) {
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
            return hasTail ? MediaCipherUtil.concat(block, new byte[]{tail}) : block;
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

    static byte[] audioMaskTransform(byte[] data, byte[] key, byte[] iv, int maskBits) {
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

    static byte[] videoMaskTransform(byte[] data, byte[] key, byte[] iv, int maskBits) {
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

    static int[] permuteIndices(int count, long seed) {
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

    static long splitMix64(long[] state) {
        long z = state[0] + 0x9E3779B97F4A7C15L;
        state[0] = z;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    static byte[] aesCtrTransform(byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (Exception exc) {
            throw new IllegalStateException("AES-CTR failed", exc);
        }
    }

}