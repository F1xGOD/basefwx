/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Locale;

final class MediaImageCipher {
    private MediaImageCipher() {}

    static File encryptImage(File input,
                                     File output,
                                     byte[] password,
                                     boolean useMaster,
                                     boolean includeTrailer,
                                     boolean archiveOriginal) {
        if (!includeTrailer && password.length == 0) {
            throw new IllegalArgumentException("Password required for image encryption without trailer");
        }
        byte[] original = MediaCipherUtil.readFileBytes(input);
        String format = formatFromPath(input);
        ImageData data = loadImage(original, input);
        int numPixels = data.width * data.height;

        byte[] materialOverride = null;
        byte[] archiveKey = null;
        byte[] trailerHeader = new byte[0];
        int trailerProfile = Constants.JMG_SECURITY_PROFILE_LEGACY;
        if (includeTrailer) {
            MediaTrailerCodec.JmgKeys keys = MediaTrailerCodec.prepareJmgKeys(password, useMaster);
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
                    MediaTrailerCodec.jmgArchiveInfoForProfile(trailerProfile)
                );
                byte[] trailerBlob = MediaCipherUtil.concat(trailerHeader, archiveBlob);
                MediaTrailerCodec.appendBalancedTrailer(output, Constants.IMAGECIPHER_TRAILER_MAGIC, trailerBlob);
            } else {
                MediaTrailerCodec.appendBalancedTrailer(output, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC, trailerHeader);
            }
        }
        return output;
    }

    static File decryptImage(File input,
                                     File output,
                                     byte[] password,
                                     boolean useMaster) {
        byte[] fileBytes = MediaCipherUtil.readFileBytes(input);
        MediaTrailerCodec.TrailerSplit split = MediaTrailerCodec.splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_TRAILER_MAGIC);
        byte[] payload = split.payload;
        byte[] trailer = split.trailer;
        byte[] keyTrailer = null;
        if (trailer == null) {
            MediaTrailerCodec.TrailerSplit keySplit = MediaTrailerCodec.splitTrailerForMagic(fileBytes, Constants.IMAGECIPHER_KEY_TRAILER_MAGIC);
            keyTrailer = keySplit.trailer;
            payload = keySplit.payload;
        }
        String format = formatFromPath(input);
        byte[] materialOverride = null;

        if (trailer != null) {
            byte[] archiveKey = null;
            int headerLen = 0;
            byte[] archiveInfo = Constants.IMAGECIPHER_ARCHIVE_INFO;
            MediaTrailerCodec.JmgHeader header = MediaTrailerCodec.parseJmgHeader(trailer, password, useMaster);
            byte[] archiveBlob;
            if (header != null) {
                headerLen = header.headerLen;
                archiveKey = header.archiveKey;
                materialOverride = header.material;
                archiveInfo = MediaTrailerCodec.jmgArchiveInfoForProfile(header.profileId);
                archiveBlob = Arrays.copyOfRange(trailer, headerLen, trailer.length);
            } else {
                byte[] material = MediaTrailerCodec.deriveMediaMaterial(password);
                archiveKey = Crypto.hkdfSha256(material, Constants.IMAGECIPHER_ARCHIVE_INFO, 32);
                archiveBlob = trailer;
            }
            try {
                byte[] original = Crypto.aesGcmDecrypt(archiveKey, archiveBlob, archiveInfo);
                MediaCipherUtil.writeFileBytes(output, original);
                return output;
            } catch (RuntimeException exc) {
                // Fall through to deterministic decode.
            }
        }

        if (keyTrailer != null) {
            MediaTrailerCodec.JmgHeader header = MediaTrailerCodec.parseJmgHeader(keyTrailer, password, useMaster);
            if (header == null) {
                throw new IllegalArgumentException("Invalid JMG key trailer");
            }
            if (header.headerLen != keyTrailer.length) {
                throw new IllegalArgumentException("Invalid JMG key trailer payload");
            }
            materialOverride = header.material;
            MediaTrailerCodec.warnNoArchivePayload();
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

    static long bytesToSeed(byte[] seedBytes) {
        long seed = 0L;
        for (byte b : seedBytes) {
            seed = (seed << 8) | (b & 0xFFL);
        }
        return seed;
    }

    static MaskState buildMaskState(byte[] password,
                                            int numPixels,
                                            int channels,
                                            byte[] materialOverride) {
        byte[] material = materialOverride;
        if (material == null) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password required for image encryption");
            }
            int iters = MediaCipherUtil.imageKdfIterations(password);
            material = Crypto.pbkdf2HmacSha256(password, Constants.IMAGECIPHER_STREAM_INFO, iters, 64);
        }
        byte[] key = Arrays.copyOfRange(material, 0, 32);
        byte[] iv = Arrays.copyOfRange(material, 32, 48);
        byte[] seedBytes = Arrays.copyOfRange(material, 48, 64);

        long s0 = MediaCipherUtil.readU64(seedBytes, 0);
        long s1 = MediaCipherUtil.readU64(seedBytes, 8);
        if (s0 == 0 && s1 == 0) {
            s1 = 1;
        }
        Xoroshiro128Plus rng = new Xoroshiro128Plus(s0, s1);

        int total = numPixels * channels;
        byte[] mask = MediaRawTransforms.aesCtrTransform(key, iv, new byte[total]);
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

    static byte[] applyPermutation(byte[] data, int numPixels, int channels, int[] perm) {
        byte[] out = new byte[data.length];
        for (int dest = 0; dest < numPixels; dest++) {
            int src = perm[dest];
            System.arraycopy(data, src * channels, out, dest * channels, channels);
        }
        return out;
    }

    static byte[] applyInversePermutation(byte[] data, int numPixels, int channels, int[] perm) {
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

    static void xorInPlace(byte[] data, byte[] mask) {
        for (int i = 0; i < data.length; i++) {
            data[i] ^= mask[i];
        }
    }

    static void applyRotations(byte[] data,
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

    static ImageData loadImage(byte[] data, File hint) {
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

    static void writeImage(ImageData data, File output) {
        String format = data.format.isEmpty() ? "png" : data.format;
        int width = data.width;
        int height = data.height;
        int channels = data.channels;
        byte[] pixels = data.pixels;
        BufferedImage out;
        if (("jpg".equals(format) || "jpeg".equals(format)) && channels == 4) {
            channels = 3;
            byte[] trimmed = new byte[width * height * 3];
            for (int i = 0, j = 0; i + 4 <= pixels.length; i += 4) {
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
            MediaCipherUtil.moveReplace(temp, output);
        } catch (IOException exc) {
            throw new IllegalStateException("Failed to write image", exc);
        } finally {
            temp.delete();
        }
    }

    static String formatFromPath(File file) {
        String ext = MediaCipherUtil.extensionLower(file);
        if (!ext.isEmpty()) {
            return ext.substring(1);
        }
        return "png";
    }

    static final class MaskState {
        final byte[] mask;
        final byte[] rotations;
        final int[] perm;

        MaskState(byte[] mask, byte[] rotations, int[] perm) {
            this.mask = mask;
            this.rotations = rotations;
            this.perm = perm;
        }
    }

    static final class ImageData {
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

    static final class Xoroshiro128Plus {
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