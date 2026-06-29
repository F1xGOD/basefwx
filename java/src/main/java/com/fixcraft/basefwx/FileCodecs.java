/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Lesser General Public License v3.0 or later.
 */

package com.fixcraft.basefwx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class FileCodecs {
    private FileCodecs() {}

    static final int PERF_OBFUSCATION_THRESHOLD = FileCodecObfuscation.PERF_OBFUSCATION_THRESHOLD;

    static boolean payloadObfuscationEnabled() {
        return FileCodecObfuscation.payloadObfuscationEnabled();
    }

    static boolean perfModeEnabled() {
        return FileCodecObfuscation.perfModeEnabled();
    }

    static boolean useFastObfuscation(long length) {
        return FileCodecObfuscation.useFastObfuscation(length);
    }

    static String resolveUserKdfLabel() {
        return FileCodecKdf.resolveUserKdfLabel();
    }

    static String resolveKdfLabel(String label) {
        return FileCodecKdf.resolveKdfLabel(label);
    }

    static int parseMetadataInt(String raw, int fallback) {
        return FileCodecMetadata.parseMetadataInt(raw, fallback);
    }

    static int hardenPbkdf2Iterations(byte[] password, int iterations) {
        return FileCodecKdf.hardenPbkdf2Iterations(password, iterations);
    }

    static byte[] obfuscateBytes(byte[] data, byte[] key) {
        return FileCodecObfuscation.obfuscateBytes(data, key);
    }

    static byte[] obfuscateBytes(byte[] data, byte[] key, boolean fast) {
        return FileCodecObfuscation.obfuscateBytes(data, key, fast);
    }

    static byte[] deobfuscateBytes(byte[] data, byte[] key) {
        return FileCodecObfuscation.deobfuscateBytes(data, key);
    }

    static byte[] deobfuscateBytes(byte[] data, byte[] key, boolean fast) {
        return FileCodecObfuscation.deobfuscateBytes(data, key, fast);
    }

    static byte[] buildInfoWithLength(byte[] prefix, int length) {
        return FileCodecObfuscation.buildInfoWithLength(prefix, length);
    }

    static void xorKeystreamInPlace(byte[] buf, byte[] key, byte[] info) {
        FileCodecObfuscation.xorKeystreamInPlace(buf, key, info);
    }

    static long seed64FromBytes(byte[] seedBytes) {
        return FileCodecObfuscation.seed64FromBytes(seedBytes);
    }

    static void reverseInPlace(byte[] data) {
        FileCodecObfuscation.reverseInPlace(data);
    }

    static void permuteInPlace(byte[] data, long seed) {
        FileCodecObfuscation.permuteInPlace(data, seed);
    }

    static void permuteInPlace(byte[] data, int length, long seed) {
        FileCodecObfuscation.permuteInPlace(data, length, seed);
    }

    static void unpermuteInPlace(byte[] data, long seed) {
        FileCodecObfuscation.unpermuteInPlace(data, seed);
    }

    static void unpermuteInPlace(byte[] data, int length, long seed) {
        FileCodecObfuscation.unpermuteInPlace(data, length, seed);
    }

    static long splitMix64Next(long[] state) {
        return FileCodecObfuscation.splitMix64Next(state);
    }

    static boolean isStreamMode(String metadataBlob) {
        return FileCodecMetadata.isStreamMode(metadataBlob);
    }

    static String peekMetadataBlob(File input) {
        return FileCodecMetadata.peekMetadataBlob(input);
    }

    static byte[] buildStreamHeader(long inputSize,
                                                byte[] streamSalt,
                                                byte[] extBytes,
                                                int chunkSize) {
        return FileCodecMetadata.buildStreamHeader(inputSize, streamSalt, extBytes, chunkSize);
    }

    static File resolveDecodedOutput(File input, File output, byte[] extBytes) {
        return FileCodecIo.resolveDecodedOutput(input, output, extBytes);
    }

    static File b512FileEncodeFileStream(File input,
                                                     File output,
                                                     String password,
                                                     boolean useMaster) {
        return B512FileCodec.b512FileEncodeFileStream(input, output, password, useMaster);
    }

    static File b512FileDecodeFileStream(File input,
                                                     File output,
                                                     String password,
                                                     boolean useMaster,
                                                     String metadataPreview) {
        return B512FileCodec.b512FileDecodeFileStream(input, output, password, useMaster, metadataPreview);
    }

    static File pb512FileEncodeFileStream(File input,
                                                      File output,
                                                      String password,
                                                      boolean useMaster) {
        return Pb512FileCodec.pb512FileEncodeFileStream(input, output, password, useMaster);
    }

    static File pb512FileDecodeFileStream(File input,
                                                      File output,
                                                      String password,
                                                      boolean useMaster,
                                                      String metadataPreview) {
        return Pb512FileCodec.pb512FileDecodeFileStream(input, output, password, useMaster, metadataPreview);
    }

    static void readExact(InputStream input, byte[] buffer, int length, String error) throws IOException {
        FileCodecIo.readExact(input, buffer, length, error);
    }

    static void readExactChannel(FileChannel channel, ByteBuffer buffer, int length, String error) throws IOException {
        FileCodecIo.readExactChannel(channel, buffer, length, error);
    }

    static void writeFully(FileChannel channel, ByteBuffer buffer) throws IOException {
        FileCodecIo.writeFully(channel, buffer);
    }

    static byte[] readExactBytes(InputStream input, int length, String error) throws IOException {
        return FileCodecIo.readExactBytes(input, length, error);
    }

    static void skipFully(InputStream input, int length, String error) throws IOException {
        FileCodecIo.skipFully(input, length, error);
    }

    static long resolvePayloadLengthFromFileSize(File input,
                                                             int lenUser,
                                                             int lenMaster,
                                                             int encodedPayloadLen) {
        return FileCodecIo.resolvePayloadLengthFromFileSize(input, lenUser, lenMaster, encodedPayloadLen);
    }

    static int readU32(InputStream input, String error) throws IOException {
        return FileCodecIo.readU32(input, error);
    }

    static int readU16(InputStream input, String error) throws IOException {
        return FileCodecIo.readU16(input, error);
    }

    static long readU64(InputStream input, String error) throws IOException {
        return FileCodecIo.readU64(input, error);
    }

    static void writeU32(OutputStream output, int value) throws IOException {
        FileCodecIo.writeU32(output, value);
    }

    static void writeU16(OutputStream output, int value) throws IOException {
        FileCodecIo.writeU16(output, value);
    }

    static void writeU64(OutputStream output, long value) throws IOException {
        FileCodecIo.writeU64(output, value);
    }

    static byte[] concat(byte[]... parts) {
        return FileCodecIo.concat(parts);
    }

    static boolean startsWith(byte[] data, byte[] prefix) {
        return FileCodecIo.startsWith(data, prefix);
    }

    static String buildMetadata(String method,
                                            boolean strip,
                                            boolean useMaster,
                                            String aead,
                                            String kdfLabel) {
        return FileCodecMetadata.buildMetadata(method, strip, useMaster, aead, kdfLabel);
    }

    static String buildMetadata(String method,
                                            boolean strip,
                                            boolean useMaster,
                                            String aead,
                                            String kdfLabel,
                                            String mode,
                                            Boolean obfuscation,
                                            String obfMode,
                                            Integer kdfIters,
                                            Integer argonTime,
                                            Integer argonMem,
                                            Integer argonPar,
                                            String pack) {
        return FileCodecMetadata.buildMetadata(method, strip, useMaster, aead, kdfLabel, mode, obfuscation, obfMode, kdfIters, argonTime, argonMem, argonPar, pack);
    }

    static String encodeJson(Map<String, String> map) {
        return FileCodecMetadata.encodeJson(map);
    }

    static String escapeJson(String value) {
        return FileCodecMetadata.escapeJson(value);
    }

    static String[] splitMetadata(String payload) {
        return FileCodecMetadata.splitMetadata(payload);
    }

    static String metaValue(String metadataBlob, String key) {
        return FileCodecMetadata.metaValue(metadataBlob, key);
    }

    static String jsonValue(String json, String key) {
        return FileCodecMetadata.jsonValue(json, key);
    }

    static int skipJsonWhitespace(String json, int idx) {
        return FileCodecMetadata.skipJsonWhitespace(json, idx);
    }

    static int parseJsonString(String json, int start, StringBuilder out) {
        return FileCodecMetadata.parseJsonString(json, start, out);
    }

    static String[] splitWithDelims(String payload, String delim, String legacy, String label) {
        return FileCodecMetadata.splitWithDelims(payload, delim, legacy, label);
    }

    static byte[] b512FileEncodeBytes(byte[] data,
                                                 String extension,
                                                 String password,
                                                 boolean useMaster) {
        return B512FileCodec.b512FileEncodeBytes(data, extension, password, useMaster);
    }

    static byte[] b512FileEncodeBytes(byte[] data,
                                                 String extension,
                                                 String password,
                                                 boolean useMaster,
                                                 boolean stripMetadata,
                                                 boolean enableAead) {
        return B512FileCodec.b512FileEncodeBytes(data, extension, password, useMaster, stripMetadata, enableAead);
    }

    static BaseFwx.DecodedFile b512FileDecodeBytes(byte[] blob,
                                                      String password,
                                                      boolean useMaster) {
        return B512FileCodec.b512FileDecodeBytes(blob, password, useMaster);
    }

    static BaseFwx.DecodedFile b512FileDecodeBytes(byte[] blob,
                                                      String password,
                                                      boolean useMaster,
                                                      boolean stripMetadata) {
        return B512FileCodec.b512FileDecodeBytes(blob, password, useMaster, stripMetadata);
    }

    static File b512FileEncodeFile(File input,
                                              File output,
                                              String password,
                                              boolean useMaster) {
        return B512FileCodec.b512FileEncodeFile(input, output, password, useMaster);
    }

    static File b512FileDecodeFile(File input,
                                              File output,
                                              String password,
                                              boolean useMaster) {
        return B512FileCodec.b512FileDecodeFile(input, output, password, useMaster);
    }

    static byte[] pb512FileEncodeBytes(byte[] data,
                                                  String extension,
                                                  String password,
                                                  boolean useMaster) {
        return Pb512FileCodec.pb512FileEncodeBytes(data, extension, password, useMaster);
    }

    static byte[] pb512FileEncodeBytes(byte[] data,
                                                  String extension,
                                                  String password,
                                                  boolean useMaster,
                                                  boolean stripMetadata) {
        return Pb512FileCodec.pb512FileEncodeBytes(data, extension, password, useMaster, stripMetadata);
    }

    static BaseFwx.DecodedFile pb512FileDecodeBytes(byte[] blob,
                                                       String password,
                                                       boolean useMaster) {
        return Pb512FileCodec.pb512FileDecodeBytes(blob, password, useMaster);
    }

    static BaseFwx.DecodedFile pb512FileDecodeBytes(byte[] blob,
                                                       String password,
                                                       boolean useMaster,
                                                       boolean stripMetadata) {
        return Pb512FileCodec.pb512FileDecodeBytes(blob, password, useMaster, stripMetadata);
    }

    static File pb512FileEncodeFile(File input,
                                              File output,
                                              String password,
                                              boolean useMaster) {
        return Pb512FileCodec.pb512FileEncodeFile(input, output, password, useMaster);
    }

    static File pb512FileDecodeFile(File input,
                                               File output,
                                               String password,
                                               boolean useMaster) {
        return Pb512FileCodec.pb512FileDecodeFile(input, output, password, useMaster);
    }

}
