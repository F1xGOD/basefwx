package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class BaseFwxCli {
    private static volatile int BENCH_SINK = 0;

    private BaseFwxCli() {}

    private static byte[] readAllBytes(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (java.io.IOException exc) {
            throw new RuntimeException("Failed to read file: " + file.getPath(), exc);
        }
    }

    private static String readText(File file) {
        byte[] data = readAllBytes(file);
        return new String(data, StandardCharsets.UTF_8);
    }

    private static int benchWarmup() {
        String value = System.getenv("BASEFWX_BENCH_WARMUP");
        if (value == null || value.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException exc) {
            return 0;
        }
    }

    private static String encodeText(String method, String text, String password, boolean useMaster) {
        switch (method) {
            case "b64":
                return BaseFwx.b64Encode(text);
            case "b256":
                return BaseFwx.b256Encode(text);
            case "a512":
                return BaseFwx.a512Encode(text);
            case "b512":
                return BaseFwx.b512Encode(text, password, useMaster);
            case "pb512":
                return BaseFwx.pb512Encode(text, password, useMaster);
            default:
                throw new IllegalArgumentException("Unsupported method " + method);
        }
    }

    private static String decodeText(String method, String text, String password, boolean useMaster) {
        switch (method) {
            case "b64":
                return BaseFwx.b64Decode(text);
            case "b256":
                return BaseFwx.b256Decode(text);
            case "a512":
                return BaseFwx.a512Decode(text);
            case "b512":
                return BaseFwx.b512Decode(text, password, useMaster);
            case "pb512":
                return BaseFwx.pb512Decode(text, password, useMaster);
            default:
                throw new IllegalArgumentException("Unsupported method " + method);
        }
    }

    private static String hashText(String method, String text) {
        switch (method) {
            case "hash512":
                return BaseFwx.hash512(text);
            case "uhash513":
                return BaseFwx.uhash513(text);
            case "bi512":
                return BaseFwx.bi512Encode(text);
            case "b1024":
                return BaseFwx.b1024Encode(text);
            default:
                throw new IllegalArgumentException("Unsupported hash method " + method);
        }
    }

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            usage();
            return;
        }
        String command = args[0];
        boolean useMaster = true;
        int argc = args.length;
        for (String arg : args) {
            if ("--no-master".equalsIgnoreCase(arg)) {
                useMaster = false;
            }
        }

        try {
            switch (command) {
                case "fwxaes-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File inEnc = new File(args[1]);
                    File outEnc = new File(args[2]);
                    String passEnc = args[3];
                    BaseFwx.fwxAesEncryptFile(inEnc, outEnc, passEnc, useMaster);
                    return;
                case "fwxaes-stream-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                         java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                        BaseFwx.fwxAesEncryptStream(inStream, outStream, args[3], useMaster);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("fwxAES stream encrypt failed", exc);
                    }
                    return;
                case "fwxaes-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File inDec = new File(args[1]);
                    File outDec = new File(args[2]);
                    String passDec = args[3];
                    BaseFwx.fwxAesDecryptFile(inDec, outDec, passDec, useMaster);
                    return;
                case "fwxaes-stream-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    try (java.io.FileInputStream inStream = new java.io.FileInputStream(args[1]);
                         java.io.FileOutputStream outStream = new java.io.FileOutputStream(args[2])) {
                        BaseFwx.fwxAesDecryptStream(inStream, outStream, args[3], useMaster);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("fwxAES stream decrypt failed", exc);
                    }
                    return;
                case "b512-enc":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b512Encode(args[1], args[2], useMaster));
                    return;
                case "b512-dec":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b512Decode(args[1], args[2], useMaster));
                    return;
                case "pb512-enc":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.pb512Encode(args[1], args[2], useMaster));
                    return;
                case "pb512-dec":
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.pb512Decode(args[1], args[2], useMaster));
                    return;
                case "b512file-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File b512In = new File(args[1]);
                    File b512Out = new File(args[2]);
                    String b512Pass = args[3];
                    BaseFwx.b512FileEncodeFile(b512In, b512Out, b512Pass, useMaster);
                    return;
                case "b512file-bytes-rt":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File b512BytesIn = new File(args[1]);
                    File b512BytesOut = new File(args[2]);
                    String b512BytesPass = args[3];
                    try {
                        byte[] data = java.nio.file.Files.readAllBytes(b512BytesIn.toPath());
                        String name = b512BytesIn.getName();
                        int dot = name.lastIndexOf('.');
                        String ext = dot >= 0 ? name.substring(dot) : "";
                        byte[] blob = BaseFwx.b512FileEncodeBytes(data, ext, b512BytesPass, useMaster);
                        BaseFwx.DecodedFile decoded = BaseFwx.b512FileDecodeBytes(blob, b512BytesPass, useMaster);
                        java.nio.file.Files.write(b512BytesOut.toPath(), decoded.data);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("b512file bytes roundtrip failed", exc);
                    }
                    return;
                case "b512file-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File b512DecIn = new File(args[1]);
                    File b512DecOut = new File(args[2]);
                    String b512DecPass = args[3];
                    BaseFwx.b512FileDecodeFile(b512DecIn, b512DecOut, b512DecPass, useMaster);
                    return;
                case "pb512file-enc":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File pb512In = new File(args[1]);
                    File pb512Out = new File(args[2]);
                    String pb512Pass = args[3];
                    BaseFwx.pb512FileEncodeFile(pb512In, pb512Out, pb512Pass, useMaster);
                    return;
                case "pb512file-dec":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File pb512DecIn = new File(args[1]);
                    File pb512DecOut = new File(args[2]);
                    String pb512DecPass = args[3];
                    BaseFwx.pb512FileDecodeFile(pb512DecIn, pb512DecOut, pb512DecPass, useMaster);
                    return;
                case "pb512file-bytes-rt":
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    File pb512BytesIn = new File(args[1]);
                    File pb512BytesOut = new File(args[2]);
                    String pb512BytesPass = args[3];
                    try {
                        byte[] data = java.nio.file.Files.readAllBytes(pb512BytesIn.toPath());
                        String name = pb512BytesIn.getName();
                        int dot = name.lastIndexOf('.');
                        String ext = dot >= 0 ? name.substring(dot) : "";
                        byte[] blob = BaseFwx.pb512FileEncodeBytes(data, ext, pb512BytesPass, useMaster);
                        BaseFwx.DecodedFile decoded = BaseFwx.pb512FileDecodeBytes(blob, pb512BytesPass, useMaster);
                        java.nio.file.Files.write(pb512BytesOut.toPath(), decoded.data);
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("pb512file bytes roundtrip failed", exc);
                    }
                    return;
                case "bench-text": {
                    if (argc < 4) {
                        usage();
                        return;
                    }
                    String method = args[1].toLowerCase();
                    File textFile = new File(args[2]);
                    String benchPass = args[3];
                    int warmup = benchWarmup();
                    String text = readText(textFile);
                    for (int i = 0; i < warmup; i++) {
                        String enc = encodeText(method, text, benchPass, useMaster);
                        String dec = decodeText(method, enc, benchPass, useMaster);
                        BENCH_SINK ^= dec.length();
                    }
                    long start = System.nanoTime();
                    String enc = encodeText(method, text, benchPass, useMaster);
                    String dec = decodeText(method, enc, benchPass, useMaster);
                    long end = System.nanoTime();
                    BENCH_SINK ^= dec.length();
                    System.out.println("BENCH_NS=" + (end - start));
                    return;
                }
                case "bench-hash": {
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    String method = args[1].toLowerCase();
                    File textFile = new File(args[2]);
                    int warmup = benchWarmup();
                    String text = readText(textFile);
                    for (int i = 0; i < warmup; i++) {
                        String digest = hashText(method, text);
                        BENCH_SINK ^= digest.length();
                    }
                    long start = System.nanoTime();
                    String digest = hashText(method, text);
                    long end = System.nanoTime();
                    BENCH_SINK ^= digest.length();
                    System.out.println("BENCH_NS=" + (end - start));
                    return;
                }
                case "bench-fwxaes": {
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    File input = new File(args[1]);
                    String benchPass = args[2];
                    int warmup = benchWarmup();
                    byte[] data = readAllBytes(input);
                    for (int i = 0; i < warmup; i++) {
                        byte[] blob = BaseFwx.fwxAesEncryptRaw(data, benchPass, useMaster);
                        byte[] plain = BaseFwx.fwxAesDecryptRaw(blob, benchPass, useMaster);
                        BENCH_SINK ^= plain.length;
                    }
                    long start = System.nanoTime();
                    byte[] blob = BaseFwx.fwxAesEncryptRaw(data, benchPass, useMaster);
                    byte[] plain = BaseFwx.fwxAesDecryptRaw(blob, benchPass, useMaster);
                    long end = System.nanoTime();
                    BENCH_SINK ^= plain.length;
                    System.out.println("BENCH_NS=" + (end - start));
                    return;
                }
                case "bench-b512file": {
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    File input = new File(args[1]);
                    String benchPass = args[2];
                    int warmup = benchWarmup();
                    String name = input.getName();
                    int dot = name.lastIndexOf('.');
                    String ext = dot >= 0 ? name.substring(dot) : "";
                    File tempDir;
                    try {
                        tempDir = Files.createTempDirectory("basefwx-bench").toFile();
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("Failed to create bench temp dir", exc);
                    }
                    File encFile = new File(tempDir, "bench.fwx");
                    File decFile = new File(tempDir, "bench_dec" + ext);
                    try {
                        for (int i = 0; i < warmup; i++) {
                            BaseFwx.b512FileEncodeFile(input, encFile, benchPass, useMaster);
                            BaseFwx.b512FileDecodeFile(encFile, decFile, benchPass, useMaster);
                            BENCH_SINK ^= (int) decFile.length();
                        }
                        long start = System.nanoTime();
                        BaseFwx.b512FileEncodeFile(input, encFile, benchPass, useMaster);
                        BaseFwx.b512FileDecodeFile(encFile, decFile, benchPass, useMaster);
                        long end = System.nanoTime();
                        BENCH_SINK ^= (int) decFile.length();
                        System.out.println("BENCH_NS=" + (end - start));
                        return;
                    } finally {
                        encFile.delete();
                        decFile.delete();
                        tempDir.delete();
                    }
                }
                case "bench-pb512file": {
                    if (argc < 3) {
                        usage();
                        return;
                    }
                    File input = new File(args[1]);
                    String benchPass = args[2];
                    int warmup = benchWarmup();
                    String name = input.getName();
                    int dot = name.lastIndexOf('.');
                    String ext = dot >= 0 ? name.substring(dot) : "";
                    File tempDir;
                    try {
                        tempDir = Files.createTempDirectory("basefwx-bench").toFile();
                    } catch (java.io.IOException exc) {
                        throw new RuntimeException("Failed to create bench temp dir", exc);
                    }
                    File encFile = new File(tempDir, "bench.fwx");
                    File decFile = new File(tempDir, "bench_dec" + ext);
                    try {
                        for (int i = 0; i < warmup; i++) {
                            BaseFwx.pb512FileEncodeFile(input, encFile, benchPass, useMaster);
                            BaseFwx.pb512FileDecodeFile(encFile, decFile, benchPass, useMaster);
                            BENCH_SINK ^= (int) decFile.length();
                        }
                        long start = System.nanoTime();
                        BaseFwx.pb512FileEncodeFile(input, encFile, benchPass, useMaster);
                        BaseFwx.pb512FileDecodeFile(encFile, decFile, benchPass, useMaster);
                        long end = System.nanoTime();
                        BENCH_SINK ^= (int) decFile.length();
                        System.out.println("BENCH_NS=" + (end - start));
                        return;
                    } finally {
                        encFile.delete();
                        decFile.delete();
                        tempDir.delete();
                    }
                }
                case "b256-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b256Encode(args[1]));
                    return;
                case "b256-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b256Decode(args[1]));
                    return;
                case "b64-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b64Encode(args[1]));
                    return;
                case "b64-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b64Decode(args[1]));
                    return;
                case "hash512":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.hash512(args[1]));
                    return;
                case "uhash513":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.uhash513(args[1]));
                    return;
                case "a512-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.a512Encode(args[1]));
                    return;
                case "a512-dec":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.a512Decode(args[1]));
                    return;
                case "bi512-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.bi512Encode(args[1]));
                    return;
                case "b1024-enc":
                    if (argc < 2) {
                        usage();
                        return;
                    }
                    System.out.println(BaseFwx.b1024Encode(args[1]));
                    return;
                default:
                    usage();
            }
        } catch (RuntimeException exc) {
            System.err.println("Error: " + exc.getMessage());
            System.exit(1);
        }
    }

    private static void usage() {
        System.out.println("BaseFWX Java CLI");
        System.out.println("  fwxaes-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-dec <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-stream-enc <in> <out> <password> [--no-master]");
        System.out.println("  fwxaes-stream-dec <in> <out> <password> [--no-master]");
        System.out.println("  b64-enc <text>");
        System.out.println("  b64-dec <text>");
        System.out.println("  hash512 <text>");
        System.out.println("  uhash513 <text>");
        System.out.println("  a512-enc <text>");
        System.out.println("  a512-dec <text>");
        System.out.println("  bi512-enc <text>");
        System.out.println("  b1024-enc <text>");
        System.out.println("  b512-enc <text> <password> [--no-master]");
        System.out.println("  b512-dec <text> <password> [--no-master]");
        System.out.println("  pb512-enc <text> <password> [--no-master]");
        System.out.println("  pb512-dec <text> <password> [--no-master]");
        System.out.println("  b512file-enc <in> <out> <password> [--no-master]");
        System.out.println("  b512file-bytes-rt <in> <out> <password> [--no-master]");
        System.out.println("  b512file-dec <in> <out> <password> [--no-master]");
        System.out.println("  pb512file-enc <in> <out> <password> [--no-master]");
        System.out.println("  pb512file-bytes-rt <in> <out> <password> [--no-master]");
        System.out.println("  pb512file-dec <in> <out> <password> [--no-master]");
        System.out.println("  b256-enc <text>");
        System.out.println("  b256-dec <text>");
        System.out.println("  bench-text <method> <text-file> <password> [--no-master]");
        System.out.println("  bench-hash <method> <text-file>");
        System.out.println("  bench-fwxaes <file> <password> [--no-master]");
        System.out.println("  bench-b512file <file> <password> [--no-master]");
        System.out.println("  bench-pb512file <file> <password> [--no-master]");
    }
}
