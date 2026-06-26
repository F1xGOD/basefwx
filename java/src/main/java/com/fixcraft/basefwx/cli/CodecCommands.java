/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;

import java.io.File;
import java.nio.charset.StandardCharsets;

final class CodecCommands {
    private CodecCommands() {}

    /** @return 0 handled, 1 usage, -1 not handled */
    static int handle(String command, String[] args, int argc, boolean useMaster) {
        switch (command) {
            case "b512-enc":
                if (argc < 3) {
                    return 1;
                }
                System.out.println(BaseFwx.b512Encode(args[1], args[2], useMaster));
                return 0;
            case "b512-dec":
                if (argc < 3) {
                    return 1;
                }
                System.out.println(BaseFwx.b512Decode(args[1], args[2], useMaster));
                return 0;
            case "pb512-enc":
                if (argc < 3) {
                    return 1;
                }
                System.out.println(BaseFwx.pb512Encode(args[1], args[2], useMaster));
                return 0;
            case "pb512-dec":
                if (argc < 3) {
                    return 1;
                }
                System.out.println(BaseFwx.pb512Decode(args[1], args[2], useMaster));
                return 0;
            case "n10-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.n10Encode(args[1]));
                return 0;
            case "n10-dec":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.n10Decode(args[1]));
                return 0;
            case "n10file-enc":
                if (argc < 3) {
                    return 1;
                }
                try {
                    byte[] data = java.nio.file.Files.readAllBytes(new File(args[1]).toPath());
                    String digits = BaseFwx.n10EncodeBytes(data);
                    java.nio.file.Files.write(new File(args[2]).toPath(), digits.getBytes(StandardCharsets.UTF_8));
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("n10 file encode failed", exc);
                }
                return 0;
            case "n10file-dec":
                if (argc < 3) {
                    return 1;
                }
                try {
                    String digits = new String(java.nio.file.Files.readAllBytes(new File(args[1]).toPath()), StandardCharsets.UTF_8);
                    byte[] decoded = BaseFwx.n10DecodeBytes(digits);
                    java.nio.file.Files.write(new File(args[2]).toPath(), decoded);
                } catch (java.io.IOException exc) {
                    throw new RuntimeException("n10 file decode failed", exc);
                }
                return 0;
            case "b256-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.b256Encode(args[1]));
                return 0;
            case "b256-dec":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.b256Decode(args[1]));
                return 0;
            case "b64-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.b64Encode(args[1]));
                return 0;
            case "b64-dec":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.b64Decode(args[1]));
                return 0;
            case "hash512":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.hash512(args[1]));
                return 0;
            case "uhash513":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.uhash513(args[1]));
                return 0;
            case "a512-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.a512Encode(args[1]));
                return 0;
            case "a512-dec":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.a512Decode(args[1]));
                return 0;
            case "bi512-enc":
                if (argc < 2) {
                    return 1;
                }
                System.out.println(BaseFwx.bi512Encode(args[1]));
                return 0;
            // b1024-enc retired in 3.6.5; was `bi512-enc $(a512-enc text)`.
            default:
                return -1;
        }
    }

    static String encodeText(String method, String text, String password, boolean useMaster) {
        switch (method) {
            case "b64":
                return BaseFwx.b64Encode(text);
            case "b256":
                return BaseFwx.b256Encode(text);
            case "a512":
                return BaseFwx.a512Encode(text);
            case "n10":
                return BaseFwx.n10Encode(text);
            case "b512":
                return BaseFwx.b512Encode(text, password, useMaster);
            case "pb512":
                return BaseFwx.pb512Encode(text, password, useMaster);
            default:
                throw new IllegalArgumentException("Unsupported method " + method);
        }
    }

    static String decodeText(String method, String text, String password, boolean useMaster) {
        switch (method) {
            case "b64":
                return BaseFwx.b64Decode(text);
            case "b256":
                return BaseFwx.b256Decode(text);
            case "a512":
                return BaseFwx.a512Decode(text);
            case "n10":
                return BaseFwx.n10Decode(text);
            case "b512":
                return BaseFwx.b512Decode(text, password, useMaster);
            case "pb512":
                return BaseFwx.pb512Decode(text, password, useMaster);
            default:
                throw new IllegalArgumentException("Unsupported method " + method);
        }
    }

    static String hashText(String method, String text) {
        switch (method) {
            case "hash512":
                return BaseFwx.hash512(text);
            case "uhash513":
                return BaseFwx.uhash513(text);
            case "bi512":
                return BaseFwx.bi512Encode(text);
            // b1024 retired in 3.6.5; chain bi512(a512(text)) in caller code.
            default:
                throw new IllegalArgumentException("Unsupported hash method " + method);
        }
    }
}
