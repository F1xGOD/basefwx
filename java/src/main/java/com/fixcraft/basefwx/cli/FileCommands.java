/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

package com.fixcraft.basefwx.cli;

import com.fixcraft.basefwx.BaseFwx;

import java.io.File;

final class FileCommands {
    private FileCommands() {}

    /** @return 0 handled, 1 usage, -1 not handled */
    static int handle(String command, String[] args, int argc, boolean useMaster) {
        switch (command) {
            case "b512file-enc":
                if (argc < 4) {
                    return 1;
                }
                BaseFwx.b512FileEncodeFile(new File(args[1]), new File(args[2]), args[3], useMaster);
                return 0;
            case "b512file-bytes-rt":
                if (argc < 4) {
                    return 1;
                }
                return b512fileBytesRt(args, useMaster);
            case "b512file-dec":
                if (argc < 4) {
                    return 1;
                }
                BaseFwx.b512FileDecodeFile(new File(args[1]), new File(args[2]), args[3], useMaster);
                return 0;
            case "pb512file-enc":
                if (argc < 4) {
                    return 1;
                }
                BaseFwx.pb512FileEncodeFile(new File(args[1]), new File(args[2]), args[3], useMaster);
                return 0;
            case "pb512file-dec":
                if (argc < 4) {
                    return 1;
                }
                BaseFwx.pb512FileDecodeFile(new File(args[1]), new File(args[2]), args[3], useMaster);
                return 0;
            case "pb512file-bytes-rt":
                if (argc < 4) {
                    return 1;
                }
                return pb512fileBytesRt(args, useMaster);
            default:
                return -1;
        }
    }

    private static int b512fileBytesRt(String[] args, boolean useMaster) {
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
        return 0;
    }

    private static int pb512fileBytesRt(String[] args, boolean useMaster) {
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
        return 0;
    }
}
