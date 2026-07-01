/*
 * BaseFWX example plugin
 * Copyright (C) 2020-2026  FixCraft Inc.
 * SPDX-License-Identifier: MIT OR Apache-2.0
 * This file is intentionally permissive so plugin authors can use it as a starting template.
 */


package com.example.basefwx.plugin;

import com.fixcraft.basefwx.plugin.BasefwxPlugin;
import com.fixcraft.basefwx.plugin.BasefwxPluginException;
import com.fixcraft.basefwx.plugin.BasefwxPluginFactory;

import java.util.Arrays;

public final class XorRotatePlugin implements BasefwxPlugin {
    // 8d4c2a01-1f70-4d3a-91ab-2c5e8f917b04
    // SAME id as the C++ example so a Java consumer can round-trip
    // payloads through the C++ host's plugin and vice versa.
    private static final byte[] PLUGIN_ID = {
        (byte)0x8d, (byte)0x4c, (byte)0x2a, (byte)0x01,
        (byte)0x1f, (byte)0x70, (byte)0x4d, (byte)0x3a,
        (byte)0x91, (byte)0xab, (byte)0x2c, (byte)0x5e,
        (byte)0x8f, (byte)0x91, (byte)0x7b, (byte)0x04,
    };

    private static final int KEY_LEN = 32;
    private final byte[] key;     // wiped in close()
    private boolean closed;

    XorRotatePlugin(byte[] config) throws BasefwxPluginException {
        if (config == null || config.length != KEY_LEN) {
            throw new BasefwxPluginException.BadInput(
                "xor-rotate requires exactly 32 bytes of config (the XOR key)");
        }
        this.key = Arrays.copyOf(config, KEY_LEN);
    }

    @Override
    public byte[] pluginId() { return Arrays.copyOf(PLUGIN_ID, PLUGIN_ID.length); }

    @Override
    public String name() { return "xor-rotate"; }

    @Override
    public String version() { return "1.0.0"; }

    @Override
    public int supportedPositions() {
        return Position.PRE_AEAD | Position.POST_AEAD;
    }

    @Override
    public int maxOutputForInput(int inLen) { return inLen; }

    @Override
    public int forward(byte[] in, int inOffset, int inLen,
                       byte[] out, int outOffset) throws BasefwxPluginException {
        return transform(in, inOffset, inLen, out, outOffset);
    }

    @Override
    public int inverse(byte[] in, int inOffset, int inLen,
                       byte[] out, int outOffset) throws BasefwxPluginException {
        return transform(in, inOffset, inLen, out, outOffset);  // XOR is self-inverse
    }

    private int transform(byte[] in, int inOffset, int inLen,
                          byte[] out, int outOffset) throws BasefwxPluginException {
        if (closed) {
            throw new BasefwxPluginException.BadState("plugin already closed");
        }
        if (inOffset < 0 || inLen < 0 || outOffset < 0
            || inOffset + inLen > in.length
            || outOffset + inLen > out.length) {
            throw new BasefwxPluginException.OutputTooSmall(
                "xor-rotate: buffer ranges out of bounds");
        }
        for (int i = 0; i < inLen; i++) {
            byte k = key[i % KEY_LEN];
            byte roll = (byte) (i * 31);
            out[outOffset + i] = (byte) (in[inOffset + i] ^ k ^ roll);
        }
        return inLen;
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        Arrays.fill(key, (byte) 0);
    }

    /**
     * ServiceLoader-discovered factory. The plugin .jar's
     * META-INF/services/com.fixcraft.basefwx.plugin.BasefwxPluginFactory
     * file lists this class name; BaseFWX picks it up at startup.
     */
    public static final class Factory implements BasefwxPluginFactory {
        @Override
        public byte[] pluginId() { return Arrays.copyOf(PLUGIN_ID, PLUGIN_ID.length); }

        @Override
        public String name() { return "xor-rotate"; }

        @Override
        public String version() { return "1.0.0"; }

        @Override
        public BasefwxPlugin create(byte[] config) throws BasefwxPluginException {
            return new XorRotatePlugin(config);
        }
    }
}
