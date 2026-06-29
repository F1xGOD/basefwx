// Licensed under the GNU Lesser General Public License v3.0 or later.
//
// Java SPI for BaseFWX blackbox plugins. Implementing classes can be
// shipped as a .jar that's added to the classpath (or via Java's
// `ServiceLoader` mechanism). Plugin .jars are NOT considered
// derivative works of BaseFWX as long as they only depend on this
// SPI package and ship as a separate artifact — see LICENSING.md
// for the safe-harbor rules.

package com.fixcraft.basefwx.plugin;

/**
 * A BaseFWX blackbox plugin. A plugin is a pair of byte transforms —
 * {@link #forward(byte[], int, int, byte[], int)} and
 * {@link #inverse(byte[], int, int, byte[], int)} — that wrap the
 * AEAD payload at encrypt time and unwrap it at decrypt time.
 *
 * <p>Plugins are loaded via Java's {@link java.util.ServiceLoader}
 * (look up <code>META-INF/services/com.fixcraft.basefwx.plugin.BasefwxPlugin</code>
 * in your plugin .jar) or via a direct {@link BasefwxPluginRegistry#register(BasefwxPlugin)}
 * call. The {@link #pluginId()} bytes go into the wrap header at
 * encrypt time, so a peer that doesn't have the matching plugin
 * loaded refuses the blob before any decryption happens.
 *
 * <p>This Java SPI is the counterpart of the C/C++ ABI in
 * <code>cpp/include/basefwx/plugin.h</code>. A .so plugin loaded
 * through the JNI bridge appears in Java as a {@link BasefwxPlugin}
 * implementation backed by the native vtable; pure-Java plugins
 * shipped as a .jar implement this interface directly.
 *
 * <h2>Contract</h2>
 *
 * <ol>
 *   <li>{@link #pluginId()} is a stable 16-byte identifier — generate
 *       once with <code>uuidgen</code>, freeze the bytes, never
 *       change them.</li>
 *   <li>{@link #forward} and {@link #inverse} are exact inverses:
 *       for any input <code>x</code>,
 *       <code>inverse(forward(x)) == x</code> byte-for-byte.</li>
 *   <li>Both transforms are deterministic. Two calls with the same
 *       input on the same instance produce the same output.</li>
 *   <li>Length change is allowed: {@link #maxOutputForInput} reports
 *       the worst-case output length for a given input length, and
 *       the host pre-sizes the destination buffer accordingly.</li>
 *   <li>One instance per session. The host creates instances via
 *       {@link BasefwxPluginFactory}; the factory's
 *       <code>create(byte[] config)</code> method receives a
 *       deployment-specific config blob.</li>
 *   <li>{@link #close()} wipes any sensitive state and is called
 *       exactly once. The interface extends {@link AutoCloseable}
 *       so try-with-resources just works.</li>
 * </ol>
 *
 * <h2>Position</h2>
 *
 * Plugins declare which pipeline positions they support via
 * {@link #supportedPositions()}. The two flags
 * ({@link Position#PRE_AEAD} and {@link Position#POST_AEAD}) can be
 * OR-ed together if your transform makes sense in both. The host
 * refuses to use a plugin in a position it didn't claim.
 *
 * <h2>Errors</h2>
 *
 * Throw a {@link BasefwxPluginException} subclass for clean error
 * reporting; arbitrary exceptions are caught and surfaced as
 * generic plugin failures.
 */
public interface BasefwxPlugin extends AutoCloseable {

    /** Length of the stable plugin identifier in bytes. */
    int PLUGIN_ID_LEN = 16;

    /** ABI version this Java SPI conforms to. Match against
     *  {@link BasefwxPluginRegistry#API_VERSION} at load time. */
    int API_VERSION = 1;

    /**
     * Stable 16-byte identifier for this plugin's transform.
     * The same value goes into the wrap header at encrypt time
     * and is used by decoders to look up the right plugin.
     *
     * <p>Implementations MUST return a freshly allocated array
     * (or a defensive copy) — callers may keep the reference.
     *
     * <p>Generate with <code>uuidgen</code> and hard-code the
     * bytes; never derive at runtime.
     */
    byte[] pluginId();

    /** Human-readable plugin name (≤ 64 ASCII chars). */
    String name();

    /** Plugin's own semver string (free-form, ≤ 64 chars). */
    String version();

    /**
     * Bitmask of {@link Position} values this plugin supports.
     * At least one bit must be set.
     */
    int supportedPositions();

    /**
     * Worst-case output length for an input of {@code inLen} bytes.
     * For length-preserving plugins, return {@code inLen}. The host
     * uses this to size the output buffer before calling
     * {@link #forward}.
     */
    int maxOutputForInput(int inLen);

    /**
     * Forward transform — used at encrypt time. Reads {@code inLen}
     * bytes from {@code in} starting at {@code inOffset}, writes
     * the transformed output to {@code out} starting at
     * {@code outOffset}, and returns the number of bytes written.
     *
     * <p>The output buffer is sized by the host using
     * {@link #maxOutputForInput(int)}. If your transform somehow
     * produces more bytes, throw {@link BasefwxPluginException.OutputTooSmall};
     * the host will surface that as a clean error rather than a
     * silent overrun.
     *
     * @return number of bytes written to {@code out}
     */
    int forward(byte[] in, int inOffset, int inLen,
                byte[] out, int outOffset) throws BasefwxPluginException;

    /**
     * Inverse transform — used at decrypt time. Must be the exact
     * inverse of {@link #forward}. If the input doesn't look like
     * valid forward()-output (truncated payload, wrong magic,
     * whatever your transform considers malformed), throw
     * {@link BasefwxPluginException.BadInput}.
     *
     * @return number of bytes written to {@code out}
     */
    int inverse(byte[] in, int inOffset, int inLen,
                byte[] out, int outOffset) throws BasefwxPluginException;

    /**
     * Optional self-test. Default implementation runs a fixed
     * 32-byte round-trip through forward → inverse. Override to
     * test your own vectors. Return {@code true} when all tests
     * pass.
     *
     * @return true if the plugin's internal vectors round-trip cleanly
     */
    default boolean selftest() {
        final byte[] kVec = {
            (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
            (byte)0x00, (byte)0xff, (byte)0x10, (byte)0x20,
            (byte)0xa5, (byte)0xa5, (byte)0x5a, (byte)0x5a,
            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44,
            (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
            (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc,
            (byte)0xdd, (byte)0xee, (byte)0xff, (byte)0x00,
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
        };
        final int cap = maxOutputForInput(kVec.length);
        final byte[] mid = new byte[cap];
        final byte[] back = new byte[cap];
        try {
            int n1 = forward(kVec, 0, kVec.length, mid, 0);
            if (n1 < 0 || n1 > cap) return false;
            int n2 = inverse(mid, 0, n1, back, 0);
            if (n2 != kVec.length) return false;
            for (int i = 0; i < kVec.length; i++) {
                if (kVec[i] != back[i]) return false;
            }
            return true;
        } catch (BasefwxPluginException exc) {
            return false;
        }
    }

    /**
     * Release any sensitive state. Called by the host exactly once
     * per instance. Use {@link java.util.Arrays#fill(byte[], byte)}
     * to wipe key material before the references become GC'able —
     * see {@link com.fixcraft.basefwx.LiveCipher.LiveEncryptor#close()}
     * for the reference pattern.
     */
    @Override
    void close();

    /** Pipeline positions a plugin can occupy. */
    final class Position {
        private Position() {}

        /** Plugin runs on the plaintext before AEAD wraps it. */
        public static final int PRE_AEAD = 1 << 0;

        /** Plugin runs on the AEAD ciphertext on the way out the door. */
        public static final int POST_AEAD = 1 << 1;
    }
}
