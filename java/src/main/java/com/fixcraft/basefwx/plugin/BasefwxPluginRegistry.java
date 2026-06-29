// Licensed under the GNU Lesser General Public License v3.0 or later.

package com.fixcraft.basefwx.plugin;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Process-wide registry of available {@link BasefwxPluginFactory}s,
 * looked up by 16-byte plugin ID. The host queries this registry
 * with the {@code plugin_id} bytes from a wrap header to find the
 * factory that should create the matching plugin instance.
 *
 * <p>Two ways to populate the registry:
 *
 * <ol>
 *   <li><b>ServiceLoader discovery.</b> Drop a plugin .jar on the
 *       classpath with a
 *       <code>META-INF/services/com.fixcraft.basefwx.plugin.BasefwxPluginFactory</code>
 *       file listing the factory class name. Call
 *       {@link #discover()} once at host startup.</li>
 *   <li><b>Direct registration.</b> Call
 *       {@link #register(BasefwxPluginFactory)} explicitly — useful
 *       for tests, for embedded plugins, or when you want to avoid
 *       the implicit-classpath-scan behavior of ServiceLoader.</li>
 * </ol>
 *
 * <p>The registry only deals with pure-Java plugins. The native bridge
 * (loading a {@code .so} / {@code .dll} via JNI) is a separate path
 * that synthesizes a {@code BasefwxPluginFactory} on the fly from the
 * C ABI vtable.
 */
public final class BasefwxPluginRegistry {
    /** Java SPI version. Match against {@link BasefwxPlugin#API_VERSION}. */
    public static final int API_VERSION = BasefwxPlugin.API_VERSION;

    private static final Map<IdKey, BasefwxPluginFactory> FACTORIES = new HashMap<>();
    private static boolean discovered = false;

    private BasefwxPluginRegistry() {}

    /**
     * Walk the classpath for {@link BasefwxPluginFactory} implementations
     * registered via {@code META-INF/services} and add them to the
     * registry. Idempotent — calling more than once is a no-op after
     * the first successful scan.
     *
     * <p>Returns the number of factories discovered (cumulative count
     * after this call).
     */
    public static synchronized int discover() {
        if (!discovered) {
            ServiceLoader<BasefwxPluginFactory> loader = ServiceLoader.load(BasefwxPluginFactory.class);
            Iterator<BasefwxPluginFactory> it = loader.iterator();
            while (it.hasNext()) {
                try {
                    register(it.next());
                } catch (RuntimeException exc) {
                    // Skip factories that misbehave at registration time.
                    // The host will log this via its own logging path.
                }
            }
            discovered = true;
        }
        return FACTORIES.size();
    }

    /**
     * Register a factory directly. The factory's {@link BasefwxPluginFactory#pluginId()}
     * must be a 16-byte array; longer or shorter throws
     * {@link IllegalArgumentException}.
     *
     * <p>Re-registering the same plugin ID throws {@link IllegalStateException}
     * — the registry is append-only by design so two plugins can't
     * silently shadow each other.
     */
    public static synchronized void register(BasefwxPluginFactory factory) {
        if (factory == null) {
            throw new IllegalArgumentException("factory must not be null");
        }
        byte[] id = factory.pluginId();
        if (id == null || id.length != BasefwxPlugin.PLUGIN_ID_LEN) {
            throw new IllegalArgumentException(
                "pluginId() must return exactly " + BasefwxPlugin.PLUGIN_ID_LEN + " bytes");
        }
        IdKey key = new IdKey(id);
        if (FACTORIES.containsKey(key)) {
            throw new IllegalStateException(
                "plugin already registered for id " + key);
        }
        FACTORIES.put(key, factory);
    }

    /**
     * Look up the factory for a given plugin ID. Returns {@code null}
     * when no matching factory is registered (the host should treat
     * this as a clean "plugin not available" error).
     *
     * @param pluginId 16 bytes, copied defensively
     */
    public static synchronized BasefwxPluginFactory factoryFor(byte[] pluginId) {
        if (pluginId == null || pluginId.length != BasefwxPlugin.PLUGIN_ID_LEN) {
            return null;
        }
        return FACTORIES.get(new IdKey(pluginId));
    }

    /** Immutable snapshot of all currently registered factories. */
    public static synchronized Collection<BasefwxPluginFactory> all() {
        return Collections.unmodifiableCollection(new java.util.ArrayList<>(FACTORIES.values()));
    }

    /** For tests only — clears the registry so a fresh ServiceLoader pass can run. */
    static synchronized void clearForTests() {
        FACTORIES.clear();
        discovered = false;
    }

    // ----- internal: byte[] key with value-based equality ------------

    private static final class IdKey {
        private final byte[] bytes;
        private final int hash;

        IdKey(byte[] src) {
            this.bytes = Arrays.copyOf(src, src.length);
            this.hash = Arrays.hashCode(this.bytes);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof IdKey
                && Arrays.equals(this.bytes, ((IdKey) other).bytes);
        }

        @Override
        public int hashCode() { return hash; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(2 * BasefwxPlugin.PLUGIN_ID_LEN);
            for (byte b : bytes) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        }
    }
}
