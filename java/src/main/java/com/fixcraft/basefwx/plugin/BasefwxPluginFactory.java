// SPDX-License-Identifier: GPL-3.0-or-later

package com.fixcraft.basefwx.plugin;

/**
 * Factory for {@link BasefwxPlugin} instances. A plugin .jar ships
 * exactly one implementation of this interface — discovered by Java's
 * {@link java.util.ServiceLoader} mechanism via the resource
 * <code>META-INF/services/com.fixcraft.basefwx.plugin.BasefwxPluginFactory</code>.
 *
 * <p>The factory is the right place to expose plugin metadata
 * ({@link #pluginId()}, {@link #name()}, {@link #version()}) without
 * paying the cost of instantiating the plugin itself. The host enumerates
 * all factories on the classpath, picks the one whose {@code pluginId}
 * matches the wrap header, and only then calls {@link #create(byte[])}.
 *
 * <p>Implementations MUST be stateless and thread-safe — factories
 * are looked up lazily and may be queried from multiple threads.
 */
public interface BasefwxPluginFactory {

    /** Stable 16-byte plugin identifier. Same value as the instance returns. */
    byte[] pluginId();

    /** Human-readable plugin name. */
    String name();

    /** Plugin version (semver). */
    String version();

    /**
     * Create a plugin instance using the deployment-specific config blob.
     *
     * @param config opaque byte blob from the caller (may be empty;
     *               may be {@code null})
     * @return a fresh {@link BasefwxPlugin} instance owned by the caller;
     *         caller is responsible for calling {@link BasefwxPlugin#close()}
     *         when done
     * @throws BasefwxPluginException if config is invalid or instance
     *         creation fails
     */
    BasefwxPlugin create(byte[] config) throws BasefwxPluginException;
}
