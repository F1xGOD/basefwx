// Licensed under the GNU Lesser General Public License v3.0 or later.

package com.fixcraft.basefwx.plugin;

/**
 * Base class for clean error reporting from a {@link BasefwxPlugin}.
 * Each concrete subclass maps to one of the {@code BASEFWX_PLUGIN_ERR_*}
 * codes on the native ABI side, so a Java-side throw bubbles up to
 * a C++ caller (via the JNI bridge) as the right error code.
 *
 * <p>Plugin authors should throw the most specific subclass that
 * matches their failure mode. Anything else thrown by the plugin is
 * caught by the host and reported as a generic plugin failure
 * (equivalent to {@link Generic} but without the message context).
 */
public class BasefwxPluginException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Native-ABI error code this exception maps to. */
    private final int nativeCode;

    protected BasefwxPluginException(int nativeCode, String message) {
        super(message);
        this.nativeCode = nativeCode;
    }

    protected BasefwxPluginException(int nativeCode, String message, Throwable cause) {
        super(message, cause);
        this.nativeCode = nativeCode;
    }

    /** The {@code BASEFWX_PLUGIN_ERR_*} value this exception maps to. */
    public final int nativeCode() {
        return nativeCode;
    }

    // ----- Mappings to BASEFWX_PLUGIN_ERR_* (plugin.h) ---------------

    /** {@code BASEFWX_PLUGIN_ERR_GENERIC} — internal error with no better code. */
    public static class Generic extends BasefwxPluginException {
        private static final long serialVersionUID = 1L;
        public Generic(String message) { super(-1, message); }
        public Generic(String message, Throwable cause) { super(-1, message, cause); }
    }

    /** {@code BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL} — caller-provided output buffer is too small. */
    public static class OutputTooSmall extends BasefwxPluginException {
        private static final long serialVersionUID = 1L;
        public OutputTooSmall(String message) { super(-2, message); }
    }

    /** {@code BASEFWX_PLUGIN_ERR_BAD_INPUT} — input doesn't satisfy the plugin's preconditions. */
    public static class BadInput extends BasefwxPluginException {
        private static final long serialVersionUID = 1L;
        public BadInput(String message) { super(-3, message); }
        public BadInput(String message, Throwable cause) { super(-3, message, cause); }
    }

    /** {@code BASEFWX_PLUGIN_ERR_BAD_STATE} — called before init() or after close(). */
    public static class BadState extends BasefwxPluginException {
        private static final long serialVersionUID = 1L;
        public BadState(String message) { super(-4, message); }
    }

    /** {@code BASEFWX_PLUGIN_ERR_NOT_SUPPORTED} — feature requested but not implemented. */
    public static class NotSupported extends BasefwxPluginException {
        private static final long serialVersionUID = 1L;
        public NotSupported(String message) { super(-5, message); }
    }
}
