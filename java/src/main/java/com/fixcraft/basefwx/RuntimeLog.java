package com.fixcraft.basefwx;

import java.util.Locale;

public final class RuntimeLog {
    private static volatile Boolean cliVerbose = null;
    private static volatile Boolean cliNoLog = null;

    private RuntimeLog() {}

    public static void configureFromCli(boolean verbose, boolean noLog) {
        cliVerbose = Boolean.valueOf(verbose);
        cliNoLog = Boolean.valueOf(noLog);
        System.setProperty("basefwx.verbose", verbose ? "1" : "0");
        System.setProperty("basefwx.noLog", noLog ? "1" : "0");
    }

    public static boolean isVerbose() {
        if (cliVerbose != null) {
            return cliVerbose.booleanValue();
        }
        if (truthy(System.getProperty("basefwx.verbose"))) {
            return true;
        }
        return truthy(System.getenv("BASEFWX_VERBOSE"));
    }

    public static boolean isNoLog() {
        if (cliNoLog != null) {
            return cliNoLog.booleanValue();
        }
        if (truthy(System.getProperty("basefwx.noLog"))) {
            return true;
        }
        return truthy(System.getenv("BASEFWX_NO_LOG"));
    }

    public static boolean shouldLog() {
        return !isNoLog();
    }

    public static void warn(String message) {
        if (!shouldLog()) {
            return;
        }
        System.err.println("WARN: " + message);
    }

    public static void info(String message) {
        if (!shouldLog()) {
            return;
        }
        System.err.println(message);
    }

    public static void hwLine(String message) {
        if (!shouldLog()) {
            return;
        }
        System.err.println(message);
    }

    public static void hwReason(String message) {
        if (!shouldLog() || !isVerbose()) {
            return;
        }
        System.err.println("   reason: " + message);
    }

    private static boolean truthy(String raw) {
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase(Locale.US);
        return "1".equals(value) || "true".equals(value) || "yes".equals(value) || "on".equals(value);
    }
}
