package com.fixcraft.basefwx;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Loads a native shared library, first from {@code /native/<os>/<arch>/<libname>}
 * inside the running JAR (extracted to a temp file), then via
 * {@link System#loadLibrary(String)}. Returns false on failure so callers can
 * fall back to a pure-Java path.
 */
final class NativeLibraryLoader {

    private NativeLibraryLoader() {}

    static boolean load(String shortName) {
        if (loadFromJar(shortName)) return true;
        try {
            System.loadLibrary(shortName);
            return true;
        } catch (UnsatisfiedLinkError ignored) {
            return false;
        }
    }

    private static boolean loadFromJar(String shortName) {
        String os = detectOs();
        String arch = detectArch();
        if (os == null || arch == null) return false;
        String filename = System.mapLibraryName(shortName);
        String resource = "/native/" + os + "/" + arch + "/" + filename;
        try (InputStream in = NativeLibraryLoader.class.getResourceAsStream(resource)) {
            if (in == null) return false;
            Path tmp = Files.createTempFile("basefwx-" + shortName + "-", suffixFor(filename));
            tmp.toFile().deleteOnExit();
            Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
            System.load(tmp.toAbsolutePath().toString());
            return true;
        } catch (IOException | UnsatisfiedLinkError | SecurityException exc) {
            RuntimeLog.warn("native library extraction failed for " + resource + ": " + exc.getMessage());
            return false;
        }
    }

    private static String detectOs() {
        String name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.contains("linux")) return "linux";
        if (name.contains("mac") || name.contains("darwin")) return "macos";
        if (name.contains("win")) return "windows";
        if (name.contains("freebsd")) return "freebsd";
        return null;
    }

    private static String detectArch() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("amd64") || arch.equals("x86_64")) return "x86_64";
        if (arch.equals("x86") || arch.equals("i386") || arch.equals("i686")) return "x86";
        if (arch.equals("aarch64") || arch.equals("arm64")) return "aarch64";
        if (arch.startsWith("armv7") || arch.equals("arm")) return "armv7";
        return null;
    }

    private static String suffixFor(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot >= 0 ? filename.substring(dot) : "";
    }
}
