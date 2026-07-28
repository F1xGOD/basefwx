/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

package com.fixcraft.basefwx.cli;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class BaseFwxCliTelemetryTest {
    public static final class ModernBean {
        public double getCpuLoad() {
            return 0.25d;
        }

        public long getTotalMemorySize() {
            return 4096L;
        }
    }

    public static final class LegacyBean {
        public double getSystemCpuLoad() {
            return 0.5d;
        }

        public long getTotalPhysicalMemorySize() {
            return 8192L;
        }
    }

    public static final class InvalidModernBean {
        public String getCpuLoad() {
            return "unavailable";
        }

        public double getSystemCpuLoad() {
            return 0.75d;
        }
    }

    @Test
    public void modernAndLegacyMetricNamesAreCompatible() {
        assertEquals(
                0.25d,
                BaseFwxCli.readOperatingSystemMetric(
                        new ModernBean(),
                        "getCpuLoad",
                        "getSystemCpuLoad").doubleValue(),
                0.0d);
        assertEquals(
                4096L,
                BaseFwxCli.readOperatingSystemMetric(
                        new ModernBean(),
                        "getTotalMemorySize",
                        "getTotalPhysicalMemorySize").longValue());
        assertEquals(
                0.5d,
                BaseFwxCli.readOperatingSystemMetric(
                        new LegacyBean(),
                        "getCpuLoad",
                        "getSystemCpuLoad").doubleValue(),
                0.0d);
        assertEquals(
                8192L,
                BaseFwxCli.readOperatingSystemMetric(
                        new LegacyBean(),
                        "getTotalMemorySize",
                        "getTotalPhysicalMemorySize").longValue());
    }

    @Test
    public void invalidOrMissingMetricsFailHarmlessly() {
        assertEquals(
                0.75d,
                BaseFwxCli.readOperatingSystemMetric(
                        new InvalidModernBean(),
                        "getCpuLoad",
                        "getSystemCpuLoad").doubleValue(),
                0.0d);
        assertNull(
                BaseFwxCli.readOperatingSystemMetric(
                        new Object(),
                        "getCpuLoad",
                        "getSystemCpuLoad"));
        assertNull(
                BaseFwxCli.readOperatingSystemMetric(
                        null,
                        "getCpuLoad",
                        "getSystemCpuLoad"));
    }
}
