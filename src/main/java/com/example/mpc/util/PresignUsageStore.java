package com.example.mpc.util;

import com.example.mpc.common.util.HexUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class PresignUsageStore {
    private static final Path FILE = Paths.get("databases", "presign-usage.jsonl");
    private static final Object LOCK = new Object();
    private static final long DEFAULT_RETENTION_DAYS = 30L;
    private static final long MILLIS_PER_DAY = 24L * 60 * 60 * 1000;
    private static final long CLEANUP_INTERVAL_MILLIS = 60L * 60 * 1000;
    private static long lastCleanupMillis = 0L;
    private static volatile long retentionMillis = DEFAULT_RETENTION_DAYS * MILLIS_PER_DAY;

    private PresignUsageStore() {
    }

    public static boolean markUsed(String groupPublicKeyHex, ECPoint gamma) {
        String id = computeId(groupPublicKeyHex, gamma);
        synchronized (LOCK) {
            ensureFile();
            cleanupIfNeeded();
            if (isUsedInternal(id)) {
                return false;
            }
            writeLine(id);
            return true;
        }
    }

    public static boolean isUsed(String groupPublicKeyHex, ECPoint gamma) {
        String id = computeId(groupPublicKeyHex, gamma);
        synchronized (LOCK) {
            ensureFile();
            cleanupIfNeeded();
            return isUsedInternal(id);
        }
    }

    public static void configureRetentionDays(long days) {
        if (days <= 0) {
            retentionMillis = DEFAULT_RETENTION_DAYS * MILLIS_PER_DAY;
            return;
        }
        retentionMillis = days * MILLIS_PER_DAY;
    }

    private static String computeId(String groupPublicKeyHex, ECPoint gamma) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(HexUtils.hexToBytes(groupPublicKeyHex));
            md.update(gamma.getEncoded(false));
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Compute presign usage id failed", e);
        }
    }

    private static void ensureFile() {
        try {
            Files.createDirectories(FILE.getParent());
            if (!Files.exists(FILE)) {
                Files.writeString(FILE, "", StandardCharsets.UTF_8, StandardOpenOption.CREATE);
            }
        } catch (IOException e) {
            throw new RuntimeException("Ensure presign usage file failed", e);
        }
    }

    private static boolean isUsedInternal(String id) {
        try {
            if (!Files.exists(FILE)) {
                return false;
            }
            List<String> lines = Files.readAllLines(FILE, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (line == null || line.isBlank()) continue;
                String trimmed = line.trim();
                if (trimmed.equals(id)) {
                    return true;
                }
                int comma = trimmed.indexOf(',');
                if (comma > 0 && trimmed.substring(comma + 1).equals(id)) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            throw new RuntimeException("Read presign usage file failed", e);
        }
    }

    private static void writeLine(String id) {
        try {
            long now = System.currentTimeMillis();
            String line = now + "," + id + System.lineSeparator();
            Files.writeString(FILE, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException("Write presign usage file failed", e);
        }
    }

    private static void cleanupIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - lastCleanupMillis < CLEANUP_INTERVAL_MILLIS) {
            return;
        }
        lastCleanupMillis = now;
        if (!Files.exists(FILE)) {
            return;
        }
        long cutoff = now - retentionMillis;
        try {
            List<String> lines = Files.readAllLines(FILE, StandardCharsets.UTF_8);
            if (lines.isEmpty()) {
                return;
            }
            StringBuilder sb = new StringBuilder(lines.size() * 48);
            for (String line : lines) {
                if (line == null || line.isBlank()) continue;
                String trimmed = line.trim();
                int comma = trimmed.indexOf(',');
                if (comma <= 0) {
                    sb.append(trimmed).append(System.lineSeparator());
                    continue;
                }
                String tsStr = trimmed.substring(0, comma);
                try {
                    long ts = Long.parseLong(tsStr);
                    if (ts >= cutoff) {
                        sb.append(trimmed).append(System.lineSeparator());
                    }
                } catch (NumberFormatException e) {
                    sb.append(trimmed).append(System.lineSeparator());
                }
            }
            Files.writeString(FILE, sb.toString(), StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Cleanup presign usage file failed", e);
        }
    }
}
