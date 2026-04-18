package antivirus.scanner;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.concurrent.ConcurrentHashMap;

public class HashCache {

    private static final String CACHE_FILE = System.getProperty("user.home") + "/.antivirus/cache.db";
    private static final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public static class CacheEntry {
        public String hash;
        public long timestamp;
        public String result;
        public long fileSize;

        CacheEntry(String hash, long timestamp, String result, long fileSize) {
            this.hash = hash;
            this.timestamp = timestamp;
            this.result = result;
            this.fileSize = fileSize;
        }
    }

    public static void init() {
        try {
            if (Files.exists(Paths.get(CACHE_FILE))) {
                Files.lines(Paths.get(CACHE_FILE)).forEach(line -> {
                    try {
                        String[] parts = line.split(":", 5);
                        if (parts.length >= 4) {
                            cache.put(parts[0], new CacheEntry(
                                parts[1],
                                Long.parseLong(parts[2]),
                                parts[3],
                                Long.parseLong(parts[4])
                            ));
                        }
                    } catch (Exception e) {
                        // skip invalid lines
                    }
                });
            }
        } catch (Exception e) {
            System.err.println("Cache load error: " + e.getMessage());
        }
    }

    public static void save() {
        try {
            Files.createDirectories(Paths.get(CACHE_FILE).getParent());
            PrintWriter w = new PrintWriter(new FileWriter(CACHE_FILE));
            for (var e : cache.entrySet()) {
                CacheEntry entry = e.getValue();
                w.println(e.getKey() + ":" + entry.hash + ":" + entry.timestamp + ":" + entry.result + ":" + entry.fileSize);
            }
            w.close();
        } catch (Exception e) {
            System.err.println("Cache save error: " + e.getMessage());
        }
    }

    public static String getQuickHash(byte[] data) {
        try {
            int len = data.length;
            int useLen = Math.min(len, 16384);
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(data, 0, useLen);
            if (len > 16384) {
                md.update(data, len - 8192, 8192);
            }
            bytesToHex(md.digest());
            return md.digest().toString();
        } catch (Exception e) {
            return String.valueOf(data.length);
        }
    }

    public static String getFileHash(Path file) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            long size = Files.size(file);
            byte[] buf = new byte[8192];

            try (InputStream in = Files.newInputStream(file)) {
                int read = in.read(buf);
                md.update(buf, 0, read);
            }

            if (size > 8192) {
                long skip = size - 8192;
                try (InputStream in = Files.newInputStream(file)) {
                    long skipped = in.skip(skip);
                    int read = in.read(buf);
                    if (read > 0) md.update(buf, 0, read);
                }
            }

            String hash = bytesToHex(md.digest());
            return hash + "-" + size;
        } catch (Exception e) {
            return String.valueOf(file.toAbsolutePath());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static boolean isCached(Path file) {
        String key = file.toAbsolutePath().toString();
        return cache.containsKey(key);
    }

    public static String getCachedResult(Path file) {
        String key = file.toAbsolutePath().toString();
        CacheEntry entry = cache.get(key);
        if (entry == null) return null;

        try {
            long currentSize = Files.size(file);
            if (currentSize != entry.fileSize) {
                cache.remove(key);
                return null;
            }
            return entry.result;
        } catch (Exception e) {
            return null;
        }
    }

    public static void put(Path file, String result) {
        try {
            String key = file.toAbsolutePath().toString();
            String hash = getFileHash(file);
            long size = Files.size(file);
            cache.put(key, new CacheEntry(hash, System.currentTimeMillis(), result, size));
        } catch (Exception e) {
            // silent
        }
    }

    public static int size() {
        return cache.size();
    }

    public static void clear() {
        cache.clear();
        try {
            Files.deleteIfExists(Path.of(CACHE_FILE));
        } catch (Exception e) {
            // silent
        }
    }
}