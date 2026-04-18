package antivirus.scanner;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

import antivirus.security.PathValidator;

public class DirectoryCache {
    
    private static final String CACHE_DIR = System.getProperty("user.home") + "/.antivirus";
    private static final Path CACHE_FILE = Path.of(CACHE_DIR, "dir_cache.txt");
    
    private static final Map<String, DirInfo> cache = new HashMap<>();
    
    public static class DirInfo {
        public long lastModified;
        public long totalSize;
        public int fileCount;
        public String result;
        
        DirInfo(long lastModified, long totalSize, int fileCount, String result) {
            this.lastModified = lastModified;
            this.totalSize = totalSize;
            this.fileCount = fileCount;
            this.result = result;
        }
    }
    
    public static void init() {
        if (!Files.exists(CACHE_FILE)) return;
        try {
            Files.lines(CACHE_FILE).forEach(line -> {
                String[] parts = line.split("\\|");
                if (parts.length >= 5) {
                    String dir = parts[0];
                    long lm = Long.parseLong(parts[1]);
                    long ts = Long.parseLong(parts[2]);
                    int fc = Integer.parseInt(parts[3]);
                    String res = parts[4];
                    cache.put(dir, new DirInfo(lm, ts, fc, res));
                }
            });
        } catch (Exception e) {
            // silencioso
        }
    }
    
    public static void save() {
        try {
            StringBuilder sb = new StringBuilder();
            for (var e : cache.entrySet()) {
                DirInfo info = e.getValue();
                sb.append(e.getKey()).append("|")
                  .append(info.lastModified).append("|")
                  .append(info.totalSize).append("|")
                  .append(info.fileCount).append("|")
                  .append(info.result).append("\n");
            }
            Files.writeString(CACHE_FILE, sb.toString());
        } catch (Exception e) {
            // silencioso
        }
    }
    
    public static DirInfo getDirInfo(String dirPath) {
        try {
            Path dir = Path.of(dirPath).toAbsolutePath().normalize();
            if (!Files.exists(dir) || !Files.isDirectory(dir)) return null;
            if (PathValidator.isSymlink(dir)) return null;
            
            long newest = 0;
            long totalSize = 0;
            int fileCount = 0;
            
            var files = Files.walk(dir).filter(p -> {
                try { 
                    if (p.toFile().isFile() && !p.toString().contains("/.") && !PathValidator.isSymlink(p)) {
                        if (Files.size(p) <= 100 * 1024 * 1024) {
                            return true;
                        }
                    }
                    return false;
                }
                catch (Exception e) { return false; }
            }).toList();
            
            for (Path f : files) {
                try {
                    long m = Files.getLastModifiedTime(f).toMillis();
                    if (m > newest) newest = m;
                    totalSize += Files.size(f);
                    fileCount++;
                } catch (Exception ignored) {}
            }
            
            return new DirInfo(newest, totalSize, fileCount, null);
        } catch (Exception e) {
            return null;
        }
    }
    
    public static boolean isDirectoryClean(String dirPath) {
        DirInfo current = getDirInfo(dirPath);
        if (current == null) return false;
        
        DirInfo cached = cache.get(dirPath);
        if (cached == null) return false;
        
        return cached.lastModified == current.lastModified && 
               cached.totalSize == current.totalSize &&
               cached.fileCount == current.fileCount;
    }
    
    public static void markDirectory(String dirPath, String result) {
        DirInfo current = getDirInfo(dirPath);
        if (current == null) return;
        
        cache.put(dirPath, new DirInfo(current.lastModified, current.totalSize, current.fileCount, result));
        save();
    }
    
    public static void clear() {
        cache.clear();
        try {
            Files.deleteIfExists(CACHE_FILE);
        } catch (Exception ignored) {}
    }
    
    public static int size() {
        return cache.size();
    }
}