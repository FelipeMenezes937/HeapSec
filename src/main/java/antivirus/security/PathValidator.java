package antivirus.security;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

public class PathValidator {

    private static final long MAX_FILE_SIZE = 100 * 1024 * 1024;
    private static final long MAX_EXTRACT_RATIO = 1000;

    public static boolean isSymlink(Path path) {
        try {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
            return attrs.isSymbolicLink();
        } catch (Exception e) {
            return true;
        }
    }

    public static boolean isOutsideBase(Path targetPath, Path basePath) {
        try {
            Path targetCanonical = targetPath.toRealPath();
            Path baseCanonical = basePath.toRealPath();
            return !targetCanonical.startsWith(baseCanonical);
        } catch (Exception e) {
            return true;
        }
    }

    public static boolean validateForRead(Path path) {
        try {
            if (!Files.exists(path)) return false;
            if (Files.isDirectory(path)) return false;
            if (isSymlink(path)) return false;
            long size = Files.size(path);
            if (size > MAX_FILE_SIZE) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean validateForWrite(Path path) {
        try {
            if (Files.exists(path)) {
                if (isSymlink(path)) return false;
                if (!Files.isRegularFile(path)) return false;
            }
            Path parent = path.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean validateForDelete(Path path) {
        try {
            if (!Files.exists(path)) return false;
            if (isSymlink(path)) return false;
            if (!Files.isRegularFile(path)) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean validateZipEntry(String entryName, Path baseDir, long compressedSize, long extractedSize) {
        if (extractedSize > MAX_FILE_SIZE) return false;
        if (compressedSize > 0 && extractedSize > compressedSize * MAX_EXTRACT_RATIO) {
            return false;
        }
        String normalized = entryName.replace('\\', '/');
        if (normalized.contains("..")) return false;
        if (normalized.startsWith("/")) return false;
        Path targetPath = baseDir.resolve(normalized).normalize();
        if (isOutsideBase(targetPath, baseDir)) return false;
        return true;
    }

    public static String sanitizePath(String path) {
        if (path == null) return null;
        return path.replaceAll("[<>:\"|?*\\x00-\\x1f]", "_");
    }

    public static class ValidationResult {
        public final boolean valid;
        public final String error;

        private ValidationResult(boolean valid, String error) {
            this.valid = valid;
            this.error = error;
        }

        public static ValidationResult ok() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult error(String msg) {
            return new ValidationResult(false, msg);
        }
    }

    public static ValidationResult validateFileOperation(Path path, Operation operation) {
        switch (operation) {
            case READ:
                if (!validateForRead(path)) {
                    return ValidationResult.error("Arquivo invalido para leitura");
                }
                break;
            case WRITE:
                if (!validateForWrite(path)) {
                    return ValidationResult.error("Arquivo invalido para escrita");
                }
                break;
            case DELETE:
                if (!validateForDelete(path)) {
                    return ValidationResult.error("Arquivo invalido para deletion");
                }
                break;
        }
        return ValidationResult.ok();
    }

    public enum Operation {
        READ, WRITE, DELETE
    }
}