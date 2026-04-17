package antivirus.scanner;

import java.io.*;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ZipExtractor {

    private static final long MAX_EXTRACT_SIZE = 100 * 1024 * 1024;
    private static final int MAX_ENTRIES = 1000;

    public static class ExtractResult {
        public boolean success;
        public String error;
        public int filesFound;
        public long totalSize;
        public Path tempDir;

        public static ExtractResult ok(Path tempDir, int files, long size) {
            ExtractResult r = new ExtractResult();
            r.success = true;
            r.tempDir = tempDir;
            r.filesFound = files;
            r.totalSize = size;
            return r;
        }

        public static ExtractResult error(String msg) {
            ExtractResult r = new ExtractResult();
            r.success = false;
            r.error = msg;
            return r;
        }
    }

    public static ExtractResult extract(byte[] data, String baseName) {
        try {
            Path tempDir = Files.createTempDirectory("antivirus_zip_");
            ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data));
            ZipEntry entry;
            int count = 0;
            long totalSize = 0;

            while ((entry = zis.getNextEntry()) != null) {
                if (count >= MAX_ENTRIES) {
                    zis.close();
                    cleanup(tempDir);
                    return ExtractResult.error(" muitos arquivos");
                }

                String name = entry.getName();
                if (name.contains("..") || name.startsWith("/")) {
                    continue;
                }

                Path outputPath = tempDir.resolve(name);

                if (entry.isDirectory()) {
                    Files.createDirectories(outputPath);
                } else {
                    long size = entry.getSize();
                    if (totalSize + size > MAX_EXTRACT_SIZE) {
                        zis.close();
                        cleanup(tempDir);
                        return ExtractResult.error(" tamanho excedido");
                    }

                    Files.createDirectories(outputPath.getParent());
                    byte[] buffer = new byte[8192];
                    int read;
                    try (OutputStream os = Files.newOutputStream(outputPath)) {
                        while ((read = zis.read(buffer)) != -1) {
                            os.write(buffer, 0, read);
                        }
                    }
                    totalSize += size;
                }
                count++;
                zis.closeEntry();
            }
            zis.close();

            return ExtractResult.ok(tempDir, count, totalSize);
        } catch (Exception e) {
            return ExtractResult.error(e.getMessage());
        }
    }

    public static void cleanup(Path tempDir) {
        try {
            Files.walk(tempDir)
                .sorted(java.util.Comparator.reverseOrder())
                .forEach(p -> {
                    try { Files.delete(p); } catch (Exception e) {}
                });
        } catch (Exception e) {}
    }
}