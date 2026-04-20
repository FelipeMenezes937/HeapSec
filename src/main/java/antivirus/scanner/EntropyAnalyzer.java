package antivirus.scanner;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class EntropyAnalyzer {

    private static final int SAMPLE_SIZE = 64 * 1024;
    private static final int STREAM_BUFFER = 4096;

    private static final java.util.Set<String> SAFE_MAGIC = java.util.Set.of(
        "FFD8FF",   // JPEG
        "494433",   // MP3
        "FFFBE0",   // MP3
        "FFFA90",   // MP3
        "504B03",   // ZIP/JAR/DOCX
        "504B05",   // ZIP empty
        "504B07",   // ZIP spanned
        "526172",   // RAR
        "377A18",   // 7z
        "89504E47", // PNG
        "47494638", // GIF
        "25504446", // PDF
        "377AB627", // JPEG2000
        "4D546864", // MIDI
        "424D",     // BMP
        "49492A00", // TIFF little-endian
        "4D4D002A", // TIFF big-endian
        "1F8B"      // GZ
    );

    public double calculateEntropy(byte[] data) {
        int len = data.length;
        if (len == 0) return 0;

        int[] freq = new int[256];
        int count = 0;

        if (len <= SAMPLE_SIZE) {
            for (byte b : data) {
                freq[b & 0xFF]++;
            }
            count = len;
        } else {
            int step = len / SAMPLE_SIZE;
            for (int i = 0; i < len && count < SAMPLE_SIZE; i += step) {
                freq[data[i] & 0xFF]++;
                count++;
            }
        }

        return calculateEntropyFromFreq(freq, count);
    }

    public double calculateEntropyStreaming(Path file) throws Exception {
        long size = Files.size(file);
        if (size == 0) return 0;

        int[] freq = new int[256];
        int count = 0;

        if (size <= SAMPLE_SIZE) {
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buffer = new byte[STREAM_BUFFER];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    for (int i = 0; i < read; i++) {
                        freq[buffer[i] & 0xFF]++;
                    }
                    count += read;
                }
            }
        } else {
            long step = size / SAMPLE_SIZE;
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buffer = new byte[STREAM_BUFFER];
                long pos = 0;
                int read;
                while ((read = in.read(buffer)) != -1) {
                    for (int i = 0; i < read && count < SAMPLE_SIZE; i++) {
                        if (pos % step == 0) {
                            freq[buffer[i] & 0xFF]++;
                            count++;
                        }
                        pos++;
                    }
                    if (count >= SAMPLE_SIZE) break;
                }
            }
        }

        return calculateEntropyFromFreq(freq, count);
    }

    private double calculateEntropyFromFreq(int[] freq, int count) {
        if (count == 0) return 0;
        double entropy = 0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / count;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    public boolean isCompressed(byte[] data) {
        if (data.length < 4) return false;
        int magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        return magic == 0x504b0304 || magic == 0x504b0506 ||
               magic == 0x377a1850 || magic == 0x425a68 ||
               (data[0] == 0x1f && data[1] == (byte)0x8b);
    }

    public boolean isCompressedStreaming(Path file) throws Exception {
        byte[] header = new byte[4];
        try (InputStream in = Files.newInputStream(file)) {
            int read = in.read(header);
            if (read < 4) return false;
        }
        int magic = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
        return magic == 0x504b0304 || magic == 0x504b0506 ||
               magic == 0x377a1850 || magic == 0x425a68 ||
               (header[0] == 0x1f && header[1] == (byte)0x8b);
    }

    public boolean isLikelyLegitimate(byte[] data, double entropy) {
        if (data.length > 50 * 1024 * 1024) return true;
        if (isCompressed(data)) return true;
        int zipHeader = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        if (zipHeader == 0x504b0304 || zipHeader == 0x504b0506) return true;
        return false;
    }

    public boolean isKnownSafeMagic(byte[] data) {
        if (data.length < 2) return false;
        int b0 = data[0] & 0xFF;
        int b1 = data[1] & 0xFF;

        if (b0 == 0xFF && (b1 == 0xFB || b1 == 0xFA || b1 == 0xF3 || b1 == 0xE0)) {
            return true;
        }

        String magic = String.format("%02X%02X%02X", b0, b1, data[2] & 0xFF);
        if (SAFE_MAGIC.contains(magic)) return true;

        if (data.length >= 4) {
            String magic4 = String.format("%02X%02X%02X%02X", b0, b1, data[2] & 0xFF, data[3] & 0xFF);
            return SAFE_MAGIC.contains(magic4);
        }
        return false;
    }
}