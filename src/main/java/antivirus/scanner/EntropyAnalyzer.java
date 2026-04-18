package antivirus.scanner;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class EntropyAnalyzer {

    private static final int SAMPLE_SIZE = 256 * 1024;
    private static final int STREAM_BUFFER = 8192;

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
}