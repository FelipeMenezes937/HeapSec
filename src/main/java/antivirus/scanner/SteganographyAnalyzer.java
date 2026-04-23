package antivirus.scanner;

public class SteganographyAnalyzer {

    private static final int CHUNK_SIZE = 65536;
    private static final double DCT_THRESHOLD = 0.95;
    private static final double CHI_SQUARE_THRESHOLD = 0.97;
    private static final int EOF_ANOMALY_SCORE = 40;
    private static final int DCT_SCORE = 70;
    private static final int LSB_SCORE = 50;
    private static final int MAGIC_MISMATCH_SCORE = 60;

    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    private static final byte[] GIF_MAGIC = {0x47, 0x49, 0x46};
    private static final byte[] BMP_MAGIC = {0x42, 0x4D};
    private static final byte[] TIFF_LE_MAGIC = {0x49, 0x49, 0x2A, 0x00};
    private static final byte[] TIFF_BE_MAGIC = {0x4D, 0x4D, 0x00, 0x2A};
    private static final byte[] PDF_MAGIC = {0x25, 0x50, 0x44, 0x46};
    private static final byte[] WAV_MAGIC = {0x52, 0x49, 0x46, 0x46};
    private static final byte[] MP3_MAGIC = {(byte) 0xFF};

    public SteganographyResult analyze(byte[] data, String fileName) {
        if (data.length < 64) {
            return new SteganographyResult(false, 0, null);
        }

        int totalScore = 0;
        StringBuilder detectedMethods = new StringBuilder();

        int eofScore = checkEOFAnomaly(data, fileName);
        if (eofScore > 0) {
            totalScore += eofScore;
            detectedMethods.append("EOF,");
        }

        int magicScore = checkMagicByteConsistency(data, fileName);
        if (magicScore > 0) {
            totalScore += magicScore;
            detectedMethods.append("MAGIC_MISMATCH,");
        }

        if (isJPEG(data)) {
            int dctScore = analyzeDCT(data);
            if (dctScore > 0) {
                totalScore += dctScore;
                detectedMethods.append("DCT,");
            }
        } else if (isPNG(data) || isBMP(data) || isGIF(data) || isTIFF(data)) {
            int lsbScore = analyzeLSB(data);
            if (lsbScore > 0) {
                totalScore += lsbScore;
                detectedMethods.append("LSB,");
            }
        } else if (isWAV(data)) {
            int lsbScore = analyzeLSB(data);
            if (lsbScore > 0) {
                totalScore += lsbScore;
                detectedMethods.append("LSB_AUDIO,");
            }
        } else if (isPDF(data)) {
            int pdfScore = checkPDFAnomaly(data);
            if (pdfScore > 0) {
                totalScore += pdfScore;
                detectedMethods.append("PDF_STREAM,");
            }
        }

        String methods = detectedMethods.length() > 0 ? detectedMethods.toString() : null;
        return new SteganographyResult(totalScore > 0, totalScore, methods);
    }

    private boolean isJPEG(byte[] data) {
        if (data.length < 3) return false;
        return data[0] == JPEG_MAGIC[0] && data[1] == JPEG_MAGIC[1] && data[2] == JPEG_MAGIC[2];
    }

    private boolean isPNG(byte[] data) {
        if (data.length < 8) return false;
        for (int i = 0; i < 8; i++) {
            if (data[i] != PNG_MAGIC[i]) return false;
        }
        return true;
    }

    private boolean isGIF(byte[] data) {
        if (data.length < 3) return false;
        return data[0] == GIF_MAGIC[0] && data[1] == GIF_MAGIC[1] && data[2] == GIF_MAGIC[2];
    }

    private boolean isBMP(byte[] data) {
        if (data.length < 2) return false;
        return data[0] == BMP_MAGIC[0] && data[1] == BMP_MAGIC[1];
    }

    private boolean isTIFF(byte[] data) {
        if (data.length < 4) return false;
        for (int i = 0; i < 4; i++) {
            if (data[i] != TIFF_LE_MAGIC[i] && data[i] != TIFF_BE_MAGIC[i]) return false;
        }
        return true;
    }

    private boolean isPDF(byte[] data) {
        if (data.length < 4) return false;
        return data[0] == PDF_MAGIC[0] && data[1] == PDF_MAGIC[1] && data[2] == PDF_MAGIC[2] && data[3] == PDF_MAGIC[3];
    }

    private boolean isWAV(byte[] data) {
        if (data.length < 4) return false;
        return data[0] == WAV_MAGIC[0] && data[1] == WAV_MAGIC[1] && data[2] == WAV_MAGIC[2] && data[3] == WAV_MAGIC[3];
    }

    private int checkEOFAnomaly(byte[] data, String fileName) {
        String ext = fileName.toLowerCase();

        if (isJPEG(data)) {
            for (int i = data.length - 2; i >= data.length - 10 && i > 0; i--) {
                if (data[i] == (byte) 0xD9 && data[i - 1] == (byte) 0xD9) {
                    if (i < data.length - 2) {
                        for (int j = i + 1; j < data.length; j++) {
                            if (data[j] != 0x00 && data[j] != (byte) 0xFF && data[j] != 0x0D && data[j] != 0x0A) {
                                return EOF_ANOMALY_SCORE;
                            }
                        }
                    }
                }
            }
        } else if (isPNG(data)) {
            int endIdx = findPNGEndMarker(data);
            if (endIdx > 0 && endIdx + 12 < data.length) {
                for (int j = endIdx + 12; j < data.length; j++) {
                    if (data[j] != 0x00) {
                        return EOF_ANOMALY_SCORE;
                    }
                }
            }
        } else if (isPDF(data)) {
            for (int i = data.length - 9; i >= 0; i--) {
                if (data[i] == 0x25 && i + 8 < data.length &&
                    data[i] == 0x25 && data[i+1] == 0x45 && data[i+2] == 0x4F &&
                    data[i+3] == 0x46) {
                    if (i + 9 < data.length) {
                        for (int j = i + 9; j < data.length; j++) {
                            if (data[j] != 0x0A && data[j] != 0x0D && data[j] != 0x20) {
                                return EOF_ANOMALY_SCORE;
                            }
                        }
                    }
                }
            }
        }

        return 0;
    }

    private int findPNGEndMarker(byte[] data) {
        for (int i = data.length - 20; i > 0; i--) {
            if (data[i] == 0x49 && data[i+1] == 0x45 && data[i+2] == 0x4E && data[i+3] == 0x44) {
                return i;
            }
        }
        return -1;
    }

    private int checkMagicByteConsistency(byte[] data, String fileName) {
        String ext = fileName.toLowerCase();

        if (ext.endsWith(".jpg") || ext.endsWith(".jpeg")) {
            if (!isJPEG(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".png")) {
            if (!isPNG(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".gif")) {
            if (!isGIF(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".bmp")) {
            if (!isBMP(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".tiff") || ext.endsWith(".tif")) {
            if (!isTIFF(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".pdf")) {
            if (!isPDF(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".wav")) {
            if (!isWAV(data)) return MAGIC_MISMATCH_SCORE;
        } else if (ext.endsWith(".mp3")) {
            if (!isMP3(data)) return MAGIC_MISMATCH_SCORE;
        }

        return 0;
    }

    private boolean isMP3(byte[] data) {
        if (data.length < 2) return false;
        return (data[0] == (byte) 0xFF && (data[1] & 0xE0) == 0xE0);
    }

    private int checkPDFAnomaly(byte[] data) {
        int streamCount = 0;
        int endstreamCount = 0;

        for (int i = 0; i < data.length - 8; i++) {
            if (data[i] == 0x73 && data[i+1] == 0x74 && data[i+2] == 0x72 && data[i+3] == 0x65 && data[i+4] == 0x61 && data[i+5] == 0x6D) {
                streamCount++;
            }
            if (data[i] == 0x65 && data[i+1] == 0x6E && data[i+2] == 0x64 && data[i+3] == 0x73 && data[i+4] == 0x74 && data[i+5] == 0x72 && data[i+6] == 0x65 && data[i+7] == 0x61 && data[i+8] == 0x6D) {
                endstreamCount++;
            }
        }

        if (streamCount > endstreamCount) {
            return EOF_ANOMALY_SCORE;
        }

        return 0;
    }

    private int analyzeDCT(byte[] data) {
        int[] dctCoeffs = extractDCTCoefficients(data);
        if (dctCoeffs.length < 64) {
            return 0;
        }

        double variance = calculateVariance(dctCoeffs);
        double mean = calculateMean(dctCoeffs);

        if (mean == 0) {
            return 0;
        }

        double ratio = variance / mean;
        if (ratio > DCT_THRESHOLD * 1000) {
            return DCT_SCORE;
        }

        int zeroCount = 0;
        for (int coeff : dctCoeffs) {
            if (coeff == 0) zeroCount++;
        }
        double zeroRatio = (double) zeroCount / dctCoeffs.length;
        if (zeroRatio < 0.05 || zeroRatio > 0.95) {
            return DCT_SCORE / 2;
        }

        return 0;
    }

    private int[] extractDCTCoefficients(byte[] data) {
        int[] coeffs = new int[Math.min(data.length / 10, 10000)];
        int idx = 0;

        for (int i = 2; i < data.length - 64 && idx < coeffs.length; i++) {
            if (data[i] == (byte) 0xFF) {
                int next = i + 1;
                if (next < data.length && (data[next] & 0xF0) == 0xC0) {
                    int skip = ((data[next + 1] & 0xFF) << 8) | (data[next + 2] & 0xFF);
                    int hoffset = i + skip + 2;

                    if (hoffset > 0 && hoffset < data.length - 64) {
                        for (int j = hoffset + 2; j < Math.min(hoffset + 66, data.length) && idx < coeffs.length; j++) {
                            coeffs[idx++] = data[j];
                        }
                    }
                } else if (next < data.length && (data[next] & 0xF0) == 0xD0) {
                    i = next;
                }
            }
        }

        int[] result = new int[idx];
        System.arraycopy(coeffs, 0, result, 0, idx);
        return result;
    }

    private int analyzeLSB(byte[] data) {
        if (data.length < 256) {
            return 0;
        }

        int sampleSize = Math.min(data.length, CHUNK_SIZE);
        int[] lsbCounts = new int[2];

        for (int i = 0; i < sampleSize; i++) {
            int lsb = data[i] & 1;
            lsbCounts[lsb]++;
        }

        double ratio = (double) lsbCounts[0] / (lsbCounts[0] + lsbCounts[1]);
        if (Math.abs(ratio - 0.5) < 1 - CHI_SQUARE_THRESHOLD) {
            return 0;
        }

        if (ratio < 0.4 || ratio > 0.6) {
            return LSB_SCORE;
        }

        int[] pairCounts = new int[256];
        for (int i = 0; i < sampleSize - 1; i++) {
            int pair = ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            pairCounts[pair]++;
        }

        int expectedPairs = sampleSize / 256;
        double chiSquare = 0;
        for (int count : pairCounts) {
            if (count > 0) {
                double diff = count - expectedPairs;
                chiSquare += (diff * diff) / expectedPairs;
            }
        }

        chiSquare = chiSquare / 256;
        if (chiSquare > 100) {
            return LSB_SCORE;
        }

        return 0;
    }

    private double calculateVariance(int[] values) {
        if (values.length == 0) return 0;
        double mean = calculateMean(values);
        double sumSquaredDiff = 0;
        for (int val : values) {
            double diff = val - mean;
            sumSquaredDiff += diff * diff;
        }
        return sumSquaredDiff / values.length;
    }

    private double calculateMean(int[] values) {
        if (values.length == 0) return 0;
        long sum = 0;
        for (int val : values) {
            sum += val;
        }
        return (double) sum / values.length;
    }

    public static class SteganographyResult {
        private final boolean detected;
        private final int score;
        private final String methods;

        public SteganographyResult(boolean detected, int score, String methods) {
            this.detected = detected;
            this.score = score;
            this.methods = methods;
        }

        public boolean isDetected() {
            return detected;
        }

        public int getScore() {
            return score;
        }

        public String getMethods() {
            return methods;
        }
    }
}